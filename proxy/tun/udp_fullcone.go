package tun

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// sub-handler specifically for udp connections under main handler
type udpConnectionHandler struct {
	sync.RWMutex

	udpConns map[net.Destination]*udpConn
	// closed is set by closeAll; a packet that arrives after it opens no flow
	closed     bool
	maxFlows   int
	queueLimit int
	queueBytes *udpQueueBudget

	handleConnection func(conn net.Conn, dest net.Destination)
	writePacket      func(data []byte, src net.Destination, dst net.Destination) error
}

func newUdpConnectionHandler(handleConnection func(conn net.Conn, dest net.Destination), writePacket func(data []byte, src net.Destination, dst net.Destination) error) *udpConnectionHandler {
	handler := &udpConnectionHandler{
		udpConns:         make(map[net.Destination]*udpConn),
		handleConnection: handleConnection,
		writePacket:      writePacket,
		queueLimit:       udpQueueLimit,
	}

	return handler
}

// HandlePacket handles UDP packets coming from tun, to forward to the dispatcher
// this custom handler support FullCone NAT of returning packets, binding connection only by the source addr:port
func (u *udpConnectionHandler) HandlePacket(src net.Destination, dst net.Destination, data *buf.Buffer) {
	data.UDP = &dst

	u.RLock()
	conn, found := u.udpConns[src]
	if found {
		if !conn.queue.push(data) {
			errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full")
			data.Release()
		}
		u.RUnlock()
		return
	}
	u.RUnlock()

	u.Lock()
	defer u.Unlock()

	if u.closed {
		data.Release()
		return
	}
	conn, found = u.udpConns[src]
	if !found {
		if u.maxFlows > 0 && len(u.udpConns) >= u.maxFlows {
			data.Release()
			return
		}
		conn = &udpConn{handler: u, queue: newPacketQueue(u.queueLimit), src: src, dst: dst}
		conn.queue.budget = u.queueBytes
		if !conn.queue.push(data) {
			data.Release()
			return
		}
		u.udpConns[src] = conn
		go u.handleConnection(conn, dst)
		return
	}

	// queue the packet for the reader of the connection, or discard it
	if !conn.queue.push(data) {
		errors.LogDebug(context.Background(), "drop udp with size ", data.Len(), " to ", dst.NetAddr(), " original ", conn.dst.NetAddr(), " > queue full 2")
		data.Release()
	}
}

// closeAll ends every UDP flow and takes no new ones: the readers get EOF, so the dispatch of each flow
// returns and lets go of its outbound. Called when the stack closes; without it an inbound's UDP flows,
// and whatever carries them, outlive the instance.
func (u *udpConnectionHandler) closeAll() {
	u.reset(true)
}

func (u *udpConnectionHandler) reset(closing bool) {
	u.Lock()
	u.closed = u.closed || closing
	conns := make([]*udpConn, 0, len(u.udpConns))
	for _, c := range u.udpConns {
		conns = append(conns, c)
	}
	u.udpConns = make(map[net.Destination]*udpConn)
	u.Unlock()
	for _, c := range conns {
		c.queue.discard()
	}
}

func (q *packetQueue) discard() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.notify)
	}
	for _, packet := range q.items {
		q.releaseCapacity(packet)
		packet.Release()
	}
	q.items = nil
}

func (u *udpConnectionHandler) connectionFinished(conn *udpConn) {
	u.Lock()
	// Close runs twice per flow; a newer conn may already own this src.
	if u.udpConns[conn.src] == conn {
		delete(u.udpConns, conn.src)
		if conn.queue.budget != nil {
			// The dispatcher has finished. Release the shared budget even
			// when no reader is left to drain its queue.
			conn.queue.discard()
		} else {
			conn.queue.close()
		}
	}
	u.Unlock()
}

// udp connection abstraction
type udpConn struct {
	handler *udpConnectionHandler

	queue *packetQueue
	src   net.Destination
	dst   net.Destination
}

func (c *udpConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b, ok := c.queue.pop()
	if !ok {
		return nil, io.EOF
	}
	return buf.MultiBuffer{b}, nil
}

// Read packets from the connection
func (c *udpConn) Read(p []byte) (int, error) {
	b, ok := c.queue.pop()
	if !ok {
		return 0, io.EOF
	}
	defer b.Release()
	n := copy(p, b.Bytes())
	if n != int(b.Len()) {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

func (c *udpConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		dst := c.dst
		if b.UDP != nil {
			if b.UDP.Address.Family().IsDomain() {
				errors.LogError(context.Background(), "impossible domain packet ", b.UDP, " reply via original target ", dst)
			} else {
				dst = *b.UDP
			}
		}
		err := c.writeReply(b.Bytes(), dst)
		if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

// Write returning packets back
func (c *udpConn) Write(p []byte) (int, error) {
	if err := c.writeReply(p, c.dst); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *udpConn) writeReply(payload []byte, from net.Destination) error {
	u := c.handler
	if c.queue.budget != nil {
		// A network change can replace the flow while its upstream still has
		// a reply in flight. Keep writes and removal ordered for this port.
		u.RLock()
		defer u.RUnlock()
		if u.udpConns[c.src] != c {
			return io.ErrClosedPipe
		}
	}
	return u.writePacket(payload, from, c.src)
}

func (c *udpConn) Close() error {
	c.handler.connectionFinished(c)

	return nil
}

func (c *udpConn) LocalAddr() net.Addr {
	return c.dst.RawNetAddr()
}

func (c *udpConn) RemoteAddr() net.Addr {
	return c.src.RawNetAddr()
}

func (c *udpConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// udpQueueLimit bounds the packets waiting for one UDP flow; more are dropped.
const udpQueueLimit = 1024

const (
	mobileUDPQueueBytes   = 2 << 20
	mobileUDPPerFlowBytes = 256 << 10
)

type udpQueueBudget struct {
	retained atomic.Int64
}

func (b *udpQueueBudget) reserve(size int64) bool {
	for retained := b.retained.Load(); retained+size <= mobileUDPQueueBytes; retained = b.retained.Load() {
		if b.retained.CompareAndSwap(retained, retained+size) {
			return true
		}
	}
	return false
}

// packetQueue holds the packets waiting for one UDP flow. Unlike a buffered
// channel of the same bound it only allocates for packets actually queued, so
// the many idle flows kept until the idle timeout cost next to nothing.
type packetQueue struct {
	mu            sync.Mutex
	items         []*buf.Buffer
	limit         int
	notify        chan struct{}
	closed        bool
	budget        *udpQueueBudget
	retainedBytes int64
}

func newPacketQueue(limit int) *packetQueue {
	return &packetQueue{limit: limit, notify: make(chan struct{}, 1)}
}

// push queues b and reports whether it was accepted.
func (q *packetQueue) push(b *buf.Buffer) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.items) >= q.limit {
		return false
	}
	if q.budget != nil {
		size := int64(b.Cap())
		if q.retainedBytes+size > mobileUDPPerFlowBytes || !q.budget.reserve(size) {
			return false
		}
		q.retainedBytes += size
	}
	q.items = append(q.items, b)
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}

// pop blocks until a packet is queued or the queue is closed and drained.
func (q *packetQueue) pop() (*buf.Buffer, bool) {
	for {
		q.mu.Lock()
		if len(q.items) > 0 {
			b := q.items[0]
			q.releaseCapacity(b)
			q.items[0] = nil
			q.items = q.items[1:]
			if len(q.items) == 0 {
				q.items = nil
			}
			q.mu.Unlock()
			return b, true
		}
		if q.closed {
			q.mu.Unlock()
			return nil, false
		}
		q.mu.Unlock()
		<-q.notify
	}
}

// releaseCapacity returns the queue reservation before giving up the buffer.
// q.mu is held.
func (q *packetQueue) releaseCapacity(packet *buf.Buffer) {
	if q.budget != nil {
		size := int64(packet.Cap())
		q.retainedBytes -= size
		q.budget.retained.Add(-size)
	}
}

func (q *packetQueue) close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		close(q.notify)
	}
}
