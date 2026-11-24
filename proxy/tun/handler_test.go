package tun

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type testCounter struct {
	value int64
}

func (c *testCounter) Value() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *testCounter) Set(value int64) int64 {
	return atomic.SwapInt64(&c.value, value)
}

func (c *testCounter) Add(value int64) int64 {
	return atomic.AddInt64(&c.value, value) - value
}

type testConn struct {
	reader *bytes.Reader
	writer bytes.Buffer
}

func newTestConn(input []byte) *testConn {
	return &testConn{reader: bytes.NewReader(input)}
}

func (c *testConn) Read(payload []byte) (int, error) {
	return c.reader.Read(payload)
}

func (c *testConn) Write(payload []byte) (int, error) {
	return c.writer.Write(payload)
}

func (c *testConn) Close() error {
	return nil
}

func (c *testConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1080}
}

func (c *testConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 12345}
}

func (c *testConn) SetDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *testConn) SetWriteDeadline(time.Time) error {
	return nil
}

type testDispatcher struct {
	writePayload []byte
	readBytes    int32
}

func (d *testDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (d *testDispatcher) Start() error {
	return nil
}

func (d *testDispatcher) Close() error {
	return nil
}

func (d *testDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	return nil, nil
}

func (d *testDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	mb, err := link.Reader.ReadMultiBuffer()
	if err != nil {
		return err
	}
	atomic.StoreInt32(&d.readBytes, mb.Len())
	buf.ReleaseMulti(mb)

	return link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(d.writePayload)})
}

// closableConn is a connection that is its own writer, as the ones of the stack are
type closableConn struct {
	*testConn
	closed int32
}

func (c *closableConn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (c *closableConn) Close() error {
	atomic.AddInt32(&c.closed, 1)
	return nil
}

// closingDispatcher does what an outbound does when the other side has no more to send
type closingDispatcher struct {
	testDispatcher
	conn   *closableConn
	closed int32
}

func (d *closingDispatcher) DispatchLink(_ context.Context, _ xnet.Destination, link *transport.Link) error {
	common.Close(link.Writer)
	d.closed = atomic.LoadInt32(&d.conn.closed)
	return nil
}

func TestHandlerClosesTunConnectionWhenBothSidesAreDone(t *testing.T) {
	conn := &closableConn{testConn: newTestConn(nil)}
	dispatcher := &closingDispatcher{conn: conn}
	handler := &Handler{
		ctx:        context.Background(),
		config:     &Config{},
		dispatcher: dispatcher,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if dispatcher.closed != 0 {
		t.Fatal("the connection was closed with its writer, while the system may still be sending")
	}
	if got := atomic.LoadInt32(&conn.closed); got != 1 {
		t.Fatalf("connection closed %d times, want 1", got)
	}
}

func TestHandlerCountsTunConnectionTraffic(t *testing.T) {
	uplinkCounter := new(testCounter)
	downlinkCounter := new(testCounter)
	dispatcher := &testDispatcher{writePayload: []byte("downlink")}
	conn := newTestConn([]byte("uplink"))

	handler := &Handler{
		ctx:             context.Background(),
		config:          &Config{},
		dispatcher:      dispatcher,
		uplinkCounter:   uplinkCounter,
		downlinkCounter: downlinkCounter,
	}
	handler.HandleConnection(conn, xnet.TCPDestination(xnet.LocalHostIP, 443))

	if got := uplinkCounter.Value(); got != int64(len("uplink")) {
		t.Fatalf("unexpected uplink counter: got %d, want %d", got, len("uplink"))
	}
	if got := downlinkCounter.Value(); got != int64(len("downlink")) {
		t.Fatalf("unexpected downlink counter: got %d, want %d", got, len("downlink"))
	}
	if got := int(atomic.LoadInt32(&dispatcher.readBytes)); got != len("uplink") {
		t.Fatalf("dispatcher read unexpected bytes: got %d, want %d", got, len("uplink"))
	}
	if got := conn.writer.String(); got != "downlink" {
		t.Fatalf("connection write mismatch: got %q, want %q", got, "downlink")
	}
}

// a dispatcher that only returns when its context ends
type blockingDispatcher struct {
	testDispatcher
	entered chan struct{}
}

type capturingDispatcher struct {
	testDispatcher
	started chan context.Context
}

func (d *capturingDispatcher) DispatchLink(ctx context.Context, _ xnet.Destination, _ *transport.Link) error {
	d.started <- ctx
	<-ctx.Done()
	return ctx.Err()
}

func TestNetworkResetRetiresTransportsBeforeDispatch(t *testing.T) {
	var reset func(bool)
	var retireCount int
	var previous context.Context
	dispatcher := &capturingDispatcher{started: make(chan context.Context, 2)}
	handler := &Handler{
		config:        &Config{MTU: testMTU},
		hostDevice:    newLink(),
		dispatcher:    dispatcher,
		policyManager: policy.DefaultManager{},
		flowReset: flowReset{
			register: func(run func(bool)) { reset = run },
		},
	}
	handler.flowReset.retireTransports = func() {
		retireCount++
		if previous.Err() != context.Canceled {
			t.Error("old flow was still live when transport pools began retiring")
		}
		if handler.flowMu.TryLock() {
			handler.flowMu.Unlock()
			t.Error("new flows could begin while transport pools were retiring")
		}
	}
	handler.ctx, handler.cancel = context.WithCancel(context.Background())
	handler.flowCtx, handler.cancelFlows = context.WithCancel(handler.ctx)
	if err := handler.Start(); err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	if reset == nil {
		t.Fatal("handler did not register a network reset")
	}

	dest := xnet.TCPDestination(xnet.LocalHostIP, 443)
	go handler.HandleConnection(newTestConn(nil), dest)
	select {
	case previous = <-dispatcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first flow did not start")
	}
	reset(false)
	if retireCount != 1 {
		t.Fatal("transport pools were not retired")
	}
	discarded := make(chan struct{})
	go func() {
		handler.HandleConnection(newTestConn(nil), dest)
		close(discarded)
	}()
	select {
	case <-discarded:
	case <-time.After(2 * time.Second):
		t.Fatal("offline flow did not close")
	}
	select {
	case <-dispatcher.started:
		t.Fatal("a flow reached the dispatcher while offline")
	default:
	}
	reset(true)
	if retireCount != 1 {
		t.Fatal("recovery retired the same transport pools twice")
	}
	go handler.HandleConnection(newTestConn(nil), dest)
	select {
	case next := <-dispatcher.started:
		if next.Err() != nil {
			t.Fatalf("new flow failed after the reset: %v", next.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new flow did not start after the reset")
	}
}

func TestRetiredTCPDoesNotDispatchOnNewNetwork(t *testing.T) {
	dispatcher := &capturingDispatcher{started: make(chan context.Context, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := &Handler{
		ctx:        ctx,
		flowCtx:    ctx,
		flowReset:  flowReset{register: func(func(bool)) {}},
		config:     &Config{},
		dispatcher: dispatcher,
	}
	conn := newTCPConn(&stack{mtu: testMTU, window: tcpWindow}, flow{
		src: netip.MustParseAddrPort("198.18.0.2:34000"),
		dst: netip.MustParseAddrPort("192.0.2.1:443"),
	})
	conn.err = io.ErrClosedPipe // The path reset completed before this goroutine ran.
	done := make(chan struct{})
	go func() {
		handler.HandleConnection(conn, conn.dst)
		close(done)
	}()
	select {
	case <-dispatcher.started:
		t.Fatal("reset TCP flow was dispatched using the new network")
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not close the reset flow")
	}
}

func TestMobileTCPResetCancelsUpstreamBeforeDialCompletes(t *testing.T) {
	dispatcher := &capturingDispatcher{started: make(chan context.Context, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := &Handler{ctx: ctx, flowCtx: ctx, config: &Config{}, dispatcher: dispatcher,
		flowReset: flowReset{register: func(func(bool)) {}},
	}
	p, l := newPeer(t, "10.0.0.1:1234", "10.0.0.2:443")
	s := newTestStack(t, l, handler.HandleConnection)
	p.connect(nil)
	var upstream context.Context
	select {
	case upstream = <-dispatcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream dial did not start")
	}
	p.send(p.seq, tcpAck|tcpFin, nil, nil)
	p.seq++
	if seg := p.receive(); seg.flags != tcpAck || seg.ack != p.seq || upstream.Err() != nil {
		t.Fatal("a graceful half-close interrupted the upstream")
	}
	p.send(p.seq, tcpRst, nil, nil)
	select {
	case <-upstream.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("TCP reset did not cancel the stalled upstream dial")
	}
	forgotten(t, s)
}

func (d *blockingDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	close(d.entered)
	<-ctx.Done()
	return ctx.Err()
}

// Closing the handler must end a dispatch that is not reading its connection: the handler's context
// is detached from the instance's, so Close is what cancels it
func TestHandlerCloseCancelsDispatches(t *testing.T) {
	dispatcher := &blockingDispatcher{entered: make(chan struct{})}
	handler := &Handler{config: &Config{}, dispatcher: dispatcher}
	handler.ctx, handler.cancel = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handler.HandleConnection(newTestConn(nil), xnet.TCPDestination(xnet.LocalHostIP, 443))
		close(done)
	}()
	<-dispatcher.entered
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("dispatch still running after Close")
	}
}
