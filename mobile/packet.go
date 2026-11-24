package mobile

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
)

const (
	inputPackets    = 128
	inputBatchBytes = 16 << 10
)

type packetDevice struct {
	mu          sync.Mutex
	data        []byte
	sizes       [inputPackets]int
	mtu         int
	read        int
	write       int
	count       int
	closed      bool
	wake        chan struct{}
	done        chan struct{}
	outputMu    sync.Mutex
	writer      PacketWriter
	output      []byte
	inputDrops  atomic.Uint64
	outputDrops atomic.Uint64
	inputCalls  atomic.Uint64
}

func newPacketDevice(writer PacketWriter, mtu int) *packetDevice {
	return &packetDevice{
		mtu: mtu, writer: writer, wake: make(chan struct{}, 1), done: make(chan struct{}),
		data: make([]byte, inputPackets*mtu), output: make([]byte, mtu),
	}
}

func (d *packetDevice) Start() error          { return nil }
func (d *packetDevice) Name() (string, error) { return "cvpn-tun", nil }
func (d *packetDevice) Index() (int, error) {
	return 0, errors.New("host packet flow has no exposed interface index")
}

func (d *packetDevice) Close() error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		d.count = 0
		d.data = nil
		close(d.done)
	}
	d.mu.Unlock()
	d.outputMu.Lock()
	d.writer = nil
	d.output = nil
	d.outputMu.Unlock()
	return nil
}

func (d *packetDevice) push(packet []byte) bool {
	d.inputCalls.Add(1)
	if len(packet) < 20 || len(packet) > d.mtu {
		d.inputDrops.Add(1)
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enqueue(packet) {
		d.inputDrops.Add(1)
		return false
	}
	return true
}

// pushBatch validates framing before changing the queue. Payload bytes are
// borrowed only for this call; the ring owns its copies after return.
func (d *packetDevice) pushBatch(data []byte, length int) int {
	d.inputCalls.Add(1)
	if length < 0 || length > len(data) || length > inputBatchBytes {
		return -1
	}
	data = data[:length]
	for remaining := data; len(remaining) > 0; {
		if len(remaining) < 2 {
			return -1
		}
		n := int(binary.BigEndian.Uint16(remaining))
		if n < 20 || n > d.mtu || n > len(remaining)-2 {
			return -1
		}
		remaining = remaining[2+n:]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	accepted := 0
	var dropped uint64
	for len(data) > 0 {
		n := int(binary.BigEndian.Uint16(data))
		if d.enqueue(data[2 : 2+n]) {
			accepted++
		} else {
			dropped++
		}
		data = data[2+n:]
	}
	if dropped != 0 {
		d.inputDrops.Add(dropped)
	}
	return accepted
}

// enqueue requires d.mu. Notify only on the transition from empty to nonempty.
func (d *packetDevice) enqueue(packet []byte) bool {
	if d.closed || d.count == inputPackets {
		return false
	}
	n := copy(d.data[d.write*d.mtu:], packet)
	d.sizes[d.write] = n
	d.write = (d.write + 1) % inputPackets
	d.count++
	if d.count == 1 {
		select {
		case d.wake <- struct{}{}:
		default:
		}
	}
	return true
}

func (d *packetDevice) queued() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.count
}

func (d *packetDevice) ReadPacket(packet []byte) ([]byte, error) {
	for {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return nil, io.EOF
		}
		if d.count > 0 {
			n := d.sizes[d.read]
			offset := d.read * d.mtu
			d.read = (d.read + 1) % inputPackets
			d.count--
			if n > len(packet) {
				d.mu.Unlock()
				d.inputDrops.Add(1)
				continue
			}
			copy(packet, d.data[offset:offset+n])
			d.mu.Unlock()
			return packet[:n], nil
		}
		d.mu.Unlock()
		select {
		case <-d.wake:
		case <-d.done:
		}
	}
}

func (d *packetDevice) WritePacket(header, payload []byte) error {
	d.outputMu.Lock()
	defer d.outputMu.Unlock()
	select {
	case <-d.done:
		return io.ErrClosedPipe
	default:
	}
	if len(header)+len(payload) > d.mtu {
		d.outputDrops.Add(1)
		return io.ErrShortBuffer
	}
	n := copy(d.output, header)
	n += copy(d.output[n:], payload)
	if !d.writer.WritePacket(d.output[:n]) {
		d.outputDrops.Add(1)
		return io.ErrShortWrite
	}
	return nil
}
