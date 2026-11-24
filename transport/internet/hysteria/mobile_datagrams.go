package hysteria

import "sync/atomic"

const (
	mobileDatagramReceiveBytes = 512 << 10
	mobileDatagramsPerFlow     = 32
)

type datagramReceiveBudget struct {
	bytes   atomic.Int64
	dropped atomic.Uint64
}

var mobileDatagramReceive datagramReceiveBudget

// MobileReceiveStats reports bytes held by UDP delivery queues and cumulative
// drops at their limits. It excludes the QUIC implementation's own queues.
func MobileReceiveStats() (queuedBytes int64, dropped uint64) {
	return mobileDatagramReceive.bytes.Load(), mobileDatagramReceive.dropped.Load()
}

func (b *datagramReceiveBudget) reserve(datagram []byte) bool {
	size := int64(cap(datagram))
	for used := b.bytes.Load(); size <= mobileDatagramReceiveBytes-used; used = b.bytes.Load() {
		if b.bytes.CompareAndSwap(used, used+size) {
			return true
		}
	}
	return false
}

func (b *datagramReceiveBudget) release(datagram []byte) {
	b.bytes.Add(-int64(cap(datagram)))
}

// enqueue never stalls the QUIC receiver because another UDP flow is slow.
// The manager lock serializes this operation with closing the queue.
func (c *InterConn) enqueue(datagram []byte) {
	if c.budget != nil && !c.budget.reserve(datagram) {
		c.budget.dropped.Add(1)
		return
	}
	select {
	case c.ch <- datagram:
	default:
		if c.budget != nil {
			c.budget.release(datagram)
			c.budget.dropped.Add(1)
		}
	}
}
