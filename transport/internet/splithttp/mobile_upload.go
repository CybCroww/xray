package splithttp

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"golang.org/x/sync/semaphore"
)

// mobileUploadQueue keeps one pending packet per flow. It accumulates small
// writes until the sender has a request slot, without starting a batch timer.
// The shared budget covers pending buffers; flight slots cover packets taken
// out of the queue until their HTTP requests return.
type mobileUploadQueue struct {
	ctx    context.Context
	cancel context.CancelFunc
	budget *semaphore.Weighted
	size   int32
	cost   int64

	writerMu sync.Mutex
	mu       sync.Mutex
	packet   buf.MultiBuffer
	length   int32
	ready    *signal.Notifier
	drained  *signal.Notifier
}

func newMobileUploadQueue(ctx context.Context, size int32, budget *semaphore.Weighted) *mobileUploadQueue {
	ctx, cancel := context.WithCancel(ctx)
	return &mobileUploadQueue{
		ctx: ctx, cancel: cancel, budget: budget, size: size,
		cost:  int64((size + buf.Size - 1) / buf.Size * buf.Size),
		ready: signal.NewNotifier(), drained: signal.NewNotifier(),
	}
}

func (q *mobileUploadQueue) Write(data []byte) (int, error) {
	q.writerMu.Lock()
	defer q.writerMu.Unlock()
	written := 0
	for len(data) > 0 {
		q.mu.Lock()
		if q.ctx.Err() != nil {
			q.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		switch q.length {
		case q.size:
			q.mu.Unlock()
			select {
			case <-q.drained.Wait():
			case <-q.ctx.Done():
				return written, io.ErrClosedPipe
			}
			continue
		case 0:
			// While this writer waits, the queue has nothing for the reader
			// to take. No other writer can insert data before this one.
			q.mu.Unlock()
			if err := q.budget.Acquire(q.ctx, q.cost); err != nil {
				return written, io.ErrClosedPipe
			}
			q.mu.Lock()
			if q.ctx.Err() != nil {
				q.mu.Unlock()
				q.budget.Release(q.cost)
				return written, io.ErrClosedPipe
			}
		}
		n := min(len(data), int(q.size-q.length))
		q.packet = buf.MergeBytes(q.packet, data[:n])
		if q.length == 0 {
			q.ready.Signal()
		}
		q.length += int32(n)
		q.mu.Unlock()
		written += n
		data = data[n:]
	}
	return written, nil
}

func (q *mobileUploadQueue) wait() bool {
	for q.ctx.Err() == nil {
		q.mu.Lock()
		ready := q.length > 0
		q.mu.Unlock()
		if ready {
			return true
		}
		select {
		case <-q.ready.Wait():
		case <-q.ctx.Done():
		}
	}
	return false
}

// take transfers the queued packet to the sender. Call only after reserving an
// HTTP request slot. Close can discard the packet before the sender gets it.
func (q *mobileUploadQueue) take(discard bool) buf.MultiBuffer {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.length == 0 {
		return nil
	}
	packet := q.packet
	q.packet, q.length = nil, 0
	if discard {
		buf.ReleaseMulti(packet)
		packet = nil
	}
	q.budget.Release(q.cost)
	q.drained.Signal()
	return packet
}

func (q *mobileUploadQueue) Close() error {
	q.cancel()
	q.take(true)
	return nil
}
