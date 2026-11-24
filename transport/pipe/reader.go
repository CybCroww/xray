package pipe

import (
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// Reader is a buf.Reader that reads content from a pipe.
type Reader struct {
	pipe *pipe
}

// ReadMultiBuffer implements buf.Reader.
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.pipe.ReadMultiBuffer()
}

// TryReadMultiBuffer takes buffered content without waiting. A nil result means
// there is nothing ready; use ReadMultiBuffer to wait or observe a terminal error.
func (r *Reader) TryReadMultiBuffer() buf.MultiBuffer {
	data, _ := r.pipe.readMultiBufferInternal()
	if data != nil {
		r.pipe.writeSignal.Signal()
	}
	return data
}

// ReadMultiBufferTimeout reads content from a pipe within the given duration, or returns buf.ErrTimeout otherwise.
func (r *Reader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	return r.pipe.ReadMultiBufferTimeout(d)
}

// Interrupt implements common.Interruptible.
func (r *Reader) Interrupt() {
	r.pipe.Interrupt()
}

// ReturnAnError makes ReadMultiBuffer return an error, only once.
func (r *Reader) ReturnAnError(err error) {
	r.pipe.errChan <- err
}

// Recover catches an error set by ReturnAnError, if exists.
func (r *Reader) Recover() (err error) {
	select {
	case err = <-r.pipe.errChan:
	default:
	}
	return
}
