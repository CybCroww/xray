package splithttp

import (
	"context"
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
)

// mobilePacketUpload owns the queued buffers until the HTTP request is done.
// Retries can read the same buffers with an independent cursor.
type mobilePacketUpload struct {
	mu       sync.Mutex
	payload  buf.MultiBuffer
	latest   *mobilePacketBody
	finished bool
	drained  chan struct{}
}

func (u *mobilePacketUpload) open() (io.ReadCloser, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.finished {
		return nil, io.ErrClosedPipe
	}
	u.latest = &mobilePacketBody{
		upload: u,
		reader: replayMultiBufferBody{payload: u.payload},
	}
	return u.latest, nil
}

// A response can arrive while the request body is still being written. Hold
// the flight slot until the last attempt closes its body or the request ends.
func (u *mobilePacketUpload) finish(ctx context.Context, succeeded bool) error {
	u.mu.Lock()
	u.finished = true
	var err error
	if succeeded && !u.latest.closed {
		u.drained = make(chan struct{})
		drained := u.drained
		u.mu.Unlock()
		select {
		case <-drained:
		case <-ctx.Done():
			err = ctx.Err()
		}
		u.mu.Lock()
	}
	payload := u.payload
	u.payload = nil
	u.latest = nil
	u.mu.Unlock()
	buf.ReleaseMulti(payload)
	return err
}

type mobilePacketBody struct {
	upload *mobilePacketUpload
	reader replayMultiBufferBody
	closed bool
}

func (b *mobilePacketBody) Read(p []byte) (int, error) {
	u := b.upload
	u.mu.Lock()
	defer u.mu.Unlock()
	if b.closed || u.payload == nil {
		return 0, io.ErrClosedPipe
	}
	return b.reader.Read(p)
}

func (b *mobilePacketBody) Close() error {
	u := b.upload
	u.mu.Lock()
	defer u.mu.Unlock()
	if !b.closed {
		b.closed = true
		b.reader.payload = nil
		if u.latest == b && u.drained != nil {
			close(u.drained)
		}
	}
	return nil
}
