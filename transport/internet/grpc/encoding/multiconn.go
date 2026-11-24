package encoding

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/signal/done"
)

type MultiHunkConn interface {
	Context() context.Context
	Send(*MultiHunk) error
	Recv() (*MultiHunk, error)
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

type MultiHunkReaderWriter struct {
	hc     MultiHunkConn
	cancel context.CancelFunc
	done   *done.Instance
}

func NewMultiHunkReadWriter(hc MultiHunkConn, cancel context.CancelFunc) *MultiHunkReaderWriter {
	return &MultiHunkReaderWriter{hc, cancel, done.New()}
}

func NewMultiHunkConn(hc MultiHunkConn, cancel context.CancelFunc, trustedXForwardedFor []string) net.Conn {
	rAddr := remoteAddrFromContext(hc.Context(), trustedXForwardedFor)
	lAddr := localAddrFromContext(hc.Context())
	wrc := NewMultiHunkReadWriter(hc, cancel)
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(wrc),
		cnc.ConnectionOutputMulti(wrc),
		cnc.ConnectionOnClose(wrc),
		cnc.ConnectionRemoteAddr(rAddr),
		cnc.ConnectionLocalAddr(lAddr),
	)
}

func (h *MultiHunkReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if h.done.Done() {
		return nil, io.EOF
	}
	hunk, err := h.hc.Recv()
	if err != nil {
		if err == io.EOF {
			return nil, err
		}

		return nil, errors.New("failed to fetch hunk from gRPC tunnel").Base(err)
	}

	mb := make(buf.MultiBuffer, 0, len(hunk.Data))
	for _, b := range hunk.Data {
		if len(b) == 0 {
			continue
		}

		if cap(b) >= buf.Size {
			mb = append(mb, buf.NewExisted(b))
		} else {
			nb := buf.New()
			nb.Extend(int32(len(b)))
			copy(nb.Bytes(), b)

			mb = append(mb, nb)
		}

	}
	return mb, nil
}

func (h *MultiHunkReaderWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if h.done.Done() {
		return io.ErrClosedPipe
	}

	hunks := make([][]byte, 0, len(mb))

	for _, b := range mb {
		if b.Len() > 0 {
			hunks = append(hunks, b.Bytes())
		}
	}

	err := h.hc.Send(&MultiHunk{Data: hunks})
	if err != nil {
		return err
	}
	return nil
}

func (h *MultiHunkReaderWriter) Close() error {
	if h.cancel != nil {
		h.cancel()
		return h.done.Close()
	}
	if sc, match := h.hc.(StreamCloser); match {
		return sc.CloseSend()
	}

	return h.done.Close()
}
