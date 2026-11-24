package encoding

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/signal/done"
	"google.golang.org/grpc"
)

type MultiHunkConn interface {
	Context() context.Context
	Send(*MultiHunk) error
	Recv() (*MultiHunk, error)
	SendMsg(m interface{}) error
	RecvMsg(m interface{}) error
}

type MultiHunkReaderWriter struct {
	hc      MultiHunkConn
	cancel  context.CancelFunc
	done    *done.Instance
	compact bool
}

func NewMultiHunkReadWriter(hc MultiHunkConn, cancel context.CancelFunc) *MultiHunkReaderWriter {
	return &MultiHunkReaderWriter{hc: hc, cancel: cancel, done: done.New()}
}

func NewMultiHunkConn(hc MultiHunkConn, cancel context.CancelFunc, trustedXForwardedFor []string) net.Conn {
	return newMultiHunkConn(NewMultiHunkReadWriter(hc, cancel), trustedXForwardedFor)
}

// OpenMultiHunkConn opens the client stream and optionally reassembles inbound
// protobuf fields directly into Xray buffers.
func OpenMultiHunkConn(ctx context.Context, cancel context.CancelFunc, client GRPCServiceClientX, service, method string, compact bool) (net.Conn, error) {
	var options []grpc.CallOption
	if compact {
		options = append(options, grpc.ForceCodecV2(compactMultiHunkCodec))
	}
	stream, err := client.TunMultiCustomName(ctx, service, method, options...)
	if err != nil {
		return nil, err
	}
	wrc := NewMultiHunkReadWriter(stream, cancel)
	wrc.compact = compact
	return newMultiHunkConn(wrc, nil), nil
}

func newMultiHunkConn(wrc *MultiHunkReaderWriter, trustedXForwardedFor []string) net.Conn {
	ctx := wrc.hc.Context()
	return cnc.NewConnection(
		cnc.ConnectionInputMulti(wrc),
		cnc.ConnectionOutputMulti(wrc),
		cnc.ConnectionOnClose(wrc),
		cnc.ConnectionRemoteAddr(remoteAddrFromContext(ctx, trustedXForwardedFor)),
		cnc.ConnectionLocalAddr(localAddrFromContext(ctx)),
	)
}

func (h *MultiHunkReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if h.done.Done() {
		return nil, io.EOF
	}
	if h.compact {
		var chunk mobileMultiHunk
		if err := h.hc.RecvMsg(&chunk); err != nil {
			buf.ReleaseMulti(chunk.payload)
			return nil, err
		}
		return chunk.payload, nil
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
