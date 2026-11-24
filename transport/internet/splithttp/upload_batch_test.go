package splithttp

import (
	"context"
	"io"
	"net/http/httptrace"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/pipe"
)

type batchRecorder struct {
	posted chan string
	first  chan struct{}
}

func (*batchRecorder) IsClosed() bool { return false }

func (*batchRecorder) OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	panic("upload-only recorder")
}

func (r *batchRecorder) PostPacket(ctx context.Context, _, _, seq string, payload buf.MultiBuffer) error {
	defer buf.ReleaseMulti(payload)
	httptrace.ContextClientTrace(ctx).WroteRequest(httptrace.WroteRequestInfo{})
	data := make([]byte, payload.Len())
	payload.Copy(data)
	r.posted <- string(data)
	if seq == "0" {
		select {
		case <-r.first:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestMobileUploadBatchesWritesWhileWaitingForCapacity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reader, writer := pipe.New(pipe.WithSizeLimit(0)) // one pending write at a time
	defer reader.Interrupt()
	recorder := &batchRecorder{posted: make(chan string, 4), first: make(chan struct{})}
	limits := &clientLimits{packets: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		uploadPackets(ctx, cancel, reader, 4096, &RangeConfig{}, limits, func(context.Context) (DialerClient, func()) {
			return recorder, func() {}
		}, "", "")
	}()
	write := func(s string) {
		b := buf.New()
		b.WriteString(s)
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string {
		select {
		case got := <-recorder.posted:
			return got
		case <-ctx.Done():
			t.Fatal("no upload")
			return ""
		}
	}
	write("first")
	if got := read(); got != "first" {
		t.Fatalf("first request: %q", got)
	}
	write("second")
	queued := make(chan error, 1)
	go func() {
		b := buf.New()
		b.WriteString("third")
		queued <- writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}()
	select {
	case err := <-queued:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("third write was not queued")
	}
	close(recorder.first)
	if got := read(); got != "secondthird" {
		t.Fatalf("expected one coalesced request, got %q", got)
	}
	writer.Close()
	<-done
	if got := limits.stats.requests.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2", got)
	}
}
