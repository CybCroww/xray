package splithttp

import (
	"context"
	"io"
	"net/http/httptrace"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

type batchRecorder struct {
	posted chan string
	first  chan struct{}
}

func (*batchRecorder) IsClosed() bool { return false }

func (*batchRecorder) OpenStream(context.Context, string, string, io.Reader, bool, context.CancelFunc) (io.ReadCloser, net.Addr, net.Addr, error) {
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
	recorder := &batchRecorder{posted: make(chan string, 4), first: make(chan struct{})}
	limits := newClientLimits(1, 1)
	queue := newMobileUploadQueue(ctx, 4096, limits.queued)
	defer queue.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		uploadPackets(ctx, cancel, nil, queue, 4096, &RangeConfig{}, limits, func(context.Context) (DialerClient, func()) {
			return recorder, func() {}
		}, "", "")
	}()
	write := func(s string) {
		if _, err := io.WriteString(queue, s); err != nil {
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
	write("third")
	close(recorder.first)
	if got := read(); got != "secondthird" {
		t.Fatalf("expected one coalesced request, got %q", got)
	}
	cancel()
	<-done
	if got := limits.stats.requests.Load(); got != 2 {
		t.Fatalf("sent %d requests, want 2", got)
	}
}

func TestMobilePendingUploadBudgetAcrossFlows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		const chunkSize = 64 << 10
		limits := newClientLimits(64, 24)
		queues := make([]*mobileUploadQueue, mobileQueuedUploadBytes/chunkSize)
		payload := make([]byte, chunkSize)
		for i := range queues {
			queues[i] = newMobileUploadQueue(ctx, chunkSize, limits.queued)
			defer queues[i].Close()
			if n, err := queues[i].Write(payload); n != len(payload) || err != nil {
				t.Fatalf("flow %d: queued %d bytes: %v", i, n, err)
			}
		}
		waiting := newMobileUploadQueue(ctx, chunkSize, limits.queued)
		defer waiting.Close()
		result := make(chan error, 1)
		go func() { _, err := io.WriteString(waiting, "next"); result <- err }()
		synctest.Wait()
		select {
		case err := <-result:
			t.Fatalf("write with exhausted budget returned %v", err)
		default:
		}
		queues[0].Close()
		if err := <-result; err != nil {
			t.Fatalf("canceled flow did not return its credit: %v", err)
		}
		packet := waiting.take(false)
		if packet.Len() != 4 || string(packet[0].Bytes()) != "next" {
			t.Fatalf("new slot delivered the wrong upload: %v", packet)
		}
		buf.ReleaseMulti(packet)
		waiting.Close()
		for _, queue := range queues {
			queue.Close()
		}
		if !limits.queued.TryAcquire(mobileQueuedUploadBytes) {
			t.Fatal("closing flows did not release the full queue budget")
		}
		limits.queued.Release(mobileQueuedUploadBytes)
	})
}
