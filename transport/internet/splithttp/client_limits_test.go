package splithttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestMobilePacketUploadsBackpressureAndCancel(t *testing.T) {
	const budget = 4
	uploads := make(chan int, 100)
	stopped := make(chan struct{}, 100)
	shutdown := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		} else {
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				return
			}
			uploads <- int(n)
			defer func() { stopped <- struct{}{} }()
		}
		select {
		case <-r.Context().Done():
		case <-shutdown:
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer close(shutdown)
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := net.ParseDestination("tcp:" + u.Host)
	if err != nil {
		t.Fatal(err)
	}
	settings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp", SecurityType: "tls",
		ProtocolSettings: &Config{Path: "/test", Mode: "packet-up", ScMinPostsIntervalMs: &RangeConfig{From: -1, To: -1}},
		SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{tls.GenerateCertHash(server.Certificate().Raw)}},
	}
	limits := &clientLimits{flows: make(chan struct{}, 2), packets: make(chan struct{}, budget)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := dial(ctx, destination, settings, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := dial(ctx, destination, settings, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	result := make(chan error, 2)
	go func() { _, err := first.Write(bytes.Repeat([]byte{1}, 2<<20)); result <- err }()
	go func() { _, err := second.Write(bytes.Repeat([]byte{2}, 2<<20)); result <- err }()
	for i := 0; i < budget; i++ {
		select {
		case n := <-uploads:
			if n == 0 || n > 64<<10 {
				t.Fatalf("unexpected packet size: %d", n)
			}
		case <-ctx.Done():
			t.Fatalf("only %d requests reached the peer", i)
		}
	}
	select {
	case <-uploads:
		t.Fatal("upload went beyond the shared budget despite all responses stalling")
	case <-result:
		t.Fatal("writer did not apply backpressure")
	case <-time.After(100 * time.Millisecond):
	}
	first.Close()
	second.Close()
	for i := 0; i < budget; i++ {
		select {
		case <-stopped:
		case <-ctx.Done():
			t.Fatal("in-flight HTTP/2 requests were not canceled")
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("writer unexpectedly completed while peer was stalled")
			}
		case <-ctx.Done():
			t.Fatal("write stayed blocked after closing the tunnel")
		}
	}
}
