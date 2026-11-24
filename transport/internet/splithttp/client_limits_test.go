package splithttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
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
	resetClientNetwork(limits)
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
	// The old callers still own their connection objects. The new path must
	// be able to start without waiting for either caller to close one.
	retry, err := dial(ctx, destination, settings, limits)
	if err != nil {
		t.Fatalf("new path could not dial after canceling old sockets: %v", err)
	}
	retry.Close()
}

func TestMobilePacketUploadFailureReleasesFlow(t *testing.T) {
	posted := make(chan struct{}, 1)
	shutdown := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable)
			posted <- struct{}{}
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-shutdown:
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer close(shutdown)
	destination, err := net.ParseDestination("tcp:" + strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	settings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp", SecurityType: "tls",
		ProtocolSettings: &Config{Path: "/test", Mode: "packet-up"},
		SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{tls.GenerateCertHash(server.Certificate().Raw)}},
	}
	limits := &clientLimits{flows: make(chan struct{}, 1), packets: make(chan struct{}, 1)}
	defer resetClientNetwork(limits)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := dial(ctx, destination, settings, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := first.Write([]byte("test packet")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-posted:
	case <-ctx.Done():
		t.Fatal("upload did not reach the server")
	}
	retry, err := dial(ctx, destination, settings, limits)
	if err != nil {
		t.Fatalf("could not dial on the same path after upload failed: %v", err)
	}
	retry.Close()
}

func TestMobilePacketUploadKeepsHeaderTransport(t *testing.T) {
	type field struct {
		sequence int
		data     []byte
	}
	fields := make(chan field, 32)
	shutdown := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Seq") == "" {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-shutdown:
			}
			return
		}
		sequence, seqErr := strconv.Atoi(r.Header.Get("X-Seq"))
		data, decodeErr := base64.RawURLEncoding.DecodeString(collectIndexedHeaderValues(r.Header, "X-Payload-"))
		if seqErr != nil || decodeErr != nil || r.Method != http.MethodGet || r.Header.Get("X-Session-Id") == "" || len(data) == 0 || len(data) > 4<<10 {
			t.Errorf("unexpected header upload: method=%s size=%d", r.Method, len(data))
		}
		fields <- field{sequence, data}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer close(shutdown)
	destination, err := net.ParseDestination("tcp:" + strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	settings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp", SecurityType: "tls",
		ProtocolSettings: &Config{
			Path: "/test", Mode: "packet-up", UplinkHTTPMethod: "GET", UplinkDataPlacement: PlacementHeader,
			UplinkDataKey: "X-Payload", SessionIDPlacement: PlacementHeader, SessionIDKey: "X-Session-Id",
			SeqPlacement: PlacementHeader, UplinkChunkSize: &RangeConfig{From: 2048, To: 2048},
		},
		SecuritySettings: &tls.Config{PinnedPeerCertSha256: [][]byte{tls.GenerateCertHash(server.Certificate().Raw)}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialCtx, cancelDial := context.WithCancel(ctx)
	conn, err := dial(dialCtx, destination, settings, &clientLimits{flows: make(chan struct{}, 1), packets: make(chan struct{}, 4)})
	cancelDial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	want := make([]byte, 10000)
	for i := range want {
		want[i] = byte((i / 313) % 251)
	}
	result := make(chan error, 1)
	go func() { _, err := conn.Write(want); result <- err }()
	parts := make(map[int][]byte)
	received := 0
	for received < len(want) {
		select {
		case packet := <-fields:
			if _, ok := parts[packet.sequence]; ok {
				t.Fatalf("duplicate packet %d", packet.sequence)
			}
			parts[packet.sequence] = packet.data
			received += len(packet.data)
		case <-ctx.Done():
			t.Fatalf("received %d of %d bytes", received, len(want))
		}
	}
	var got []byte
	for i := range len(parts) {
		got = append(got, parts[i]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("header payload changed")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
