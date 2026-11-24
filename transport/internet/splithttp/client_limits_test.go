package splithttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type streamRoundTripper func(*http.Request) (*http.Response, error)

func (f streamRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMobilePoolExpiresOnlyAfterLastLease(t *testing.T) {
	limits := newClientLimits(2, 2)
	defer resetClientNetwork(limits)
	path := limits.path.current()
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{
		Xmux: &XmuxConfig{MaxConnections: &RangeConfig{From: 2, To: 2}},
	}}
	key := dialerConf{Destination: net.TCPDestination(net.LocalHostIP, 443), MemoryStreamConfig: settings, mobile: true, path: path}
	lease := func(t *testing.T) *XmuxClient {
		t.Helper()
		_, client, err := getHTTPClient(context.Background(), key.Destination, settings, path)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	// Creating the clients can start the shared logger. Only test the pool
	// clocks inside the synctest bubble.
	first, last := lease(t), lease(t)
	if first == last {
		t.Fatal("expected two clients in the pool")
	}
	synctest.Test(t, func(t *testing.T) {
		assertState := func(retained, expires bool) {
			t.Helper()
			globalDialerAccess.Lock()
			defer globalDialerAccess.Unlock()
			manager := globalDialerMap[key]
			if (manager != nil) != retained || (manager != nil && manager.idleTimer != nil) != expires {
				t.Fatalf("pool retained = %t, timer pending = %t", manager != nil, manager != nil && manager.idleTimer != nil)
			}
		}
		first.DoneRunning()
		assertState(true, false)
		last.DoneRunning()
		assertState(true, true)
		time.Sleep(mobilePoolIdleTimeout - time.Second)
		active := lease(t)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		assertState(true, false)
		active.DoneRunning()
		time.Sleep(mobilePoolIdleTimeout)
		synctest.Wait()
		assertState(false, false)
		if !first.closed.Load() || !last.closed.Load() {
			t.Fatal("expired clients did not close")
		}
	})
}

func TestMobileUploadRetainsBodyThroughRetry(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		name := "response before body close"
		if cancelled {
			name = "request canceled"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				want := bytes.Repeat([]byte("upload"), 2000)
				payload := buf.MergeBytes(nil, want)
				replayed := make(chan io.ReadCloser, 1)
				client := DefaultDialerClient{
					mobile: true, httpVersion: "2", transportConfig: &Config{Path: "/test/"},
					client: &http.Client{Transport: streamRoundTripper(func(req *http.Request) (*http.Response, error) {
						var prefix [32]byte
						if _, err := io.ReadFull(req.Body, prefix[:]); err != nil {
							return nil, err
						}
						req.Body.Close()
						if req.ContentLength != int64(len(want)) || !bytes.Equal(prefix[:], want[:len(prefix)]) {
							return nil, errors.New("original request body has the wrong payload")
						}
						body, err := req.GetBody()
						if err != nil {
							return nil, err
						}
						replayed <- body
						return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
					})},
				}
				result := make(chan error, 1)
				go func() { result <- client.PostPacket(ctx, "https://test.invalid/test/", "session", "0", payload) }()
				var replay io.ReadCloser
				select {
				case replay = <-replayed:
				case err := <-result:
					t.Fatalf("upload returned before replay: %v", err)
				}
				synctest.Wait()
				select {
				case err := <-result:
					t.Fatalf("upload returned before its active body closed: %v", err)
				default:
				}
				if cancelled {
					cancel()
					if err := <-result; !errors.Is(err, context.Canceled) {
						t.Fatalf("canceled upload returned %v", err)
					}
					if _, err := replay.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
						t.Fatalf("read after canceled upload returned %v", err)
					}
					replay.Close()
				} else {
					got, err := io.ReadAll(replay)
					replay.Close()
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("replay read %d bytes, want %d: %v", len(got), len(want), err)
					}
					if err := <-result; err != nil {
						t.Fatal(err)
					}
				}
				for _, buffer := range payload {
					if buffer != nil {
						t.Fatal("upload retained its packet buffers")
					}
				}
			})
		})
	}
}

func TestMobilePathChangeClosesPendingTLS(t *testing.T) {
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.(*stdnet.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			destination, err := net.ParseDestination("tcp:" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			settings := &internet.MemoryStreamConfig{
				ProtocolName: "splithttp", SecurityType: "tls",
				ProtocolSettings: &Config{Path: "/test/", Mode: "packet-up"},
				SecuritySettings: &tls.Config{NextProtocol: []string{protocol}},
			}
			limits := newClientLimits(1, 1)
			defer resetClientNetwork(limits)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dialResult := make(chan error, 1)
			go func() {
				conn, err := dial(ctx, destination, settings, limits)
				if conn != nil {
					conn.Close()
				}
				dialResult <- err
			}()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var record [5]byte
			if _, err := io.ReadFull(peer, record[:]); err != nil || record[0] != 22 {
				t.Fatalf("expected a TLS handshake record, got %v (%v)", record, err)
			}
			// Cancel the path before touching the pool. Closing the idle pool
			// can incidentally cancel a dial, depending on request timing.
			limits.path.change()
			if _, err := io.Copy(io.Discard, peer); err != nil {
				t.Fatalf("the old TLS socket stayed open after the path change: %v", err)
			}
			select {
			case err := <-dialResult:
				if err == nil {
					t.Fatal("dial succeeded on a retired path")
				}
			case <-ctx.Done():
				t.Fatal("the path change did not release the flow")
			}
		})
	}
}

func TestMobileDownlinkHeaderDeadline(t *testing.T) {
	const timeout = 200 * time.Millisecond
	for _, tt := range []struct {
		name   string
		status int
	}{
		{"timeout", 0},
		{"rejected", http.StatusServiceUnavailable},
		{"established", http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flowCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			local, remote := stdnet.Pipe()
			defer local.Close()
			defer remote.Close()
			respond := make(chan struct{})
			client := DefaultDialerClient{
				transportConfig: &Config{Path: "/test", Mode: "packet-up"},
				downlinkTimeout: timeout,
				client: &http.Client{Transport: streamRoundTripper(func(r *http.Request) (*http.Response, error) {
					httptrace.ContextClientTrace(r.Context()).GotConn(httptrace.GotConnInfo{Conn: local})
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-respond:
						return &http.Response{StatusCode: tt.status, Body: io.NopCloser(strings.NewReader("payload"))}, nil
					}
				})},
			}
			stream, _, _, err := client.OpenStream(flowCtx, "https://test.invalid/test/", "session", nil, false, cancel)
			if err != nil {
				t.Fatalf("could not open downlink before response headers: %v", err)
			}
			defer stream.Close()
			if tt.status != 0 {
				close(respond)
			}
			if tt.status == http.StatusOK {
				select {
				case <-flowCtx.Done():
					t.Fatal("the header timer canceled an established stream")
				case <-time.After(2 * timeout):
				}
				data, err := io.ReadAll(stream)
				if err != nil || string(data) != "payload" {
					t.Fatalf("response did not survive past the header deadline: %q, %v", data, err)
				}
				return
			}
			select {
			case <-flowCtx.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("a failed downlink did not release the flow")
			}
			if client.IsClosed() {
				t.Fatal("one failed downlink retired the shared client")
			}
		})
	}
}

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
	limits := newClientLimits(2, budget)
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
	limits := newClientLimits(1, 1)
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
	conn, err := dial(dialCtx, destination, settings, newClientLimits(1, 4))
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
