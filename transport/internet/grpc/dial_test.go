package grpc

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestNetworkResetRetiresSharedGRPCChannel(t *testing.T) {
	t.Cleanup(ResetMobileNetwork)
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	destination := net.TCPDestination(net.LocalHostIP, net.Port(1))
	ordinary, err := getGrpcClient(context.Background(), destination, settings, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		delete(globalDialerMap, dialerConf{destination, settings, false})
		globalDialerAccess.Unlock()
		ordinary.Close()
	})
	old, err := getGrpcClient(context.Background(), destination, settings, true)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := getGrpcClient(context.Background(), destination, settings, true)
	if err != nil || shared != old {
		t.Fatal("test did not share the channel")
	}
	ResetMobileNetwork()
	if old.GetState() != connectivity.Shutdown {
		t.Fatal("previous channel was not shut down")
	}
	if ordinary.GetState() == connectivity.Shutdown {
		t.Fatal("the mobile network reset closed a standard channel")
	}
	staleCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := getGrpcClient(staleCtx, destination, settings, true); conn != nil || err != context.Canceled {
		t.Fatalf("canceled flow repopulated the channel pool: %v, %v", conn, err)
	}
	fresh, err := getGrpcClient(context.Background(), destination, settings, true)
	if err != nil || fresh == old || fresh.GetState() == connectivity.Shutdown {
		t.Fatalf("new channel failed: %v", err)
	}
}

type echoTunnelServer struct {
	encoding.UnimplementedGRPCServiceServer
}

func (echoTunnelServer) Tun(stream encoding.GRPCService_TunServer) error {
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := stream.Send(request); err != nil {
			return err
		}
	}
}

func TestMobileGRPCTrimKeepsLiveStreams(t *testing.T) {
	t.Cleanup(ResetMobileNetwork)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := &Config{}
	server := grpc.NewServer()
	defer server.Stop()
	encoding.RegisterGRPCServiceServerX(server, echoTunnelServer{}, cfg.getServiceName(), cfg.getTunStreamName(), cfg.getTunMultiStreamName())
	go server.Serve(ln)
	dest := net.TCPDestination(net.LocalHostIP, net.Port(ln.Addr().(*net.TCPAddr).Port))
	activeSettings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: cfg}
	idleSettings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: cfg}

	open := func(ctx context.Context, settings *internet.MemoryStreamConfig) net.Conn {
		t.Helper()
		conn, err := dialgRPC(ctx, dest, settings, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	echo := func(conn net.Conn, message string) {
		t.Helper()
		if _, err := io.WriteString(conn, message); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(message))
		if _, err := io.ReadFull(conn, response); err != nil || string(response) != message {
			t.Fatalf("echo response %q: %v", response, err)
		}
	}
	cached := func(settings *internet.MemoryStreamConfig) *cachedChannel {
		globalDialerAccess.Lock()
		defer globalDialerAccess.Unlock()
		return globalDialerMap[dialerConf{dest, settings, true}]
	}
	first, active := open(ctx, activeSettings), open(ctx, activeSettings)
	echo(first, "first")
	echo(active, "active")
	activeChannel := cached(activeSettings)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	idleCtx, cancelIdle := context.WithCancel(ctx)
	defer cancelIdle()
	idle := open(idleCtx, idleSettings)
	echo(idle, "will become idle")
	idleChannel := cached(idleSettings)
	cancelIdle()
	// Parent cancellation must return the lease even if the caller has not
	// yet closed the connection object.
	for cached(idleSettings) != nil && ctx.Err() == nil {
		TrimIdleClients()
		time.Sleep(time.Millisecond)
	}
	if cached(idleSettings) != nil || idleChannel.GetState() != connectivity.Shutdown {
		t.Fatal("trimming retained the canceled stream's channel")
	}
	if cached(activeSettings) != activeChannel || activeChannel.GetState() == connectivity.Shutdown {
		t.Fatal("trim closed a shared channel that still had a live stream")
	}
	echo(active, "still active")
	echo(open(ctx, idleSettings), "reconnected")
	if fresh := cached(idleSettings); fresh == nil || fresh == idleChannel {
		t.Fatal("reconnect reused a retired channel")
	}
}

// A path notification can arrive while HTTP/2 is still waiting for its
// server preface. Retiring that channel must release the dial and allow a
// fresh channel to connect, rather than poisoning the shared pool.
func TestMobileGRPCResetDuringServerPreface(t *testing.T) {
	t.Cleanup(ResetMobileNetwork)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.TCPAddr).Port))
	failed := make(chan error, 1)
	go func() {
		conn, err := dialgRPC(ctx, dest, settings, true)
		if conn != nil {
			conn.Close()
		}
		failed <- err
	}()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-ctx.Done():
		t.Fatal("dial never reached listener")
	}
	ResetMobileNetwork()
	select {
	case err := <-failed:
		if err == nil {
			t.Fatal("interrupted preface unexpectedly succeeded")
		}
	case <-ctx.Done():
		t.Fatal("interrupted preface remained blocked")
	}
	server := grpc.NewServer()
	defer server.Stop()
	cfg := settings.ProtocolSettings.(*Config)
	encoding.RegisterGRPCServiceServerX(server, echoTunnelServer{}, cfg.getServiceName(), cfg.getTunStreamName(), cfg.getTunMultiStreamName())
	go server.Serve(listener)
	conn, err := dialgRPC(ctx, dest, settings, true)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "after reset"); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len("after reset"))
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != "after reset" {
		t.Fatalf("fresh channel failed: %q, %v", response, err)
	}
}

type largeResponseServer struct {
	encoding.UnimplementedGRPCServiceServer
	payload []byte
}

func (s largeResponseServer) Tun(stream encoding.GRPCService_TunServer) error {
	return stream.Send(&encoding.Hunk{Data: s.payload})
}

func TestMobileGRPCReceivesMessageLargerThanWindow(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := bytes.Repeat([]byte("x"), 768<<10)
	server := grpc.NewServer()
	defer server.Stop()
	encoding.RegisterGRPCServiceServer(server, largeResponseServer{payload: payload})
	go server.Serve(listener)
	options := appendReceiveWindowOptions([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, 0, true)
	channel, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := encoding.NewGRPCServiceClient(channel).Tun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply.Data, payload) {
		t.Fatalf("received %d bytes, expected %d", len(reply.Data), len(payload))
	}
}

type fragmentedMultiHunkServer struct {
	encoding.UnimplementedGRPCServiceServer
	fragments [][]byte
}

func (s fragmentedMultiHunkServer) TunMulti(stream encoding.GRPCService_TunMultiServer) error {
	request, err := stream.Recv()
	if err != nil {
		return err
	}
	return stream.Send(&encoding.MultiHunk{Data: append(request.Data, s.fragments...)})
}

func TestMobileGRPCCompactsMultiHunk(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fragments := make([][]byte, 0, 1026)
	for i := range 1024 {
		fragments = append(fragments, bytes.Repeat([]byte{byte(i)}, 96))
	}
	fragments = append(fragments, nil, bytes.Repeat([]byte{0x2f}, 768<<10))
	server := grpc.NewServer()
	defer server.Stop()
	settings := &Config{MultiMode: true}
	encoding.RegisterGRPCServiceServerX(server, fragmentedMultiHunkServer{fragments: fragments},
		settings.getServiceName(), settings.getTunStreamName(), settings.getTunMultiStreamName())
	go server.Serve(listener)
	options := appendReceiveWindowOptions([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, 0, true)
	channel, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), options...)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := encoding.NewGRPCServiceClient(channel).(encoding.GRPCServiceClientX)
	conn, err := encoding.OpenMultiHunkConn(ctx, cancel, client, settings.getServiceName(), settings.getTunMultiStreamName(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "echo"); err != nil {
		t.Fatal(err)
	}
	data, err := conn.(buf.Reader).ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(data)
	want := append([]byte("echo"), bytes.Join(fragments, nil)...)
	got := make([]byte, data.Len())
	data.Copy(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("byte stream changed: received %d bytes, want %d", len(got), len(want))
	}
	var capacity int
	for _, block := range data {
		capacity += int(block.Cap())
		if block.Cap() != buf.Size {
			t.Fatalf("read retained a block larger than the release unit: %d", block.Cap())
		}
	}
	if capacity > len(want)+buf.Size-1 {
		t.Fatalf("retained %d bytes of buffer backing for %d bytes of payload", capacity, len(want))
	}
	t.Logf("%d bytes of buffer backing for %d bytes of payload", capacity, len(want))
}

type silentTunnelServer struct {
	encoding.UnimplementedGRPCServiceServer
	started chan struct{}
	ended   chan struct{}
}

func (s silentTunnelServer) Tun(stream encoding.GRPCService_TunServer) error {
	_, err := stream.Recv()
	return s.wait(stream.Context(), err)
}

func (s silentTunnelServer) TunMulti(stream encoding.GRPCService_TunMultiServer) error {
	_, err := stream.Recv()
	return s.wait(stream.Context(), err)
}

func (s silentTunnelServer) wait(ctx context.Context, err error) error {
	if err != nil {
		return err
	}
	close(s.started)
	<-ctx.Done()
	close(s.ended)
	return ctx.Err()
}

func TestGRPCCloseCancelsBlockedReceive(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run("multi="+strconv.FormatBool(multi), func(t *testing.T) {
			t.Cleanup(ResetMobileNetwork)
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cfg := &Config{MultiMode: multi}
			settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: cfg}
			service := silentTunnelServer{started: make(chan struct{}), ended: make(chan struct{})}
			server := grpc.NewServer()
			defer server.Stop()
			encoding.RegisterGRPCServiceServerX(server, service, cfg.getServiceName(), cfg.getTunStreamName(), cfg.getTunMultiStreamName())
			go server.Serve(ln)
			dest := net.TCPDestination(net.LocalHostIP, net.Port(ln.Addr().(*net.TCPAddr).Port))
			conn, err := dialgRPC(ctx, dest, settings, true)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.Write([]byte("start")); err != nil {
				t.Fatal(err)
			}
			select {
			case <-service.started:
			case <-ctx.Done():
				t.Fatal("server did not receive stream")
			}

			read := make(chan error, 1)
			go func() {
				_, err := conn.Read(make([]byte, 1))
				read <- err
			}()
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			closeDeadline, stopWaiting := context.WithTimeout(context.Background(), 2*time.Second)
			defer stopWaiting()
			select {
			case <-service.ended:
			case <-closeDeadline.Done():
				t.Fatal("server RPC stayed open after connection close")
			}
			select {
			case err := <-read:
				if err == nil {
					t.Fatal("read unexpectedly succeeded")
				}
			case <-closeDeadline.Done():
				t.Fatal("connection close did not unblock read")
			}
			if ctx.Err() != nil {
				t.Fatal("stream ended only after the parent deadline")
			}
		})
	}
}
