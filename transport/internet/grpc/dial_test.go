package grpc

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestNetworkResetRetiresSharedGRPCChannel(t *testing.T) {
	t.Cleanup(resetCachedChannels)
	settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, ProtocolSettings: &Config{}}
	destination := net.TCPDestination(net.LocalHostIP, net.Port(1))
	old, err := getGrpcClient(context.Background(), destination, settings)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := getGrpcClient(context.Background(), destination, settings)
	if err != nil || shared != old {
		t.Fatal("test did not share the channel")
	}
	resetCachedChannels()
	if old.GetState() != connectivity.Shutdown {
		t.Fatal("previous channel was not shut down")
	}
	fresh, err := getGrpcClient(context.Background(), destination, settings)
	if err != nil || fresh == old || fresh.GetState() == connectivity.Shutdown {
		t.Fatalf("new channel failed: %v", err)
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
			t.Cleanup(resetCachedChannels)
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
			conn, err := dialgRPC(ctx, dest, settings)
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
