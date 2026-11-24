package grpc

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"google.golang.org/grpc/connectivity"
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
