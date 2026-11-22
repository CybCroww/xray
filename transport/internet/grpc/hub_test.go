package grpc

import (
	"context"
	stdnet "net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestListenReturnsBindError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix listener fixture")
	}
	path := filepath.Join(t.TempDir(), "grpc.socket")
	occupied, err := stdnet.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	listener, err := Listen(context.Background(), net.DomainAddress(path), 0,
		&internet.MemoryStreamConfig{ProtocolSettings: &Config{}}, nil)
	if listener != nil {
		listener.Close()
		t.Fatal("occupied socket returned a ready listener")
	}
	if err == nil {
		t.Fatal("occupied socket did not return its bind error")
	}
}
