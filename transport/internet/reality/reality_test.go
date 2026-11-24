package reality

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestMobileRealityRejectsUnauthenticatedPeer(t *testing.T) {
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer := net.DestinationFromAddr(server.Listener.Addr())
	conn, err := stdnet.DialTimeout("tcp", peer.NetAddr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(internet.ContextWithMobileProfile(context.Background()), 3*time.Second)
	defer cancel()
	secured, err := UClient(conn, &Config{
		ServerName: "example.com", Fingerprint: "chrome", PublicKey: key.PublicKey().Bytes(),
	}, ctx, peer)
	if secured != nil || err == nil || !strings.Contains(err.Error(), "REALITY: peer did not authenticate") {
		t.Fatalf("invalid peer returned %v, %v", secured, err)
	}
	if err := conn.SetDeadline(time.Now()); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("failed REALITY handshake kept the socket alive: %v", err)
	}
}
