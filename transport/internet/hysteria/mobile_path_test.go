package hysteria

import (
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestMobileHysteriaIdleDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expired := make(chan uint64, 1)
		idle := &mobileQUICIdle{expire: func(epoch uint64) { expired <- epoch }}
		defer idle.stop()
		idle.acquire()
		idle.acquire()
		idle.release()
		time.Sleep(2 * net.ConnIdleTimeout)
		synctest.Wait()
		select {
		case <-expired:
			t.Fatal("an active flow did not keep its connection warm")
		default:
		}
		idle.release()
		time.Sleep(net.ConnIdleTimeout - time.Second)
		idle.acquire()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case <-expired:
			t.Fatal("reusing the connection did not cancel its first deadline")
		default:
		}
		idle.release()
		time.Sleep(net.ConnIdleTimeout)
		synctest.Wait()
		select {
		case epoch := <-expired:
			if !idle.hasExpired(epoch) {
				t.Fatal("the deadline did not match the idle connection")
			}
			idle.acquire()
			if idle.hasExpired(epoch) {
				t.Fatal("a delayed timeout could close a reused connection")
			}
		default:
			t.Fatal("the connection stayed warm after its idle deadline")
		}
	})
}

func TestMobileHysteriaPathResetCancelsAuthentication(t *testing.T) {
	entered := make(chan struct{}, 1)
	var accept atomic.Bool
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.LocalHostIP.IP()})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	certificate, hash := cert.MustGenerate(nil, cert.CommonName("vpn.test"))
	key, err := x509.ParsePKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		TLSConfig:  &gotls.Config{Certificates: []gotls.Certificate{{Certificate: [][]byte{certificate.Certificate}, PrivateKey: key}}},
		QUICConfig: &quic.Config{EnableDatagrams: true},
		StreamDispatcher: func(frame http3.FrameType, stream *quic.Stream, err error) (bool, error) {
			if err != nil || frame != FrameTypeTCPRequest {
				return false, err
			}
			if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
				return false, err
			}
			go func() {
				defer stream.Close()
				_, _ = io.Copy(stream, stream)
			}()
			return true, nil
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if accept.Load() {
				w.WriteHeader(StatusAuthOK)
				return
			}
			select {
			case entered <- struct{}{}:
			default:
			}
			<-r.Context().Done()
		}),
	}
	defer server.Close()
	go server.Serve(listener)

	m := newClientManager(true)
	defer m.resetNetwork()
	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName, SecurityType: "tls", ProtocolSettings: &Config{Auth: "test"},
		SecuritySettings: &tls.Config{ServerName: "vpn.test", PinnedPeerCertSha256: [][]byte{hash[:]}},
		QuicParams:       &internet.QuicParams{Congestion: "reno", DisableChromeParrot: true},
	}
	dest := net.DestinationFromAddr(listener.LocalAddr())
	oldFlow, cancel := context.WithCancel(context.Background())
	defer cancel()
	authentication := make(chan error, 1)
	go func() {
		conn, err := m.dial(oldFlow, dest, settings)
		if conn != nil {
			conn.Close()
		}
		authentication <- err
	}()
	select {
	case <-entered:
	case err := <-authentication:
		t.Fatalf("old auth returned before its request arrived: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP/3 auth request did not reach the test server")
	}
	m.RLock()
	old := m.m[dialerConf{dest, settings}]
	m.RUnlock()
	if old == nil {
		t.Fatal("authenticating client is missing from its pool")
	}
	waiting := make(chan error, 1)
	go func() {
		conn, err := old.udp(oldFlow)
		if conn != nil {
			conn.Close()
		}
		waiting <- err
	}()
	accept.Store(true)
	m.resetNetwork()
	for _, attempt := range []<-chan error{authentication, waiting} {
		select {
		case err := <-attempt:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("old path returned %v, want cancellation", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("previous-path attempt stayed blocked")
		}
	}
	if oldFlow.Err() != nil {
		t.Fatal("reset canceled the caller's context")
	}
	if conn, err := old.tcp(oldFlow); conn != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("retired client accepted a fresh dial: %v", err)
	}
	newCtx, cancelNew := context.WithTimeout(oldFlow, 3*time.Second)
	defer cancelNew()
	fresh, err := m.dial(newCtx, dest, settings)
	if err != nil {
		t.Fatalf("new network failed to open a stream: %v", err)
	}
	defer fresh.Close()
	if err := fresh.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fresh, "echo"); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(fresh, reply[:]); err != nil || string(reply[:]) != "echo" {
		t.Fatalf("data after path reset: %q, %v", reply, err)
	}
	m.RLock()
	newClient := m.m[dialerConf{dest, settings}]
	m.RUnlock()
	if newClient == nil || newClient == old {
		t.Fatal("new network reused the previous QUIC client")
	}
	if err := newClient.acquire(newCtx); err != nil {
		t.Fatal(err)
	}
	activeQUIC := newClient.conn
	idle := newClient.mobileIdle
	newClient.unlock()
	if err := activeQUIC.Context().Err(); err != nil {
		t.Fatalf("new connection closed before its path was reset: %v", err)
	}
	udp, err := m.dial(ContextWithDatagram(newCtx, true), dest, settings)
	if err != nil {
		t.Fatalf("new network failed to open a UDP session: %v", err)
	}
	defer udp.Close()
	fresh.Close()
	idle.mu.Lock()
	users, timed := idle.users, idle.timer != nil
	idle.mu.Unlock()
	if users != 1 || timed {
		t.Fatal("closing TCP armed the timer while UDP still used the connection")
	}
	m.trimIdleClients()
	if err := activeQUIC.Context().Err(); err != nil {
		t.Fatalf("memory pressure closed an active UDP session: %v", err)
	}
	udp.Close()
	idle.mu.Lock()
	users, timed = idle.users, idle.timer != nil
	idle.mu.Unlock()
	if users != 0 || !timed {
		t.Fatal("closing the last UDP session did not arm the timer")
	}
	m.trimIdleClients()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := newClient.acquire(newCtx); err != nil {
			t.Fatal(err)
		}
		retired := newClient.conn == nil && newClient.pktConn == nil && newClient.mobileIdle == nil
		newClient.unlock()
		if retired {
			break
		}
		select {
		case <-newCtx.Done():
			t.Fatal("QUIC shutdown did not release its socket")
		case <-ticker.C:
		}
	}
	conn, err := m.dial(newCtx, dest, settings)
	if err != nil {
		t.Fatalf("failed to dial after QUIC shutdown: %v", err)
	}
	defer conn.Close()
	if err := newClient.acquire(newCtx); err != nil {
		t.Fatal(err)
	}
	activeQUIC = newClient.conn
	newClient.unlock()
	m.resetNetwork()
	select {
	case <-activeQUIC.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("network reset left an established QUIC connection open")
	}
}
