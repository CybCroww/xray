//go:build xhysteria_interop && xhysteria_native && cgo && (linux || android)

package interop_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	apppolicy "github.com/xtls/xray-core/app/policy"
	appstats "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/userlimit"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	hyproxy "github.com/xtls/xray-core/proxy/hysteria"
	"github.com/xtls/xray-core/proxy/hysteria/account"
)

func TestNativeServerUserLimitAndAccounting(t *testing.T) {
	// A Go client exercises the native server's authenticated DispatchLink path.
	t.Setenv("XRAY_HYSTERIA_NATIVE", "0")
	file := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"users":{"458":{"uplinkBytesPerSecond":131072,"downlinkBytesPerSecond":131072}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	old := userlimit.Default
	userlimit.Default = userlimit.New(file)
	t.Cleanup(func() { userlimit.Default = old })
	server, caPath, instance := xrayServerWithConfig(t, true, func(c *core.Config) {
		nativeServerConfig(t, c, false)
		c.Inbound[0].ProxySettings = serial.ToTypedMessage(&hyproxy.ServerConfig{Users: []*protocol.User{{Email: "458", Account: serial.ToTypedMessage(&account.Account{Auth: auth})}}})
		c.App = append(c.App, serial.ToTypedMessage(&apppolicy.Config{Level: map[uint32]*apppolicy.Policy{0: {Stats: &apppolicy.Policy_Stats{UserUplink: true, UserDownlink: true, UserOnline: true}}}}), serial.ToTypedMessage(&appstats.Config{}))
	})
	ca, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	// Stats intentionally ignores 127.0.0.1; relay from a distinct real source.
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		t.Fatal(err)
	}
	upstream, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)}, address)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	var relay sync.WaitGroup
	relay.Add(2)
	peer := make(chan *net.UDPAddr, 1)
	go func() {
		defer relay.Done()
		packet := make([]byte, 65536)
		for {
			n, client, err := front.ReadFromUDP(packet)
			if err != nil {
				return
			}
			select {
			case peer <- client:
			default:
			}
			if _, err := upstream.Write(packet[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer relay.Done()
		packet := make([]byte, 65536)
		var client *net.UDPAddr
		for {
			n, err := upstream.Read(packet)
			if err != nil {
				return
			}
			if client == nil {
				client = <-peer
			}
			if _, err := front.WriteToUDP(packet[:n], client); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { front.Close(); upstream.Close(); relay.Wait() })
	client := embeddedClient(t, front.LocalAddr().String(), ca, true)
	tcp, _ := echoTargets(t)
	target, err := xnet.ParseDestination("tcp:" + tcp)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var connections []net.Conn
	for range 2 {
		conn, err := core.Dial(ctx, client, target)
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, conn)
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(15 * time.Second))
	}
	const size = 192 << 10
	payload := bytes.Repeat([]byte{0xa7}, size)
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	started := time.Now()
	for _, conn := range connections {
		wg.Add(2)
		go func() { defer wg.Done(); _, err := conn.Write(payload); errors <- err }()
		go func() {
			defer wg.Done()
			got := make([]byte, size)
			_, err := io.ReadFull(conn, got)
			if err == nil && !bytes.Equal(payload, got) {
				err = io.ErrUnexpectedEOF
			}
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(started); elapsed < 2*time.Second {
		t.Fatalf("two streams bypassed the shared 128 KiB/s budget: %s", elapsed)
	} else {
		t.Logf("shared limit: %d bytes per direction in %s", 2*size, elapsed)
	}
	m := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	for _, direction := range []string{"uplink", "downlink"} {
		counter := m.GetCounter("user>>>458>>>traffic>>>" + direction)
		if counter == nil || counter.Value() != 2*size {
			t.Fatalf("lost authenticated %s accounting: %v", direction, counter)
		}
	}
	online := m.GetOnlineMap("user>>>458>>>online")
	if online == nil || online.Count() != 1 {
		t.Fatalf("native source IP not tracked: %v", online)
	}
	online.ForEach(func(ip string, _ int64) bool {
		if ip != "127.0.0.2" {
			t.Errorf("source IP = %q, want loopback client", ip)
		}
		return true
	})
	for _, conn := range connections {
		conn.Close()
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for online.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if online.Count() != 0 {
		t.Fatal("closed native streams retained an online IP")
	}
}
