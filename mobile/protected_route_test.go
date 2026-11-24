package mobile

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	testtcp "github.com/xtls/xray-core/testing/servers/tcp"
	testudp "github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	wiretcp "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type tunnelDialAudit struct {
	peer    string
	denied  chan string
	allowed atomic.Uint64
}

var dialAudit atomic.Pointer[tunnelDialAudit]

func init() {
	// Install once, before any test can dial. The active capture is atomic so
	// outstanding transport goroutines never race with setting up a test.
	err := internet.RegisterDialerController(func(_, address string, _ syscall.RawConn) error {
		audit := dialAudit.Load()
		if audit == nil {
			return nil
		}
		if address != audit.peer {
			select {
			case audit.denied <- address:
			default:
			}
			return errors.New("blocked unexpected system dial in protected tunnel test")
		}
		audit.allowed.Add(1)
		return nil
	})
	if err != nil {
		panic(err)
	}
}

func TestProtectedTunnelTrafficStaysOnVPN(t *testing.T) {
	transportCases := []struct {
		name, network, jsonOptions string
		config                     any
		alpn                       []string
	}{
		{"raw", "tcp", "", &wiretcp.Config{}, nil},
		{"grpc", "grpc", `,"grpcSettings":{"serviceName":"cvpn-test"}`, &grpc.Config{ServiceName: "cvpn-test"}, []string{"h2"}},
		{"grpc-multi", "grpc", `,"grpcSettings":{"serviceName":"cvpn-test","multiMode":true}`, &grpc.Config{ServiceName: "cvpn-test"}, []string{"h2"}},
		{"xhttp", "splithttp", `,"xhttpSettings":{"path":"/test/","mode":"packet-up"}`, &splithttp.Config{Path: "/test/", Mode: "packet-up"}, []string{"h2"}},
		{"xhttp-h3", "splithttp", `,"xhttpSettings":{"path":"/test/","mode":"packet-up"}`, &splithttp.Config{Path: "/test/", Mode: "packet-up"}, []string{"h3"}},
		{"xhttp-stream-one", "splithttp", `,"xhttpSettings":{"path":"/test/","mode":"stream-one"}`, &splithttp.Config{Path: "/test/", Mode: "stream-one"}, []string{"h2"}},
		{"xhttp-stream-one-h3", "splithttp", `,"xhttpSettings":{"path":"/test/","mode":"stream-one"}`, &splithttp.Config{Path: "/test/", Mode: "stream-one"}, []string{"h3"}},
		{"xhttp-stream-up", "splithttp", `,"xhttpSettings":{"path":"/test/","mode":"stream-up"}`, &splithttp.Config{Path: "/test/", Mode: "stream-up"}, []string{"h2"}},
		{"xhttp-header", "splithttp", `,"xhttpSettings":{"path":"/test/","mode":"packet-up","uplinkHTTPMethod":"GET","sessionIDPlacement":"header","seqPlacement":"header","uplinkDataPlacement":"header","uplinkDataKey":"X-Payload"}`,
			&splithttp.Config{Path: "/test/", Mode: "packet-up", UplinkHTTPMethod: "GET", SessionIDPlacement: "header", SeqPlacement: "header", UplinkDataPlacement: "header", UplinkDataKey: "X-Payload"}, []string{"h2"}},
	}
	for _, tc := range transportCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serverCert, fingerprint := cert.MustGenerate(nil, cert.CommonName("vpn.test"))
			id := uuid.New()
			validator := &vless.MemoryValidator{}
			if err := validator.Add(&protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(id)}}); err != nil {
				t.Fatal(err)
			}
			probes := make(chan xnet.Destination, 16)
			var dropResponse atomic.Bool
			var port xnet.Port
			if len(tc.alpn) == 1 && tc.alpn[0] == "h3" {
				port = testudp.PickPort()
			} else {
				port = testtcp.PickPort()
			}
			listener, err := internet.ListenTCP(ctx, xnet.LocalHostIP, port, &internet.MemoryStreamConfig{
				ProtocolName:     tc.network,
				ProtocolSettings: tc.config,
				SecuritySettings: &tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(serverCert)}, NextProtocol: tc.alpn},
			}, func(conn stat.Connection) {
				go func() {
					defer conn.Close()
					_, request, addons, _, err := encoding.DecodeRequestHeader(false, nil, conn, validator)
					if err != nil {
						return
					}
					reader := encoding.DecodeBodyAddons(conn, request, addons)
					payload, err := reader.ReadMultiBuffer()
					if err != nil {
						buf.ReleaseMulti(payload)
						return
					}
					withhold := dropResponse.Load()
					select {
					case probes <- request.Destination():
					case <-ctx.Done():
						buf.ReleaseMulti(payload)
						return
					}
					if withhold {
						buf.ReleaseMulti(payload)
						select {
						case <-ctx.Done():
						case <-time.After(2 * time.Second):
						}
						return
					}
					if err := encoding.EncodeResponseHeader(conn, request, &encoding.Addons{}); err != nil {
						buf.ReleaseMulti(payload)
						return
					}
					writer := buf.NewWriter(conn)
					if request.Command == protocol.RequestCommandUDP {
						payload[0].Bytes()[2] |= 0x80 // DNS response bit.
						writer = encoding.NewMultiLengthPacketWriter(writer)
					}
					writer.WriteMultiBuffer(payload)
				}()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			audit := &tunnelDialAudit{peer: net.JoinHostPort("127.0.0.1", port.String()), denied: make(chan string, 1)}
			dialAudit.Store(audit)
			defer dialAudit.Store(nil)
			alpn, err := json.Marshal(tc.alpn)
			if err != nil {
				t.Fatal(err)
			}
			config := fmt.Sprintf(`{
				"log":{"loglevel":"none"},"inbounds":[{"protocol":"tun"}],"outbounds":[
					{"protocol":"vless","settings":{"address":"127.0.0.1","port":%d,"id":%q,"encryption":"none"},
					"streamSettings":{"network":%q,"security":"tls","tlsSettings":{"serverName":"vpn.test","fingerprint":"unsafe","pinnedPeerCertSha256":"%x","alpn":%s}%s}},
					{"protocol":"blackhole","tag":"block"}
			]}`, port, id.String(), tc.network, fingerprint, alpn, tc.jsonOptions)
			packets := make(capturePackets, 32)
			tunnel, err := StartProtected(config, packets, 1280, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Stop()
			query := []byte{0xb0, 0x01, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
			addresses := []xnet.Address{xnet.ParseAddress("192.0.2.1"), xnet.ParseAddress("2001:db8::1")}
			for phase, reply := range []bool{true, false, true} {
				dropResponse.Store(!reply)
				dialsBefore := audit.allowed.Load()
				if phase != 0 {
					tunnel.NetworkChanged()
				}
				for i, address := range addresses {
					probeDNS(t, tunnel, packets, probes, xnet.UDPDestination(address, 53), query, audit.denied, reply)
					probeTCP(t, tunnel, packets, probes, audit.denied, xnet.TCPDestination(address, 443), 23532+uint16(2*phase+i), reply)
				}
				if audit.allowed.Load() == dialsBefore {
					t.Fatalf("phase %d reused a socket from the previous path", phase)
				}
			}
			if xhttp, ok := tc.config.(*splithttp.Config); ok && xhttp.Mode == "packet-up" {
				requests, _, _ := splithttp.MobileUploadStats()
				if requests <= tunnel.xhttpRequests {
					t.Fatal("the embedded tunnel did not use mobile XHTTP limits")
				}
			}
			select {
			case address := <-audit.denied:
				t.Fatalf("opened system socket to %s instead of VPN", address)
			default:
			}
		})
	}
}

func probeDNS(t *testing.T, tunnel *Tunnel, packets capturePackets, probes <-chan xnet.Destination, dest xnet.Destination, query []byte, denied <-chan string, wantReply bool) {
	t.Helper()
	packet := makeUDP4(query, uint16(dest.Port))
	if dest.Address.Family().IsIPv6() {
		packet = makeUDP6(query, uint16(dest.Port))
	}
	if !tunnel.PushPacket(packet) {
		t.Fatal("packet input refused")
	}
	expectVPNProbe(t, probes, denied, dest)
	wait := 4 * time.Second
	if !wantReply {
		wait = 120 * time.Millisecond
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case reply := <-packets:
			if len(reply) < 20 || !(reply[0]>>4 == 4 && reply[9] == 17 || reply[0]>>4 == 6 && reply[6] == 17) {
				continue
			}
			expected := bytes.Clone(query)
			expected[2] |= 0x80
			if !wantReply || len(reply) != len(packet) || !bytes.HasSuffix(reply, expected) {
				t.Fatalf("unexpected DNS response: %x", reply)
			}
			return
		case address := <-denied:
			t.Fatalf("DNS attempted to leave the VPN via %s", address)
		case <-timer.C:
			if wantReply {
				t.Fatalf("no tunneled reply from %s", dest)
			}
			return
		}
	}
}

func expectVPNProbe(t *testing.T, probes <-chan xnet.Destination, denied <-chan string, dest xnet.Destination) {
	t.Helper()
	select {
	case observed := <-probes:
		if observed != dest {
			t.Fatalf("VPN saw %s, want %s", observed, dest)
		}
	case address := <-denied:
		t.Fatalf("attempted system dial to %s", address)
	case <-time.After(4 * time.Second):
		t.Fatalf("VPN server did not receive traffic for %s", dest)
	}
}

func probeTCP(t *testing.T, tunnel *Tunnel, packets capturePackets, probes <-chan xnet.Destination, denied <-chan string, dest xnet.Destination, port uint16, wantReply bool) {
	t.Helper()
	ipv6 := dest.Address.Family().IsIPv6()
	if !tunnel.PushPacket(makeTCPPacket(dest, port, 100, 0, 0x02, nil)) {
		t.Fatal("TCP SYN rejected")
	}
	synAck := waitTCP(t, packets, denied, ipv6, port, 0x12, nil, 4*time.Second)
	if synAck == nil {
		t.Fatal("no SYN-ACK from TUN stack")
	}
	serverSeq := binary.BigEndian.Uint32(synAck[4:8]) + 1
	payload := []byte("TCP via VPN")
	if !tunnel.PushPacket(makeTCPPacket(dest, port, 101, serverSeq, 0x18, payload)) {
		t.Fatal("TCP payload rejected")
	}
	expectVPNProbe(t, probes, denied, dest)
	wait := 4 * time.Second
	if !wantReply {
		wait = 120 * time.Millisecond
	}
	if got := waitTCP(t, packets, denied, ipv6, port, 0, payload, wait); (got != nil) != wantReply {
		t.Fatalf("TCP payload received = %t, want %t", got != nil, wantReply)
	}
}

func waitTCP(t *testing.T, packets capturePackets, denied <-chan string, ipv6 bool, port uint16, flags byte, payload []byte, wait time.Duration) []byte {
	t.Helper()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ipHeader, version, protocolIndex := 20, byte(4), 9
	if ipv6 {
		ipHeader, version, protocolIndex = 40, 6, 6
	}
	for {
		select {
		case packet := <-packets:
			if len(packet) < ipHeader+20 || packet[0]>>4 != version || packet[protocolIndex] != 6 {
				continue
			}
			tcp := packet[ipHeader:]
			if binary.BigEndian.Uint16(tcp[2:4]) == port && tcp[13]&flags == flags && bytes.HasSuffix(tcp, payload) {
				return tcp
			}
		case address := <-denied:
			t.Fatalf("TCP attempted to leave the VPN via %s", address)
		case <-timer.C:
			return nil
		}
	}
}

func makeUDP6(payload []byte, port uint16) []byte {
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
	src, dst := netip.MustParseAddr("fd00:6376:706e::2").As16(), netip.MustParseAddr("2001:db8::1").As16()
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	binary.BigEndian.PutUint16(packet[40:], 23531)
	binary.BigEndian.PutUint16(packet[42:], port)
	binary.BigEndian.PutUint16(packet[44:], uint16(len(packet)-40))
	copy(packet[48:], payload)
	binary.BigEndian.PutUint16(packet[46:], packetChecksum(packet[8:], uint32(len(packet)-40)+17))
	return packet
}

func makeTCPPacket(dest xnet.Destination, port uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	ipHeader, addressAt := 20, 12
	if dest.Address.Family().IsIPv6() {
		ipHeader, addressAt = 40, 8
	}
	packet := make([]byte, ipHeader+20+len(payload))
	if ipHeader == 40 {
		packet[0], packet[6], packet[7] = 0x60, 6, 64
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-ipHeader))
		src := netip.MustParseAddr("fd00:6376:706e::2").As16()
		copy(packet[8:24], src[:])
		copy(packet[24:40], dest.Address.IP())
	} else {
		packet[0], packet[8], packet[9] = 0x45, 64, 6
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[12:16], []byte{198, 18, 0, 2})
		copy(packet[16:20], dest.Address.IP())
		binary.BigEndian.PutUint16(packet[10:], packetChecksum(packet[:20], 0))
	}
	tcp := packet[ipHeader:]
	binary.BigEndian.PutUint16(tcp, port)
	binary.BigEndian.PutUint16(tcp[2:], uint16(dest.Port))
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:], packetChecksum(packet[addressAt:], uint32(len(tcp))+6))
	return packet
}

func packetChecksum(buf []byte, sum uint32) uint16 {
	for i := 0; i < len(buf); i += 2 {
		sum += uint32(buf[i]) << 8
		if i+1 < len(buf) {
			sum += uint32(buf[i+1])
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
