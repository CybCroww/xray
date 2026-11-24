package mobile

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"runtime/debug"
	"testing"
	"time"
)

type capturePackets chan []byte

func (c capturePackets) WritePacket(packet []byte) bool {
	select {
	case c <- append([]byte(nil), packet...):
		return true
	default:
		return false
	}
}

func TestEmbeddedPacketTunnelUDPAndRestart(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		b := make([]byte, 1500)
		for {
			n, from, err := server.ReadFromUDP(b)
			if err != nil {
				return
			}
			if _, err := server.WriteToUDP(b[:n], from); err != nil {
				return
			}
		}
	}()
	defer func() { server.Close(); <-serverDone }()
	config := fmt.Sprintf(`{"log":{"loglevel":"none"},"inbounds":[{"protocol":"tun","settings":{"mtu":1500}}],"outbounds":[{"protocol":"freedom","settings":{"redirect":%q}}]}`, server.LocalAddr().String())
	oldLimit := debug.SetMemoryLimit(-1)
	for i := range 2 {
		packets := make(capturePackets, 8)
		tunnel, err := Start(config, packets, 1280, 30)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tunnel.Stop() })
		body := []byte{byte(i), 2, 3, 4, 5}
		packet := makeUDP4(body, uint16(server.LocalAddr().(*net.UDPAddr).Port))
		if !tunnel.PushPacket(packet) {
			t.Fatal("input rejected")
		}
		for j := range packet {
			packet[j] = 0
		} // host memory is not retained
		select {
		case response := <-packets:
			if len(response) != 28+len(body) || string(response[28:]) != string(body) {
				t.Fatalf("wrong response: %x", response)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no response from the external UDP echo")
		}
		if !json.Valid([]byte(tunnel.MemoryStatsJSON())) {
			t.Fatal("invalid diagnostics")
		}
		if err := tunnel.Stop(); err != nil {
			t.Fatal(err)
		}
		if tunnel.PushPacket(packet) {
			t.Fatal("closed tunnel accepted a packet")
		}
		if debug.SetMemoryLimit(-1) != oldLimit {
			t.Fatal("process memory target was not restored")
		}
	}
}

func makeUDP4(payload []byte, port uint16) []byte {
	b := make([]byte, 28+len(payload))
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:], []byte{198, 18, 0, 2})
	copy(b[16:], []byte{192, 0, 2, 1})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	sum = sum>>16 + sum&0xffff
	binary.BigEndian.PutUint16(b[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(b[20:], 23531)
	binary.BigEndian.PutUint16(b[22:], port)
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func TestPacketDeviceShedsOverloadAndPreservesOrder(t *testing.T) {
	d := newPacketDevice(make(capturePackets, 1), 1280)
	defer d.Close()
	b := make([]byte, 40)
	for i := range inputPackets {
		b[1] = byte(i)
		if !d.push(b) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	if d.push(b) || d.inputDrops.Load() != 1 {
		t.Fatal("input queue exceeded its bound")
	}
	for i := range inputPackets {
		p, err := d.ReadPacket(b)
		if err != nil || p[1] != byte(i) {
			t.Fatalf("read %d: %v", i, err)
		}
	}
}
