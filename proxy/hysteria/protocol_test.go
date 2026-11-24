package hysteria

import (
	"bytes"
	"io"
	"testing"

	transportHysteria "github.com/xtls/xray-core/transport/internet/hysteria"
)

func TestParseUDPMessage(t *testing.T) {
	msg := &UDPMessage{
		PacketID:  7,
		FragCount: 1,
		Addr:      "example.com:53",
		Data:      []byte("payload"),
	}
	packet := make([]byte, transportHysteria.MaxDatagramFrameSize)
	n := msg.Serialize(packet)
	if n < 0 {
		t.Fatal("failed to serialize UDP message")
	}

	parsed, err := ParseUDPMessage(packet[:n])
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PacketID != msg.PacketID || parsed.FragCount != msg.FragCount || parsed.Addr != msg.Addr || string(parsed.Data) != string(msg.Data) {
		t.Fatalf("unexpected parsed message: %#v", parsed)
	}
}

func TestUDPReaderReadFromFragmentedDatagram(t *testing.T) {
	first := bytes.Repeat([]byte{'a'}, 700)
	second := bytes.Repeat([]byte{'b'}, 400)
	packets := makeFragmentPackets(t, first, second)
	want := append(first, second...)
	for _, order := range []struct {
		name    string
		packets [][]byte
	}{
		{name: "in order", packets: packets},
		{name: "reversed", packets: [][]byte{packets[1], packets[0]}},
	} {
		t.Run(order.name, func(t *testing.T) {
			reader := &UDPReader{
				reader: &datagramListReader{packets: order.packets},
				df:     &Defragger{byteLimit: mobileUDPReassemblyBudget},
			}

			payload := make([]byte, 2048)
			n, addr, err := reader.ReadFrom(payload)
			if err != nil {
				t.Fatal(err)
			}
			if addr == nil || addr.NetAddr() != "example.com:53" {
				t.Fatalf("unexpected destination: %v", addr)
			}
			if !bytes.Equal(payload[:n], want) || reader.df.pendingBytes != 0 {
				t.Fatalf("assembled %d bytes, have %d bytes pending", n, reader.df.pendingBytes)
			}
		})
	}
}

func TestUDPReaderDropsFragmentsExceedingOutputCapacity(t *testing.T) {
	large := makeFragmentPackets(t, bytes.Repeat([]byte{'a'}, 8), bytes.Repeat([]byte{'b'}, 8))
	small := makeFragmentPackets(t, []byte("abc"), []byte("def"))
	reader := &UDPReader{
		reader: &datagramListReader{packets: append(large, small...)},
		df:     &Defragger{byteLimit: mobileUDPReassemblyBudget},
	}
	payload := make([]byte, 12)
	n, _, err := reader.ReadFrom(payload)
	if err != nil || string(payload[:n]) != "abcdef" || reader.df.pendingBytes != 0 {
		t.Fatalf("read %q, err = %v, pending bytes = %d", payload[:n], err, reader.df.pendingBytes)
	}
}

func TestDefraggerEvictsOldestBeforeExceedingBudget(t *testing.T) {
	d := &Defragger{byteLimit: 1700}
	data := bytes.Repeat([]byte{'a'}, 500)
	for id := uint16(1); id <= 3; id++ {
		d.Feed(&UDPMessage{PacketID: id, FragCount: 3, Addr: "example.com:53", Data: data})
	}
	if d.findSlot(1) != nil || d.findSlot(2) == nil || d.findSlot(3) == nil || d.pendingBytes > d.byteLimit {
		t.Fatalf("expected packets 2 and 3 to remain, pending bytes = %d", d.pendingBytes)
	}
	before := d.pendingBytes
	d.Feed(&UDPMessage{PacketID: 2, FragCount: 3, Addr: "example.com:53", Data: data})
	if d.pendingBytes != before {
		t.Fatalf("duplicate changed pending bytes from %d to %d", before, d.pendingBytes)
	}
	d.Feed(&UDPMessage{PacketID: 3, FragID: 1, FragCount: 3, Addr: "example.com:53", Data: bytes.Repeat([]byte{'b'}, 700)})
	if d.findSlot(2) != nil || d.findSlot(3) == nil || d.pendingBytes > d.byteLimit {
		t.Fatalf("expected only packet 3 to remain, pending bytes = %d", d.pendingBytes)
	}
	last := bytes.Repeat([]byte{'c'}, 500)
	got := d.Feed(&UDPMessage{PacketID: 3, FragID: 2, FragCount: 3, Addr: "example.com:53", Data: last})
	if got == nil || len(got.Data) != 1700 || !bytes.HasSuffix(got.Data, last) || d.pendingBytes != 0 {
		t.Fatalf("packet did not complete correctly, pending bytes = %d", d.pendingBytes)
	}
}

func TestDefraggerHandlesInterleavedPackets(t *testing.T) {
	d := &Defragger{}
	if got := d.Feed(&UDPMessage{PacketID: 1, FragID: 0, FragCount: 2, Addr: "example.com:53", Data: []byte("a")}); got != nil {
		t.Fatal("first fragment unexpectedly completed")
	}
	if got := d.Feed(&UDPMessage{PacketID: 2, FragID: 0, FragCount: 2, Addr: "example.com:53", Data: []byte("c")}); got != nil {
		t.Fatal("second packet unexpectedly completed")
	}
	if got := d.Feed(&UDPMessage{PacketID: 1, FragID: 1, FragCount: 2, Addr: "example.com:53", Data: []byte("b")}); got == nil || string(got.Data) != "ab" {
		t.Fatalf("first packet = %#v", got)
	}
	if got := d.Feed(&UDPMessage{PacketID: 2, FragID: 1, FragCount: 2, Addr: "example.com:53", Data: []byte("d")}); got == nil || string(got.Data) != "cd" {
		t.Fatalf("second packet = %#v", got)
	}
}

func makeFragmentPackets(t *testing.T, first []byte, second []byte) [][]byte {
	t.Helper()
	messages := []UDPMessage{
		{PacketID: 9, FragID: 0, FragCount: 2, Addr: "example.com:53", Data: first},
		{PacketID: 9, FragID: 1, FragCount: 2, Addr: "example.com:53", Data: second},
	}
	packets := make([][]byte, 0, len(messages))
	for i := range messages {
		packet := make([]byte, transportHysteria.MaxDatagramFrameSize)
		n := messages[i].Serialize(packet)
		if n < 0 {
			t.Fatal("failed to serialize UDP fragment")
		}
		packets = append(packets, packet[:n])
	}
	return packets
}

type datagramListReader struct {
	packets [][]byte
	index   int
}

func (r *datagramListReader) Read(p []byte) (int, error) {
	if r.index >= len(r.packets) {
		return 0, io.EOF
	}
	packet := r.packets[r.index]
	r.index++
	return copy(p, packet), nil
}
