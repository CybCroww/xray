package mobile

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func appendBatchPacket(batch, packet []byte) []byte {
	batch = binary.BigEndian.AppendUint16(batch, uint16(len(packet)))
	return append(batch, packet...)
}

func TestPacketBatchWrapAndOverflow(t *testing.T) {
	device := newPacketDevice(nil, 1280)
	t.Cleanup(func() { device.Close() })
	scratch := make([]byte, 1280)
	packet := make([]byte, 20)
	for i := range inputPackets - 1 {
		packet[0] = byte(i)
		if !device.push(packet) {
			t.Fatalf("packet %d dropped before queue filled", i)
		}
	}
	for i := range 2 {
		got, err := device.ReadPacket(scratch)
		if err != nil || len(got) != len(packet) || got[0] != byte(i) {
			t.Fatalf("packet %d: got %x, %v", i, got, err)
		}
	}

	batch := make([]byte, 0, 4*(2+len(packet))+1)
	for i := inputPackets - 1; i < inputPackets+3; i++ {
		packet[0] = byte(i)
		batch = appendBatchPacket(batch, packet)
	}
	// The native caller supplies a reusable buffer with a shorter valid prefix.
	if accepted := device.pushBatch(append(batch, 0xff), len(batch)); accepted != 3 {
		t.Fatalf("accepted %d packets into three available slots", accepted)
	}
	if drops := device.inputDrops.Load(); drops != 1 {
		t.Fatalf("counted %d packet drops, want 1", drops)
	}
	clear(batch)
	for i := 2; i < inputPackets+2; i++ {
		got, err := device.ReadPacket(scratch)
		if err != nil || len(got) != len(packet) || got[0] != byte(i) {
			t.Fatalf("packet %d: got %x, %v", i, got, err)
		}
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	batch = appendBatchPacket(batch[:0], packet)
	if accepted := device.pushBatch(batch, len(batch)); accepted != 0 || device.inputDrops.Load() != 2 {
		t.Fatalf("closed queue accepted %d, total drops %d", accepted, device.inputDrops.Load())
	}
}

func TestPacketBatchRejectsMalformedInputAtomically(t *testing.T) {
	device := newPacketDevice(nil, 1280)
	t.Cleanup(func() { device.Close() })
	packet := make([]byte, 20)
	valid := appendBatchPacket(nil, packet)
	two := appendBatchPacket(append([]byte(nil), valid...), packet)
	tooLarge := make([]byte, inputBatchBytes+1)
	invalid := []struct {
		name   string
		data   []byte
		length int
	}{
		{"negative length", valid, -1},
		{"length beyond buffer", valid, len(valid) + 1},
		{"length beyond cap", tooLarge, len(tooLarge)},
		{"truncated length", two, len(valid) + 1},
		{"truncated packet", two, len(two) - 1},
		{"undersized packet", appendBatchPacket(nil, packet[:19]), 21},
		{"oversized packet", appendBatchPacket(nil, make([]byte, 1281)), 1283},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			accepted := device.pushBatch(tc.data, tc.length)
			if queued, _ := device.inputState(); accepted != -1 || queued != 0 {
				t.Fatalf("malformed batch accepted %d, queue size %d", accepted, queued)
			}
		})
	}
}

func TestOfflineInputDropsBacklogAndResumes(t *testing.T) {
	device := newPacketDevice(nil, 1280)
	defer device.Close()
	old := make([]byte, 20)
	if !device.push(old) || !device.pauseInput(true) || device.pauseInput(true) {
		t.Fatal("first outage did not pause input exactly once")
	}
	if count, paused := device.inputState(); !paused || count != 0 {
		t.Fatalf("input state after outage: %d queued, paused = %t", count, paused)
	}
	if device.push(old) {
		t.Fatal("single input accepted during outage")
	}
	batch := appendBatchPacket(nil, old)
	if got := device.pushBatch(batch, len(batch)); got != 0 {
		t.Fatalf("batch accepted %d packets during outage", got)
	}
	if drops := device.inputDrops.Load(); drops != 3 {
		t.Fatalf("got %d dropped packets, want 3", drops)
	}
	if !device.pauseInput(false) {
		t.Fatal("input did not resume")
	}
	newPacket := make([]byte, 20)
	newPacket[0] = 42
	if !device.push(newPacket) {
		t.Fatal("packet after recovery was rejected")
	}
	got, err := device.ReadPacket(make([]byte, 1280))
	if err != nil || len(got) != 20 || got[0] != 42 {
		t.Fatalf("first packet after recovery: %x, %v", got, err)
	}
}

func BenchmarkPacketIngress(b *testing.B) {
	const burst = 8
	for _, size := range []int{120, 1200} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			packet := make([]byte, size)
			var batch []byte
			for range burst {
				batch = appendBatchPacket(batch, packet)
			}
			for _, mode := range []string{"single", "batch"} {
				b.Run(mode, func(b *testing.B) {
					device := newPacketDevice(nil, 1280)
					scratch := make([]byte, 1280)
					b.SetBytes(int64(size * burst))
					b.ReportAllocs()
					for b.Loop() {
						if mode == "single" {
							for range burst {
								device.push(packet)
							}
						} else {
							device.pushBatch(batch, len(batch))
						}
						for range burst {
							if _, err := device.ReadPacket(scratch); err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		})
	}
}
