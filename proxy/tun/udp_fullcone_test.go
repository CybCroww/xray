package tun

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// BenchmarkUDPNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPNewSession(b *testing.B) {
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {}, nil)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		u.HandlePacket(src, dst, &buf.Buffer{})
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		b := buf.New()
		b.WriteByte(byte(i))
		if !q.push(b) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		b, ok := q.pop()
		if !ok || b.Byte(0) != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, b, ok)
		}
		b.Release()
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&buf.Buffer{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push above the limit accepted")
	}
}

func TestPacketQueueCloseUnblocksReader(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan bool)
	go func() {
		_, ok := q.pop()
		done <- ok
	}()
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("blocked pop returned a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake the reader")
	}
}

func TestPacketQueueDropsDrainedStorage(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 100; i++ {
		q.push(&buf.Buffer{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}

func TestMobileUDPQueuesShareByteBudget(t *testing.T) {
	u := newUdpConnectionHandler(func(net.Conn, net.Destination) {}, nil)
	u.queueLimit = 16
	u.queueBytes = new(udpQueueBudget)
	defer u.closeAll()
	src := func(i int) net.Destination {
		return net.UDPDestination(net.ParseAddress("10.0.0.1"), net.Port(1200+i))
	}
	dst := net.UDPDestination(net.ParseAddress("10.0.0.2"), 443)
	large := make([]byte, 60<<10)
	send := func(source net.Destination, payload []byte) int64 {
		b := buf.NewWithSize(int32(len(payload)))
		b.Write(payload)
		u.HandlePacket(source, dst, b)
		return int64(b.Cap()) // Zero when HandlePacket dropped and released it.
	}
	largeCapacity := send(src(0), large)
	if largeCapacity == 0 || send(src(0), large) != largeCapacity || send(src(0), large) != 0 {
		t.Fatal("one flow was not capped by allocated buffer size")
	}
	other := net.UDPDestination(net.ParseAddress("10.0.0.2"), 53)
	dns := []byte("a short datagram")
	small := buf.NewWithSize(int32(len(dns)))
	small.Write(dns)
	u.HandlePacket(src(1), other, small)
	if small.Cap() == 0 {
		t.Fatal("one stalled UDP flow prevented a small datagram on another flow")
	}
	u.udpConns[src(1)].Close()
	if used := u.queueBytes.retained.Load(); used != 2*largeCapacity {
		t.Fatalf("closing a nonempty flow retained budget: %d", used)
	}

	flowCount := mobileUDPQueueBytes / int(2*largeCapacity)
	for i := 1; i < flowCount; i++ {
		if send(src(i), large) != largeCapacity || send(src(i), large) != largeCapacity {
			t.Fatalf("shared budget rejected flow %d prematurely", i)
		}
	}
	if used := u.queueBytes.retained.Load(); used != mobileUDPQueueBytes {
		t.Fatalf("expected fully reserved shared budget, got %d", used)
	}
	if send(src(flowCount), dns) != 0 || u.udpConns[src(flowCount)] != nil {
		t.Fatal("full queue budget let a new flow through")
	}
	queued, err := u.udpConns[src(0)].ReadMultiBuffer()
	if err != nil || queued.Len() != int32(len(large)) {
		t.Fatalf("queued datagram lost or changed: %d bytes, %v", queued.Len(), err)
	}
	buf.ReleaseMulti(queued)
	if send(src(flowCount), dns) == 0 {
		t.Fatal("dequeue did not make shared budget available")
	}
	u.reset(false)
	if len(u.udpConns) != 0 || u.queueBytes.retained.Load() != 0 {
		t.Fatal("path reset did not recover the shared UDP budget")
	}
}

func TestMobileUDPResetRejectsLateReplies(t *testing.T) {
	writes := 0
	u := newUdpConnectionHandler(func(net.Conn, net.Destination) {}, func([]byte, net.Destination, net.Destination) error {
		writes++
		return nil
	})
	u.queueBytes = new(udpQueueBudget)
	defer u.closeAll()
	src := net.UDPDestination(net.ParseAddress("198.18.0.2"), 40000)
	dst := net.UDPDestination(net.ParseAddress("192.0.2.1"), 53)
	u.HandlePacket(src, dst, buf.MergeBytes(nil, []byte("query"))[0])
	old := u.udpConns[src]
	u.reset(false)
	u.HandlePacket(src, dst, buf.MergeBytes(nil, []byte("new query"))[0])
	if _, err := old.Write([]byte("late response")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("old upstream could write back into the new flow: %v", err)
	}
	if err := old.WriteMultiBuffer(buf.MergeBytes(nil, []byte("late buffered response"))); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("old buffered reply could write back into the new flow: %v", err)
	}
	if _, err := u.udpConns[src].Write([]byte("new response")); err != nil || writes != 1 {
		t.Fatalf("want exactly one reply from the new flow, got %d, %v", writes, err)
	}
}

func TestMobileUDPReusesIdleFlowAtCapacity(t *testing.T) {
	for _, evictIdle := range []bool{false, true} {
		name := "all flows active"
		if evictIdle {
			name = "oldest idle flow reclaimed"
		}
		t.Run(name, func(t *testing.T) {
			const limit = 64
			u := newUdpConnectionHandler(func(net.Conn, net.Destination) {}, func([]byte, net.Destination, net.Destination) error { return nil })
			u.maxFlows, u.queueBytes = limit, new(udpQueueBudget)
			defer u.closeAll()
			source := func(i int) net.Destination {
				return net.UDPDestination(net.ParseAddress("198.18.0.2"), net.Port(40000+i))
			}
			for i := range limit {
				u.HandlePacket(source(i), net.UDPDestination(net.ParseAddress("192.0.2.1"), 443), buf.MergeBytes(nil, []byte("quic data"))[0])
			}
			oldest, receiving, otherIdle := u.udpConns[source(0)], u.udpConns[source(1)], u.udpConns[source(2)]
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if !oldest.bindCancel(cancel) {
				t.Fatal("registered flow could not bind to its upstream context")
			}
			if evictIdle {
				oldest.lastActive.Add(-int64(mobileUDPIdleBeforeReuse + 2*time.Second))
				otherIdle.lastActive.Add(-int64(mobileUDPIdleBeforeReuse + time.Second))
				receiving.lastActive.Add(-int64(mobileUDPIdleBeforeReuse + 3*time.Second))
				if _, err := receiving.Write([]byte("reply")); err != nil {
					t.Fatal(err)
				}
			}
			bytesBefore := u.queueBytes.retained.Load()
			dns := net.UDPDestination(net.ParseAddress("192.0.2.53"), 53)
			u.HandlePacket(source(limit), dns, buf.MergeBytes(nil, []byte("dns query"))[0])
			if len(u.udpConns) != limit || u.queueBytes.retained.Load() != bytesBefore {
				t.Fatal("UDP flow or queue budget changed at capacity")
			}
			if evictIdle {
				if u.udpConns[source(limit)] == nil || u.udpConns[source(0)] != nil || ctx.Err() != context.Canceled {
					t.Fatal("DNS did not replace the oldest idle upstream")
				}
				if oldest.bindCancel(func() { t.Error("retired upstream was bound again") }) {
					t.Fatal("a late dispatch could still bind the retired flow")
				}
			} else if u.udpConns[source(limit)] != nil || u.udpConns[source(0)] != oldest || ctx.Err() != nil || u.recheckAt == 0 {
				t.Fatal("a request at capacity disturbed an active flow or failed to defer the next scan")
			}
			if u.udpConns[source(1)] != receiving || u.udpConns[source(2)] != otherIdle {
				t.Fatal("reclaim changed additional slots")
			}
		})
	}
}

// A closing stack must end its UDP flows: the dispatch reading a flow gets EOF and returns, instead of
// waiting on the queue forever and keeping its outbound alive past the instance; a packet that arrives
// afterwards opens no flow.
func TestUDPHandlerCloseAllEndsFlows(t *testing.T) {
	done := make(chan struct{}, 2)
	handler := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {
		b := make([]byte, 2048)
		for {
			if _, err := conn.Read(b); err != nil {
				done <- struct{}{}
				return
			}
		}
	}, func(data []byte, src net.Destination, dst net.Destination) error { return nil })
	dst := net.UDPDestination(net.IPAddress([]byte{10, 6, 0, 2}), 53)
	for _, port := range []net.Port{40000, 40001} {
		src := net.UDPDestination(net.IPAddress([]byte{10, 255, 0, 2}), port)
		handler.HandlePacket(src, dst, buf.FromBytes([]byte("query")))
	}
	handler.closeAll()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("flow %d still running after closeAll", i)
		}
	}
	handler.HandlePacket(net.UDPDestination(net.IPAddress([]byte{10, 255, 0, 2}), 40002), dst, buf.FromBytes([]byte("late")))
	handler.RLock()
	n := len(handler.udpConns)
	handler.RUnlock()
	if n != 0 {
		t.Fatalf("%d flows in the table after closeAll", n)
	}
}
