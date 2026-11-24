package hysteria

import (
	"io"
	"testing"
)

func TestMobileDatagramReceiveBudgetAcrossFlows(t *testing.T) {
	const capacity = 1200
	const flows = mobileDatagramReceiveBytes/(capacity*mobileDatagramsPerFlow) + 2
	budget := new(datagramReceiveBudget)
	addSession := func(m *udpSessionManager, id uint32) *InterConn {
		c := &InterConn{id: id, ch: make(chan []byte, mobileDatagramsPerFlow), budget: budget}
		m.m[id] = c
		return c
	}
	manager := &udpSessionManager{m: make(map[uint32]*InterConn), budget: budget}
	otherManager := &udpSessionManager{m: make(map[uint32]*InterConn), budget: budget}
	var sent int
	for id := range uint32(flows - 1) {
		addSession(manager, id)
		for byteValue := range mobileDatagramsPerFlow + 1 {
			packet := make([]byte, 900, capacity)
			packet[0] = byte(byteValue)
			manager.feed(id, packet)
			sent++
		}
	}
	other := addSession(otherManager, 0)
	otherManager.feed(0, make([]byte, 900, capacity))
	sent++
	if got := len(manager.m[0].ch); got != mobileDatagramsPerFlow {
		t.Fatalf("first flow holds %d datagrams, want %d", got, mobileDatagramsPerFlow)
	}
	queued := mobileDatagramReceiveBytes / capacity
	if len(other.ch) != 0 || budget.bytes.Load() != int64(queued*capacity) || budget.dropped.Load() != uint64(sent-queued) {
		t.Fatalf("unexpected state at capacity: bytes=%d drops=%d second queue=%d", budget.bytes.Load(), budget.dropped.Load(), len(other.ch))
	}
	first := manager.m[0]
	packet := make([]byte, capacity)
	if n, err := first.Read(packet); n != 900 || err != nil || packet[0] != 0 {
		t.Fatalf("oldest datagram changed: size=%d first byte=%d err=%v", n, packet[0], err)
	}
	otherManager.feed(0, make([]byte, 900, capacity))
	if len(other.ch) != 1 || budget.bytes.Load() != int64(queued*capacity) {
		t.Fatal("reading a datagram did not free capacity across connections")
	}
	manager.Lock()
	for _, conn := range manager.m {
		manager.close(conn)
	}
	manager.Unlock()
	if _, err := first.Read(packet); err != io.EOF || budget.bytes.Load() != capacity {
		t.Fatalf("closing the queues retained an unread backlog: err=%v bytes=%d", err, budget.bytes.Load())
	}
	otherManager.Lock()
	otherManager.close(other)
	otherManager.Unlock()
	if budget.bytes.Load() != 0 {
		t.Fatalf("closing all queues retained %d bytes", budget.bytes.Load())
	}
}
