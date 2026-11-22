package userlimit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

func save(t *testing.T, m *Manager, users map[string]Limit) {
	t.Helper()
	data, err := json.Marshal(config{Version: 1, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(m.path+".new", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(m.path+".new", m.path); err != nil {
		t.Fatal(err)
	}
	m.next.Store(0)
	m.refresh()
}

func manager(t *testing.T, rate int64) *Manager {
	t.Helper()
	m := New(filepath.Join(t.TempDir(), "limits.json"))
	save(t, m, map[string]Limit{"458": {UplinkBytesPerSecond: rate, DownlinkBytesPerSecond: rate}})
	return m
}

func TestSharedAccountBudgetAndIndependentDirections(t *testing.T) {
	m := manager(t, 512<<10)
	start := time.Now()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Wait(context.Background(), "458", Downlink, 3*burstBytes); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 570*time.Millisecond {
		t.Fatalf("parallel streams exceeded shared budget: %s", elapsed)
	}
	start = time.Now()
	for _, id := range []string{"458", "other"} {
		if err := m.Wait(context.Background(), id, Uplink, burstBytes); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("other users/direction throttled: %s", elapsed)
	}
}

func TestCancellationDoesNotReserveFutureBudget(t *testing.T) {
	m := manager(t, 512<<10)
	if err := m.Wait(context.Background(), "458", Uplink, burstBytes); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.Wait(ctx, "458", Uplink, 1<<20); err != context.DeadlineExceeded {
		t.Fatalf("cancellation: %v", err)
	}
	start := time.Now()
	if err := m.Wait(context.Background(), "458", Uplink, 1024); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("cancelled reservation left debt: %s", elapsed)
	}
}

func TestInvalidFilesRetainLastValidLimits(t *testing.T) {
	m := manager(t, 125000)
	for _, data := range []string{`{`, `{"version":2,"users":{}}`, `{"version":1,"users":{"458":{"downlinkBytesPerSecond":-1}}}`, `{"version":1,"users":{},"typo":1}`, `{"version":1,"users":{}}{}`} {
		if err := os.WriteFile(m.path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		m.next.Store(0)
		m.refresh()
		if !m.limited("458", Downlink) {
			t.Fatal("invalid update silently removed limit")
		}
	}
	if err := os.Remove(m.path); err != nil {
		t.Fatal(err)
	}
	m.next.Store(0)
	m.refresh()
	if !m.limited("458", Uplink) {
		t.Fatal("missing file silently removed limit")
	}
	save(t, m, map[string]Limit{})
	if m.limited("458", Uplink) || len(m.buckets) != 0 {
		t.Fatal("explicit removal retained account bucket")
	}
}

func TestConfigIsBounded(t *testing.T) {
	m := manager(t, 125000)
	tooMany := map[string]Limit{}
	for i := range maxUsers + 1 {
		tooMany["user"+time.Duration(i).String()] = Limit{DownlinkBytesPerSecond: 1}
	}
	save(t, m, tooMany)
	if len(m.config.Load().Users) != 1 {
		t.Fatal("unbounded account map accepted")
	}
	if err := os.WriteFile(m.path, make([]byte, maxFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	m.next.Store(0)
	m.refresh()
	if len(m.config.Load().Users) != 1 {
		t.Fatal("oversize file accepted")
	}
}

type recorder struct {
	calls, sizes        int
	closed, interrupted bool
}

func (r *recorder) WriteMultiBuffer(mb buf.MultiBuffer) error {
	r.calls++
	r.sizes += int(mb.Len())
	buf.ReleaseMulti(mb)
	return nil
}
func (r *recorder) Close() error { r.closed = true; return nil }
func (r *recorder) Interrupt()   { r.interrupted = true }

func TestExistingWriterSeesNewLimitAndRemoval(t *testing.T) {
	m := manager(t, 0)
	r := new(recorder)
	w := NewWriter(context.Background(), m, "458", Downlink, r)
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("one")), buf.FromBytes([]byte("two"))}); err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 {
		t.Fatal("unlimited writer lost batching")
	}
	save(t, m, map[string]Limit{"458": {DownlinkBytesPerSecond: 1024}})
	if err := m.Wait(context.Background(), "458", Downlink, burstBytes); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes(make([]byte, 8192))}) }()
	select {
	case <-done:
		t.Fatal("existing writer bypassed new limit")
	case <-time.After(20 * time.Millisecond):
	}
	save(t, m, map[string]Limit{})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("removal did not wake existing writer")
	}
	w.Interrupt()
	if !r.interrupted {
		t.Fatal("underlying writer not interrupted")
	}
	w.Close()
	if !r.closed {
		t.Fatal("underlying writer not closed")
	}
}

type source struct{ mb buf.MultiBuffer }

func (s *source) ReadMultiBuffer() (buf.MultiBuffer, error) { return s.mb, io.EOF }

func TestReaderPreservesUDPAndReleasesOnCancellation(t *testing.T) {
	m := manager(t, 125000)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b := buf.New()
	b.Write([]byte("payload"))
	r := NewReader(ctx, m, "458", &source{mb: buf.MultiBuffer{b}})
	mb, err := r.ReadMultiBuffer()
	if mb != nil || err != context.Canceled || !b.IsEmpty() {
		t.Fatal("cancelled reader retained buffer")
	}
	packet := buf.FromBytes([]byte("datagram"))
	destination := net.UDPDestination(net.LocalHostIP, 53)
	packet.UDP = &destination
	reader := NewReader(context.Background(), m, "458", &source{mb: buf.MultiBuffer{packet}})
	result, err := reader.ReadMultiBuffer()
	if err != io.EOF || len(result) != 1 || result[0].UDP != &destination || string(result[0].Bytes()) != "datagram" {
		t.Fatal("UDP datagram or EOF changed")
	}
	buf.ReleaseMulti(result)
}

func BenchmarkUnlimitedWait(b *testing.B) {
	m := New(filepath.Join(b.TempDir(), "missing.json"))
	b.ResetTimer()
	for range b.N {
		if m.limited("unlimited", Downlink) {
			b.Fatal("unexpected limit")
		}
	}
}
