package userlimit

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func saveGlobal(t *testing.T, m *Manager, broker *brokerConfig, rate int64) {
	t.Helper()
	next := config{Version: 1, Users: map[string]Limit{}, Broker: broker}
	if rate > 0 {
		next.Users["458"] = Limit{UplinkBytesPerSecond: rate, DownlinkBytesPerSecond: rate, Global: true}
	}
	data, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(m.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m.next.Store(0)
	m.mu.Lock()
	m.stamp = ""
	m.mu.Unlock()
	m.refresh()
}

func globalManager(t *testing.T, server *httptest.Server, rate int64) *Manager {
	t.Helper()
	m := New(filepath.Join(t.TempDir(), "limits.json"))
	client := m.client.(*http.Client)
	client.Transport = server.Client().Transport
	t.Cleanup(client.CloseIdleConnections)
	saveGlobal(t, m, &brokerConfig{URL: server.URL + "/grant", Token: "test-node"}, rate)
	return m
}

func jsonGrant(w http.ResponseWriter, amount int64, retry int) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(brokerGrant{Bytes: amount, TTLms: 500, RetryAfterMs: retry})
}

func TestGlobalBudgetSharedAcrossManagers(t *testing.T) {
	const rate = 256 << 10
	var mu sync.Mutex
	tokens, updated := float64(burstBytes), time.Now()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			UID       string `json:"uid"`
			Direction string `json:"direction"`
			Bytes     int64  `json:"bytes"`
		}
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-node" || json.NewDecoder(r.Body).Decode(&request) != nil || request.UID != "458" || request.Direction != "downlink" || request.Bytes != burstBytes {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		mu.Lock()
		now := time.Now()
		tokens = min(float64(burstBytes), tokens+now.Sub(updated).Seconds()*rate)
		updated = now
		amount := min(request.Bytes, int64(tokens))
		if amount < 4096 {
			amount = 0
		}
		tokens -= float64(amount)
		mu.Unlock()
		jsonGrant(w, amount, 16)
	}))
	defer server.Close()
	first, second := globalManager(t, server, rate), globalManager(t, server, rate)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, manager := range []*Manager{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.Wait(ctx, "458", Downlink, 4*burstBytes); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("two node managers exceeded one global budget: %s", elapsed)
	}
}

func TestGlobalPoolSharedAcrossStreamsAndSeparateDirections(t *testing.T) {
	var calls [2]atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct{ Direction string }
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid request")
		}
		direction := 0
		if request.Direction == "downlink" {
			direction = 1
		}
		calls[direction].Add(1)
		jsonGrant(w, burstBytes, 0)
	}))
	defer server.Close()
	m := globalManager(t, server, 625000)
	var wg sync.WaitGroup
	for range 100 {
		for _, direction := range []Direction{Uplink, Downlink} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := m.Wait(context.Background(), "458", direction, 64); err != nil {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if calls[0].Load() != 1 || calls[1].Load() != 1 {
		t.Fatalf("stream-specific grants instead of shared pools: up=%d down=%d", calls[0].Load(), calls[1].Load())
	}
}

func TestGlobalBrokerOutageDoesNotFallBackOrBlockUnlimitedUsers(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	m := globalManager(t, server, 625000)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.Wait(ctx, "458", Downlink, 1) }()
	<-started
	start := time.Now()
	if err := m.Wait(context.Background(), "other", Downlink, burstBytes); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("broker network wait held all users: %s", elapsed)
	}
	if err := <-done; err != context.DeadlineExceeded {
		t.Fatalf("global account escaped unavailable broker: %v", err)
	}
}

func TestGlobalInvalidResponsesFailClosed(t *testing.T) {
	for _, payload := range []string{`{`, `{"bytes":-1,"ttlMs":500}`, `{"bytes":65537,"ttlMs":500}`, `{"bytes":65536,"ttlMs":501}`, `{"bytes":65536,"ttlMs":0}`, `{"bytes":0,"ttlMs":500}`, `{"unlimited":true,"bytes":1}`, `{"bytes":1,"ttlMs":500,"unexpected":true}`, `{"bytes":1,"ttlMs":500}{}`, string(make([]byte, 4097))} {
		t.Run(payload[:min(30, len(payload))], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, payload) }))
			defer server.Close()
			m := globalManager(t, server, 625000)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			if err := m.Wait(ctx, "458", Downlink, 1); err != context.DeadlineExceeded {
				t.Fatalf("malformed grant allowed traffic: %v", err)
			}
		})
	}
}

func TestGlobalRequiresHTTPSAndDoesNotFollowRedirects(t *testing.T) {
	for _, mode := range []string{"http", "untrusted-tls", "redirect", "missing-broker", "missing-token"} {
		t.Run(mode, func(t *testing.T) {
			var redirected atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirected" {
					redirected.Add(1)
					jsonGrant(w, burstBytes, 0)
					return
				}
				if mode == "redirect" {
					http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
					return
				}
				jsonGrant(w, burstBytes, 0)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			if mode == "http" {
				server.Start()
			} else {
				server.StartTLS()
			}
			defer server.Close()
			m := globalManager(t, server, 625000)
			if mode == "untrusted-tls" {
				m.client = newBrokerClient()
			}
			if mode == "missing-broker" {
				saveGlobal(t, m, nil, 625000)
			}
			if mode == "missing-token" {
				saveGlobal(t, m, &brokerConfig{URL: server.URL}, 625000)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
			defer cancel()
			if err := m.Wait(ctx, "458", Downlink, 1); err != context.DeadlineExceeded {
				t.Fatalf("untrusted broker allowed traffic: %v", err)
			}
			if redirected.Load() != 0 {
				t.Fatal("broker redirect was followed")
			}
		})
	}
}

func TestGlobalPoolExpiresAndInvalidatesOnChanges(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		jsonGrant(w, burstBytes, 0)
	}))
	defer server.Close()
	m := globalManager(t, server, 625000)
	wait := func() {
		t.Helper()
		if err := m.Wait(context.Background(), "458", Downlink, 1); err != nil {
			t.Fatal(err)
		}
	}
	wait()
	pool := &m.global["458"][Downlink]
	pool.expires = time.Now().Add(-time.Second)
	wait()
	if calls.Load() != 2 {
		t.Fatal("expired unused credits were reused")
	}
	saveGlobal(t, m, m.config.Load().Broker, 312500)
	wait()
	if calls.Load() != 3 {
		t.Fatal("rate change reused old credits")
	}
	saveGlobal(t, m, &brokerConfig{URL: server.URL + "/grant", Token: "changed-node"}, 312500)
	wait()
	if calls.Load() != 4 {
		t.Fatal("broker change reused old credits")
	}
	saveGlobal(t, m, nil, 0)
	wait()
	if calls.Load() != 4 || len(m.global) != 0 {
		t.Fatal("explicit cap removal retained broker dependency")
	}
}

func TestGlobalLateGrantsCannotExtendTheirTTL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(40 * time.Millisecond)
		io.WriteString(w, `{"bytes":65536,"ttlMs":20}`)
	}))
	defer server.Close()
	m := globalManager(t, server, 625000)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	if err := m.Wait(ctx, "458", Downlink, 1); err != context.DeadlineExceeded {
		t.Fatalf("stale delayed credits allowed traffic: %v", err)
	}
}

func TestGlobalAuthoritativeRemovalReleasesBlockedAccount(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"unlimited":true}`)
	}))
	defer server.Close()
	m := globalManager(t, server, 625000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.Wait(ctx, "458", Downlink, 10*burstBytes); err != nil {
		t.Fatal(err)
	}
}
