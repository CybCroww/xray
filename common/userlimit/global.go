package userlimit

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type brokerConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type globalPool struct {
	gate    chan struct{}
	credit  int64
	expires time.Time
}

type brokerClient interface {
	Do(*http.Request) (*http.Response, error)
}

type brokerGrant struct {
	Bytes        int64 `json:"bytes"`
	TTLms        int   `json:"ttlMs"`
	RetryAfterMs int   `json:"retryAfterMs"`
	Unlimited    bool  `json:"unlimited"`
}

func sameBroker(a, b *brokerConfig) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func newBrokerClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxIdleConnsPerHost = 16
	return &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (m *Manager) requestGrant(ctx context.Context, broker *brokerConfig, email string, direction Direction) (brokerGrant, time.Time, error) {
	started := time.Now()
	if broker == nil || broker.Token == "" || len(broker.Token) > 4096 || strings.ContainsAny(broker.Token, "\r\n") || len(broker.URL) > 4096 {
		return brokerGrant{}, started, fmt.Errorf("global bandwidth broker unavailable")
	}
	target, err := url.ParseRequestURI(broker.URL)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Fragment != "" {
		return brokerGrant{}, started, fmt.Errorf("global bandwidth broker requires verified HTTPS")
	}
	name := "uplink"
	if direction == Downlink {
		name = "downlink"
	}
	body, err := json.Marshal(struct {
		UID       string `json:"uid"`
		Direction string `json:"direction"`
		Bytes     int    `json:"bytes"`
	}{email, name, burstBytes})
	if err != nil {
		return brokerGrant{}, started, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, broker.URL, bytes.NewReader(body))
	if err != nil {
		return brokerGrant{}, started, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+broker.Token)
	response, err := m.client.Do(req)
	if err != nil {
		return brokerGrant{}, started, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return brokerGrant{}, started, fmt.Errorf("global bandwidth broker rejected request")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(payload) > 4096 {
		return brokerGrant{}, started, fmt.Errorf("invalid global bandwidth response size")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var grant brokerGrant
	if err := decoder.Decode(&grant); err != nil {
		return brokerGrant{}, started, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return brokerGrant{}, started, fmt.Errorf("trailing global bandwidth response")
	}
	if grant.Unlimited {
		if grant.Bytes != 0 || grant.TTLms != 0 || grant.RetryAfterMs != 0 {
			return brokerGrant{}, started, fmt.Errorf("ambiguous global bandwidth response")
		}
	} else if grant.Bytes < 0 || grant.Bytes > burstBytes || grant.TTLms < 1 || grant.TTLms > 500 || grant.RetryAfterMs < 0 || grant.RetryAfterMs > 1000 || grant.Bytes == 0 && grant.RetryAfterMs == 0 {
		return brokerGrant{}, started, fmt.Errorf("invalid global bandwidth grant")
	}
	return grant, started, nil
}

func waitGlobalRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (m *Manager) waitGlobal(ctx context.Context, settings *config, pool *globalPool, email string, direction Direction, size int64) (int64, bool, error) {
	select {
	case pool.gate <- struct{}{}:
		defer func() { <-pool.gate }()
	case <-ctx.Done():
		return 0, false, ctx.Err()
	}
	if m.config.Load() != settings {
		return 0, false, nil
	}
	if time.Now().Before(pool.expires) && pool.credit > 0 {
		charged := min(size, pool.credit)
		pool.credit -= charged
		return charged, false, nil
	}
	pool.credit = 0
	grant, started, err := m.requestGrant(ctx, settings.Broker, email, direction)
	m.refresh()
	if m.config.Load() != settings {
		return 0, false, nil
	}
	if err != nil {
		// A local fallback would multiply the global budget during a partition.
		return 0, false, waitGlobalRetry(ctx, 100*time.Millisecond)
	}
	if grant.Unlimited {
		return 0, true, nil
	}
	pool.expires = started.Add(time.Duration(grant.TTLms) * time.Millisecond)
	if grant.Bytes == 0 {
		return 0, false, waitGlobalRetry(ctx, time.Duration(grant.RetryAfterMs)*time.Millisecond)
	}
	if !time.Now().Before(pool.expires) {
		return 0, false, waitGlobalRetry(ctx, 10*time.Millisecond)
	}
	pool.credit = grant.Bytes
	charged := min(size, pool.credit)
	pool.credit -= charged
	return charged, false, nil
}
