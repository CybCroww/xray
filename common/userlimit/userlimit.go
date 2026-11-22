// Package userlimit shares optional bandwidth budgets across one user's streams.
package userlimit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

const (
	maxFile    = 1 << 20
	maxUsers   = 1000
	burstBytes = 64 << 10
)

type Direction uint8

const (
	Uplink Direction = iota
	Downlink
)

type Limit struct {
	UplinkBytesPerSecond   int64 `json:"uplinkBytesPerSecond"`
	DownlinkBytesPerSecond int64 `json:"downlinkBytesPerSecond"`
	Global                 bool  `json:"global,omitempty"`
}

type config struct {
	Version int              `json:"version"`
	Users   map[string]Limit `json:"users"`
	Broker  *brokerConfig    `json:"broker,omitempty"`
}

type bucket struct {
	tokens float64
	last   time.Time
}

type Manager struct {
	path    string
	mu      sync.Mutex
	next    atomic.Int64
	config  atomic.Pointer[config]
	stamp   string
	buckets map[string]*[2]bucket
	global  map[string]*[2]globalPool
	client  brokerClient
}

var Default = New(os.Getenv("XRAY_USER_LIMITS_FILE"))

// New returns nil when the optional feature is disabled.
func New(path string) *Manager {
	if path == "" {
		return nil
	}
	m := &Manager{path: path, buckets: make(map[string]*[2]bucket), global: make(map[string]*[2]globalPool), client: newBrokerClient()}
	m.config.Store(&config{Version: 1, Users: map[string]Limit{}})
	m.refresh()
	return m
}

func (m *Manager) refresh() {
	now := time.Now()
	if now.UnixNano() < m.next.Load() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if now.UnixNano() < m.next.Load() {
		return
	}
	m.next.Store(now.Add(time.Second).UnixNano())
	info, err := os.Stat(m.path)
	stamp := "missing"
	if err == nil {
		stamp = fmt.Sprintf("%d/%d", info.ModTime().UnixNano(), info.Size())
	}
	if stamp == m.stamp {
		return
	}
	m.stamp = stamp
	if err == nil && (!info.Mode().IsRegular() || info.Size() > maxFile) {
		err = fmt.Errorf("not a bounded regular file")
	}
	var data []byte
	if err == nil {
		var file *os.File
		file, err = os.Open(m.path)
		if err == nil {
			data, err = io.ReadAll(io.LimitReader(file, maxFile+1))
			file.Close()
			if len(data) > maxFile {
				err = fmt.Errorf("limits file too large")
			}
		}
	}
	var next config
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&next)
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				err = fmt.Errorf("trailing limits data")
			}
		}
		if err == nil && (next.Version != 1 || next.Users == nil || len(next.Users) > maxUsers) {
			err = fmt.Errorf("invalid limits configuration")
		}
		if err == nil {
			for email, limit := range next.Users {
				if email == "" || len(email) > 128 || strings.TrimSpace(email) != email || strings.ContainsAny(email, "\x00\r\n") || limit.UplinkBytesPerSecond < 0 || limit.DownlinkBytesPerSecond < 0 || limit.UplinkBytesPerSecond > 1<<40 || limit.DownlinkBytesPerSecond > 1<<40 {
					err = fmt.Errorf("invalid account bandwidth limit")
					break
				}
			}
		}
	}
	if err != nil {
		errors.LogWarning(context.Background(), "User bandwidth limits unavailable; retaining last valid settings")
		return
	}
	kept := make(map[string]*[2]bucket, len(next.Users))
	globals := make(map[string]*[2]globalPool)
	previous := m.config.Load()
	for email, limit := range next.Users {
		if limit.UplinkBytesPerSecond == 0 && limit.DownlinkBytesPerSecond == 0 {
			delete(next.Users, email)
			continue
		}
		state := m.buckets[email]
		if state == nil {
			state = &[2]bucket{{tokens: burstBytes, last: now}, {tokens: burstBytes, last: now}}
		}
		kept[email] = state
		if limit.Global {
			pools := m.global[email]
			if pools == nil || previous.Users[email] != limit || !sameBroker(previous.Broker, next.Broker) {
				pools = &[2]globalPool{{gate: make(chan struct{}, 1)}, {gate: make(chan struct{}, 1)}}
			}
			globals[email] = pools
		}
	}
	m.buckets = kept
	m.global = globals
	m.config.Store(&next)
}

func (m *Manager) limited(email string, direction Direction) bool {
	if m == nil {
		return false
	}
	m.refresh()
	limit, ok := m.config.Load().Users[email]
	return ok && (direction == Uplink && limit.UplinkBytesPerSecond > 0 || direction == Downlink && limit.DownlinkBytesPerSecond > 0)
}

// Wait charges bytes only when available, so cancellation never leaves future debt.
func (m *Manager) Wait(ctx context.Context, email string, direction Direction, size int64) error {
	if m == nil {
		return nil
	}
	if direction > Downlink {
		return fmt.Errorf("invalid bandwidth direction")
	}
	for size > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.refresh()
		m.mu.Lock()
		settings := m.config.Load()
		limit, ok := settings.Users[email]
		rate := limit.UplinkBytesPerSecond
		if direction == Downlink {
			rate = limit.DownlinkBytesPerSecond
		}
		if !ok || rate == 0 {
			m.mu.Unlock()
			return nil
		}
		if limit.Global {
			pool := &m.global[email][int(direction)]
			m.mu.Unlock()
			charged, unlimited, err := m.waitGlobal(ctx, settings, pool, email, direction, size)
			if err != nil || unlimited {
				return err
			}
			size -= charged
			continue
		}
		state := &m.buckets[email][int(direction)]
		now := time.Now()
		state.tokens = min(float64(burstBytes), state.tokens+now.Sub(state.last).Seconds()*float64(rate))
		state.last = now
		part := min(size, int64(burstBytes))
		if state.tokens >= float64(part) {
			state.tokens -= float64(part)
			m.mu.Unlock()
			size -= part
			continue
		}
		delay := min(time.Second, time.Duration((float64(part)-state.tokens)/float64(rate)*float64(time.Second))+time.Microsecond)
		m.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}

type Reader struct {
	buf.Reader
	manager *Manager
	email   string
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewReader(ctx context.Context, manager *Manager, email string, reader buf.Reader) *Reader {
	ctx, cancel := context.WithCancel(ctx)
	return &Reader{Reader: reader, manager: manager, email: email, ctx: ctx, cancel: cancel}
}

func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if r.manager.limited(r.email, Uplink) {
		if waitErr := r.manager.Wait(r.ctx, r.email, Uplink, int64(mb.Len())); waitErr != nil {
			buf.ReleaseMulti(mb)
			return nil, waitErr
		}
	}
	return mb, err
}

func (r *Reader) Close() error { r.cancel(); return common.Close(r.Reader) }
func (r *Reader) Interrupt()   { r.cancel(); common.Interrupt(r.Reader) }

type Writer struct {
	buf.Writer
	manager   *Manager
	email     string
	direction Direction
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewWriter(ctx context.Context, manager *Manager, email string, direction Direction, writer buf.Writer) *Writer {
	ctx, cancel := context.WithCancel(ctx)
	return &Writer{Writer: writer, manager: manager, email: email, direction: direction, ctx: ctx, cancel: cancel}
}

func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if !w.manager.limited(w.email, w.direction) {
		return w.Writer.WriteMultiBuffer(mb)
	}
	for len(mb) > 0 {
		remaining, part := buf.SplitFirst(mb)
		mb = remaining
		if err := w.manager.Wait(w.ctx, w.email, w.direction, int64(part.Len())); err != nil {
			part.Release()
			buf.ReleaseMulti(mb)
			return err
		}
		if err := w.Writer.WriteMultiBuffer(buf.MultiBuffer{part}); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}

func (w *Writer) Close() error { w.cancel(); return common.Close(w.Writer) }
func (w *Writer) Interrupt()   { w.cancel(); common.Interrupt(w.Writer) }
