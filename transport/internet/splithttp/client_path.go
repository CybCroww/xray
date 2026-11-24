package splithttp

import (
	"context"
	"sync"
	"time"
)

const mobilePoolIdleTimeout = 45 * time.Second

// A mobile path belongs to one generation of the device's network. A new
// path may have no usable return route to sockets from the previous one.
type clientPath struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

func (p *clientPath) current() context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx == nil {
		p.ctx, p.cancel = context.WithCancel(context.Background())
	}
	return p.ctx
}

func (p *clientPath) change() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		p.cancel()
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
}

// ResetMobileNetwork invalidates previous-path XHTTP sockets. It leaves the
// packet tunnel and its routing in place. Applications can retry over a new
// connection; byte streams from the failed path cannot be replayed safely.
func ResetMobileNetwork() { resetClientNetwork(mobileLimits) }

func resetClientNetwork(limits *clientLimits) {
	limits.path.change()
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	for key, manager := range globalDialerMap {
		if key.path != nil && key.path.Err() != nil {
			delete(globalDialerMap, key)
			manager.retire()
		}
	}
}

// The mobile pool has no periodic polling. Start its expiry when the last
// lease is released and cancel it when the pool is used again.
func scheduleIdlePoolCleanup(key dialerConf, manager *XmuxManager) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	if globalDialerMap[key] != manager || manager.idleTimer != nil || !manager.isIdle() {
		return
	}
	var timer *time.Timer
	timer = time.AfterFunc(mobilePoolIdleTimeout, func() {
		globalDialerAccess.Lock()
		if globalDialerMap[key] != manager || manager.idleTimer != timer {
			globalDialerAccess.Unlock()
			return
		}
		manager.idleTimer = nil
		delete(globalDialerMap, key)
		globalDialerAccess.Unlock()
		manager.retire()
	})
	manager.idleTimer = timer
}

// stopIdleTimer is called under the pool lock or after removing the manager.
func (m *XmuxManager) stopIdleTimer() {
	if m.idleTimer != nil {
		m.idleTimer.Stop()
		m.idleTimer = nil
	}
}

func reapDesktopPools() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		globalDialerAccess.Lock()
		for key, manager := range globalDialerMap {
			if !key.mobile && !manager.HasActiveClients() {
				delete(globalDialerMap, key)
				manager.retire()
			}
		}
		globalDialerAccess.Unlock()
	}
}

// TrimIdleClients drops mobile connection pools that have no users. Active
// streams keep running when a Packet Tunnel receives a memory-pressure event.
func TrimIdleClients() {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	for key, manager := range globalDialerMap {
		if key.mobile && manager.isIdle() {
			delete(globalDialerMap, key)
			manager.retire()
		}
	}
}
