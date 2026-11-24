package splithttp

import (
	"context"
	"sync"
)

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
