package hysteria

import (
	"context"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/net"
)

// mobileQUICIdle keeps the QUIC connection warm while it has TCP or UDP users
// and for a short period after the last one leaves.
type mobileQUICIdle struct {
	mu      sync.Mutex
	users   int
	stopped bool
	timer   *time.Timer
	epoch   uint64
	expire  func(uint64)
}

func (i *mobileQUICIdle) arm() {
	i.epoch++
	epoch := i.epoch
	i.timer = time.AfterFunc(net.ConnIdleTimeout, func() { i.expire(epoch) })
}

func (i *mobileQUICIdle) acquire() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cancelTimer()
	i.users++
}

func (i *mobileQUICIdle) release() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.users--
	if i.users == 0 && !i.stopped {
		i.arm()
	}
}

func (i *mobileQUICIdle) hasExpired(epoch uint64) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.timer != nil && i.epoch == epoch
}

func (i *mobileQUICIdle) stop() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.stopped = true
	i.cancelTimer()
}

func (i *mobileQUICIdle) cancelTimer() {
	if i.timer != nil {
		i.timer.Stop()
		i.timer = nil
	}
}

// TrimIdleClients releases warm mobile sockets on memory pressure. Busy
// clients, including pending authentication, are left to their current owner.
func TrimIdleClients() {
	mobileManager.RLock()
	clients := make([]*client, 0, len(mobileManager.m))
	for _, c := range mobileManager.m {
		clients = append(clients, c)
	}
	mobileManager.RUnlock()
	for _, c := range clients {
		select {
		case c.lock <- struct{}{}:
			if idle := c.mobileIdle; idle != nil {
				idle.mu.Lock()
				unused := idle.users == 0
				idle.mu.Unlock()
				if unused {
					c.close(false)
				}
			}
			c.unlock()
		default:
		}
	}
}

// watchMobileConnection runs under the client lock. Both callbacks verify
// ownership in case a new authenticated connection replaced the old one.
func (c *client) watchMobileConnection(conn *quic.Conn) {
	idle := &mobileQUICIdle{}
	idle.expire = func(epoch uint64) {
		c.lock <- struct{}{}
		defer c.unlock()
		if c.mobileIdle == idle && idle.hasExpired(epoch) {
			c.close(false)
		}
	}
	idle.arm()
	c.mobileIdle = idle
	c.udpSM.idle = idle
	c.stopOnClose = context.AfterFunc(conn.Context(), func() {
		c.lock <- struct{}{}
		defer c.unlock()
		if c.conn == conn {
			c.close(false)
		}
	})
}
