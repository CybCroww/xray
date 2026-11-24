package splithttp

import (
	"context"
	"math"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
)

type XmuxConn interface {
	IsClosed() bool
}

type XmuxClient struct {
	XmuxConn     XmuxConn
	Running      atomic.Int32
	leftUsage    int32
	LeftRequests atomic.Int32
	UnreusableAt time.Time
	NotUsed      atomic.Bool
	onIdle       func()
	closed       atomic.Bool
}

func (c *XmuxClient) AddRunning() {
	c.Running.Add(1)
}

func (c *XmuxClient) DoneRunning() {
	idle := c.Running.Add(-1) == 0
	c.maybeClose()
	if idle && c.onIdle != nil && !c.NotUsed.Load() {
		c.onIdle()
	}
}

// close the XmuxConn if it is not used and has no running requests
func (c *XmuxClient) maybeClose() {
	if c.NotUsed.Load() && c.Running.Load() <= 0 && c.closed.CompareAndSwap(false, true) {
		common.Close(c.XmuxConn)
	}
}

func (m *XmuxManager) isIdle() bool {
	for _, client := range m.xmuxClients {
		if client.Running.Load() > 0 {
			return false
		}
	}
	return true
}

func (m *XmuxManager) retire() {
	m.stopIdleTimer()
	for _, client := range m.xmuxClients {
		client.NotUsed.Store(true)
		client.maybeClose()
	}
}

type XmuxManager struct {
	xmuxConfig  *XmuxConfig
	concurrency int32
	connections int32
	maxPool     int
	newConnFunc func() XmuxConn
	xmuxClients []*XmuxClient
	onIdle      func()
	idleTimer   *time.Timer
}

func NewXmuxManager(xmuxConfig *XmuxConfig, newConnFunc func() XmuxConn) *XmuxManager {
	if xmuxConfig == nil {
		xmuxConfig = &XmuxConfig{}
	}
	return &XmuxManager{
		xmuxConfig:  xmuxConfig,
		concurrency: xmuxConfig.GetNormalizedMaxConcurrency().rand(),
		connections: xmuxConfig.GetNormalizedMaxConnections().rand(),
		newConnFunc: newConnFunc,
		xmuxClients: make([]*XmuxClient, 0),
	}
}

func (m *XmuxManager) HasActiveClients() bool {
	for _, client := range m.xmuxClients {
		if !client.XmuxConn.IsClosed() || client.Running.Load() > 0 {
			return true
		}
	}
	return len(m.xmuxClients) == 0 // new manager without clients is considered active
}

func (m *XmuxManager) newXmuxClient() *XmuxClient {
	xmuxClient := &XmuxClient{
		XmuxConn:  m.newConnFunc(),
		leftUsage: -1,
		onIdle:    m.onIdle,
	}
	if x := m.xmuxConfig.GetNormalizedCMaxReuseTimes().rand(); x > 0 {
		xmuxClient.leftUsage = x - 1
	}
	xmuxClient.LeftRequests.Store(math.MaxInt32)
	if x := m.xmuxConfig.GetNormalizedHMaxRequestTimes().rand(); x > 0 {
		xmuxClient.LeftRequests.Store(x)
	}
	if x := m.xmuxConfig.GetNormalizedHMaxReusableSecs().rand(); x > 0 {
		xmuxClient.UnreusableAt = time.Now().Add(time.Duration(x) * time.Second)
	}
	m.xmuxClients = append(m.xmuxClients, xmuxClient)
	return xmuxClient
}

func (m *XmuxManager) GetXmuxClient(ctx context.Context) *XmuxClient { // when locking
	return m.getXmuxClient(ctx, true)
}

func (m *XmuxManager) GetExistingXmuxClient(ctx context.Context) *XmuxClient {
	return m.getXmuxClient(ctx, false)
}

func (m *XmuxManager) getXmuxClient(ctx context.Context, create bool) *XmuxClient {
	for i := 0; i < len(m.xmuxClients); {
		xmuxClient := m.xmuxClients[i]
		if xmuxClient.XmuxConn.IsClosed() ||
			xmuxClient.leftUsage == 0 ||
			xmuxClient.LeftRequests.Load() <= 0 ||
			(xmuxClient.UnreusableAt != time.Time{} && time.Now().After(xmuxClient.UnreusableAt)) {
			errors.LogDebug(ctx, "XMUX: removing xmuxClient, IsClosed() = ", xmuxClient.XmuxConn.IsClosed(),
				", Running = ", xmuxClient.Running.Load(),
				", leftUsage = ", xmuxClient.leftUsage,
				", LeftRequests = ", xmuxClient.LeftRequests.Load(),
				", UnreusableAt = ", xmuxClient.UnreusableAt)
			xmuxClient.NotUsed.Store(true)
			xmuxClient.maybeClose()
			copy(m.xmuxClients[i:], m.xmuxClients[i+1:])
			m.xmuxClients[len(m.xmuxClients)-1] = nil
			m.xmuxClients = m.xmuxClients[:len(m.xmuxClients)-1]
		} else {
			i++
		}
	}

	if len(m.xmuxClients) == 0 {
		if !create {
			return nil
		}
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because xmuxClients is empty")
		return m.newXmuxClient()
	}

	canGrow := create && (m.maxPool == 0 || len(m.xmuxClients) < m.maxPool)
	if canGrow && m.connections > 0 && len(m.xmuxClients) < int(m.connections) {
		errors.LogDebug(ctx, "XMUX: creating xmuxClient because maxConnections was not hit, xmuxClients = ", len(m.xmuxClients))
		return m.newXmuxClient()
	}

	if m.concurrency > 0 {
		eligible := 0
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.Running.Load() < m.concurrency {
				eligible++
			}
		}
		if eligible == 0 {
			if !create {
				return nil
			}
			if canGrow {
				errors.LogDebug(ctx, "XMUX: creating xmuxClient because maxConcurrency was hit, xmuxClients = ", len(m.xmuxClients))
				return m.newXmuxClient()
			}
			return reuseXmuxClient(m.leastBusy())
		}

		selected := rand.IntN(eligible)
		for _, xmuxClient := range m.xmuxClients {
			if xmuxClient.Running.Load() < m.concurrency {
				if selected == 0 {
					return reuseXmuxClient(xmuxClient)
				}
				selected--
			}
		}
	}

	if m.maxPool > 0 {
		return reuseXmuxClient(m.leastBusy())
	}
	return reuseXmuxClient(m.xmuxClients[rand.IntN(len(m.xmuxClients))])
}

func (m *XmuxManager) leastBusy() *XmuxClient {
	best := m.xmuxClients[0]
	for _, client := range m.xmuxClients[1:] {
		if client.Running.Load() < best.Running.Load() {
			best = client
		}
	}
	return best
}

func reuseXmuxClient(xmuxClient *XmuxClient) *XmuxClient {
	if xmuxClient.leftUsage > 0 {
		xmuxClient.leftUsage -= 1
	}
	return xmuxClient
}
