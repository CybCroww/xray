// Package mobile embeds the client core in a host-owned packet tunnel.
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/proxy/tun"
	grpctransport "github.com/xtls/xray-core/transport/internet/grpc"
	hysteriatransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

// PacketWriter synchronously passes an IP packet to the host packet flow.
// Implementations must consume the packet before returning and must not call Stop.
type PacketWriter interface {
	WritePacket(packet []byte) bool
}

var owner struct {
	sync.Mutex
	tunnel *Tunnel
}

type Tunnel struct {
	instance      *core.Instance
	device        *packetDevice
	cancel        context.CancelFunc
	oldLimit      int64
	limit         int64
	xhttpRequests uint64
	xhttpBytes    uint64
	xhttpFailures uint64
	lastTrim      atomic.Int64
	stopped       atomic.Bool
	resetFlows    func()
	pathChanges   atomic.Uint64
}

// Start attaches the core to a packet flow whose network settings are already
// configured by the app. The JSON must contain one TUN inbound. A zero memory
// limit selects the platform default. The limit is a Go runtime soft target.
func Start(configJSON string, writer PacketWriter, mtu, memoryLimitMiB int) (*Tunnel, error) {
	return start(configJSON, writer, mtu, memoryLimitMiB, false)
}

// StartProtected starts the full-tunnel profile. The host must also enable
// includeAllNetworks and install default IPv4 and IPv6 routes.
func StartProtected(configJSON string, writer PacketWriter, mtu, memoryLimitMiB int) (*Tunnel, error) {
	return start(configJSON, writer, mtu, memoryLimitMiB, true)
}

func start(configJSON string, writer PacketWriter, mtu, memoryLimitMiB int, protected bool) (*Tunnel, error) {
	if writer == nil || mtu < 1280 || mtu > 1500 {
		return nil, errors.New("packet writer and an MTU between 1280 and 1500 are required")
	}
	if memoryLimitMiB == 0 {
		memoryLimitMiB = 32
		if runtime.GOOS == "android" {
			memoryLimitMiB = 48
		}
	}
	if memoryLimitMiB < 20 || memoryLimitMiB > 96 {
		return nil, errors.New("memory target must be between 20 and 96 MiB")
	}
	owner.Lock()
	defer owner.Unlock()
	if owner.tunnel != nil {
		return nil, errors.New("a mobile tunnel is already running")
	}
	device := newPacketDevice(writer, mtu)
	var resetFlows func()
	ctx := tun.ContextWithDevice(context.Background(), device)
	ctx = tun.ContextWithFlowReset(ctx, func(reset func()) { resetFlows = reset })
	ctx, cancel := context.WithCancel(ctx)
	oldLimit := debug.SetMemoryLimit(-1)
	limit := min(oldLimit, int64(memoryLimitMiB)<<20)
	debug.SetMemoryLimit(limit)
	requests, bytes, failures := splithttp.MobileUploadStats()
	instance, err := startInstance(ctx, configJSON, mtu, protected)
	if err != nil {
		cancel()
		device.Close()
		debug.SetMemoryLimit(oldLimit)
		return nil, err
	}
	tunnel := &Tunnel{
		instance: instance, device: device, cancel: cancel, oldLimit: oldLimit, limit: limit,
		xhttpRequests: requests, xhttpBytes: bytes, xhttpFailures: failures, resetFlows: resetFlows,
	}
	owner.tunnel = tunnel
	return tunnel, nil
}

func startInstance(ctx context.Context, configJSON string, mtu int, protected bool) (*core.Instance, error) {
	if len(configJSON) > 512<<10 || !json.Valid([]byte(configJSON)) {
		return nil, errors.New("invalid or oversized mobile JSON configuration")
	}
	cfg, err := serial.DecodeJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return nil, err
	}
	if len(cfg.Env) != 0 || len(cfg.InboundConfigs) != 1 || !strings.EqualFold(cfg.InboundConfigs[0].Protocol, "tun") {
		return nil, errors.New("mobile configuration requires exactly one TUN inbound without environment overrides")
	}
	if protected {
		if err := protectProfile(cfg); err != nil {
			return nil, err
		}
	}
	inbound := &cfg.InboundConfigs[0]
	tunConfig := conf.TunConfig{}
	if inbound.Settings != nil {
		if err := json.Unmarshal(*inbound.Settings, &tunConfig); err != nil {
			return nil, err
		}
	}
	tunConfig.Name = "cvpn-tun"
	tunConfig.MTU = uint32(mtu)
	// The Network Extension has already configured IPs, DNS, and routes.
	tunConfig.AutoSystemRoutingTable = nil
	tunConfig.AutoOutboundsInterface = nil
	tunConfig.AutoSystemDnsToGateway = false
	tunConfig.AutoSystemWfpBlockLeak = nil
	settings, err := json.Marshal(tunConfig)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(settings)
	inbound.Settings = &raw
	if cfg.Policy == nil {
		cfg.Policy = &conf.PolicyConfig{}
	}
	if cfg.Policy.Levels == nil {
		cfg.Policy.Levels = make(map[uint32]*conf.Policy)
	}
	for _, level := range []uint32{0, tunConfig.UserLevel} {
		if cfg.Policy.Levels[level] == nil {
			cfg.Policy.Levels[level] = &conf.Policy{}
		}
	}
	for _, level := range cfg.Policy.Levels {
		if level != nil && (level.BufferSize == nil || *level.BufferSize < 0 || *level.BufferSize > 32) {
			size := int32(32)
			level.BufferSize = &size
		}
	}
	built, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	instance, err := core.NewWithContext(ctx, built)
	if err != nil {
		return nil, err
	}
	if err := instance.Start(); err != nil {
		return nil, errors.Join(err, instance.Close())
	}
	return instance, nil
}

// PushPacket copies a packet into the bounded input queue without blocking the
// native read callback. false means that the packet was dropped.
func (t *Tunnel) PushPacket(packet []byte) bool { return t.device.push(packet) }

// PushPacketBatch accepts length bytes of [big-endian uint16 length, IP packet]
// records. It copies accepted packets before returning. The caller may reuse
// the buffer immediately. Returns the accepted count, or -1 for invalid framing.
func (t *Tunnel) PushPacketBatch(batch []byte, length int) int {
	return t.device.pushBatch(batch, length)
}

// RecordInputDrops accounts for invalid packets discarded by the native reader.
func (t *Tunnel) RecordInputDrops(count int) {
	if count > 0 {
		t.device.inputDrops.Add(uint64(count))
	}
}

// NetworkChanged resets app flows without removing the native VPN routes.
// It sends no probes and does not change the selected VPN endpoint.
func (t *Tunnel) NetworkChanged() {
	owner.Lock()
	defer owner.Unlock()
	if owner.tunnel != t || t.resetFlows == nil {
		return
	}
	t.pathChanges.Add(1)
	resetTransportPaths()
	t.resetFlows()
}

func resetTransportPaths() {
	splithttp.ResetMobileNetwork()
	grpctransport.ResetMobileNetwork()
	hysteriatransport.ResetMobileNetwork()
}

// Stop releases the extension's tunnel and is safe to call more than once.
func (t *Tunnel) Stop() error {
	owner.Lock()
	defer owner.Unlock()
	if owner.tunnel != t {
		return nil
	}
	t.stopped.Store(true)
	t.cancel()
	resetTransportPaths()
	err := t.instance.Close()
	t.device.Close()
	t.instance = nil
	t.resetFlows = nil
	splithttp.TrimIdleClients()
	debug.SetMemoryLimit(t.oldLimit)
	owner.tunnel = nil
	return err
}

// TrimMemory drops idle XHTTP pools without disrupting active flows. On a
// critical signal it also asks Go to release heap pages, at most once per 10s.
// Call from a utility queue and never from the packet I/O callback.
func (t *Tunnel) TrimMemory(critical bool) {
	if t.stopped.Load() {
		return
	}
	splithttp.TrimIdleClients()
	if critical {
		now := time.Now().UnixNano()
		previous := t.lastTrim.Load()
		if now-previous >= int64(10*time.Second) && t.lastTrim.CompareAndSwap(previous, now) {
			debug.FreeOSMemory()
		}
	}
}

// MemoryStatsJSON reports Go memory and packet counters without identifiers or
// user traffic. Native code should collect its process footprint separately.
func (t *Tunnel) MemoryStatsJSON() string {
	s := [...]metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/sched/goroutines:goroutines"},
	}
	metrics.Read(s[:])
	requests, bytes, failures := splithttp.MobileUploadStats()
	return fmt.Sprintf(`{"goManagedBytes":%d,"goHeapBytes":%d,"goTargetBytes":%d,"goroutines":%d,"queuedPackets":%d,"inputCalls":%d,"droppedInputPackets":%d,"droppedOutputPackets":%d,"xhttpUploadRequests":%d,"xhttpUploadPayloadBytes":%d,"xhttpUploadFailures":%d,"networkChanges":%d}`,
		s[0].Value.Uint64()-s[1].Value.Uint64(), s[2].Value.Uint64(), t.limit, s[3].Value.Uint64(),
		t.device.queued(), t.device.inputCalls.Load(), t.device.inputDrops.Load(), t.device.outputDrops.Load(),
		requests-t.xhttpRequests, bytes-t.xhttpBytes, failures-t.xhttpFailures, t.pathChanges.Load())
}
