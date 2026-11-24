package hysteria

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/internal/quicconfig"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type client struct {
	lock         chan struct{}
	path         context.Context // canceled when the mobile socket path is retired
	instance     *core.Instance
	forced       bool
	dest         net.Destination
	config       *Config
	tlsConfig    *gotls.Config
	socketConfig *internet.SocketConfig
	finalMask    *finalmask.FinalMask
	quicParams   *internet.QuicParams

	conn      *quic.Conn
	tr        *quic.Transport
	pktConn   net.PacketConn
	udpSM     *udpSessionManager
	aliveTCP  *atomic.Int64
	lastAlive time.Time
}

func (c *client) status() status {
	if c.conn == nil {
		return StatusNull
	}
	select {
	case <-c.conn.Context().Done():
		return StatusInactive
	default:
		return StatusActive
	}
}

func (c *client) close(force bool) {
	if c.udpSM != nil {
		c.udpSM.closeAll()
	}
	if force {
		// Wake the packet reader and any blocked writer on a retired path.
		c.pktConn.Close()
	}
	c.conn.CloseWithError(closeErrCodeOK, "")
	if !force {
		c.pktConn.Close()
	}
	c.tr.Close()
	c.conn = nil
	c.tr = nil
	c.pktConn = nil
	c.udpSM = nil
}

const mobileAuthTimeout = 12 * time.Second

func (c *client) dial(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.path != nil {
		if err := c.path.Err(); err != nil {
			return err
		}
	}
	if c.forced {
		return errors.New("client is closed")
	}

	switch c.status() {
	case StatusActive:
		return nil
	case StatusInactive:
		c.close(false)
	}
	if c.path != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, mobileAuthTimeout)
		defer cancel()
		stop := context.AfterFunc(c.path, cancel)
		defer stop()
	}

	quicParams := c.quicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		ChromeParrot:                   !quicParams.DisableChromeParrot,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           MaxDatagramFrameSize,
		OmitMaxDatagramFrameSize:       true,
		DisablePathManager:             true,
	}
	if quicParams.InitStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = 8388608
	}
	if quicParams.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = 8388608
	}
	if quicParams.InitConnReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if quicParams.MaxConnReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = 8388608 * 5 / 2
	}
	if c.path != nil {
		if quicConfig.ChromeParrot {
			quicConfig.OmitMaxDatagramFrameSize = false
		}
		quicconfig.LimitMobileReceiveWindow(quicConfig)
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}
	if quicParams.KeepAlivePeriod == 0 {
		quicConfig.KeepAlivePeriod = net.QuicgoH3KeepAlivePeriod
	}

	var pktConn net.PacketConn
	var udpAddr net.Addr
	if c.finalMask != nil {
		conn, err := c.finalMask.DialUDP(ctx, c.dest)
		if err != nil {
			return errors.New("failed to dial to dest").Base(err)
		}
		pktConn = conn.(*net.PacketConnWrapper).PacketConn
		udpAddr = conn.RemoteAddr()
	} else {
		conn, err := internet.DialSystem(ctx, c.dest, c.socketConfig)
		if err != nil {
			return errors.New("failed to dial to dest").Base(err)
		}
		switch c := conn.(type) {
		case *net.PacketConnWrapper:
			pktConn = c.PacketConn
			udpAddr = c.RemoteAddr()
		case *cnc.Connection:
			pktConn = &internet.FakePacketConn{Conn: c}
			udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
		default:
			panic(reflect.TypeOf(c))
		}
	}

	tr := &quic.Transport{Conn: pktConn, DisableGSO: quicParams.DisableGSO}

	if quicConfig.ChromeParrot {
		tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
		c.tlsConfig.GetCertificate = nil
	}

	var conn *quic.Conn
	rt := &http3.Transport{
		TLSClientConfig: c.tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qc, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			conn = qc
			return qc, nil
		},
	}
	connected := false
	defer func() {
		if !connected {
			// QUIC's transport shutdown waits for the packet reader. Close
			// the socket first, including wrappers without read deadlines.
			_ = pktConn.Close()
			_ = rt.Close()
			_ = tr.Close()
		}
	}()
	req := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   URLHost,
			Path:   URLPath,
		},
		Header: http.Header{
			RequestHeaderAuth:   []string{c.config.Auth},
			CommonHeaderCCRX:    []string{strconv.FormatUint(quicParams.BrutalDown, 10)},
			CommonHeaderPadding: []string{AuthRequestPadding.String()},
		},
	}
	resp, err := rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	_ = resp.Body.Close()

	if resp.StatusCode != StatusAuthOK {
		return errors.New("auth failed code ", resp.StatusCode)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.path != nil {
		if err := c.path.Err(); err != nil {
			return err
		}
	}

	// udp, _ := strconv.ParseBool(resp.Header.Get(ResponseHeaderUDPEnabled))
	down, _ := strconv.ParseUint(resp.Header.Get(CommonHeaderCCRX), 10, 64)
	errors.LogDebug(context.Background(), "ECHAccepted ", conn.ConnectionState().TLS.ECHAccepted)

	switch quicParams.Congestion {
	case "reno":
	case "bbr":
		congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
	case "", "brutal":
		if quicParams.BrutalUp == 0 || down == 0 {
			congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
		} else {
			congestion.UseBrutal(conn, min(quicParams.BrutalUp, down), quicParams.BrutalDisableLossCompensation)
		}
	case "force-brutal":
		congestion.UseBrutal(conn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
	default:
		panic(quicParams.Congestion)
	}

	c.pktConn = pktConn
	c.tr = tr
	c.conn = conn
	c.aliveTCP = &atomic.Int64{}
	c.lastAlive = time.Now()
	c.udpSM = &udpSessionManager{
		conn: conn,
		m:    make(map[uint32]*InterConn),
		next: 1,
	}
	if c.path != nil {
		c.udpSM.budget = &mobileDatagramReceive
	}
	go c.udpSM.run()
	connected = true

	return nil
}

func (c *client) unlock() {
	<-c.lock
}

func (c *client) acquire(ctx context.Context) error {
	var pathDone <-chan struct{}
	if c.path != nil {
		pathDone = c.path.Done()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-pathDone:
		return c.path.Err()
	case c.lock <- struct{}{}:
		return nil
	}
}

func (c *client) tcp(ctx context.Context) (stat.Connection, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if err := c.dial(ctx); err != nil {
		return nil, err
	}

	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}

	c.lastAlive = time.Now()
	c.aliveTCP.Add(1)
	return &interConn{
		stream: stream,
		local:  c.conn.LocalAddr(),
		remote: c.conn.RemoteAddr(),

		client:   true,
		lock:     make(chan struct{}, 1),
		aliveTCP: c.aliveTCP,
	}, nil
}

func (c *client) udp(ctx context.Context) (stat.Connection, error) {
	if err := c.acquire(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if err := c.dial(ctx); err != nil {
		return nil, err
	}

	return c.udpSM.udp()
}

func (c *client) clean(force bool) {
	c.lock <- struct{}{}
	defer c.unlock()
	if force {
		c.forced = true
	}

	status := c.status()
	if status == StatusInactive || force && status != StatusNull {
		c.close(force)
		return
	}
	if status != StatusActive {
		return
	}

	udpSessions := 0
	if c.udpSM != nil {
		c.udpSM.RLock()
		udpSessions = len(c.udpSM.m)
		c.udpSM.RUnlock()
	}
	if udpSessions == 0 && (c.aliveTCP == nil || c.aliveTCP.Load() == 0) {
		if time.Since(c.lastAlive) >= net.ConnIdleTimeout {
			c.close(false)
			return
		}
	} else {
		c.lastAlive = time.Now()
	}
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

type clientManager struct {
	sync.RWMutex
	startOnce  sync.Once
	m          map[dialerConf]*client
	path       context.Context
	cancelPath context.CancelFunc
}

func newClientManager(mobile bool) *clientManager {
	m := &clientManager{m: make(map[dialerConf]*client)}
	if mobile {
		m.path, m.cancelPath = context.WithCancel(context.Background())
	}
	return m
}

func (m *clientManager) clean() {
	ticker := time.NewTicker(idleCleanupInterval)
	for range ticker.C {
		m.RLock()
		entries := make(map[dialerConf]*client, len(m.m))
		for k, c := range m.m {
			entries[k] = c
		}
		m.RUnlock()
		for k, c := range entries {
			force := c.instance != nil && !c.instance.IsRunning()
			c.clean(force)
			if force {
				m.Lock()
				if m.m[k] == c {
					delete(m.m, k)
				}
				m.Unlock()
			}
		}
	}
}

var (
	standardManager = newClientManager(false)
	mobileManager   = newClientManager(true)
)

// ResetMobileNetwork cancels authentication and retires the old QUIC pool.
func ResetMobileNetwork() { mobileManager.resetNetwork() }

func (m *clientManager) resetNetwork() {
	m.Lock()
	if m.cancelPath == nil {
		m.Unlock()
		return
	}
	m.cancelPath()
	m.path, m.cancelPath = context.WithCancel(context.Background())
	old := m.m
	m.m = make(map[dialerConf]*client)
	m.Unlock()
	if len(old) != 0 {
		go func() {
			for _, c := range old {
				c.clean(true)
			}
		}()
	}
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	m := standardManager
	if internet.UsesMobileProfile(ctx) {
		m = mobileManager
	}
	m.startOnce.Do(func() { go m.clean() })
	return m.dial(ctx, dest, streamSettings)
}

func (m *clientManager) dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}

	datagram := DatagramFromContext(ctx)
	dest.Network = net.Network_UDP

	dialerConfKey := dialerConf{dest, streamSettings}

	m.RLock()
	c := m.m[dialerConfKey]
	m.RUnlock()

	if c == nil {
		m.Lock()
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return nil, err
		}
		c = m.m[dialerConfKey]
		if c == nil {
			c = &client{
				lock:         make(chan struct{}, 1),
				path:         m.path,
				instance:     core.FromContext(ctx),
				dest:         dest,
				config:       streamSettings.ProtocolSettings.(*Config),
				tlsConfig:    tlsConfig.GetTLSConfig(tls.WithDestination(dest)),
				socketConfig: streamSettings.SocketSettings,
				finalMask:    streamSettings.FinalMask,
				quicParams:   streamSettings.QuicParams,
			}
			m.m[dialerConfKey] = c
		}
		m.Unlock()
	}

	if datagram {
		return c.udp(ctx)
	}
	return c.tcp(ctx)
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
