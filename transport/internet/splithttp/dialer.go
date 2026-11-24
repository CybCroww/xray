package splithttp

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/internal/quicconfig"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"
)

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
	mobile bool
	path   context.Context
}

var (
	globalDialerMap    map[dialerConf]*XmuxManager
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, path context.Context) (DialerClient, *XmuxClient, error) {
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	if browser_dialer.HasBrowserDialer() && realityConfig == nil {
		return &BrowserDialerClient{transportConfig: streamSettings.ProtocolSettings.(*Config)}, nil, nil
	}

	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	if path != nil && path.Err() != nil {
		return nil, nil, path.Err()
	}
	mobile := path != nil

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}

	key := dialerConf{dest, streamSettings, mobile, path}

	xmuxManager, found := globalDialerMap[key]

	if !found {
		transportConfig := streamSettings.ProtocolSettings.(*Config)
		xmuxManager = NewXmuxManager(transportConfig.Xmux, func() XmuxConn {
			return createHTTPClient(dest, streamSettings, mobile)
		})
		if mobile {
			xmuxManager.maxPool = 2
		}
		globalDialerMap[key] = xmuxManager
	}

	xmuxClient := xmuxManager.GetXmuxClient(ctx)
	xmuxClient.AddRunning()
	return xmuxClient.XmuxConn.(DialerClient), xmuxClient, nil
}

func decideHTTPVersion(tlsConfig *tls.Config, realityConfig *reality.Config) string {
	if realityConfig != nil {
		return "2"
	}
	if tlsConfig == nil {
		return "1.1"
	}
	if len(tlsConfig.NextProtocol) != 1 {
		return "2"
	}
	if tlsConfig.NextProtocol[0] == "http/1.1" {
		return "1.1"
	}
	if tlsConfig.NextProtocol[0] == "h3" {
		return "3"
	}
	return "2"
}

func createHTTPClient(dest net.Destination, streamSettings *internet.MemoryStreamConfig, mobile bool) DialerClient {
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	httpVersion := decideHTTPVersion(tlsConfig, realityConfig)
	if httpVersion == "3" {
		dest.Network = net.Network_UDP // better to keep this line
	}

	var gotlsConfig *gotls.Config

	if tlsConfig != nil {
		gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	}

	transportConfig := streamSettings.ProtocolSettings.(*Config)
	keepAlivePeriod := time.Duration(transportConfig.Xmux.GetHKeepAlivePeriod()) * time.Second
	socketSettings := streamSettings.SocketSettings
	if mobile && httpVersion == "2" && keepAlivePeriod >= 0 &&
		socketSettings.GetTcpKeepAliveIdle() == 0 && socketSettings.GetTcpKeepAliveInterval() == 0 {
		// HTTP/2 already verifies liveness. Sending TCP probes as well wakes
		// the radio twice for the same idle tunnel. Respect explicit sockopts.
		if socketSettings == nil {
			socketSettings = &internet.SocketConfig{}
		} else {
			socketSettings = proto.CloneOf(socketSettings)
		}
		socketSettings.TcpKeepAliveIdle = -1
	}

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		var conn net.Conn
		var err error
		if streamSettings.FinalMask != nil {
			conn, err = streamSettings.FinalMask.DialTCP(ctxInner, dest)
		} else {
			conn, err = internet.DialSystem(ctxInner, dest, socketSettings)
		}
		if err != nil {
			return nil, err
		}

		if realityConfig != nil {
			return reality.UClient(conn, realityConfig, ctxInner, dest)
		}

		if gotlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				conn = tls.UClient(conn, gotlsConfig, fingerprint)
				if err := conn.(*tls.UConn).HandshakeContext(ctxInner); err != nil {
					conn.Close()
					return nil, err
				}
			} else {
				conn = tls.Client(conn, gotlsConfig)
			}
		}

		return conn, nil
	}

	var transport http.RoundTripper

	if httpVersion == "3" {
		quicParams := streamSettings.QuicParams
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
			MaxIncomingStreams:             quicParams.MaxIncomingStreams,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
			ChromeParrot:                   !quicParams.DisableChromeParrot,
		}
		if mobile {
			quicconfig.LimitMobileReceiveWindow(quicConfig)
		}
		if quicParams.MaxIdleTimeout == 0 {
			quicConfig.MaxIdleTimeout = net.ConnIdleTimeout
		}
		if quicParams.KeepAlivePeriod == 0 {
			if keepAlivePeriod == 0 {
				quicConfig.KeepAlivePeriod = net.QuicgoH3KeepAlivePeriod
			} else if keepAlivePeriod > 0 {
				quicConfig.KeepAlivePeriod = keepAlivePeriod
			}
		}
		if quicParams.MaxIncomingStreams == 0 {
			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			quicConfig.MaxIncomingStreams = -1
		}

		transport = &http3.Transport{
			QUICConfig:      quicConfig,
			TLSClientConfig: gotlsConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				var pktConn net.PacketConn
				var udpAddr net.Addr
				if streamSettings.FinalMask != nil {
					conn, err := streamSettings.FinalMask.DialUDP(ctx, dest)
					if err != nil {
						return nil, errors.New("failed to dial to dest").Base(err)
					}
					pktConn = conn.(*net.PacketConnWrapper).PacketConn
					udpAddr = conn.RemoteAddr()
				} else {
					conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
					if err != nil {
						return nil, errors.New("failed to dial to dest").Base(err)
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

				if cfg.ChromeParrot {
					tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
					tlsCfg.GetCertificate = nil
				}

				conn, err := tr.DialEarly(ctx, udpAddr, tlsCfg, cfg)
				if err != nil {
					// pktConn first: tr.Close() waits for the read from it to return, which with dialerProxy has no deadline
					pktConn.Close()
					tr.Close()
					return nil, err
				}
				context.AfterFunc(conn.Context(), func() { pktConn.Close(); tr.Close() })

				switch quicParams.Congestion {
				case "reno":
				case "", "bbr":
					congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
				case "force-brutal":
					congestion.UseBrutal(conn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
				default:
					panic(quicParams.Congestion)
				}

				return conn, nil
			},
		}
	} else if httpVersion == "2" {
		if keepAlivePeriod == 0 {
			keepAlivePeriod = net.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		h2 := &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: net.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
		if mobile {
			h1 := &http.Transport{HTTP2: &http.HTTP2Config{
				MaxReceiveBufferPerConnection: 2 << 20,
				MaxReceiveBufferPerStream:     512 << 10,
			}}
			h2 = common.Must2(http2.ConfigureTransports(h1))
			h2.DialTLSContext = func(ctx context.Context, _, _ string, _ *gotls.Config) (net.Conn, error) {
				return dialContext(ctx)
			}
			h2.IdleConnTimeout = net.ConnIdleTimeout
			h2.ReadIdleTimeout = keepAlivePeriod
			h2.MaxHeaderListSize = 64 << 10
		}
		transport = h2
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}

		transport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: net.ConnIdleTimeout,
			// chunked transfer download with KeepAlives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
	}

	client := &DefaultDialerClient{
		transportConfig: transportConfig,
		client: &http.Client{
			Transport: transport,
		},
		httpVersion:    httpVersion,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}
	if httpVersion == "1.1" && mobile {
		upload := transport.(*http.Transport).Clone()
		upload.DisableKeepAlives = false
		upload.MaxIdleConns = 4
		upload.MaxIdleConnsPerHost = 4
		upload.MaxResponseHeaderBytes = 64 << 10
		client.packetHTTP1 = &http.Client{Transport: upload}
	}

	return client
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			globalDialerAccess.Lock()
			for key, manager := range globalDialerMap {
				if (key.mobile && manager.idleFor(45*time.Second)) || !manager.HasActiveClients() {
					delete(globalDialerMap, key)
					manager.retire()
				}
			}
			globalDialerAccess.Unlock()
		}
	}()
}

// TrimIdleClients drops mobile connection pools that have no users. Active
// streams keep running when a Packet Tunnel receives a memory-pressure event.
func TrimIdleClients() {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	for key, manager := range globalDialerMap {
		if key.mobile && manager.idleFor(0) {
			delete(globalDialerMap, key)
			manager.retire()
		}
	}
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	return dial(ctx, dest, streamSettings, platformClientLimits())
}

func dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, limits *clientLimits) (stat.Connection, error) {
	// Keep context values, but once Dial succeeds the connection owns the
	// request lifetime. A caller may stop its handshake context after Dial.
	connCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopDial := context.AfterFunc(ctx, cancel)
	defer stopDial()
	var path context.Context
	var stopPath func() bool
	if limits != nil {
		path = limits.path.current()
		stopPath = context.AfterFunc(path, cancel)
		queueCtx, stopQueue := context.WithTimeout(ctx, 3*time.Second)
		stopWaiting := context.AfterFunc(connCtx, stopQueue)
		acquired := acquireSlot(queueCtx, limits.flows)
		stopWaiting()
		stopQueue()
		if !acquired {
			stopPath()
			cancel()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, errors.New("XHTTP mobile flow capacity exhausted")
		}
	}
	var xmuxClient, xmuxClient2 *XmuxClient
	returningConn := false
	var conn splitConn
	defer func() {
		if !returningConn {
			conn.Close()
		}
	}()
	reader, writer := io.Pipe()
	conn.writer = writer
	var closed atomic.Bool
	conn.onClose = func() {
		if !closed.CompareAndSwap(false, true) {
			return
		}
		if stopPath != nil {
			stopPath()
			<-limits.flows
		}
		cancel()
		reader.Close()
		if xmuxClient != nil {
			xmuxClient.DoneRunning()
		}
		if xmuxClient2 != nil {
			xmuxClient2.DoneRunning()
		}
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)

	httpVersion := decideHTTPVersion(tlsConfig, realityConfig)
	if httpVersion == "3" {
		dest.Network = net.Network_UDP
	}

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	var requestURL url.URL

	if tlsConfig != nil || realityConfig != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" && tlsConfig != nil {
		requestURL.Host = tlsConfig.ServerName
	}
	if requestURL.Host == "" && realityConfig != nil {
		requestURL.Host = realityConfig.ServerName
	}
	if requestURL.Host == "" {
		requestURL.Host = dest.Address.String()
	}
	if browser_dialer.HasBrowserDialer() && realityConfig == nil {
		// For Browser Dialer's optimized IP and non-standard port
		if !(requestURL.Scheme == "http" && dest.Port == 80) && !(requestURL.Scheme == "https" && dest.Port == 443) {
			requestURL.Host += ":" + dest.Port.String()
		}
	}

	requestURL.Path = transportConfiguration.GetNormalizedPath()
	requestURL.RawQuery = transportConfiguration.GetNormalizedQuery()

	httpClient, sharedClient, err := getHTTPClient(ctx, dest, streamSettings, path)
	if err != nil {
		return nil, err
	}
	xmuxClient = sharedClient

	mode := transportConfiguration.Mode
	if mode == "" || mode == "auto" {
		mode = "packet-up"
		if realityConfig != nil {
			mode = "stream-one"
			if transportConfiguration.DownloadSettings != nil {
				mode = "stream-up"
			}
		}
	}

	sessionId := ""
	if mode != "stream-one" {
		sessionId = transportConfiguration.GenerateSessionID()
	}

	errors.LogInfo(ctx, fmt.Sprintf("XHTTP is dialing to %s, mode %s, HTTP version %s, host %s", dest, mode, httpVersion, requestURL.Host))

	requestURL2 := requestURL
	httpClient2 := httpClient
	downloadClient := xmuxClient
	if transportConfiguration.DownloadSettings != nil {
		globalDialerAccess.Lock()
		if streamSettings.DownloadSettings == nil {
			streamSettings.DownloadSettings = common.Must2(internet.ToMemoryStreamConfig(transportConfiguration.DownloadSettings))
			if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.Penetrate {
				streamSettings.DownloadSettings.SocketSettings = streamSettings.SocketSettings
			}
		}
		globalDialerAccess.Unlock()
		memory2 := streamSettings.DownloadSettings
		dest2 := *memory2.Destination // just panic
		tlsConfig2 := tls.ConfigFromStreamSettings(memory2)
		realityConfig2 := reality.ConfigFromStreamSettings(memory2)
		httpVersion2 := decideHTTPVersion(tlsConfig2, realityConfig2)
		if httpVersion2 == "3" {
			dest2.Network = net.Network_UDP
		}
		if tlsConfig2 != nil || realityConfig2 != nil {
			requestURL2.Scheme = "https"
		} else {
			requestURL2.Scheme = "http"
		}
		config2 := memory2.ProtocolSettings.(*Config)
		requestURL2.Host = config2.Host
		if requestURL2.Host == "" && tlsConfig2 != nil {
			requestURL2.Host = tlsConfig2.ServerName
		}
		if requestURL2.Host == "" && realityConfig2 != nil {
			requestURL2.Host = realityConfig2.ServerName
		}
		if requestURL2.Host == "" {
			requestURL2.Host = dest2.Address.String()
		}
		if browser_dialer.HasBrowserDialer() && realityConfig2 == nil {
			// For Browser Dialer's optimized IP and non-standard port
			if !(requestURL2.Scheme == "http" && dest2.Port == 80) && !(requestURL2.Scheme == "https" && dest2.Port == 443) {
				requestURL2.Host += ":" + dest2.Port.String()
			}
		}
		requestURL2.Path = config2.GetNormalizedPath()
		requestURL2.RawQuery = config2.GetNormalizedQuery()
		httpClient2, xmuxClient2, err = getHTTPClient(ctx, dest2, memory2, path)
		if err != nil {
			return nil, err
		}
		downloadClient = xmuxClient2
		errors.LogInfo(ctx, fmt.Sprintf("XHTTP is downloading from %s, mode %s, HTTP version %s, host %s", dest2, "stream-down", httpVersion2, requestURL2.Host))
	}

	if mode == "stream-one" {
		requestURL.Path = transportConfiguration.GetNormalizedPath()
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient.OpenStream(connCtx, requestURL.String(), sessionId, reader, false)
		if err != nil {
			return nil, err
		}
		returningConn = true
		return stat.Connection(&conn), nil
	} else { // stream-down
		if downloadClient != nil {
			downloadClient.LeftRequests.Add(-1)
		}
		conn.reader, conn.remoteAddr, conn.localAddr, err = httpClient2.OpenStream(connCtx, requestURL2.String(), sessionId, nil, false)
		if err != nil {
			return nil, err
		}
	}
	if mode == "stream-up" {
		if xmuxClient != nil {
			xmuxClient.LeftRequests.Add(-1)
		}
		_, _, _, err = httpClient.OpenStream(connCtx, requestURL.String(), sessionId, reader, true)
		if err != nil {
			return nil, err
		}
		returningConn = true
		return stat.Connection(&conn), nil
	}

	maxUploadSize := packetSize(transportConfiguration, limits)
	if maxUploadSize <= 0 {
		return nil, errors.New("XHTTP upload packet size must be positive")
	}
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(max(0, maxUploadSize-buf.Size)))
	conn.writer = uploadWriter{uploadPipeWriter, maxUploadSize}
	stopUpload := context.AfterFunc(connCtx, uploadPipeReader.Interrupt)
	if xmuxClient != nil {
		xmuxClient.AddRunning()
	}

	go func() {
		defer stopUpload()
		dynamicHTTPClient := httpClient
		dynamicXmuxClient := xmuxClient
		if dynamicXmuxClient != nil {
			defer func() { dynamicXmuxClient.DoneRunning() }()
		}
		requestURI := requestURL.String()
		uploadPackets(connCtx, cancel, uploadPipeReader, maxUploadSize, transportConfiguration.GetNormalizedScMinPostsIntervalMs(), limits,
			func(requestCtx context.Context) (DialerClient, func()) {
				if dynamicXmuxClient == nil {
					return dynamicHTTPClient, func() {}
				}
				if dynamicXmuxClient.LeftRequests.Add(-1) <= 0 ||
					(dynamicXmuxClient.UnreusableAt != time.Time{} && time.Now().After(dynamicXmuxClient.UnreusableAt)) {
					next, lease, err := getHTTPClient(requestCtx, dest, streamSettings, path)
					if err != nil {
						return nil, nil
					}
					dynamicXmuxClient.DoneRunning()
					dynamicHTTPClient, dynamicXmuxClient = next, lease
				}
				dynamicXmuxClient.AddRunning()
				return dynamicHTTPClient, dynamicXmuxClient.DoneRunning
			}, requestURI, sessionId)
	}()
	returningConn = true

	return stat.Connection(&conn), nil
}

// The pipe admits one write beyond its size limit, so bound each batch before
// allocating buffers. The upload reader splits the result into exact packets.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if w.maxLen <= 0 {
		return 0, errors.New("upload batch size must be positive")
	}
	written := 0
	for len(b) > 0 {
		n := min(len(b), int(w.maxLen))
		buffer := buf.MultiBufferContainer{}
		common.Must2(buffer.Write(b[:n]))
		// WriteMultiBuffer takes ownership on both success and failure.
		if err := w.WriteMultiBuffer(buffer.MultiBuffer); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
