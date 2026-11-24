package grpc

import (
	"context"
	"reflect"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "creating connection to ", dest)

	conn, err := dialgRPC(ctx, dest, streamSettings, internet.UsesMobileProfile(ctx))
	if err != nil {
		return nil, errors.New("failed to dial gRPC").Base(err)
	}
	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
	mobile bool
}

type cachedChannel struct {
	*grpc.ClientConn
	streams int // protected by globalDialerAccess
}

func (c *cachedChannel) release() {
	globalDialerAccess.Lock()
	c.streams--
	globalDialerAccess.Unlock()
}

var (
	globalDialerMap    map[dialerConf]*cachedChannel
	globalDialerAccess sync.Mutex
)

// ResetMobileNetwork closes cached channels from the previous device path.
// Keep channel shutdown outside the pool lock so dialing can resume promptly.
func ResetMobileNetwork() { retireMobileChannels(false) }

// TrimIdleClients releases mobile channels with no live streams, including
// channels that are still kept warm by gRPC's idle timeout.
func TrimIdleClients() { retireMobileChannels(true) }

func retireMobileChannels(idleOnly bool) {
	var retired []*cachedChannel
	globalDialerAccess.Lock()
	for key, channel := range globalDialerMap {
		if key.mobile && (!idleOnly || channel.streams == 0) {
			delete(globalDialerMap, key)
			retired = append(retired, channel)
		}
	}
	globalDialerAccess.Unlock()
	for _, channel := range retired {
		channel.Close()
	}
}

func dialgRPC(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, mobile bool) (net.Conn, error) {
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	channel, err := getGrpcClient(ctx, dest, streamSettings, mobile)
	if err != nil {
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}
	client := encoding.NewGRPCServiceClient(channel)
	streamCtx, cancel := context.WithCancel(ctx)
	if mobile {
		stopRelease := context.AfterFunc(streamCtx, channel.release)
		cancelStream := cancel
		cancel = func() {
			releaseHere := stopRelease()
			cancelStream()
			if releaseHere {
				channel.release()
			}
		}
	}
	if grpcSettings.MultiMode {
		errors.LogDebug(ctx, "using gRPC multi mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunMultiStreamName()+"`")
		conn, err := encoding.OpenMultiHunkConn(streamCtx, cancel, client.(encoding.GRPCServiceClientX),
			grpcSettings.getServiceName(), grpcSettings.getTunMultiStreamName(), mobile)
		if err != nil {
			cancel()
			return nil, errors.New("Cannot dial gRPC").Base(err)
		}
		return conn, nil
	}

	errors.LogDebug(ctx, "using gRPC tun mode service name: `"+grpcSettings.getServiceName()+"` stream name: `"+grpcSettings.getTunStreamName()+"`")
	grpcService, err := client.(encoding.GRPCServiceClientX).TunCustomName(streamCtx, grpcSettings.getServiceName(), grpcSettings.getTunStreamName())
	if err != nil {
		cancel()
		return nil, errors.New("Cannot dial gRPC").Base(err)
	}

	return encoding.NewHunkConn(grpcService, cancel, nil), nil
}

func getGrpcClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig, mobile bool) (*cachedChannel, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*cachedChannel)
	}
	key := dialerConf{dest, streamSettings, mobile}
	if client := globalDialerMap[key]; client != nil && client.GetState() != connectivity.Shutdown {
		if mobile {
			client.streams++
		}
		return client, nil
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	realityConfig := reality.ConfigFromStreamSettings(streamSettings)
	grpcSettings := streamSettings.ProtocolSettings.(*Config)

	// The cached channel needs socket routing metadata, not the first
	// stream's entire context and its connection objects.
	sessionID := c.IDFromContext(ctx)
	outbounds := session.OutboundsFromContext(ctx)
	embedded := internet.UsesEmbeddedMobileProfile(ctx)
	dialOptions := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithContextDialer(func(gctx context.Context, s string) (net.Conn, error) {
			select {
			case <-gctx.Done():
				return nil, gctx.Err()
			default:
			}

			rawHost, rawPort, err := net.SplitHostPort(s)
			if err != nil {
				return nil, err
			}
			if len(rawPort) == 0 {
				rawPort = "443"
			}
			port, err := net.PortFromString(rawPort)
			if err != nil {
				return nil, err
			}
			address := net.ParseAddress(rawHost)

			gctx = c.ContextWithID(gctx, sessionID)
			gctx = session.ContextWithOutbounds(gctx, outbounds)
			gctx = session.ContextWithTimeoutOnly(gctx, true)
			if embedded {
				gctx = internet.ContextWithMobileProfile(gctx)
			}

			var c net.Conn
			if streamSettings.FinalMask != nil {
				c, err = streamSettings.FinalMask.DialTCP(gctx, net.TCPDestination(address, port))
			} else {
				c, err = internet.DialSystem(gctx, net.TCPDestination(address, port), streamSettings.SocketSettings)
			}
			if err == nil {
				if tlsConfig != nil {
					config := tlsConfig.GetTLSConfig(tls.WithDestination(dest))
					if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
						return tls.UClient(c, config, fingerprint), nil
					} else { // Fallback to normal gRPC TLS
						return tls.Client(c, config), nil
					}
				}
				if realityConfig != nil {
					return reality.UClient(c, realityConfig, gctx, dest)
				}
			}
			return c, err
		}),
	}

	dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))

	authority := ""
	if grpcSettings.Authority != "" {
		authority = grpcSettings.Authority
	} else if tlsConfig != nil && tlsConfig.ServerName != "" {
		authority = tlsConfig.ServerName
	} else if realityConfig == nil && dest.Address.Family().IsDomain() {
		authority = dest.Address.Domain()
	}
	dialOptions = append(dialOptions, grpc.WithAuthority(authority))

	if grpcSettings.IdleTimeout > 0 || grpcSettings.HealthCheckTimeout > 0 || grpcSettings.PermitWithoutStream {
		dialOptions = append(dialOptions, grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                time.Second * time.Duration(grpcSettings.IdleTimeout),
			Timeout:             time.Second * time.Duration(grpcSettings.HealthCheckTimeout),
			PermitWithoutStream: grpcSettings.PermitWithoutStream,
		}))
	}

	dialOptions = appendReceiveWindowOptions(dialOptions, grpcSettings.InitialWindowsSize, mobile)
	if mobile {
		dialOptions = append(dialOptions, grpc.WithIdleTimeout(net.ConnIdleTimeout))
	}

	var grpcDestHost string
	if dest.Address.Family().IsDomain() {
		grpcDestHost = dest.Address.Domain()
	} else {
		grpcDestHost = dest.Address.IP().String()
	}

	conn, err := grpc.NewClient(
		"passthrough:///"+net.JoinHostPort(grpcDestHost, dest.Port.String()),
		dialOptions...,
	)
	if err != nil {
		return nil, err
	}
	userAgent := grpcSettings.UserAgent
	// It's NOT recommended to set the UA of gRPC connections to that of real browsers, as they are fundamentally incapable of initiating real gRPC connections.
	switch userAgent {
	case "chrome", "":
		userAgent = utils.ChromeUA
	case "firefox":
		userAgent = utils.FirefoxUA
	case "edge":
		userAgent = utils.MSEdgeUA
	case "golang":
		userAgent = ""
	}
	setUserAgent(conn, userAgent)
	channel := &cachedChannel{ClientConn: conn}
	if mobile {
		channel.streams = 1
		// NewStream connects on demand for the first live RPC.
	} else {
		conn.Connect()
	}
	globalDialerMap[key] = channel
	return channel, nil
}

func appendReceiveWindowOptions(options []grpc.DialOption, configured int32, mobile bool) []grpc.DialOption {
	if mobile {
		const streamLimit, connLimit = 256 << 10, 2 << 20
		window := int32(streamLimit)
		if configured >= 65535 {
			window = min(configured, streamLimit)
		}
		return append(options, grpc.WithStaticStreamWindowSize(window), grpc.WithStaticConnWindowSize(connLimit))
	}
	if configured > 0 {
		options = append(options, grpc.WithInitialWindowSize(configured))
	}
	return options
}

// setUserAgent overrides the user-agent on a ClientConn to remove the
// "grpc-go/version" suffix that grpc.WithUserAgent unconditionally appends.
func setUserAgent(conn *grpc.ClientConn, ua string) {
	if f := reflect.ValueOf(conn).Elem().FieldByName("dopts").FieldByName("copts").FieldByName("UserAgent"); f.IsValid() {
		*(*string)(f.Addr().UnsafePointer()) = ua
	}
}
