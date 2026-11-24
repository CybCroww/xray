package mobile

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"github.com/xtls/xray-core/infra/conf"
)

// The strict profile deliberately accepts the app's own VPN outbounds and
// block rules, rather than arbitrary imported server configs. In particular a
// freedom fallback would bypass the native tunnel from inside the extension.
func protectProfile(cfg *conf.Config) error {
	if len(cfg.OutboundConfigs) == 0 || cfg.DNSConfig != nil || cfg.Reverse != nil || cfg.API != nil || cfg.Metrics != nil || cfg.Geodata != nil {
		return errors.New("protected profile requires at least one VPN outbound and no core DNS, reverse, API, metrics or geodata services")
	}
	if cfg.RouterConfig != nil {
		if cfg.RouterConfig.Script != "" {
			return errors.New("protected profile does not support routing scripts")
		}
		if strategy := cfg.RouterConfig.DomainStrategy; strategy != nil && *strategy != "" && !strings.EqualFold(*strategy, "AsIs") {
			return errors.New("protected profile routes domains without local DNS resolution")
		}
	}
	for i := range cfg.OutboundConfigs {
		o := &cfg.OutboundConfigs[i]
		protocol := strings.ToLower(o.Protocol)
		if i > 0 && protocol == "blackhole" {
			continue
		}
		if (protocol != "vless" && protocol != "trojan" && protocol != "hysteria" && protocol != "hysteria2") || o.Settings == nil || o.StreamSetting == nil {
			return errors.New("protected profile only supports VPN outbounds and a block outbound")
		}
		if o.ProxySettings != nil || (o.TargetStrategy != "" && !strings.EqualFold(o.TargetStrategy, "AsIs")) {
			return errors.New("protected profile does not support an outbound proxy chain or local resolution")
		}
		var endpoint struct {
			Address string                     `json:"address"`
			Vnext   []struct{ Address string } `json:"vnext"`
			Servers []struct{ Address string } `json:"servers"`
			Testpre uint32                     `json:"testpre"`
			Reverse json.RawMessage            `json:"reverse"`
		}
		if err := json.Unmarshal(*o.Settings, &endpoint); err != nil || endpoint.Testpre != 0 || (len(endpoint.Reverse) != 0 && string(endpoint.Reverse) != "null") {
			return errors.New("protected profile does not support preconnect or reverse settings")
		}
		address := endpoint.Address
		if address == "" && len(endpoint.Vnext) == 1 {
			address = endpoint.Vnext[0].Address
		}
		if address == "" && len(endpoint.Servers) == 1 {
			address = endpoint.Servers[0].Address
		}
		if !literalIP(address) {
			return errors.New("protected profile needs a pre-resolved VPN endpoint IP; keep the hostname in TLS settings")
		}
		if err := protectStream(o.StreamSetting, false); err != nil {
			return err
		}
	}
	return nil
}

func literalIP(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
}

func protectStream(stream *conf.StreamConfig, download bool) error {
	if (download && stream.Address == nil) || (stream.Address != nil && (stream.Address.Address == nil || !literalIP(stream.Address.String()))) {
		return errors.New("protected profile needs a pre-resolved transport IP")
	}
	if !strings.EqualFold(stream.Security, "tls") && !strings.EqualFold(stream.Security, "reality") {
		return errors.New("protected profile requires TLS or REALITY")
	}
	if tls := stream.TLSSettings; tls != nil {
		if tls.AllowInsecure || tls.MasterKeyLog != "" {
			return errors.New("protected profile requires TLS verification without key logging")
		}
		if strings.Contains(tls.ECHConfigList, "://") {
			return errors.New("protected profile needs a static ECH configuration")
		}
	}
	method := stream.Network
	if stream.Method != nil {
		method = stream.Method
	}
	if method != nil {
		name, err := method.Build()
		if err != nil {
			return err
		}
		switch name {
		case "tcp", "grpc", "splithttp", "websocket", "hysteria":
		default:
			return errors.New("unsupported transport in protected profile")
		}
	}
	if sock := stream.SocketSettings; sock != nil && (sock.DialerProxy != "" || sock.Interface != "" || len(sock.CustomSockopt) > 0) {
		return errors.New("protected profile does not permit custom socket routing")
	}
	if stream.FinalMask != nil {
		return errors.New("protected profile does not permit custom transport masks")
	}
	if stream.GRPCSettings != nil {
		stream.GRPCSettings.PermitWithoutStream = false
	}
	for _, xhttp := range []*conf.SplitHTTPConfig{stream.SplitHTTPSettings, stream.XHTTPSettings} {
		if xhttp == nil {
			continue
		}
		if xhttp.Extra != nil {
			var extra conf.SplitHTTPConfig
			if err := json.Unmarshal(xhttp.Extra, &extra); err != nil {
				return err
			}
			xhttp = &extra // Build uses Extra in place of the main transport fields.
		}
		if xhttp.DownloadSettings != nil {
			if download {
				return errors.New("nested XHTTP download settings are not supported")
			}
			if err := protectStream(xhttp.DownloadSettings, true); err != nil {
				return err
			}
		}
	}
	return nil
}
