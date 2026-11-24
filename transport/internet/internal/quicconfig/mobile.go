package quicconfig

import "github.com/apernet/quic-go"

// LimitMobileReceiveWindow bounds data that QUIC can buffer ahead of app reads.
func LimitMobileReceiveWindow(cfg *quic.Config) {
	const streamLimit, connLimit = 512 << 10, 2 << 20
	// The Chrome preset overrides both initial windows and raises their maxima.
	cfg.ChromeParrot = false
	cfg.InitialStreamReceiveWindow = window(cfg.InitialStreamReceiveWindow, streamLimit)
	cfg.MaxStreamReceiveWindow = max(cfg.InitialStreamReceiveWindow, window(cfg.MaxStreamReceiveWindow, streamLimit))
	cfg.InitialConnectionReceiveWindow = window(cfg.InitialConnectionReceiveWindow, connLimit)
	cfg.MaxConnectionReceiveWindow = max(cfg.InitialConnectionReceiveWindow, window(cfg.MaxConnectionReceiveWindow, connLimit))
}

func window(configured, limit uint64) uint64 {
	if configured == 0 {
		return limit
	}
	return min(configured, limit)
}
