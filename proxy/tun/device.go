package tun

import "context"

type deviceKey struct{}

// ContextWithDevice supplies the TUN device for an embedded Xray instance.
// The host owns interface settings; the handler owns the device's lifecycle.
func ContextWithDevice(ctx context.Context, device Tun) context.Context {
	return context.WithValue(ctx, deviceKey{}, device)
}
