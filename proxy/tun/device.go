package tun

import "context"

type (
	deviceKey struct{}
	flowsKey  struct{}
)

// ContextWithDevice supplies the TUN device for an embedded Xray instance.
// The host owns interface settings; the handler owns the device's lifecycle.
func ContextWithDevice(ctx context.Context, device Tun) context.Context {
	return context.WithValue(ctx, deviceKey{}, device)
}

// ContextWithFlowReset registers the currently running stack's flow reset
// with the mobile owner. The device and stack stay up during a reset.
func ContextWithFlowReset(ctx context.Context, register func(func())) context.Context {
	return context.WithValue(ctx, flowsKey{}, register)
}
