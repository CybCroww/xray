package tun

import "context"

type (
	deviceKey struct{}
	flowsKey  struct{}
)

type flowReset struct {
	register         func(func(bool))
	retireTransports func()
}

// ContextWithDevice supplies the TUN device for an embedded Xray instance.
// The host owns interface settings; the handler owns the device's lifecycle.
func ContextWithDevice(ctx context.Context, device Tun) context.Context {
	return context.WithValue(ctx, deviceKey{}, device)
}

// ContextWithFlowReset registers the stack's reset with the mobile owner.
// A reset retires transport pools and new dispatches resume only when the
// reset function is called with true. The device and stack stay up.
func ContextWithFlowReset(ctx context.Context, register func(func(bool)), retireTransports func()) context.Context {
	return context.WithValue(ctx, flowsKey{}, flowReset{register, retireTransports})
}
