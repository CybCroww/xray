package tun

import "context"

type (
	deviceKey struct{}
	flowsKey  struct{}
)

type flowReset struct {
	register         func(func())
	retireTransports func()
}

// ContextWithDevice supplies the TUN device for an embedded Xray instance.
// The host owns interface settings; the handler owns the device's lifecycle.
func ContextWithDevice(ctx context.Context, device Tun) context.Context {
	return context.WithValue(ctx, deviceKey{}, device)
}

// ContextWithFlowReset registers the currently running stack's flow reset
// with the mobile owner. Transport pools retire between canceling the old
// dispatch context and admitting new flows. The device and stack stay up.
func ContextWithFlowReset(ctx context.Context, register func(func()), retireTransports func()) context.Context {
	return context.WithValue(ctx, flowsKey{}, flowReset{register, retireTransports})
}
