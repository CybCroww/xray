package internet

import (
	"context"
	"runtime"
)

type mobileProfileKey struct{}

// ContextWithMobileProfile selects bounded transport buffers and mobile
// connection lifetimes for flows from an embedded packet tunnel.
func ContextWithMobileProfile(ctx context.Context) context.Context {
	return context.WithValue(ctx, mobileProfileKey{}, true)
}

// UsesEmbeddedMobileProfile identifies flows owned by the embedded packet
// tunnel, which explicitly retires its connections on Stop.
func UsesEmbeddedMobileProfile(ctx context.Context) bool {
	mobile, _ := ctx.Value(mobileProfileKey{}).(bool)
	return mobile
}

// UsesMobileProfile also enables the profile for callers that embed the
// transports directly on iOS and Android.
func UsesMobileProfile(ctx context.Context) bool {
	if runtime.GOOS == "ios" || runtime.GOOS == "android" {
		return true
	}
	return UsesEmbeddedMobileProfile(ctx)
}
