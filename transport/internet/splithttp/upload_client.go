package splithttp

import (
	"context"
	"net/http/httptrace"
	"runtime"
	"strconv"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/pipe"
)

// The flight slots cover the whole request, including a stalled response, rather
// than just the time it takes to send the request body.
type clientLimits struct {
	flows   chan struct{}
	packets chan struct{}
}

var mobileLimits = &clientLimits{flows: make(chan struct{}, 64), packets: make(chan struct{}, 24)}

func platformClientLimits() *clientLimits {
	if runtime.GOOS == "ios" || runtime.GOOS == "android" {
		return mobileLimits
	}
	return nil
}

func acquireSlot(ctx context.Context, slots chan struct{}) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case slots <- struct{}{}:
		if ctx.Err() != nil {
			<-slots
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}

func packetSize(config *Config, limits *clientLimits) int32 {
	size := config.GetNormalizedScMaxEachPostBytes().rand()
	if limits == nil {
		return size
	}
	switch config.GetNormalizedUplinkDataPlacement() {
	case PlacementHeader, PlacementCookie:
		return min(size, 4<<10) // before base64 expansion, controls and HTTP headers
	default:
		return min(size, 64<<10)
	}
}

func uploadPackets(ctx context.Context, cancel context.CancelFunc, reader *pipe.Reader, size int32, interval *RangeConfig, limits *clientLimits, selectClient func(context.Context) (DialerClient, func()), requestURI, sessionID string) {
	parallel := 8
	if limits != nil {
		parallel = 3
	}
	local := make(chan struct{}, parallel)
	var seq int64
	var lastWrite time.Time
	var remainder buf.MultiBuffer
	defer func() { buf.ReleaseMulti(remainder) }()
	defer reader.Interrupt()
	for ctx.Err() == nil {
		if remainder.IsEmpty() {
			var err error
			remainder, err = reader.ReadMultiBuffer()
			if err != nil {
				return
			}
		}
		if interval.From > 0 {
			if wait := time.Duration(interval.rand())*time.Millisecond - time.Since(lastWrite); wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
		}
		if !acquireSlot(ctx, local) {
			return
		}
		if limits != nil && !acquireSlot(ctx, limits.packets) {
			<-local
			return
		}
		var chunk buf.MultiBuffer
		remainder, chunk = buf.SplitSize(remainder, size)
		wrote := make(chan struct{}, 1)
		signalWritten := func() {
			select {
			case wrote <- struct{}{}:
			default:
			}
		}
		lastWrite = time.Now()
		seqStr := strconv.FormatInt(seq, 10)
		seq++
		client, releaseClient := selectClient(ctx)
		go func() {
			defer func() {
				<-local
				if limits != nil {
					<-limits.packets
				}
				signalWritten()
			}()
			defer releaseClient()
			requestCtx, stop := context.WithTimeout(ctx, 30*time.Second)
			defer stop()
			requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
				WroteRequest: func(info httptrace.WroteRequestInfo) {
					if info.Err == nil {
						signalWritten()
					}
				},
			})
			if err := client.PostPacket(requestCtx, requestURI, sessionID, seqStr, chunk); err != nil && ctx.Err() == nil {
				errors.LogInfoInner(ctx, err, "failed to send upload")
				cancel()
			}
		}()
		// Start requests in transport write order. HTTP/2 and HTTP/3 can then
		// wait for replies in parallel without buffering unbounded uploads.
		select {
		case <-wrote:
		case <-ctx.Done():
			return
		}
	}
}
