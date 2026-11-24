package retry // import "github.com/xtls/xray-core/common/retry"

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var ErrRetryFailed = errors.New("all retry attempts failed")

// Strategy is a way to retry on a specific function.
type Strategy interface {
	// On performs a retry on a specific function, until it doesn't return any error.
	On(func() error) error
}

type retryer struct {
	ctx          context.Context
	totalAttempt int
	nextDelay    func() uint32
}

// On implements Strategy.On.
func (r *retryer) On(method func() error) error {
	accumulatedError := make([]error, 0, r.totalAttempt)
	for attempt := range r.totalAttempt {
		if r.ctx != nil && r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		err := method()
		if err == nil {
			return nil
		}
		numErrors := len(accumulatedError)
		if numErrors == 0 || err.Error() != accumulatedError[numErrors-1].Error() {
			accumulatedError = append(accumulatedError, err)
		}
		if r.ctx != nil && attempt+1 == r.totalAttempt {
			break
		}
		delay := time.Duration(r.nextDelay()) * time.Millisecond
		if r.ctx == nil {
			time.Sleep(delay)
		} else if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-r.ctx.Done():
				timer.Stop()
				return r.ctx.Err()
			}
		}
	}
	if r.ctx != nil && r.ctx.Err() != nil {
		return r.ctx.Err()
	}
	return errors.New(accumulatedError).Base(ErrRetryFailed)
}

// Timed returns a retry strategy with fixed interval.
func Timed(attempts int, delay uint32) Strategy {
	return &retryer{
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			return delay
		},
	}
}

func ExponentialBackoff(attempts int, delay uint32) Strategy {
	return exponentialBackoff(nil, attempts, delay)
}

// ExponentialBackoffContext stops retrying when ctx is canceled and waits
// only between attempts. The operation should use the same context.
func ExponentialBackoffContext(ctx context.Context, attempts int, delay uint32) Strategy {
	return exponentialBackoff(ctx, attempts, delay)
}

func exponentialBackoff(ctx context.Context, attempts int, delay uint32) Strategy {
	nextDelay := uint32(0)
	return &retryer{
		ctx:          ctx,
		totalAttempt: attempts,
		nextDelay: func() uint32 {
			r := nextDelay
			nextDelay += delay
			return r
		},
	}
}
