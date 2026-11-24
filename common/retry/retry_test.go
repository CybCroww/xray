package retry_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	. "github.com/xtls/xray-core/common/retry"
)

var errorTestOnly = errors.New("this is a fake error")

func TestContextBackoffCancelsPendingRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		attempts := 0
		result := make(chan error, 1)
		go func() {
			result <- ExponentialBackoffContext(ctx, 5, 60_000).On(func() error {
				attempts++
				return errorTestOnly
			})
		}()
		synctest.Wait()
		if attempts != 2 {
			t.Fatalf("started %d attempts before the first delay", attempts)
		}
		start := time.Now()
		cancel()
		if err := <-result; err != context.Canceled || attempts != 2 || time.Since(start) != 0 {
			t.Fatalf("retry did not stop immediately: err %v, attempts %d, elapsed %v", err, attempts, time.Since(start))
		}
	})
}

func TestContextBackoffSkipsFinalDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		err := ExponentialBackoffContext(context.Background(), 2, 60_000).On(func() error {
			return errorTestOnly
		})
		if errors.Cause(err) != ErrRetryFailed || time.Since(start) != 0 {
			t.Fatalf("unexpected error or final delay: %v after %v", err, time.Since(start))
		}
	})
}

func TestNoRetry(t *testing.T) {
	startTime := time.Now().Unix()
	err := Timed(10, 100000).On(func() error {
		return nil
	})
	endTime := time.Now().Unix()

	common.Must(err)
	if endTime < startTime {
		t.Error("endTime < startTime: ", startTime, " -> ", endTime)
	}
}

func TestRetryOnce(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := Timed(10, 1000).On(func() error {
		if called == 0 {
			called++
			return errorTestOnly
		}
		return nil
	})
	duration := time.Since(startTime)

	common.Must(err)
	if v := int64(duration / time.Millisecond); v < 900 {
		t.Error("duration: ", v)
	}
}

func TestRetryMultiple(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := Timed(10, 1000).On(func() error {
		if called < 5 {
			called++
			return errorTestOnly
		}
		return nil
	})
	duration := time.Since(startTime)

	common.Must(err)
	if v := int64(duration / time.Millisecond); v < 4900 {
		t.Error("duration: ", v)
	}
}

func TestRetryExhausted(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := Timed(2, 1000).On(func() error {
		called++
		return errorTestOnly
	})
	duration := time.Since(startTime)

	if errors.Cause(err) != ErrRetryFailed {
		t.Error("cause: ", err)
	}

	if v := int64(duration / time.Millisecond); v < 1900 {
		t.Error("duration: ", v)
	}
}

func TestExponentialBackoff(t *testing.T) {
	startTime := time.Now()
	called := 0
	err := ExponentialBackoff(10, 100).On(func() error {
		called++
		return errorTestOnly
	})
	duration := time.Since(startTime)

	if errors.Cause(err) != ErrRetryFailed {
		t.Error("cause: ", err)
	}
	if v := int64(duration / time.Millisecond); v < 4000 {
		t.Error("duration: ", v)
	}
}
