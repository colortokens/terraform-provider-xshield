package keyservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

const (
	maxKeyServiceAttempts = 5
	firstRetryDelay       = 500 * time.Millisecond
	longestRetryAfter     = 30 * time.Second
)

// transientError is a key service failure that the same call may not meet again: throttling, a server error or
// a dropped connection.
type transientError struct {
	cause      error
	retryAfter time.Duration
}

func (e *transientError) Error() string { return e.cause.Error() }

func (e *transientError) Unwrap() error { return e.cause }

func transientRefusal(cause error, header http.Header) error {
	return &transientError{cause: cause, retryAfter: retryAfter(header, time.Now())}
}

func transientIfConnectionDropped(cause error) error {
	if !connectionDropped(cause) {
		return cause
	}
	return &transientError{cause: cause}
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

func connectionDropped(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

// retryAfter reads Retry-After as seconds or as an HTTP date; it is zero when the header is absent or unreadable.
func retryAfter(header http.Header, now time.Time) time.Duration {
	value := header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil && at.After(now) {
		return at.Sub(now)
	}
	return 0
}

// retryPolicy makes a key service call again after a transient failure. Its zero value waits on a timer with full
// jitter; tests replace the wait and the jitter.
type retryPolicy struct {
	wait   func(ctx context.Context, delay time.Duration) error
	jitter func(limit time.Duration) time.Duration
}

func (p retryPolicy) call(ctx context.Context, attempt func() error) error {
	for attempts := 1; ; attempts++ {
		err := attempt()
		var transient *transientError
		if !errors.As(err, &transient) {
			return err
		}
		if attempts == maxKeyServiceAttempts {
			return fmt.Errorf("%w; gave up after %d attempts", transient.cause, attempts)
		}
		delay := transient.retryAfter
		if delay == 0 {
			delay = p.backoff(attempts)
		}
		if delay > longestRetryAfter {
			return fmt.Errorf("%w; the key service asked to wait %s before trying again", transient.cause, delay)
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < delay {
			return fmt.Errorf("%w; the request's deadline leaves no time to try again", transient.cause)
		}
		if err := p.waitFor(ctx, delay); err != nil {
			return fmt.Errorf("%w; stopped before trying again: %w", transient.cause, err)
		}
	}
}

func (p retryPolicy) backoff(failedAttempts int) time.Duration {
	limit := firstRetryDelay << (failedAttempts - 1)
	if p.jitter != nil {
		return p.jitter(limit)
	}
	return fullJitter(limit)
}

func (p retryPolicy) waitFor(ctx context.Context, delay time.Duration) error {
	if p.wait != nil {
		return p.wait(ctx, delay)
	}
	return waitOnTimer(ctx, delay)
}

func fullJitter(limit time.Duration) time.Duration {
	return rand.N(limit)
}

func waitOnTimer(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
