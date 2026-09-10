// Package ratelimit paces outbound requests so a scan stays inside the
// request ceiling a target's rules of engagement allow.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter enforces a minimum interval between the requests that pass through
// it. It is safe for concurrent use and is shared by every renderer and every
// target in a run, so the ceiling applies to the process as a whole rather
// than to each worker. A nil *Limiter never waits.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time // earliest time the next request may start
}

// New returns a limiter allowing at most ratePerSecond requests per second
// (0 = unlimited) and never starting two requests closer together than
// minDelay (0 = none). When both are set the stricter one wins. If neither
// is set, New returns nil, which callers may use without a check.
func New(ratePerSecond float64, minDelay time.Duration) *Limiter {
	var interval time.Duration
	if ratePerSecond > 0 {
		interval = time.Duration(float64(time.Second) / ratePerSecond)
	}
	if minDelay > interval {
		interval = minDelay
	}
	if interval <= 0 {
		return nil
	}
	return &Limiter{interval: interval}
}

// Interval returns the enforced spacing between requests (0 for a nil limiter).
func (l *Limiter) Interval() time.Duration {
	if l == nil {
		return 0
	}
	return l.interval
}

// Wait blocks until the next request may start, or until ctx is done, in
// which case it returns ctx's error and consumes no slot. Slots are handed
// out in call order, so a burst of callers is spread evenly rather than
// released together.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	l.mu.Lock()
	now := time.Now()
	start := l.next
	if start.Before(now) {
		start = now
	}
	l.next = start.Add(l.interval)
	l.mu.Unlock()

	delay := time.Until(start)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
