package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNilLimiterNeverWaits(t *testing.T) {
	var l *Limiter
	if l != New(0, 0) {
		t.Fatal("New(0, 0) should return nil")
	}
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Error("nil limiter waited")
	}
}

// TestRateIsEnforcedAcrossGoroutines is the PRD's acceptance test in miniature:
// N concurrent callers at R requests/second must take about (N-1)/R seconds.
func TestRateIsEnforcedAcrossGoroutines(t *testing.T) {
	const rate, n = 20.0, 21
	l := New(rate, 0)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Wait(context.Background())
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	want := time.Duration(float64(n-1) / rate * float64(time.Second)) // 1s
	if elapsed < want-50*time.Millisecond {
		t.Errorf("%d requests at %.0f/s finished in %v, want at least %v", n, rate, elapsed, want)
	}
	if elapsed > want+500*time.Millisecond {
		t.Errorf("%d requests at %.0f/s took %v, far more than %v", n, rate, elapsed, want)
	}
}

func TestStricterOfRateAndDelayWins(t *testing.T) {
	if got := New(10, 500*time.Millisecond).Interval(); got != 500*time.Millisecond {
		t.Errorf("delay should win over rate: interval = %v", got)
	}
	if got := New(2, 100*time.Millisecond).Interval(); got != 500*time.Millisecond {
		t.Errorf("rate should win over delay: interval = %v", got)
	}
}

func TestWaitHonorsContext(t *testing.T) {
	l := New(1, 0) // 1 rps
	_ = l.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.Wait(ctx); err == nil {
		t.Error("expected context error while waiting for a slot")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("Wait did not return promptly on context expiry")
	}
}
