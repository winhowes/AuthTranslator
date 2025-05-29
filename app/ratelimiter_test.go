package main

import (
	"testing"
	"time"
)

func TestRateLimiterExceedLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Hour)
	t.Cleanup(rl.Stop)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("first call should be allowed")
	}
	if !rl.Allow(key) {
		t.Fatal("second call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("third call should be rejected")
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(1, 20*time.Millisecond)
	t.Cleanup(rl.Stop)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("limit should be reached")
	}

	// wait for reset
	time.Sleep(25 * time.Millisecond)

	if !rl.Allow(key) {
		t.Fatal("rate limiter should reset after duration")
	}
}

func TestRateLimiterUnlimited(t *testing.T) {
	rl := NewRateLimiter(0, time.Hour)
	t.Cleanup(rl.Stop)
	key := "caller"

	for i := 0; i < 100; i++ {
		if !rl.Allow(key) {
			t.Fatalf("call %d should be allowed", i)
		}
	}
}

func TestRateLimiterUnlimitedNegative(t *testing.T) {
	rl := NewRateLimiter(-1, time.Hour)
	t.Cleanup(rl.Stop)
	key := "caller"

	for i := 0; i < 100; i++ {
		if !rl.Allow(key) {
			t.Fatalf("call %d should be allowed", i)
		}
	}
}

func TestRateLimiterRedisFallback(t *testing.T) {
	old := *redisAddr
	*redisAddr = "127.0.0.1:0" // unreachable
	oldTimeout := *redisTimeout
	*redisTimeout = time.Millisecond
	rl := NewRateLimiter(1, 10*time.Millisecond)
	t.Cleanup(func() {
		rl.Stop()
		*redisAddr = old
		*redisTimeout = oldTimeout
	})

	if !rl.Allow("k") {
		t.Fatal("first call should be allowed")
	}
	if rl.Allow("k") {
		t.Fatal("second call should be rate limited using fallback")
	}
}
