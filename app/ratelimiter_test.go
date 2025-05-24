package main

import (
	"testing"
	"time"
)

func TestRateLimiterExceedLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Hour)
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
	rl := NewRateLimiter(1, 10*time.Millisecond)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("limit should be reached")
	}

	// wait for reset
	time.Sleep(15 * time.Millisecond)

	if !rl.Allow(key) {
		t.Fatal("rate limiter should reset after duration")
	}
	rl.resetTicker.Stop()
}
