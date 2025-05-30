package main

import (
	"testing"
	"time"
)

func TestRateLimiterExceedLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Hour, "")
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
	rl := NewRateLimiter(1, 20*time.Millisecond, "")
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
	rl := NewRateLimiter(0, time.Hour, "")
	t.Cleanup(rl.Stop)
	key := "caller"

	for i := 0; i < 100; i++ {
		if !rl.Allow(key) {
			t.Fatalf("call %d should be allowed", i)
		}
	}
}

func TestRateLimiterUnlimitedNegative(t *testing.T) {
	rl := NewRateLimiter(-1, time.Hour, "")
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
	rl := NewRateLimiter(1, 10*time.Millisecond, "")
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

func TestRedisTTLArgs(t *testing.T) {
	cmd, val := redisTTLArgs(1500 * time.Millisecond)
	if cmd != "PEXPIRE" || val != "1500" {
		t.Fatalf("expected PEXPIRE 1500, got %s %s", cmd, val)
	}

	cmd, val = redisTTLArgs(500 * time.Millisecond)
	if cmd != "PEXPIRE" || val != "500" {
		t.Fatalf("expected PEXPIRE 500, got %s %s", cmd, val)
	}

	cmd, val = redisTTLArgs(0)
	if cmd != "EXPIRE" || val != "0" {
		t.Fatalf("expected EXPIRE 0 for zero duration, got %s %s", cmd, val)
	}
}

func TestRedisTTLArgsNegative(t *testing.T) {
	cmd, val := redisTTLArgs(-500 * time.Millisecond)
	if cmd != "EXPIRE" || val != "0" {
		t.Fatalf("expected EXPIRE 0 for negative duration, got %s %s", cmd, val)
	}
}

func TestRedisTTLArgsSeconds(t *testing.T) {
	cmd, val := redisTTLArgs(2 * time.Second)
	if cmd != "EXPIRE" || val != "2" {
		t.Fatalf("expected EXPIRE 2, got %s %s", cmd, val)
	}
}

func TestRedisTTLArgsSubMillisecond(t *testing.T) {
	cmd, val := redisTTLArgs(500 * time.Microsecond)
	if cmd != "PEXPIRE" || val != "1" {
		t.Fatalf("expected PEXPIRE 1 for sub-millisecond duration, got %s %s", cmd, val)
	}
}

func TestTokenBucketRefill(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond, "token_bucket")
	t.Cleanup(rl.Stop)
	key := "caller"
	if !rl.Allow(key) {
		t.Fatal("first call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("second immediate call should be rate limited")
	}
	time.Sleep(120 * time.Millisecond)
	if !rl.Allow(key) {
		t.Fatal("token should refill after window")
	}
}
