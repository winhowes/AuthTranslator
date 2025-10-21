package main

import (
	"bufio"
	"net"
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

func TestRateLimiterFixedWindowRefreshesOnAllow(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour, "")
	t.Cleanup(rl.Stop)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("second call should be rejected before refresh")
	}

	rl.mu.Lock()
	rl.resetTime = time.Now().Add(-2 * rl.window)
	rl.mu.Unlock()

	if !rl.Allow(key) {
		t.Fatal("call should be allowed once window has elapsed")
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

func TestLeakyBucketSmoothing(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond, "leaky_bucket")
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
		t.Fatal("call should be allowed after leak")
	}
}

func TestTokenBucketMaxTokens(t *testing.T) {
	rl := NewRateLimiter(2, 50*time.Millisecond, "token_bucket")
	t.Cleanup(rl.Stop)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}

	time.Sleep(200 * time.Millisecond)

	if !rl.Allow(key) {
		t.Fatal("first call after refill should be allowed")
	}
	if !rl.Allow(key) {
		t.Fatal("second call after refill should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("third call should exceed the limit")
	}
}

func TestLeakyBucketPartialLeak(t *testing.T) {
	rl := NewRateLimiter(2, 100*time.Millisecond, "leaky_bucket")
	t.Cleanup(rl.Stop)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("first call should be allowed")
	}
	if !rl.Allow(key) {
		t.Fatal("second call should be allowed")
	}

	time.Sleep(25 * time.Millisecond)
	if rl.Allow(key) {
		t.Fatal("call before sufficient leak should be rate limited")
	}

	time.Sleep(50 * time.Millisecond)
	if !rl.Allow(key) {
		t.Fatal("call should succeed after enough leak")
	}
	if rl.Allow(key) {
		t.Fatal("next immediate call should be rate limited")
	}
}

func TestRetryAfterFixedWindow(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond, "")
	t.Cleanup(rl.Stop)
	key := "caller"

	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("second call should be rate limited")
	}
	if d := rl.RetryAfter(key); d <= 0 || d > 50*time.Millisecond {
		t.Fatalf("unexpected retry after %v", d)
	}
	time.Sleep(60 * time.Millisecond)
	if d := rl.RetryAfter(key); d == 0 {
		// we waited long enough for the window to reset; skip further check if ticker timing reached the next cycle
	} else if d > 50*time.Millisecond {
		t.Fatalf("retry after too large: %v", d)
	}
}

func TestRetryAfterTokenBucket(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond, "token_bucket")
	key := "caller"
	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("second call should be rate limited")
	}
	if d := rl.RetryAfter("other"); d != 0 {
		t.Fatalf("expected 0 for unused key, got %v", d)
	}
	if d := rl.RetryAfter(key); d <= 0 || d > 100*time.Millisecond {
		t.Fatalf("unexpected retry after %v", d)
	}
}

func TestRetryAfterLeakyBucket(t *testing.T) {
	rl := NewRateLimiter(1, 100*time.Millisecond, "leaky_bucket")
	key := "caller"
	if !rl.Allow(key) {
		t.Fatal("initial call should be allowed")
	}
	if rl.Allow(key) {
		t.Fatal("second call should be rate limited")
	}
	if d := rl.RetryAfter("other"); d != 0 {
		t.Fatalf("expected 0 for unused key, got %v", d)
	}
	if d := rl.RetryAfter(key); d <= 0 || d > 100*time.Millisecond {
		t.Fatalf("unexpected retry after %v", d)
	}
}

func TestRetryAfterLeakyBucketAfterLeak(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond, "leaky_bucket")
	key := "caller"
	if !rl.Allow(key) {
		t.Fatal("first call should be allowed")
	}
	time.Sleep(60 * time.Millisecond)
	if d := rl.RetryAfter(key); d != 0 {
		t.Fatalf("expected 0 after leak, got %v", d)
	}
}

func TestRetryAfterNoLimit(t *testing.T) {
	rl := NewRateLimiter(0, time.Hour, "")
	if d := rl.RetryAfter("k"); d != 0 {
		t.Fatalf("expected 0 for unlimited limiter, got %v", d)
	}
}

func TestRetryAfterUnknownStrategy(t *testing.T) {
	rl := NewRateLimiter(1, 42*time.Millisecond, "bogus")
	if d := rl.RetryAfter("k"); d != 42*time.Millisecond {
		t.Fatalf("expected %v got %v", 42*time.Millisecond, d)
	}
}

func TestAllowUnknownStrategy(t *testing.T) {
	rl := NewRateLimiter(1, time.Hour, "bogus")
	t.Cleanup(rl.Stop)
	key := "caller"
	if !rl.Allow(key) {
		t.Fatal("first call should be allowed")
	}
	if !rl.Allow(key) {
		t.Fatal("second call should still be allowed for unknown strategy")
	}
}

func TestRetryAfterRedisPath(t *testing.T) {
	old := *redisAddr
	*redisAddr = "dummy"
	rl := NewRateLimiter(1, time.Second, "")
	t.Cleanup(func() { *redisAddr = old; rl.Stop() })

	srv, cli := net.Pipe()
	rl.conns <- cli
	done := make(chan struct{})
	go func() {
		defer func() { srv.Close(); close(done) }()
		br := bufio.NewReader(srv)
		if cmd, args := parseRedisCommand(t, br); cmd != "PTTL" || args[0] != "k" {
			t.Errorf("unexpected command %s %v", cmd, args)
			return
		}
		srv.Write([]byte(":1000\r\n"))
	}()

	d := rl.RetryAfter("k")
	if d != time.Second {
		t.Fatalf("expected 1s, got %v", d)
	}
	<-done
}
