package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/fsnotify/fsnotify"

	http3 "github.com/quic-go/quic-go/http3"
	authplugins "github.com/winhowes/AuthTranslator/app/auth"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins"
	"github.com/winhowes/AuthTranslator/app/metrics"
	_ "github.com/winhowes/AuthTranslator/app/metrics/plugins"
	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

// version is the application version. It can be overridden at build time using
// the -ldflags "-X main.version=<version>" option.
var version = "dev"

type AllowlistEntry struct {
	Integration string         `json:"integration" yaml:"integration"`
	Callers     []CallerConfig `json:"callers" yaml:"callers"`
}

type Config struct {
	Integrations []Integration `json:"integrations" yaml:"integrations"`
}

func loadAllowlists(filename string) ([]AllowlistEntry, error) {
	f, err := openSource(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var entries []AllowlistEntry
	if err := dec.Decode(&entries); err != nil {
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		return nil, err
	}

	return entries, nil
}

var disableXATInt = flag.Bool("disable_x_at_int", false, "ignore X-AT-Int header for routing")
var xAtIntHost = flag.String("x_at_int_host", "", "only respect X-AT-Int header when request Host matches this value")
var addr = flag.String("addr", ":8080", "listen address")
var allowlistFile = flag.String("allowlist", "allowlist.yaml", "path to allowlist configuration")
var configFile = flag.String("config", "config.yaml", "path to configuration file")
var allowlistURL = flag.String("allowlist-url", "", "URL to remote allowlist file")
var configURL = flag.String("config-url", "", "URL to remote configuration file")
var tlsCert = flag.String("tls-cert", "", "path to TLS certificate")
var tlsKey = flag.String("tls-key", "", "path to TLS key")
var logLevel = flag.String("log-level", "INFO", "log level: DEBUG, INFO, WARN, ERROR")
var logFormat = flag.String("log-format", "text", "log output format: text or json")
var redisAddr = flag.String("redis-addr", "", "redis address for rate limits (host:port or redis:// URL)")
var redisTimeout = flag.Duration("redis-timeout", 5*time.Second, "dial timeout for redis")
var redisCA = flag.String("redis-ca", "", "path to CA certificate for Redis TLS; disables InsecureSkipVerify")
var maxBodySizeFlag = flag.Int64("max_body_size", authplugins.MaxBodySize, "maximum bytes buffered from request bodies (0 to disable)")
var secretRefresh = flag.Duration("secret-refresh", 0, "refresh interval for cached secrets (0 disables)")
var readTimeout = flag.Duration("read-timeout", 0, "HTTP server read timeout")
var writeTimeout = flag.Duration("write-timeout", 0, "HTTP server write timeout")
var showVersion = flag.Bool("version", false, "print version and exit")
var watch = flag.Bool("watch", false, "watch config and allowlist files for changes")
var metricsUser = flag.String("metrics-user", "", "username for metrics endpoint")
var metricsPass = flag.String("metrics-pass", "", "password for metrics endpoint")
var enableMetrics = flag.Bool("enable-metrics", true, "expose /metrics endpoint")
var enableHTTP3 = flag.Bool("enable-http3", false, "serve HTTP/3 in addition to HTTP/1 and HTTP/2")
var logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

// setAllowlist is used by reload to register caller allowlists. It is declared
// as a variable so tests can override it.
var setAllowlist = SetAllowlist

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: authtranslator [options]\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
}

func isRemote(path string) bool {
	u, err := url.Parse(path)
	return err == nil && u.Scheme != "" && u.Scheme != "file"
}

func openSource(path string) (io.ReadCloser, error) {
	if isRemote(path) {
		resp, err := http.Get(path)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("remote fetch %s: %s", path, resp.Status)
		}
		return resp.Body, nil
	}
	return os.Open(path)
}

func loadConfig(filename string) (*Config, error) {
	f, err := openSource(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var config Config
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}

	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// reload reparses the configuration and allowlist files, replacing all
// registered integrations and allowlists. Existing rate limiters are
// stopped before the new configuration is loaded.
func reload() error {
	logger.Info("reloading configuration")

	src := *configFile
	if *configURL != "" {
		src = *configURL
	}
	cfg, err := loadConfig(src)
	if err != nil {
		return err
	}

	// Build new integration set without mutating the existing one so we can
	// roll back on failure.
	integrations.RLock()
	oldIntegrations := integrations.m
	integrations.RUnlock()

	newMap := make(map[string]*Integration)
	for i := range cfg.Integrations {
		integ := cfg.Integrations[i]
		if err := prepareIntegration(&integ); err != nil {
			// cleanup any created limiters
			for _, ni := range newMap {
				ni.inLimiter.Stop()
				ni.outLimiter.Stop()
			}
			return fmt.Errorf("failed to load integration %s: %w", integ.Name, err)
		}
		if _, exists := newMap[integ.Name]; exists {
			for _, ni := range newMap {
				ni.inLimiter.Stop()
				ni.outLimiter.Stop()
			}
			return fmt.Errorf("integration %s already exists", integ.Name)
		}
		window := integ.rateLimitDur
		if window == 0 {
			window = time.Minute
		}
		integ.inLimiter = NewRateLimiter(integ.InRateLimit, window, integ.RateLimitStrategy)
		integ.outLimiter = NewRateLimiter(integ.OutRateLimit, window, integ.RateLimitStrategy)
		newMap[integ.Name] = &integ
	}

	// Replace integrations and stop the old ones after success.
	integrations.Lock()
	integrations.m = newMap
	integrations.Unlock()

	for _, i := range oldIntegrations {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	}

	// Clear secret cache so reloaded integrations use fresh values.
	secrets.ClearCache()

	alSrc := *allowlistFile
	if *allowlistURL != "" {
		alSrc = *allowlistURL
	}
	entries, err := loadAllowlists(alSrc)
	allowlists.RLock()
	old := allowlists.m
	allowlists.RUnlock()
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("allowlist file missing; keeping existing entries", "file", alSrc)
		} else {
			logger.Error("failed to load allowlist; keeping existing entries", "error", err)
		}
	} else {
		if err := validateAllowlistEntries(entries); err != nil {
			allowlists.Lock()
			allowlists.m = old
			allowlists.Unlock()
			return fmt.Errorf("invalid allowlist: %w", err)
		}

		allowlists.Lock()
		allowlists.m = make(map[string]map[string]CallerConfig)
		allowlists.Unlock()

		for _, al := range entries {
			if err := setAllowlist(al.Integration, al.Callers); err != nil {
				allowlists.Lock()
				allowlists.m = old
				allowlists.Unlock()
				return fmt.Errorf("failed to load allowlist for %s: %w", al.Integration, err)
			}
		}
	}

	metrics.LastReloadTime.Set(time.Now().Format(time.RFC3339))

	return nil
}

type RateLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	strategy    string
	requests    map[string]int
	buckets     map[string]*tokenBucket
	leaky       map[string]*leakyBucket
	resetTicker *time.Ticker
	done        chan struct{}
	resetTime   time.Time
	useRedis    bool
	conns       chan net.Conn
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type leakyBucket struct {
	level float64
	last  time.Time
}

// NewRateLimiter creates a RateLimiter that limits how many
// requests a caller may make in a given window. The limit parameter
// sets the maximum number of allowed requests; a limit of zero or less
// disables rate limiting. Duration specifies the length of the window
// and how often counters reset. If a redis address is configured,
// counts are stored in Redis so limits are shared across instances.
func NewRateLimiter(limit int, duration time.Duration, strategy string) *RateLimiter {
	if strategy == "" {
		strategy = "fixed_window"
	}
	rl := &RateLimiter{
		limit:     limit,
		window:    duration,
		strategy:  strategy,
		done:      make(chan struct{}),
		resetTime: time.Now(),
		useRedis:  *redisAddr != "",
	}
	if strategy == "fixed_window" {
		rl.requests = make(map[string]int)
	} else if strategy == "token_bucket" {
		rl.buckets = make(map[string]*tokenBucket)
	} else if strategy == "leaky_bucket" {
		rl.leaky = make(map[string]*leakyBucket)
	}

	if rl.useRedis {
		rl.conns = make(chan net.Conn, 4)
	}

	if limit > 0 && strategy == "fixed_window" {
		rl.resetTicker = time.NewTicker(duration)

		go func() {
			for {
				select {
				case <-rl.resetTicker.C:
					rl.mu.Lock()
					rl.requests = make(map[string]int)
					rl.resetTime = time.Now()
					rl.mu.Unlock()
				case <-rl.done:
					return
				}
			}
		}()
	}

	return rl
}

func redisTTLArgs(d time.Duration) (string, string) {
	if d <= 0 {
		return "EXPIRE", "0"
	}
	if d%time.Second == 0 {
		return "EXPIRE", strconv.Itoa(int(d.Seconds()))
	}
	ms := d.Milliseconds()
	if ms == 0 {
		ms = 1
	}
	return "PEXPIRE", strconv.FormatInt(ms, 10)
}

// Stop stops the rate limiter's reset goroutine and ticker.
func (rl *RateLimiter) Stop() {
	if rl.resetTicker != nil {
		rl.resetTicker.Stop()
	}
	select {
	case <-rl.done:
	default:
		close(rl.done)
	}

	if rl.conns != nil {
		for {
			select {
			case c := <-rl.conns:
				c.Close()
			default:
				return
			}
		}
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	if rl.limit <= 0 {
		return true
	}
	if rl.useRedis {
		ok, err := rl.allowRedis(key)
		if err == nil {
			return ok
		}
		logger.Error("redis limiter failed, falling back to memory", "error", err)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	switch rl.strategy {
	case "fixed_window":
		if rl.requests[key] >= rl.limit {
			return false
		}
		rl.requests[key]++
		return true
	case "token_bucket":
		b := rl.buckets[key]
		now := time.Now()
		if b == nil {
			rl.buckets[key] = &tokenBucket{tokens: float64(rl.limit - 1), last: now}
			return true
		}
		refill := now.Sub(b.last).Seconds() * float64(rl.limit) / rl.window.Seconds()
		if refill > 0 {
			b.tokens += refill
			if b.tokens > float64(rl.limit) {
				b.tokens = float64(rl.limit)
			}
			b.last = now
		}
		if b.tokens < 1 {
			return false
		}
		b.tokens--
		return true
	case "leaky_bucket":
		l := rl.leaky[key]
		now := time.Now()
		if l == nil {
			rl.leaky[key] = &leakyBucket{level: 1, last: now}
			return true
		}
		leaked := now.Sub(l.last).Seconds() * float64(rl.limit) / rl.window.Seconds()
		level := l.level - leaked
		if level < 0 {
			level = 0
		}
		if level+1 > float64(rl.limit) {
			l.level = level
			l.last = now
			return false
		}
		l.level = level + 1
		l.last = now
		return true
	default:
		return true
	}
}

func (rl *RateLimiter) RetryAfter(key string) time.Duration {
	if rl.limit <= 0 {
		return 0
	}
	if rl.useRedis {
		if d, err := rl.retryAfterRedis(key); err == nil {
			return d
		}
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	switch rl.strategy {
	case "fixed_window":
		d := rl.window - time.Since(rl.resetTime)
		if d < 0 {
			return 0
		}
		return d
	case "token_bucket":
		b := rl.buckets[key]
		if b == nil {
			return 0
		}
		rate := float64(rl.limit) / rl.window.Seconds()
		need := 1 - b.tokens
		if need <= 0 {
			return 0
		}
		secs := need / rate
		if secs < 0 {
			return 0
		}
		return time.Duration(secs * float64(time.Second))
	case "leaky_bucket":
		l := rl.leaky[key]
		if l == nil {
			return 0
		}
		rate := float64(rl.limit) / rl.window.Seconds()
		level := l.level - now.Sub(l.last).Seconds()*rate
		if level < 0 {
			level = 0
		}
		over := level + 1 - float64(rl.limit)
		if over <= 0 {
			return 0
		}
		secs := over / rate
		if secs < 0 {
			return 0
		}
		return time.Duration(secs * float64(time.Second))
	default:
		return rl.window
	}
}

func (rl *RateLimiter) allowRedis(key string) (bool, error) {
	var conn net.Conn
	if rl.conns != nil {
		select {
		case conn = <-rl.conns:
		default:
		}
	}
	var err error
	var username, password string
	if conn == nil {
		addr := *redisAddr
		useTLS := false
		if strings.Contains(addr, "://") {
			u, err := url.Parse(addr)
			if err != nil {
				return false, err
			}
			if u.Host != "" {
				addr = u.Host
			}
			switch u.Scheme {
			case "rediss":
				useTLS = true
			case "", "redis":
			default:
				return false, fmt.Errorf("unsupported redis scheme %q", u.Scheme)
			}
			if u.User != nil {
				username = u.User.Username()
				password, _ = u.User.Password()
			}
		}
		d := net.Dialer{Timeout: *redisTimeout}
		if useTLS {
			tlsConf := &tls.Config{}
			if *redisCA != "" {
				caData, err := os.ReadFile(*redisCA)
				if err != nil {
					return false, err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(caData) {
					return false, fmt.Errorf("failed to load CA file")
				}
				tlsConf.RootCAs = pool
			} else {
				tlsConf.InsecureSkipVerify = true
			}
			conn, err = tls.DialWithDialer(&d, "tcp", addr, tlsConf)
		} else {
			conn, err = d.Dial("tcp", addr)
		}
		if err != nil {
			return false, err
		}
		if username != "" || password != "" {
			args := []string{"AUTH"}
			if username != "" {
				args = append(args, username, password)
			} else {
				args = append(args, password)
			}
			if err := redisCmd(conn, args...); err != nil {
				conn.Close()
				return false, err
			}
		}
	}
	bad := false
	var allowed bool
	switch rl.strategy {
	case "token_bucket":
		allowed, err = rl.allowRedisTokenBucket(conn, key)
		if err != nil {
			bad = true
		}
	case "leaky_bucket":
		allowed, err = rl.allowRedisLeakyBucket(conn, key)
		if err != nil {
			bad = true
		}
	default:
		var n int
		n, err = redisCmdInt(conn, "INCR", key)
		if err != nil {
			bad = true
		}
		if n == 1 {
			cmd, ttl := redisTTLArgs(rl.window)
			_, err = redisCmdInt(conn, cmd, key, ttl)
			if err != nil {
				bad = true
			}
		}
		allowed = n <= rl.limit
	}
	if rl.conns != nil {
		if bad {
			conn.Close()
		} else {
			select {
			case rl.conns <- conn:
			default:
				conn.Close()
			}
		}
	} else {
		conn.Close()
	}
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func (rl *RateLimiter) allowRedisTokenBucket(conn net.Conn, key string) (bool, error) {
	now := time.Now()
	val, err := redisCmdString(conn, "GET", key)
	if err != nil {
		return false, err
	}
	var tokens float64
	var last int64
	if val != "" {
		parts := strings.Fields(val)
		if len(parts) == 2 {
			tokens, _ = strconv.ParseFloat(parts[0], 64)
			last, _ = strconv.ParseInt(parts[1], 10, 64)
		}
	} else {
		tokens = float64(rl.limit)
		last = now.UnixNano()
	}
	lastTime := time.Unix(0, last)
	refill := now.Sub(lastTime).Seconds() * float64(rl.limit) / rl.window.Seconds()
	if refill > 0 {
		tokens += refill
		if tokens > float64(rl.limit) {
			tokens = float64(rl.limit)
		}
		lastTime = now
	}
	if tokens < 1 {
		val = fmt.Sprintf("%f %d", tokens, lastTime.UnixNano())
		if err := redisCmd(conn, "SET", key, val); err != nil {
			return false, err
		}
		cmd, ttl := redisTTLArgs(rl.window)
		_, err := redisCmdInt(conn, cmd, key, ttl)
		return false, err
	}
	tokens--
	val = fmt.Sprintf("%f %d", tokens, now.UnixNano())
	if err := redisCmd(conn, "SET", key, val); err != nil {
		return false, err
	}
	cmd, ttl := redisTTLArgs(rl.window)
	_, err = redisCmdInt(conn, cmd, key, ttl)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (rl *RateLimiter) allowRedisLeakyBucket(conn net.Conn, key string) (bool, error) {
	now := time.Now()
	val, err := redisCmdString(conn, "GET", key)
	if err != nil {
		return false, err
	}
	var level float64
	var last int64
	if val != "" {
		parts := strings.Fields(val)
		if len(parts) == 2 {
			level, _ = strconv.ParseFloat(parts[0], 64)
			last, _ = strconv.ParseInt(parts[1], 10, 64)
		}
	} else {
		level = 0
		last = now.UnixNano()
	}
	lastTime := time.Unix(0, last)
	leaked := now.Sub(lastTime).Seconds() * float64(rl.limit) / rl.window.Seconds()
	level -= leaked
	if level < 0 {
		level = 0
	}
	if level+1 > float64(rl.limit) {
		val = fmt.Sprintf("%f %d", level, now.UnixNano())
		if err := redisCmd(conn, "SET", key, val); err != nil {
			return false, err
		}
		cmd, ttl := redisTTLArgs(rl.window)
		_, err := redisCmdInt(conn, cmd, key, ttl)
		return false, err
	}
	level++
	val = fmt.Sprintf("%f %d", level, now.UnixNano())
	if err := redisCmd(conn, "SET", key, val); err != nil {
		return false, err
	}
	cmd, ttl := redisTTLArgs(rl.window)
	_, err = redisCmdInt(conn, cmd, key, ttl)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (rl *RateLimiter) retryAfterRedis(key string) (time.Duration, error) {
	var conn net.Conn
	if rl.conns != nil {
		select {
		case conn = <-rl.conns:
		default:
		}
	}
	var err error
	var username, password string
	if conn == nil {
		addr := *redisAddr
		useTLS := false
		if strings.Contains(addr, "://") {
			u, err := url.Parse(addr)
			if err != nil {
				return 0, err
			}
			if u.Host != "" {
				addr = u.Host
			}
			switch u.Scheme {
			case "rediss":
				useTLS = true
			case "", "redis":
			default:
				return 0, fmt.Errorf("unsupported redis scheme %q", u.Scheme)
			}
			if u.User != nil {
				username = u.User.Username()
				password, _ = u.User.Password()
			}
		}
		d := net.Dialer{Timeout: *redisTimeout}
		if useTLS {
			tlsConf := &tls.Config{}
			if *redisCA != "" {
				caData, err := os.ReadFile(*redisCA)
				if err != nil {
					return 0, err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(caData) {
					return 0, fmt.Errorf("failed to load CA file")
				}
				tlsConf.RootCAs = pool
			} else {
				tlsConf.InsecureSkipVerify = true
			}
			conn, err = tls.DialWithDialer(&d, "tcp", addr, tlsConf)
		} else {
			conn, err = d.Dial("tcp", addr)
		}
		if err != nil {
			return 0, err
		}
		if username != "" || password != "" {
			args := []string{"AUTH"}
			if username != "" {
				args = append(args, username, password)
			} else {
				args = append(args, password)
			}
			if err := redisCmd(conn, args...); err != nil {
				conn.Close()
				return 0, err
			}
		}
	}

	ttlMS, err := redisCmdInt(conn, "PTTL", key)
	bad := err != nil
	if rl.conns != nil {
		if bad {
			conn.Close()
		} else {
			select {
			case rl.conns <- conn:
			default:
				conn.Close()
			}
		}
	} else {
		conn.Close()
	}
	if err != nil {
		return 0, err
	}
	if ttlMS < 0 {
		return 0, nil
	}
	return time.Duration(ttlMS) * time.Millisecond, nil
}

func redisCmdInt(conn net.Conn, args ...string) (int, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	br := bufio.NewReader(conn)
	prefix, err := br.ReadByte()
	if err != nil {
		return 0, err
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, err
	}
	switch prefix {
	case ':', '+':
		return strconv.Atoi(strings.TrimSpace(line))
	case '-':
		return 0, fmt.Errorf("redis error: %s", strings.TrimSpace(line))
	default:
		return 0, fmt.Errorf("unexpected reply: %q", prefix)
	}
}

func redisCmdString(conn net.Conn, args ...string) (string, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return "", err
	}
	br := bufio.NewReader(conn)
	prefix, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	switch prefix {
	case '+', ':':
		return strings.TrimSpace(line), nil
	case '$':
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			return "", err
		}
		if n == -1 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	case '-':
		return "", fmt.Errorf("redis error: %s", strings.TrimSpace(line))
	default:
		return "", fmt.Errorf("unexpected reply: %q", prefix)
	}
}

func redisCmd(conn net.Conn, args ...string) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&buf, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	prefix, err := br.ReadByte()
	if err != nil {
		return err
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	switch prefix {
	case '+', ':':
		return nil
	case '-':
		return fmt.Errorf("redis error: %s", strings.TrimSpace(line))
	default:
		return fmt.Errorf("unexpected reply: %q", prefix)
	}
}

type fileWatcher interface {
	Add(string) error
	Close() error
	Events() <-chan fsnotify.Event
	Errors() <-chan error
}

type fswatcher struct{ *fsnotify.Watcher }

func (f fswatcher) Events() <-chan fsnotify.Event { return f.Watcher.Events }
func (f fswatcher) Errors() <-chan error          { return f.Watcher.Errors }

var newWatcher = func() (fileWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return fswatcher{w}, nil
}

func watchFiles(ctx context.Context, files []string, out chan<- struct{}) {
	w, err := newWatcher()
	if err != nil {
		logger.Error("failed to create watcher", "error", err)
		return
	}
	defer w.Close()

	for _, f := range files {
		if err := w.Add(f); err != nil {
			logger.Error("watch add failed", "file", f, "error", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events():
			if !ok {
				return
			}
			if ev.Op&(fsnotify.Rename|fsnotify.Remove) != 0 {
				go func(name string) {
					for i := 0; i < 50; i++ {
						if err := w.Add(name); err == nil {
							return
						} else if !os.IsNotExist(err) {
							logger.Error("watch re-add failed", "file", name, "error", err)
							return
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(10 * time.Millisecond):
						}
					}
				}(ev.Name)
			} else if ev.Op&fsnotify.Create != 0 {
				if err := w.Add(ev.Name); err != nil && !os.IsNotExist(err) {
					logger.Error("watch re-add failed", "file", ev.Name, "error", err)
				}
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				select {
				case out <- struct{}{}:
				default:
				}
			}
		case err, ok := <-w.Errors():
			if !ok {
				return
			}
			logger.Error("watch error", "error", err)
		}
	}
}

// healthzHandler reports server readiness.
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Last-Reload", metrics.LastReloadTime.Value())
	w.WriteHeader(http.StatusOK)
}

// metricsHandler exposes Prometheus metrics with optional basic auth.
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics.Handler(w, r, *metricsUser, *metricsPass)
}

// proxyHandler handles incoming requests and proxies them according to the integration.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !*disableXATInt {
		hdr := r.Header.Get("X-AT-Int")
		if hdr != "" && (*xAtIntHost == "" || strings.EqualFold(r.Host, *xAtIntHost)) {
			host = hdr
		}
	}
	hostLookup := strings.ToLower(host)
	integ, ok := GetIntegration(hostLookup)
	if !ok {
		logger.Warn("no integration configured", "host", host)
		metrics.IncRequest("unknown")
		w.Header().Set("X-AT-Upstream-Error", "false")
		w.Header().Set("X-AT-Error-Reason", "integration not found")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, fmt.Sprintf("integration for host %s not found", host), http.StatusNotFound)
		return
	}

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	rateKey := clientIP
	callerID := "*"
	for _, cfg := range integ.IncomingAuth {
		p := authplugins.GetIncoming(cfg.Type)
		if p != nil {
			if !p.Authenticate(r.Context(), r, cfg.parsed) {
				logger.Warn("authentication failed", "host", host, "remote", r.RemoteAddr)
				metrics.IncAuthFailure(integ.Name)
				w.Header().Set("X-AT-Upstream-Error", "false")
				w.Header().Set("X-AT-Error-Reason", "authentication failed")
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				http.Error(w, fmt.Sprintf("Unauthorized: authentication failed for integration %s", integ.Name), http.StatusUnauthorized)
				return
			}
			if idp, ok := p.(authplugins.Identifier); ok {
				if id, ok := idp.Identify(r, cfg.parsed); ok {
					callerID = id
					rateKey = id
				}
			}
			if stripper, ok := p.(authplugins.AuthStripper); ok {
				stripper.StripAuth(r, cfg.parsed)
			}
		}
	}

	logger.Info("incoming request", "method", r.Method, "integration", integ.Name, "path", r.URL.Path, "caller_id", callerID)

	r = r.WithContext(metrics.WithCaller(r.Context(), callerID))

	if !integ.inLimiter.Allow(rateKey) {
		logger.Warn("caller exceeded rate limit", "caller", rateKey, "host", host)
		metrics.IncRateLimit(integ.Name)
		if d := integ.inLimiter.RetryAfter(rateKey); d > 0 {
			secs := int(math.Ceil(d.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		w.Header().Set("X-AT-Upstream-Error", "false")
		w.Header().Set("X-AT-Error-Reason", "caller rate limited")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, fmt.Sprintf("Too Many Requests: caller %s exceeded rate limit", rateKey), http.StatusTooManyRequests)
		return
	}
	if !integ.outLimiter.Allow(host) {
		logger.Warn("host exceeded rate limit", "host", host)
		metrics.IncRateLimit(integ.Name)
		if d := integ.outLimiter.RetryAfter(host); d > 0 {
			secs := int(math.Ceil(d.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		w.Header().Set("X-AT-Upstream-Error", "false")
		w.Header().Set("X-AT-Error-Reason", "integration rate limited")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, fmt.Sprintf("Too Many Requests: host %s exceeded rate limit", host), http.StatusTooManyRequests)
		return
	}

	callers := GetAllowlist(integ.Name)
	if len(callers) > 0 {
		cons, ok := findConstraint(integ, callerID, r.URL.Path, r.Method)
		if !ok {
			reason := "no allowlist match"
			logger.Warn("request blocked", "integration", integ.Name, "caller_id", callerID, "reason", reason)
			w.Header().Set("X-AT-Error-Reason", reason)
			w.Header().Set("X-AT-Upstream-Error", "false")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.Error(w, fmt.Sprintf("Forbidden: %s", reason), http.StatusForbidden)
			return
		}
		if ok2, reason := validateRequestReason(r, cons); !ok2 {
			logger.Warn("request failed constraints", "integration", integ.Name, "caller_id", callerID, "reason", reason)
			w.Header().Set("X-AT-Error-Reason", reason)
			w.Header().Set("X-AT-Upstream-Error", "false")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.Error(w, fmt.Sprintf("Forbidden: %s", reason), http.StatusForbidden)
			return
		}
	}

	for _, cfg := range integ.OutgoingAuth {
		p := authplugins.GetOutgoing(cfg.Type)
		if p != nil {
			p.AddAuth(r.Context(), r, cfg.parsed)
		}
	}

	if integ.proxy == nil {
		w.Header().Set("X-AT-Upstream-Error", "false")
		w.Header().Set("X-AT-Error-Reason", "no proxy configured")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, fmt.Sprintf("Bad Gateway: no proxy configured for integration %s", integ.Name), http.StatusBadGateway)
		return
	}

	metrics.OnRequest(integ.Name, r)
	rec := &statusRecorder{ResponseWriter: w}
	integ.proxy.ServeHTTP(rec, r)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	logger.Info("upstream response", "host", host, "status", rec.status)
}

type server interface {
	ListenAndServe() error
	ListenAndServeTLS(certFile, keyFile string) error
}

func serve(s server, cert, key string) error {
	switch {
	case cert != "" && key != "":
		return s.ListenAndServeTLS(cert, key)
	case cert == "" && key == "":
		return s.ListenAndServe()
	default:
		return fmt.Errorf("both cert and key must be provided")
	}
}

func newHTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:         addr,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
	}
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if (*metricsUser != "" && *metricsPass == "") || (*metricsUser == "" && *metricsPass != "") {
		log.Fatal("both -metrics-user and -metrics-pass must be provided")
	}

	authplugins.MaxBodySize = *maxBodySizeFlag
	secrets.CacheTTL = *secretRefresh

	if *showVersion {
		fmt.Println(version)
		return
	}

	var handler slog.Handler
	if strings.ToLower(*logFormat) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(*logLevel)})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(*logLevel)})
	}
	logger = slog.New(handler)

	if err := reload(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/_at_internal/healthz", healthzHandler)
	if *enableMetrics {
		http.HandleFunc("/_at_internal/metrics", metricsHandler)
	}

	http.HandleFunc("/", proxyHandler)

	srv := newHTTPServer(*addr)
	var h3srv *http3.Server

	go func() {
		if err := serve(srv, *tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	if *enableHTTP3 && *tlsCert != "" && *tlsKey != "" {
		h3srv = &http3.Server{Addr: *addr, Handler: http.DefaultServeMux}
		go func() {
			if err := h3srv.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
				log.Fatalf("listen http3: %v", err)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	reloadSig := make(chan os.Signal, 1)
	watchSig := make(chan struct{}, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	signal.Notify(reloadSig, syscall.SIGHUP)

	var cancelWatch context.CancelFunc
	if *watch {
		files := make([]string, 0, 2)
		if *configURL == "" && !isRemote(*configFile) {
			files = append(files, *configFile)
		}
		if *allowlistURL == "" && !isRemote(*allowlistFile) {
			files = append(files, *allowlistFile)
		}
		if len(files) > 0 {
			var watchCtx context.Context
			watchCtx, cancelWatch = context.WithCancel(context.Background())
			go watchFiles(watchCtx, files, watchSig)
		}
	}

	for {
		select {
		case <-reloadSig:
			if err := reload(); err != nil {
				logger.Error("reload failed", "error", err)
			} else {
				logger.Info("reloaded configuration")
			}
		case <-watchSig:
			if err := reload(); err != nil {
				logger.Error("reload failed", "error", err)
			} else {
				logger.Info("reloaded configuration")
			}
		case <-stop:
			goto shutdown
		}
	}

shutdown:

	if cancelWatch != nil {
		cancelWatch()
	}

	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown", "error", err)
	}
	if h3srv != nil {
		if err := h3srv.Close(); err != nil {
			logger.Error("http3 shutdown", "error", err)
		}
	}

	for _, i := range ListIntegrations() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	}
}
