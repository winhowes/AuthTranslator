package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"log"
	"log/slog"
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

	"github.com/fsnotify/fsnotify"

	"github.com/winhowes/AuthTranslator/app/auth"
	_ "github.com/winhowes/AuthTranslator/app/auth/plugins"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins"
	"github.com/winhowes/AuthTranslator/app/metrics"
	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

// version is the application version. It can be overridden at build time using
// the -ldflags "-X main.version=<version>" option.
var version = "dev"

type AllowlistEntry struct {
	Integration string         `json:"integration"`
	Callers     []CallerConfig `json:"callers"`
}

type Config struct {
	Integrations []Integration `json:"integrations"`
}

func loadAllowlists(filename string) ([]AllowlistEntry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var entries []AllowlistEntry
	if err := dec.Decode(&entries); err != nil {
		return nil, err
	}

	return entries, nil
}

var disableXATInt = flag.Bool("disable_x_at_int", false, "ignore X-AT-Int header for routing")
var xAtIntHost = flag.String("x_at_int_host", "", "only respect X-AT-Int header when request Host matches this value")
var addr = flag.String("addr", ":8080", "listen address")
var allowlistFile = flag.String("allowlist", "allowlist.yaml", "path to allowlist configuration")
var configFile = flag.String("config", "config.yaml", "path to configuration file")
var tlsCert = flag.String("tls-cert", "", "path to TLS certificate")
var tlsKey = flag.String("tls-key", "", "path to TLS key")
var logLevel = flag.String("log-level", "INFO", "log level: DEBUG, INFO, WARN, ERROR")
var logFormat = flag.String("log-format", "text", "log output format: text or json")
var redisAddr = flag.String("redis-addr", "", "redis address for rate limits (host:port or redis:// URL)")
var redisTimeout = flag.Duration("redis-timeout", 5*time.Second, "dial timeout for redis")
var redisCA = flag.String("redis-ca", "", "path to CA certificate for Redis TLS; disables InsecureSkipVerify")
var maxBodySizeFlag = flag.Int64("max_body_size", authplugins.MaxBodySize, "maximum bytes buffered from request bodies (0 to disable)")
var secretRefresh = flag.Duration("secret-refresh", 0, "refresh interval for cached secrets (0 disables)")
var showVersion = flag.Bool("version", false, "print version and exit")
var watch = flag.Bool("watch", false, "watch config and allowlist files for changes")
var metricsUser = flag.String("metrics-user", "", "username for metrics endpoint")
var metricsPass = flag.String("metrics-pass", "", "password for metrics endpoint")
var enableMetrics = flag.Bool("enable-metrics", true, "expose /metrics endpoint")
var logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: authtranslator [options]\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
}

func loadConfig(filename string) (*Config, error) {
	f, err := os.Open(filename)
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

	cfg, err := loadConfig(*configFile)
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
		integ.inLimiter = NewRateLimiter(integ.InRateLimit, window)
		integ.outLimiter = NewRateLimiter(integ.OutRateLimit, window)
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

	entries, err := loadAllowlists(*allowlistFile)
	allowlists.RLock()
	old := allowlists.m
	allowlists.RUnlock()
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("allowlist file missing; keeping existing entries", "file", *allowlistFile)
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
			if err := SetAllowlist(al.Integration, al.Callers); err != nil {
				allowlists.Lock()
				allowlists.m = old
				allowlists.Unlock()
				return fmt.Errorf("failed to load allowlist for %s: %w", al.Integration, err)
			}
		}
	}

	lastReloadTime.Set(time.Now().Format(time.RFC3339))

	return nil
}

type RateLimiter struct {
	mu          sync.Mutex
	limit       int
	window      time.Duration
	requests    map[string]int
	resetTicker *time.Ticker
	done        chan struct{}
	useRedis    bool
	conns       chan net.Conn
}

// NewRateLimiter creates a RateLimiter that limits how many
// requests a caller may make in a given window. The limit parameter
// sets the maximum number of allowed requests; a limit of zero or less
// disables rate limiting. Duration specifies the length of the window
// and how often counters reset. If a redis address is configured,
// counts are stored in Redis so limits are shared across instances.
func NewRateLimiter(limit int, duration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:    limit,
		window:   duration,
		done:     make(chan struct{}),
		useRedis: *redisAddr != "",
		requests: make(map[string]int),
	}

	if rl.useRedis {
		rl.conns = make(chan net.Conn, 4)
	}

	if limit > 0 {
		rl.resetTicker = time.NewTicker(duration)

		go func() {
			for {
				select {
				case <-rl.resetTicker.C:
					rl.mu.Lock()
					rl.requests = make(map[string]int)
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
		if err != nil {
			logger.Error("redis limiter failed, falling back to memory", "error", err)
		} else {
			return ok
		}
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.requests[key] >= rl.limit {
		return false
	}

	rl.requests[key]++
	return true
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

	n, err := redisCmdInt(conn, "INCR", key)
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
	return n <= rl.limit, nil
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

func watchFiles(ctx context.Context, files []string, out chan<- struct{}) {
	w, err := fsnotify.NewWatcher()
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
		case ev, ok := <-w.Events:
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
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			logger.Error("watch error", "error", err)
		}
	}
}

// healthzHandler reports server readiness.
func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Last-Reload", lastReloadTime.Value())
	w.WriteHeader(http.StatusOK)
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
		incRequest("unknown")
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	defer incRequest(integ.Name)
	start := time.Now()
	defer func() {
		recordDuration(integ.Name, time.Since(start))
	}()

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
				incAuthFailure(integ.Name)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if idp, ok := p.(authplugins.Identifier); ok {
				if id, ok := idp.Identify(r, cfg.parsed); ok {
					callerID = id
					rateKey = id
				}
			}
		}
	}

	logger.Info("incoming request", "method", r.Method, "integration", integ.Name, "path", r.URL.Path, "caller_id", callerID)

	r = r.WithContext(metrics.WithCaller(r.Context(), callerID))

	if !integ.inLimiter.Allow(rateKey) {
		logger.Warn("caller exceeded rate limit", "caller", rateKey, "host", host)
		incRateLimit(integ.Name)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	if !integ.outLimiter.Allow(host) {
		logger.Warn("host exceeded rate limit", "host", host)
		incRateLimit(integ.Name)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	callers := GetAllowlist(integ.Name)
	if len(callers) > 0 {
		cons, ok := findConstraint(integ, callerID, r.URL.Path, r.Method)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !validateRequest(r, cons) {
			http.Error(w, "Forbidden", http.StatusForbidden)
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
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	metrics.OnRequest(integ.Name, r)
	rec := &statusRecorder{ResponseWriter: w}
	integ.proxy.ServeHTTP(rec, r)
	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	recordStatus(integ.Name, rec.status)
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

	srv := &http.Server{Addr: *addr}

	go func() {
		if err := serve(srv, *tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	reloadSig := make(chan os.Signal, 1)
	watchSig := make(chan struct{}, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	signal.Notify(reloadSig, syscall.SIGHUP)

	var cancelWatch context.CancelFunc
	if *watch {
		var watchCtx context.Context
		watchCtx, cancelWatch = context.WithCancel(context.Background())
		go watchFiles(watchCtx, []string{*configFile, *allowlistFile}, watchSig)
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

	for _, i := range ListIntegrations() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	}
}
