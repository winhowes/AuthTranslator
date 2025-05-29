package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	yaml "gopkg.in/yaml.v3"
	"log"
	"log/slog"
	"net"
	"net/http"
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

var debug = flag.Bool("debug", false, "enable debug mode")
var disableXATInt = flag.Bool("disable_x_at_int", false, "ignore X-AT-Int header for routing")
var xAtIntHost = flag.String("x_at_int_host", "", "only respect X-AT-Int header when request Host matches this value")
var addr = flag.String("addr", ":8080", "listen address")
var allowlistFile = flag.String("allowlist", "allowlist.yaml", "path to allowlist configuration")
var configFile = flag.String("config", "config.yaml", "path to configuration file")
var tlsCert = flag.String("tls-cert", "", "path to TLS certificate")
var tlsKey = flag.String("tls-key", "", "path to TLS key")
var logLevel = flag.String("log-level", "INFO", "log level: DEBUG, INFO, WARN, ERROR")
var logFormat = flag.String("log-format", "text", "log output format: text or json")
var redisAddr = flag.String("redis-addr", "", "redis address for rate limits (host:port)")
var redisTimeout = flag.Duration("redis-timeout", 5*time.Second, "dial timeout for redis")
var maxBodySizeFlag = flag.Int64("max_body_size", authplugins.MaxBodySize, "maximum bytes buffered from request bodies (0 to disable)")
var showVersion = flag.Bool("version", false, "print version and exit")
var watch = flag.Bool("watch", false, "watch config and allowlist files for changes")
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

	// Clear existing integrations and stop their limiters.
	integrations.Lock()
	for _, i := range integrations.m {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	}
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()

	// Clear secret cache so reloaded integrations use fresh values.
	secrets.ClearCache()

	for i := range cfg.Integrations {
		if err := AddIntegration(&cfg.Integrations[i]); err != nil {
			return fmt.Errorf("failed to load integration %s: %w", cfg.Integrations[i].Name, err)
		}
	}

	entries, err := loadAllowlists(*allowlistFile)
	old := allowlists.m
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
	if conn == nil {
		conn, err = net.DialTimeout("tcp", *redisAddr, *redisTimeout)
		if err != nil {
			return false, err
		}
	}
	bad := false

	n, err := redisCmdInt(conn, "INCR", key)
	if err != nil {
		bad = true
	}
	if n == 1 {
		_, err = redisCmdInt(conn, "EXPIRE", key, strconv.Itoa(int(rl.window.Seconds())))
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
					for i := 0; i < 5; i++ {
						if err := w.Add(name); err == nil {
							return
						} else if !os.IsNotExist(err) {
							logger.Error("watch re-add failed", "file", name, "error", err)
							return
						}
						time.Sleep(100 * time.Millisecond)
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

// integrationsHandler manages creation and listing of integrations.
func integrationsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var i Integration
		if err := json.NewDecoder(r.Body).Decode(&i); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := AddIntegration(&i); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	case http.MethodPut:
		var i Integration
		if err := json.NewDecoder(r.Body).Decode(&i); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := UpdateIntegration(&i); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		DeleteIntegration(req.Name)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		list := ListIntegrations()
		json.NewEncoder(w).Encode(list)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
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
	logger.Info("incoming request", "method", r.Method, "host", host, "path", r.URL.Path, "remote", r.RemoteAddr)
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

	authplugins.MaxBodySize = *maxBodySizeFlag

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

	if *debug {
		http.HandleFunc("/integrations", integrationsHandler)
	}

	http.HandleFunc("/_at_internal/healthz", healthzHandler)
	http.HandleFunc("/_at_internal/metrics", metricsHandler)

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
