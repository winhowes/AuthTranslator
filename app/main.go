package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
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

	"github.com/winhowes/AuthTranslator/app/authplugins"
	_ "github.com/winhowes/AuthTranslator/app/authplugins/plugins"
	_ "github.com/winhowes/AuthTranslator/app/integrationplugins/plugins"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

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

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

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
var allowlistFile = flag.String("allowlist", "allowlist.json", "path to allowlist configuration")
var configFile = flag.String("config", "config.json", "path to configuration file")
var tlsCert = flag.String("tls-cert", "", "path to TLS certificate")
var tlsKey = flag.String("tls-key", "", "path to TLS key")
var logLevel = flag.String("log-level", "INFO", "log level: DEBUG, INFO, WARN, ERROR")
var redisAddr = flag.String("redis-addr", "", "redis address for rate limits (host:port)")
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

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()

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

	for i := range cfg.Integrations {
		if err := AddIntegration(&cfg.Integrations[i]); err != nil {
			return fmt.Errorf("failed to load integration %s: %w", cfg.Integrations[i].Name, err)
		}
	}

	entries, err := loadAllowlists(*allowlistFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load allowlist: %w", err)
	}

	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	seenAllow := make(map[string]struct{})
	for _, al := range entries {
		if _, dup := seenAllow[al.Integration]; dup {
			return fmt.Errorf("duplicate allowlist entry for %s", al.Integration)
		}
		seenAllow[al.Integration] = struct{}{}
		if err := SetAllowlist(al.Integration, al.Callers); err != nil {
			return fmt.Errorf("failed to load allowlist for %s: %w", al.Integration, err)
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
}

func NewRateLimiter(limit int, duration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:    limit,
		window:   duration,
		done:     make(chan struct{}),
		useRedis: *redisAddr != "",
		requests: make(map[string]int),
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
	conn, err := net.Dial("tcp", *redisAddr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	n, err := redisCmdInt(conn, "INCR", key)
	if err != nil {
		return false, err
	}
	if n == 1 {
		_, err = redisCmdInt(conn, "EXPIRE", key, strconv.Itoa(int(rl.window.Seconds())))
		if err != nil {
			return false, err
		}
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
			if !p.Authenticate(r, cfg.parsed) {
				logger.Warn("authentication failed", "host", host, "remote", r.RemoteAddr)
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
			p.AddAuth(r, cfg.parsed)
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

	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))

	if err := reload(); err != nil {
		log.Fatal(err)
	}

	if *debug {
		http.HandleFunc("/integrations", integrationsHandler)
	}

	http.HandleFunc("/healthz", healthzHandler)
	http.HandleFunc("/metrics", metricsHandler)

	http.HandleFunc("/", proxyHandler)

	srv := &http.Server{Addr: *addr}

	go func() {
		if err := serve(srv, *tlsCert, *tlsKey); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	reloadSig := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	signal.Notify(reloadSig, syscall.SIGHUP)

	for {
		select {
		case <-reloadSig:
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
