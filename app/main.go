package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	_ "github.com/winhowes/AuthTransformer/app/authplugins/incoming"
	_ "github.com/winhowes/AuthTransformer/app/authplugins/outgoing"
	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
)

type Config struct {
	Integrations []Integration `json:"integrations"`
}

var debug = flag.Bool("debug", false, "enable debug mode")
var addr = flag.String("addr", ":8080", "listen address")

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

	return &config, nil
}

type RateLimiter struct {
	mu          sync.Mutex
	limit       int
	duration    time.Duration
	requests    map[string]int
	resetTicker *time.Ticker
	done        chan struct{}
}

func NewRateLimiter(limit int, duration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:       limit,
		duration:    duration,
		requests:    make(map[string]int),
		resetTicker: time.NewTicker(duration),
		done:        make(chan struct{}),
	}

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

	return rl
}

// Stop stops the rate limiter's reset goroutine and ticker.
func (rl *RateLimiter) Stop() {
	rl.resetTicker.Stop()
	close(rl.done)
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.requests[key] >= rl.limit {
		return false
	}

	rl.requests[key]++
	return true
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
	case http.MethodGet:
		list := ListIntegrations()
		json.NewEncoder(w).Encode(list)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// proxyHandler handles incoming requests and proxies them according to the integration.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-AT-Int")
	if host == "" {
		host = r.Host
	}
	log.Printf("Incoming %s request for %s%s from %s", r.Method, host, r.URL.Path, r.RemoteAddr)
	integ, ok := GetIntegration(host)
	if !ok {
		log.Printf("No integration configured for host %s", host)
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	for _, cfg := range integ.IncomingAuth {
		p := authplugins.GetIncoming(cfg.Type)
		if p != nil && !p.Authenticate(r, cfg.parsed) {
			log.Printf("Authentication failed for host %s from %s", host, r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	caller := r.RemoteAddr
	if !integ.inLimiter.Allow(caller) {
		log.Printf("Caller %s exceeded rate limit on host %s", caller, host)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}
	if !integ.outLimiter.Allow(host) {
		log.Printf("Host %s exceeded rate limit", host)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	for _, cfg := range integ.OutgoingAuth {
		p := authplugins.GetOutgoing(cfg.Type)
		if p != nil {
			p.AddAuth(r, cfg.parsed)
		}
	}

	target, err := url.Parse(integ.Destination)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(w, r)
}

func main() {
	flag.Parse()

	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatal(err)
	}

	for i := range config.Integrations {
		if err := AddIntegration(&config.Integrations[i]); err != nil {
			log.Fatalf("failed to load integration %s: %v", config.Integrations[i].Name, err)
		}
	}

	// Include timestamps in log output
	log.SetFlags(log.LstdFlags)

	if *debug {
		http.HandleFunc("/integrations", integrationsHandler)
	}

	http.HandleFunc("/", proxyHandler)

	srv := &http.Server{Addr: *addr}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server shutdown: %v", err)
	}

	for _, i := range ListIntegrations() {
		i.inLimiter.Stop()
		i.outLimiter.Stop()
	}
}
