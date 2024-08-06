package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

type Config struct {
	AuthPlugins map[string]AuthPlugin `json:"auth_plugins"`
	Routes      map[string]Route      `json:"routes"`
}

type AuthPlugin struct {
	Type  string `json:"type"`
	Owner string `json:"owner"`
}

type Route struct {
	Target    string          `json:"target"`
	RateLimit RateLimitConfig `json:"rate_limit"`
}

type RateLimitConfig struct {
	PerCaller int `json:"per_caller"`
	PerHost   int `json:"per_host"`
}

func loadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	return &config, err
}

type Authenticator interface {
	Authenticate(r *http.Request) bool
	AddAuth(r *http.Request)
}

type BasicAuth struct{}

func (a *BasicAuth) Authenticate(r *http.Request) bool {
	// Basic auth logic
	return true
}

func (a *BasicAuth) AddAuth(r *http.Request) {
	// Add basic auth headers
}

type TokenAuth struct{}

func (a *TokenAuth) Authenticate(r *http.Request) bool {
	// Token auth logic
	return true
}

func (a *TokenAuth) AddAuth(r *http.Request) {
	// Add token auth headers
}

func getAuthenticator(pluginType string) Authenticator {
	switch pluginType {
	case "basic":
		return &BasicAuth{}
	case "token":
		return &TokenAuth{}
	default:
		return nil
	}
}

type RateLimiter struct {
	mu          sync.Mutex
	limit       int
	duration    time.Duration
	requests    map[string]int
	resetTicker *time.Ticker
}

func NewRateLimiter(limit int, duration time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limit:       limit,
		duration:    duration,
		requests:    make(map[string]int),
		resetTicker: time.NewTicker(duration),
	}

	go func() {
		for range rl.resetTicker.C {
			rl.mu.Lock()
			rl.requests = make(map[string]int)
			rl.mu.Unlock()
		}
	}()

	return rl
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

func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		route, exists := config.Routes[host]
		if !exists {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		// Authentication
		authPlugin, exists := config.AuthPlugins[host]
		if exists {
			auth := getAuthenticator(authPlugin.Type)
			if !auth.Authenticate(r) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			auth.AddAuth(r)
		}

		// Rate limiting
		caller := r.RemoteAddr
		rlCaller := NewRateLimiter(route.RateLimit.PerCaller, time.Minute)
		rlHost := NewRateLimiter(route.RateLimit.PerHost, time.Minute)

		if !rlCaller.Allow(caller) || !rlHost.Allow(host) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Forward the request
		target, err := url.Parse(route.Target)
		if err != nil {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
