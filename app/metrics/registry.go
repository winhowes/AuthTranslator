package metrics

import (
	"net/http"
	"sync"
)

// Plugin can record custom metrics for each request and response.
type Plugin interface {
	OnRequest(integration string, r *http.Request)
	OnResponse(integration, caller string, r *http.Request, resp *http.Response)
}

var (
	mu      sync.RWMutex
	plugins []Plugin
)

// Reset removes all registered plugins. Primarily used in tests.
func Reset() {
	mu.Lock()
	plugins = nil
	mu.Unlock()
}

// Register adds a metrics plugin.
func Register(p Plugin) {
	mu.Lock()
	plugins = append(plugins, p)
	mu.Unlock()
}

// OnRequest triggers all registered plugins for a new request.
func OnRequest(integration string, r *http.Request) {
	mu.RLock()
	ps := append([]Plugin(nil), plugins...)
	mu.RUnlock()
	for _, p := range ps {
		p.OnRequest(integration, r)
	}
}

// OnResponse triggers all registered plugins for a completed response.
func OnResponse(integration, caller string, r *http.Request, resp *http.Response) {
	mu.RLock()
	ps := append([]Plugin(nil), plugins...)
	mu.RUnlock()
	for _, p := range ps {
		p.OnResponse(integration, caller, r, resp)
	}
}
