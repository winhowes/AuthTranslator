package main

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
)

// AuthPluginConfig ties an auth plugin type to its parameters.
type AuthPluginConfig struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}

// Integration represents a configured proxy integration.
type Integration struct {
	Name         string             `json:"name"`
	Destination  string             `json:"destination"`
	InRateLimit  int                `json:"in_rate_limit"`
	OutRateLimit int                `json:"out_rate_limit"`
	IncomingAuth []AuthPluginConfig `json:"incoming_auth"`
	OutgoingAuth []AuthPluginConfig `json:"outgoing_auth"`

	inLimiter  *RateLimiter
	outLimiter *RateLimiter
}

var integrations = struct {
	sync.RWMutex
	m map[string]*Integration
}{m: make(map[string]*Integration)}

var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// AddIntegration validates and stores a new integration.
func AddIntegration(i *Integration) error {
	if !nameRegexp.MatchString(i.Name) {
		return errors.New("invalid integration name")
	}

	for _, a := range i.IncomingAuth {
		p := authplugins.GetIncoming(a.Type)
		if p == nil {
			return fmt.Errorf("unknown incoming auth type %s", a.Type)
		}
		known := map[string]struct{}{}
		for _, req := range p.RequiredParams() {
			if _, ok := a.Params[req]; !ok {
				return fmt.Errorf("missing param %s for auth %s", req, a.Type)
			}
			known[req] = struct{}{}
		}
		for _, opt := range p.OptionalParams() {
			known[opt] = struct{}{}
		}
		for k := range a.Params {
			if _, ok := known[k]; !ok {
				return fmt.Errorf("unknown param %s for auth %s", k, a.Type)
			}
		}
	}

	for _, a := range i.OutgoingAuth {
		p := authplugins.GetOutgoing(a.Type)
		if p == nil {
			return fmt.Errorf("unknown outgoing auth type %s", a.Type)
		}
		known := map[string]struct{}{}
		for _, req := range p.RequiredParams() {
			if _, ok := a.Params[req]; !ok {
				return fmt.Errorf("missing param %s for auth %s", req, a.Type)
			}
			known[req] = struct{}{}
		}
		for _, opt := range p.OptionalParams() {
			known[opt] = struct{}{}
		}
		for k := range a.Params {
			if _, ok := known[k]; !ok {
				return fmt.Errorf("unknown param %s for auth %s", k, a.Type)
			}
		}
	}

	i.inLimiter = NewRateLimiter(i.InRateLimit, time.Minute)
	i.outLimiter = NewRateLimiter(i.OutRateLimit, time.Minute)

	integrations.Lock()
	integrations.m[i.Name] = i
	integrations.Unlock()
	return nil
}

// GetIntegration retrieves an integration by name.
func GetIntegration(name string) (*Integration, bool) {
	integrations.RLock()
	i, ok := integrations.m[name]
	integrations.RUnlock()
	return i, ok
}

// ListIntegrations returns all current integrations.
func ListIntegrations() []*Integration {
	integrations.RLock()
	defer integrations.RUnlock()
	res := make([]*Integration, 0, len(integrations.m))
	for _, i := range integrations.m {
		res = append(res, i)
	}
	return res
}
