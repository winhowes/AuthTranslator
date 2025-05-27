package main

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"authtransformer/app/authplugins"
)

// AuthPluginConfig ties an auth plugin type to its parameters.
// AuthPluginConfig ties an auth plugin type to its parameters. The Params field
// holds the raw configuration from the JSON config while parsed is used at
// runtime after being validated by the plugin's ParseParams function.
type AuthPluginConfig struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`

	parsed interface{}
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

	for idx, a := range i.IncomingAuth {
		p := authplugins.GetIncoming(a.Type)
		if p == nil {
			return fmt.Errorf("unknown incoming auth type %s", a.Type)
		}
		cfg, err := p.ParseParams(a.Params)
		if err != nil {
			return fmt.Errorf("invalid params for auth %s: %v", a.Type, err)
		}
		i.IncomingAuth[idx].parsed = cfg
	}

	for idx, a := range i.OutgoingAuth {
		p := authplugins.GetOutgoing(a.Type)
		if p == nil {
			return fmt.Errorf("unknown outgoing auth type %s", a.Type)
		}
		cfg, err := p.ParseParams(a.Params)
		if err != nil {
			return fmt.Errorf("invalid params for auth %s: %v", a.Type, err)
		}
		i.OutgoingAuth[idx].parsed = cfg
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
