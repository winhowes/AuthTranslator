package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/winhowes/AuthTranslator/app/auth"
	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	"github.com/winhowes/AuthTranslator/app/secrets"
)

// paramRules is the interface every auth-plugin already satisfies.
type paramRules interface {
	RequiredParams() []string
	OptionalParams() []string
}

// validateRequired checks that all fields named in rules.RequiredParams()
// are non-zero in v.  It assumes v has already been produced by the plugin’s
// ParseParams, which should take care of “unknown field” errors by calling
// json.Decoder.DisallowUnknownFields internally.
func validateRequired(v interface{}, rules paramRules) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("validateRequired: expected struct, got %T", v)
	}

	// Build map jsonTag → fieldValue for zero-check lookup.
	fields := make(map[string]reflect.Value)
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)

		// Determine the JSON key name for the field. Tags may omit the
		// name like `json:",omitempty"` which means use the field name.
		jsonTag := sf.Tag.Get("json")
		name := sf.Name
		if jsonTag != "" {
			if jsonTag == "-" {
				continue
			}
			if comma := strings.Index(jsonTag, ","); comma >= 0 {
				if comma > 0 {
					name = jsonTag[:comma]
				}
				// comma == 0 means default field name
			} else {
				name = jsonTag
			}
		}

		fields[name] = rv.Field(i)
	}

	// All required params must be present and non-zero.
	for _, req := range rules.RequiredParams() {
		fv, ok := fields[req]
		if !ok {
			return fmt.Errorf("required param %q not found in struct", req)
		}
		if fv.IsZero() {
			return fmt.Errorf("missing param %q", req)
		}
	}

	return nil
}

// collectSecretRefs returns any fields named "secrets" (case-insensitive) that
// are slices of strings. It assumes cfg is a struct or pointer to struct.
func collectSecretRefs(cfg interface{}) []string {
	rv := reflect.ValueOf(cfg)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}
	rt := rv.Type()
	var refs []string
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		name := sf.Tag.Get("json")
		if comma := strings.Index(name, ","); comma >= 0 {
			name = name[:comma]
		}
		if name == "" {
			name = sf.Name
		}
		if strings.EqualFold(name, "secrets") && sf.Type.Kind() == reflect.Slice && sf.Type.Elem().Kind() == reflect.String {
			slice := rv.Field(i)
			for j := 0; j < slice.Len(); j++ {
				refs = append(refs, slice.Index(j).String())
			}
		}
	}
	return refs
}

// AuthPluginConfig ties an auth plugin type to its parameters. The Params field
// holds the raw configuration from the YAML config while parsed is used at
// runtime after being validated by the plugin's ParseParams function.
type AuthPluginConfig struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`

	parsed interface{}
}

// CallerConfig defines allowed paths and methods for a specific caller
// identifier.
type CallerConfig = integrationplugins.CallerConfig
type CallRule = integrationplugins.CallRule
type RequestConstraint = integrationplugins.RequestConstraint

// Integration represents a configured proxy integration.
type Integration struct {
	Name              string             `json:"name"`
	Destination       string             `json:"destination"`
	InRateLimit       int                `json:"in_rate_limit"`
	OutRateLimit      int                `json:"out_rate_limit"`
	IncomingAuth      []AuthPluginConfig `json:"incoming_auth"`
	OutgoingAuth      []AuthPluginConfig `json:"outgoing_auth"`
	RateLimitWindow   string             `json:"rate_limit_window"`
	RateLimitStrategy string             `json:"rate_limit_strategy,omitempty"`

	rateLimitDur time.Duration `json:"-"`

	IdleConnTimeout       string `json:"idle_conn_timeout,omitempty"`
	TLSHandshakeTimeout   string `json:"tls_handshake_timeout,omitempty"`
	ResponseHeaderTimeout string `json:"response_header_timeout,omitempty"`
	TLSInsecureSkipVerify bool   `json:"tls_insecure_skip_verify,omitempty"`
	DisableKeepAlives     bool   `json:"disable_keep_alives,omitempty"`
	MaxIdleConns          int    `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost   int    `json:"max_idle_conns_per_host,omitempty"`

	inLimiter  *RateLimiter
	outLimiter *RateLimiter

	destinationURL *url.URL               `json:"-"`
	proxy          *httputil.ReverseProxy `json:"-"`
}

var integrations = struct {
	sync.RWMutex
	m map[string]*Integration
}{m: make(map[string]*Integration)}

var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// prepareIntegration validates the config and populates parsed fields
// without storing it in the global map.
func prepareIntegration(i *Integration) error {
	i.Name = strings.ToLower(i.Name)
	if !nameRegexp.MatchString(i.Name) {
		return errors.New("invalid integration name")
	}

	u, err := url.Parse(i.Destination)
	if err != nil {
		return fmt.Errorf("invalid destination URL: %w", err)
	}
	i.destinationURL = u
	i.proxy = httputil.NewSingleHostReverseProxy(u)

	if i.RateLimitWindow != "" {
		d, err := time.ParseDuration(i.RateLimitWindow)
		if err != nil {
			return fmt.Errorf("invalid rate_limit_window: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("rate_limit_window must be > 0")
		}
		i.rateLimitDur = d
	} else {
		i.rateLimitDur = 0
	}

	if i.RateLimitStrategy == "" {
		i.RateLimitStrategy = "fixed_window"
	}
	switch i.RateLimitStrategy {
	case "fixed_window", "token_bucket":
	default:
		return fmt.Errorf("invalid rate_limit_strategy %s", i.RateLimitStrategy)
	}

	// ─── Validate incoming-auth configs ───────────────────────────────────────
	for idx, a := range i.IncomingAuth {
		p := authplugins.GetIncoming(a.Type)
		if p == nil {
			return fmt.Errorf("unknown incoming auth type %s", a.Type)
		}
		cfg, err := p.ParseParams(a.Params)
		if err != nil {
			return fmt.Errorf("invalid params for auth %s: %v", a.Type, err)
		}
		if err := validateRequired(cfg, p); err != nil {
			return fmt.Errorf("invalid params for auth %s: %w", a.Type, err)
		}
		for _, ref := range collectSecretRefs(cfg) {
			if err := secrets.ValidateSecret(ref); err != nil {
				return fmt.Errorf("invalid params for auth %s: %w", a.Type, err)
			}
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
		if err := validateRequired(cfg, p); err != nil {
			return fmt.Errorf("invalid params for auth %s: %w", a.Type, err)
		}
		for _, ref := range collectSecretRefs(cfg) {
			if err := secrets.ValidateSecret(ref); err != nil {
				return fmt.Errorf("invalid params for auth %s: %w", a.Type, err)
			}
		}
		i.OutgoingAuth[idx].parsed = cfg

		if tp, ok := p.(interface {
			Transport(interface{}) *http.Transport
		}); ok {
			if t := tp.Transport(cfg); t != nil {
				i.proxy.Transport = t
			}
		}
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	if existing, ok := i.proxy.Transport.(*http.Transport); ok {
		tr = existing.Clone()
	}

	if i.IdleConnTimeout != "" {
		d, err := time.ParseDuration(i.IdleConnTimeout)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid idle_conn_timeout: %w", err)
		}
		tr.IdleConnTimeout = d
	}
	if i.TLSHandshakeTimeout != "" {
		d, err := time.ParseDuration(i.TLSHandshakeTimeout)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid tls_handshake_timeout: %w", err)
		}
		tr.TLSHandshakeTimeout = d
	}
	if i.ResponseHeaderTimeout != "" {
		d, err := time.ParseDuration(i.ResponseHeaderTimeout)
		if err != nil || d < 0 {
			return fmt.Errorf("invalid response_header_timeout: %w", err)
		}
		tr.ResponseHeaderTimeout = d
	}
	if i.TLSInsecureSkipVerify {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		}
		tr.TLSClientConfig.InsecureSkipVerify = true
	}
	if i.DisableKeepAlives {
		tr.DisableKeepAlives = true
	}
	if i.MaxIdleConns > 0 {
		tr.MaxIdleConns = i.MaxIdleConns
	}
	if i.MaxIdleConnsPerHost > 0 {
		tr.MaxIdleConnsPerHost = i.MaxIdleConnsPerHost
	}

	i.proxy.Transport = tr

	return nil
}

// AddIntegration validates and stores a new integration.
func AddIntegration(i *Integration) error {
	if err := prepareIntegration(i); err != nil {
		return err
	}
	window := i.rateLimitDur
	if window == 0 {
		window = time.Minute
	}
	integrations.Lock()
	if _, exists := integrations.m[i.Name]; exists {
		integrations.Unlock()
		return fmt.Errorf("integration %s already exists", i.Name)
	}
	i.inLimiter = NewRateLimiter(i.InRateLimit, window, i.RateLimitStrategy)
	i.outLimiter = NewRateLimiter(i.OutRateLimit, window, i.RateLimitStrategy)
	integrations.m[i.Name] = i
	integrations.Unlock()

	return nil
}

// GetIntegration retrieves an integration by name.
func GetIntegration(name string) (*Integration, bool) {
	integrations.RLock()
	i, ok := integrations.m[strings.ToLower(name)]
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

// UpdateIntegration replaces an existing integration or adds it if missing.
func UpdateIntegration(i *Integration) error {
	if err := prepareIntegration(i); err != nil {
		return err
	}
	window := i.rateLimitDur
	if window == 0 {
		window = time.Minute
	}
	integrations.Lock()
	if old, exists := integrations.m[i.Name]; exists {
		old.inLimiter.Stop()
		old.outLimiter.Stop()
	}
	i.inLimiter = NewRateLimiter(i.InRateLimit, window, i.RateLimitStrategy)
	i.outLimiter = NewRateLimiter(i.OutRateLimit, window, i.RateLimitStrategy)
	integrations.m[i.Name] = i
	integrations.Unlock()
	return nil
}

// DeleteIntegration removes an integration by name.
func DeleteIntegration(name string) {
	n := strings.ToLower(name)
	integrations.Lock()
	if old, ok := integrations.m[n]; ok {
		old.inLimiter.Stop()
		old.outLimiter.Stop()
		delete(integrations.m, n)
	}
	integrations.Unlock()

	allowlists.Lock()
	delete(allowlists.m, n)
	allowlists.Unlock()
}
