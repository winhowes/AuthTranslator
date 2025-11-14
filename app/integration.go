package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
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
	"github.com/winhowes/AuthTranslator/app/metrics"
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
	Type   string                 `json:"type" yaml:"type"`
	Params map[string]interface{} `json:"params" yaml:"params"`

	parsed interface{}
}

// CallerConfig defines allowed paths and methods for a specific caller
// identifier.
type CallerConfig = integrationplugins.CallerConfig
type CallRule = integrationplugins.CallRule
type RequestConstraint = integrationplugins.RequestConstraint

// Integration represents a configured proxy integration.
type Integration struct {
	Name              string             `json:"name" yaml:"name"`
	Destination       string             `json:"destination" yaml:"destination"`
	InRateLimit       int                `json:"in_rate_limit" yaml:"in_rate_limit"`
	OutRateLimit      int                `json:"out_rate_limit" yaml:"out_rate_limit"`
	IncomingAuth      []AuthPluginConfig `json:"incoming_auth" yaml:"incoming_auth"`
	OutgoingAuth      []AuthPluginConfig `json:"outgoing_auth" yaml:"outgoing_auth"`
	RateLimitWindow   string             `json:"rate_limit_window" yaml:"rate_limit_window,omitempty"`
	RateLimitStrategy string             `json:"rate_limit_strategy,omitempty" yaml:"rate_limit_strategy,omitempty"`

	rateLimitDur time.Duration `json:"-" yaml:"-"`

	IdleConnTimeout       string `json:"idle_conn_timeout,omitempty" yaml:"idle_conn_timeout,omitempty"`
	TLSHandshakeTimeout   string `json:"tls_handshake_timeout,omitempty" yaml:"tls_handshake_timeout,omitempty"`
	ResponseHeaderTimeout string `json:"response_header_timeout,omitempty" yaml:"response_header_timeout,omitempty"`
	TLSInsecureSkipVerify bool   `json:"tls_insecure_skip_verify,omitempty" yaml:"tls_insecure_skip_verify,omitempty"`
	DisableKeepAlives     bool   `json:"disable_keep_alives,omitempty" yaml:"disable_keep_alives,omitempty"`
	MaxIdleConns          int    `json:"max_idle_conns,omitempty" yaml:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost   int    `json:"max_idle_conns_per_host,omitempty" yaml:"max_idle_conns_per_host,omitempty"`

	inLimiter  *RateLimiter
	outLimiter *RateLimiter

	destinationURL *url.URL               `json:"-" yaml:"-"`
	proxy          *httputil.ReverseProxy `json:"-" yaml:"-"`

	requiresDestinationHeader bool
	wildcardHostPattern       string
}

var integrations = struct {
	sync.RWMutex
	m map[string]*Integration
}{m: make(map[string]*Integration)}

var nameRegexp = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

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

	hostPattern := u.Hostname()
	hasWildcard := strings.Contains(hostPattern, "*")
	if hasWildcard {
		if u.User != nil {
			return fmt.Errorf("invalid destination URL: wildcard destinations cannot include user info")
		}
		if strings.Contains(u.Scheme, "*") || strings.Contains(u.Path, "*") || strings.Contains(u.RawQuery, "*") || strings.Contains(u.Fragment, "*") {
			return fmt.Errorf("invalid destination URL: wildcard destinations must not include * outside the host")
		}
		if strings.Contains(u.Port(), "*") {
			return fmt.Errorf("invalid destination URL: wildcard destinations must not include * in the port")
		}
		trimmed := strings.Trim(strings.ReplaceAll(hostPattern, "*", ""), ".")
		if trimmed == "" && hostPattern != "*" {
			return fmt.Errorf("invalid destination URL: wildcard host must include a base domain")
		}
		i.requiresDestinationHeader = true
		i.wildcardHostPattern = strings.ToLower(hostPattern)
	} else {
		i.requiresDestinationHeader = false
		i.wildcardHostPattern = ""
	}

	i.proxy = httputil.NewSingleHostReverseProxy(u)
	oldDirector := i.proxy.Director
	if hasWildcard {
		i.proxy.Director = func(req *http.Request) {
			dest, ok := resolvedDestinationFromContext(req.Context())
			if !ok {
				oldDirector(req)
				req.Host = u.Host
				return
			}
			if resolvedDestinationApplied(req.Context()) {
				return
			}
			applyResolvedDestination(req, dest)
		}
	} else {
		i.proxy.Director = func(req *http.Request) {
			oldDirector(req)
			req.Host = u.Host
		}
	}

	i.proxy.ModifyResponse = func(resp *http.Response) error {
		caller := metrics.Caller(resp.Request.Context())
		metrics.OnResponse(i.Name, caller, resp.Request, resp)
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= 300 {
			resp.Header.Set("X-AT-Upstream-Error", "true")
		}
		return nil
	}

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
	case "fixed_window", "token_bucket", "leaky_bucket":
	default:
		return fmt.Errorf("invalid rate_limit_strategy %s", i.RateLimitStrategy)
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
func (i *Integration) resolveRequestDestination(r *http.Request) (*url.URL, error) {
	if !i.requiresDestinationHeader {
		return i.destinationURL, nil
	}

	header := r.Header.Get("X-AT-Destination")
	if header == "" {
		return nil, errors.New("missing X-AT-Destination header")
	}

	dest, err := url.Parse(header)
	if err != nil {
		return nil, fmt.Errorf("invalid X-AT-Destination header: %w", err)
	}
	if dest.User != nil {
		return nil, errors.New("invalid X-AT-Destination header: user info not allowed")
	}
	if dest.Host == "" {
		return nil, errors.New("invalid X-AT-Destination header: missing host")
	}
	if strings.Contains(dest.Hostname(), "*") {
		return nil, errors.New("invalid X-AT-Destination header: wildcard not allowed")
	}

	scheme := dest.Scheme
	if scheme == "" {
		scheme = i.destinationURL.Scheme
	}
	if !strings.EqualFold(scheme, i.destinationURL.Scheme) {
		return nil, errors.New("invalid X-AT-Destination header: unexpected scheme")
	}

	if !matchWildcardHost(i.wildcardHostPattern, dest.Hostname()) {
		return nil, errors.New("invalid X-AT-Destination header: host not permitted")
	}

	port := dest.Port()
	cfgPort := i.destinationURL.Port()
	switch {
	case cfgPort != "" && port == "":
		dest.Host = net.JoinHostPort(dest.Hostname(), cfgPort)
	case cfgPort != "" && port != cfgPort:
		return nil, errors.New("invalid X-AT-Destination header: unexpected port")
	case cfgPort == "" && port != "":
		return nil, errors.New("invalid X-AT-Destination header: unexpected port")
	}

	resolved := *i.destinationURL
	resolved.Scheme = scheme
	resolved.Host = dest.Host
	resolved.User = nil
	return &resolved, nil
}

type resolvedDestinationKey struct{}

type resolvedDestinationState struct {
	dest    *url.URL
	applied bool
}

func contextWithResolvedDestination(ctx context.Context, dest *url.URL) context.Context {
	return context.WithValue(ctx, resolvedDestinationKey{}, &resolvedDestinationState{dest: dest})
}

func resolvedDestinationFromContext(ctx context.Context) (*url.URL, bool) {
	state, _ := ctx.Value(resolvedDestinationKey{}).(*resolvedDestinationState)
	if state == nil || state.dest == nil {
		return nil, false
	}
	return state.dest, true
}

func resolvedDestinationApplied(ctx context.Context) bool {
	state, _ := ctx.Value(resolvedDestinationKey{}).(*resolvedDestinationState)
	if state == nil {
		return false
	}
	return state.applied
}

func markResolvedDestinationApplied(ctx context.Context) {
	state, _ := ctx.Value(resolvedDestinationKey{}).(*resolvedDestinationState)
	if state != nil {
		state.applied = true
	}
}

func applyResolvedDestination(req *http.Request, dest *url.URL) {
	path, rawPath := joinProxyPath(dest, req)
	targetQuery := dest.RawQuery

	req.URL.Scheme = dest.Scheme
	req.URL.Host = dest.Host
	req.Host = dest.Host
	req.URL.Path = path
	req.URL.RawPath = rawPath

	if targetQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = targetQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}

	markResolvedDestinationApplied(req.Context())
}

func matchWildcardHost(pattern, host string) bool {
	if pattern == "" {
		return strings.EqualFold(pattern, host)
	}
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if !strings.Contains(pattern, "*") {
		return host == pattern
	}

	segments := strings.Split(pattern, "*")
	if !strings.HasPrefix(host, segments[0]) {
		return false
	}
	host = host[len(segments[0]):]
	for i := 1; i < len(segments); i++ {
		segment := segments[i]
		last := i == len(segments)-1
		if last {
			if segment == "" {
				return true
			}
			if !strings.HasSuffix(host, segment) {
				return false
			}
			if strings.HasPrefix(pattern, "*") && len(host) == len(segment) {
				return false
			}
			return true
		}
		pos := strings.Index(host, segment)
		if pos < 0 {
			return false
		}
		host = host[pos+len(segment):]
	}
	return true
}

func joinProxyPath(target *url.URL, req *http.Request) (string, string) {
	if target.RawPath == "" && req.URL.RawPath == "" {
		return singleJoiningSlash(target.Path, req.URL.Path), ""
	}

	tgtEscaped := target.EscapedPath()
	reqEscaped := req.URL.EscapedPath()

	tgtHasSlash := strings.HasSuffix(tgtEscaped, "/")
	reqHasSlash := strings.HasPrefix(reqEscaped, "/")

	switch {
	case tgtHasSlash && reqHasSlash:
		return target.Path + req.URL.Path[1:], tgtEscaped + reqEscaped[1:]
	case !tgtHasSlash && !reqHasSlash:
		return target.Path + "/" + req.URL.Path, tgtEscaped + "/" + reqEscaped
	default:
		return target.Path + req.URL.Path, tgtEscaped + reqEscaped
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		if a == "" || b == "" {
			return a + b
		}
		return a + "/" + b
	}
	return a + b
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
