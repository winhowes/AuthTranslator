package main

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/winhowes/AuthTransformer/app/authplugins"
	"github.com/winhowes/AuthTransformer/app/secrets"
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

		// Determine the JSON key name for the field.
		jsonTag := sf.Tag.Get("json")
		name := sf.Name
		if jsonTag != "" {
			if comma := strings.Index(jsonTag, ","); comma >= 0 {
				if comma == 0 {
					// Tag like ",omitempty" – field is skipped unless renamed; ignore.
					continue
				}
				name = jsonTag[:comma]
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
// holds the raw configuration from the JSON config while parsed is used at
// runtime after being validated by the plugin's ParseParams function.
type AuthPluginConfig struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params"`

	parsed interface{}
}

// CallerConfig defines allowed paths and methods for a specific caller
// identifier.
type CallerConfig struct {
	ID    string     `json:"id"`
	Rules []CallRule `json:"rules"`
}

// CallRule ties a path pattern to method-specific constraints.
type CallRule struct {
	Path    string                       `json:"path"`
	Methods map[string]RequestConstraint `json:"methods"`
}

// RequestConstraint lists required headers and body parameters.
type RequestConstraint struct {
	Headers []string               `json:"headers"`
	Body    map[string]interface{} `json:"body"`
}

// Integration represents a configured proxy integration.
type Integration struct {
	Name           string             `json:"name"`
	Destination    string             `json:"destination"`
	InRateLimit    int                `json:"in_rate_limit"`
	OutRateLimit   int                `json:"out_rate_limit"`
	IncomingAuth   []AuthPluginConfig `json:"incoming_auth"`
	OutgoingAuth   []AuthPluginConfig `json:"outgoing_auth"`
	AllowedCallers []CallerConfig     `json:"allowlist"`

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

	// ─── Validate incoming-auth configs ───────────────────────────────────────
	for idx, a := range i.IncomingAuth {
		p := authplugins.GetIncoming(a.Type)
		if p == nil {
			return fmt.Errorf("unknown incoming auth type %s", a.Type)
		}

		cfg, err := p.ParseParams(a.Params) // plugin handles json + unknown fields
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

	// ─── Validate outgoing-auth configs ───────────────────────────────────────
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
	}

	// ─── Rate limiters & storage ──────────────────────────────────────────────
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
