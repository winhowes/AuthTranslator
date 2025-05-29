package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/winhowes/AuthTranslator/app/auth"
	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
)

var allowlists = struct {
	sync.RWMutex
	m map[string]map[string]CallerConfig
}{m: make(map[string]map[string]CallerConfig)}

// validateAllowlist ensures callers and rules are unique after capability
// expansion. The ID "" is treated as "*".
func validateAllowlist(name string, callers []CallerConfig) error {
	seenIDs := make(map[string]struct{})
	for ci, c := range callers {
		id := c.ID
		if id == "" {
			id = "*"
		}
		if _, dup := seenIDs[id]; dup {
			return fmt.Errorf("duplicate caller id %q in allowlist %s", id, name)
		}
		seenIDs[id] = struct{}{}

		// track path+method combos to prevent duplicates
		ruleSeen := make(map[string]map[string]struct{})
		for ri, r := range c.Rules {
			if ruleSeen[r.Path] == nil {
				ruleSeen[r.Path] = make(map[string]struct{})
			}
			for m := range r.Methods {
				if _, dup := ruleSeen[r.Path][m]; dup {
					return fmt.Errorf("duplicate rule for caller %q path %q method %s (index %d rule %d)", id, r.Path, m, ci, ri)
				}
				ruleSeen[r.Path][m] = struct{}{}
			}
		}
	}
	return nil
}

// SetAllowlist registers the caller allowlist for an integration. It returns an
// error if duplicate caller IDs or rules are detected.
func SetAllowlist(name string, callers []CallerConfig) error {
	name = strings.ToLower(name)
	callers = integrationplugins.ExpandCapabilities(name, callers)
	if err := validateAllowlist(name, callers); err != nil {
		return err
	}

	m := make(map[string]CallerConfig, len(callers))
	for _, c := range callers {
		id := c.ID
		if id == "" {
			id = "*"
		}
		m[id] = c
	}
	allowlists.Lock()
	allowlists.m[name] = m
	allowlists.Unlock()
	return nil
}

// GetAllowlist retrieves the allowlist for an integration.
func GetAllowlist(name string) []CallerConfig {
	allowlists.RLock()
	m := allowlists.m[name]
	allowlists.RUnlock()
	res := make([]CallerConfig, 0, len(m))
	for _, c := range m {
		res = append(res, c)
	}
	return res
}

// matchPath checks whether the request path matches the pattern. '*' matches a
// single path segment while '**' matches any remaining segments.
func matchPath(pattern, p string) bool {
	pattSegs := strings.Split(strings.Trim(path.Clean(pattern), "/"), "/")
	segs := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
	return matchSegments(pattSegs, segs)
}

func matchSegments(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if pattern[0] == "**" {
		if matchSegments(pattern[1:], path) {
			// "**" matches zero segments
			return true
		}
		if len(path) > 0 && matchSegments(pattern, path[1:]) {
			// consume one segment and try again
			return true
		}
		return false
	}
	if len(path) == 0 {
		return false
	}
	if pattern[0] == "*" || pattern[0] == path[0] {
		return matchSegments(pattern[1:], path[1:])
	}
	return false
}

// validateRequest checks headers and body according to the request constraint.
func validateRequest(r *http.Request, c RequestConstraint) bool {
	for _, h := range c.Headers {
		if r.Header.Get(h) == "" {
			return false
		}
	}
	if len(c.Body) == 0 {
		return true
	}
	bodyBytes, err := authplugins.GetBody(r)
	if err != nil {
		return false
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var data map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			return false
		}
		return matchBodyMap(data, c.Body)
	}
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			return false
		}
		return matchForm(vals, c.Body)
	}
	// unsupported content type
	return false
}

func matchForm(vals url.Values, rule map[string]interface{}) bool {
	for k, v := range rule {
		if !vals.Has(k) {
			return false
		}
		if arr, ok := v.([]interface{}); ok {
			present := vals[k]
			for _, want := range arr {
				s, ok := want.(string)
				if !ok {
					return false
				}
				found := false
				for _, p := range present {
					if p == s {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}
	return true
}

func matchBodyMap(data map[string]interface{}, rule map[string]interface{}) bool {
	return matchValue(data, rule)
}

func matchValue(data, rule interface{}) bool {
	switch rv := rule.(type) {
	case map[string]interface{}:
		dm, ok := data.(map[string]interface{})
		if !ok {
			return false
		}
		for k, v := range rv {
			dv, ok := dm[k]
			if !ok {
				return false
			}
			if !matchValue(dv, v) {
				return false
			}
		}
		return true
	case []interface{}:
		da, ok := data.([]interface{})
		if !ok {
			return false
		}
		for _, want := range rv {
			found := false
			for _, elem := range da {
				if matchValue(elem, want) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return data == rule
	}
}

// findConstraint returns the RequestConstraint for the given caller, path and
// method if one exists.
func findConstraint(i *Integration, callerID, pth, method string) (RequestConstraint, bool) {
	allowlists.RLock()
	callers := allowlists.m[i.Name]
	wildcard, hasWildcard := callers["*"]
	c, ok := callers[callerID]
	allowlists.RUnlock()

	if ok {
		for _, r := range c.Rules {
			if matchPath(r.Path, pth) {
				if m, ok := r.Methods[method]; ok {
					return m, true
				}
			}
		}
	}
	if hasWildcard {
		for _, r := range wildcard.Rules {
			if matchPath(r.Path, pth) {
				if m, ok := r.Methods[method]; ok {
					return m, true
				}
			}
		}
	}
	return RequestConstraint{}, false
}
