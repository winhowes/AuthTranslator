package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/winhowes/AuthTranslator/app/authplugins"
	integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"
)

var allowlists = struct {
	sync.RWMutex
	m map[string]map[string]CallerConfig
}{m: make(map[string]map[string]CallerConfig)}

// SetAllowlist registers the caller allowlist for an integration.
func SetAllowlist(name string, callers []CallerConfig) {
	callers = integrationplugins.ExpandCapabilities(name, callers)
	m := make(map[string]CallerConfig, len(callers))
	for _, c := range callers {
		m[c.ID] = c
	}
	allowlists.Lock()
	allowlists.m[name] = m
	allowlists.Unlock()
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
		return true
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
		if vals.Get(k) == "" {
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
	if !ok {
		return RequestConstraint{}, false
	}
	for _, r := range c.Rules {
		if matchPath(r.Path, pth) {
			if m, ok := r.Methods[method]; ok {
				return m, true
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
