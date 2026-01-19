package main

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
)

var allowlists = struct {
	sync.RWMutex
	m map[string]map[string]CallerConfig
}{m: make(map[string]map[string]CallerConfig)}

func splitPath(p string) []string {
	clean := path.Clean(p)
	if clean == "." {
		return []string{}
	}
	clean = strings.Trim(clean, "/")
	if clean == "" {
		return []string{}
	}
	return strings.Split(clean, "/")
}

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
		for ri := range c.Rules {
			r := &c.Rules[ri]
			r.Segments = splitPath(r.Path)
			methods := make(map[string]RequestConstraint, len(r.Methods))
			for mth, cons := range r.Methods {
				method := strings.TrimSpace(mth)
				if method == "" {
					continue
				}
				methods[strings.ToUpper(method)] = cons
			}
			r.Methods = methods
		}
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
	res := make([]CallerConfig, 0, len(m))
	for _, c := range m {
		res = append(res, c)
	}
	allowlists.RUnlock()
	return res
}

// matchPath checks whether the request path matches the pattern. '*' matches a
// single path segment while '**' matches any remaining segments.
func matchPath(pattern, p string) bool {
	return matchSegments(splitPath(pattern), splitPath(p))
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
	ok, _ := validateRequestReason(r, c)
	return ok
}

// validateRequestReason checks headers, query parameters and body according to
// the request constraint. It returns a boolean indicating success and a string
// describing the first failure encountered when the request does not satisfy
// the constraint.
func validateRequestReason(r *http.Request, c RequestConstraint) (bool, string) {
	for name, wantVals := range c.Headers {
		canon := http.CanonicalHeaderKey(name)
		gotVals, ok := r.Header[canon]
		if !ok {
			return false, "missing header " + canon
		}
		for _, want := range wantVals {
			found := false
			for _, got := range gotVals {
				if got == want {
					found = true
					break
				}
			}
			if !found {
				return false, fmt.Sprintf("missing header %s=%s", canon, want)
			}
		}
	}

	if len(c.Query) > 0 {
		vals := r.URL.Query()
		for k, wantVals := range c.Query {
			present, ok := vals[k]
			if !ok {
				return false, "missing query param " + k
			}
			for _, want := range wantVals {
				found := false
				for _, got := range present {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					return false, fmt.Sprintf("missing query param %s=%s", k, want)
				}
			}
		}
	}

	if len(c.Body) == 0 {
		return true, ""
	}
	bodyBytes, err := authplugins.GetBody(r)
	if err != nil {
		return false, "error reading body"
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		data, err := decodeJSONBody(bodyBytes)
		if err != nil {
			return false, "invalid json"
		}
		if ok, reason := validateBodySchema(c.Body, data); !ok {
			return false, reason
		}
		return true, ""
	}
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			return false, "invalid form encoding"
		}
		data := formValuesToJSON(vals)
		if ok, reason := validateBodySchema(c.Body, data); !ok {
			return false, reason
		}
		return true, ""
	}
	// unsupported content type -> skip body filtering
	return true, ""
}

// findConstraint returns the RequestConstraint for the given caller, path and
// method if one exists.
func findConstraint(i *Integration, callerID, pth, method string) (RequestConstraint, bool) {
	segments := splitPath(pth)

	allowlists.RLock()
	callers := allowlists.m[i.Name]
	// NOTE: We check wildcard callers too incase an allowlist has both defined callers
	// and a fallback wildcard caller.
	wildcard, hasWildcard := callers["*"]
	c, ok := callers[callerID]
	allowlists.RUnlock()

	if ok {
		if len(c.Capabilities) > 0 {
			c = integrationplugins.ExpandCapabilities(i.Name, []CallerConfig{c})[0]
		}
		for _, r := range c.Rules {
			if matchSegments(r.Segments, segments) {
				if m, ok := r.Methods[method]; ok {
					return m, true
				}
			}
		}
	}
	if hasWildcard {
		if len(wildcard.Capabilities) > 0 {
			wildcard = integrationplugins.ExpandCapabilities(i.Name, []CallerConfig{wildcard})[0]
		}
		for _, r := range wildcard.Rules {
			if matchSegments(r.Segments, segments) {
				if m, ok := r.Methods[method]; ok {
					return m, true
				}
			}
		}
	}
	return RequestConstraint{}, false
}
