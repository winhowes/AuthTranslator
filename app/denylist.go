package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	authplugins "github.com/winhowes/AuthTranslator/app/auth"
)

var denylists = struct {
	sync.RWMutex
	m map[string]map[string][]CallRule
}{m: make(map[string]map[string][]CallRule)}

func validateDenylist(name, caller string, rules []CallRule) error {
	seen := make(map[string]map[string]struct{})
	for ri, r := range rules {
		path := strings.TrimSpace(r.Path)
		if path == "" {
			return fmt.Errorf("caller %s rule %d missing path", caller, ri)
		}
		if len(r.Methods) == 0 {
			return fmt.Errorf("caller %s rule %d has no methods", caller, ri)
		}
		if seen[path] == nil {
			seen[path] = make(map[string]struct{})
		}
		for m := range r.Methods {
			method := strings.TrimSpace(m)
			if method == "" {
				return fmt.Errorf("caller %s rule %d invalid method %q", caller, ri, m)
			}
			method = strings.ToUpper(method)
			if _, dup := seen[path][method]; dup {
				return fmt.Errorf("duplicate rule for caller %s path %q method %s (rule %d)", caller, path, method, ri)
			}
			seen[path][method] = struct{}{}
		}
	}
	return nil
}

func validateDenylistCallers(name string, callers []DenylistCaller) error {
	seen := make(map[string]struct{})
	for ci, c := range callers {
		id := c.ID
		if id == "" {
			id = "*"
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("duplicate caller id %q in denylist %s (index %d)", id, name, ci)
		}
		seen[id] = struct{}{}
		if err := validateDenylist(name, id, c.Rules); err != nil {
			return err
		}
	}
	return nil
}

func SetDenylist(name string, callers []DenylistCaller) error {
	name = strings.ToLower(name)
	if err := validateDenylistCallers(name, callers); err != nil {
		return err
	}

	processed := make(map[string][]CallRule, len(callers))
	for _, caller := range callers {
		id := caller.ID
		if id == "" {
			id = "*"
		}
		rules := make([]CallRule, len(caller.Rules))
		for i := range caller.Rules {
			r := caller.Rules[i]
			r.Segments = splitPath(r.Path)
			methods := make(map[string]RequestConstraint, len(r.Methods))
			for method, cons := range r.Methods {
				cleaned := strings.ToUpper(strings.TrimSpace(method))
				methods[cleaned] = cons
			}
			r.Methods = methods
			rules[i] = r
		}
		processed[id] = rules
	}

	denylists.Lock()
	denylists.m[name] = processed
	denylists.Unlock()
	return nil
}

func GetDenylist(name string) []DenylistCaller {
	denylists.RLock()
	callers := denylists.m[strings.ToLower(name)]
	res := make([]DenylistCaller, 0, len(callers))
	for id, rules := range callers {
		copyRules := make([]CallRule, len(rules))
		for i := range rules {
			copyRules[i] = rules[i]
		}
		res = append(res, DenylistCaller{ID: id, Rules: copyRules})
	}
	denylists.RUnlock()
	return res
}

func matchDenylist(i *Integration, callerID string, r *http.Request) (bool, string) {
	denylists.RLock()
	callers := denylists.m[strings.ToLower(i.Name)]
	denylists.RUnlock()
	if len(callers) == 0 {
		return false, ""
	}

	if callerID == "" {
		callerID = "*"
	}

	segments := splitPath(r.URL.Path)
	method := strings.ToUpper(r.Method)

	if rules, ok := callers[callerID]; ok {
		if matched, path := matchDenylistRules(r, rules, segments, method); matched {
			return true, fmt.Sprintf("denylist matched caller %s %s %s", callerID, method, path)
		}
	}
	if callerID != "*" {
		if rules, ok := callers["*"]; ok {
			if matched, path := matchDenylistRules(r, rules, segments, method); matched {
				return true, fmt.Sprintf("denylist matched caller * %s %s", method, path)
			}
		}
	}
	return false, ""
}

func matchDenylistRules(r *http.Request, rules []CallRule, segments []string, method string) (bool, string) {
	for _, rule := range rules {
		if !matchSegments(rule.Segments, segments) {
			continue
		}
		cons, ok := rule.Methods[method]
		if !ok {
			continue
		}
		if constraintMatchesRequest(r, cons) {
			return true, rule.Path
		}
	}
	return false, ""
}

func constraintMatchesRequest(r *http.Request, c RequestConstraint) bool {
	for name, wantVals := range c.Headers {
		canon := http.CanonicalHeaderKey(name)
		gotVals, ok := r.Header[canon]
		if !ok {
			return false
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
				return false
			}
		}
	}

	if len(c.Query) > 0 {
		vals := r.URL.Query()
		for k, wantVals := range c.Query {
			present, ok := vals[k]
			if !ok {
				return false
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
					return false
				}
			}
		}
	}

	if len(c.Body) == 0 {
		return true
	}

	bodyBytes, err := authplugins.GetBody(r)
	if err != nil {
		return false
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "application/json"):
		var data map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			return false
		}
		return matchBodyMap(data, c.Body)
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		vals, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			return false
		}
		return matchForm(vals, c.Body)
	default:
		return false
	}
}
