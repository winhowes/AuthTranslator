package main

import (
	"fmt"
	"strings"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"
)

// validateAllowlistEntries checks for duplicate integrations, well formatted
// rules and capabilities and validates capability parameters.
func validateAllowlistEntries(entries []AllowlistEntry) error {
	seen := make(map[string]struct{})
	for i, e := range entries {
		name := strings.ToLower(e.Integration)
		if name == "" {
			return fmt.Errorf("allowlist entry %d missing integration", i)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("duplicate integration %s in allowlist", name)
		}
		seen[name] = struct{}{}
		if err := validateAllowlistEntry(name, e.Callers); err != nil {
			return fmt.Errorf("integration %s: %w", name, err)
		}
	}
	return nil
}

func validateAllowlistEntry(name string, callers []CallerConfig) error {
	seenIDs := make(map[string]struct{})
	for _, c := range callers {
		id := c.ID
		if id == "" {
			id = "*"
		}
		if _, dup := seenIDs[id]; dup {
			return fmt.Errorf("duplicate caller id %q", id)
		}
		seenIDs[id] = struct{}{}
		if len(c.Rules) == 0 && len(c.Capabilities) == 0 {
			return fmt.Errorf("caller %q has no rules or capabilities", id)
		}
		for _, cap := range c.Capabilities {
			if err := validateCapability(name, cap); err != nil {
				return err
			}
		}
		for ri, r := range c.Rules {
			if strings.TrimSpace(r.Path) == "" {
				return fmt.Errorf("caller %q rule %d missing path", id, ri)
			}
			if len(r.Methods) == 0 {
				return fmt.Errorf("caller %q rule %d has no methods", id, ri)
			}
			for m := range r.Methods {
				if m == "" || strings.ToUpper(m) != m {
					return fmt.Errorf("caller %q rule %d invalid method %s", id, ri, m)
				}
			}
		}
	}
	expanded := integrationplugins.ExpandCapabilities(name, callers)
	return validateAllowlist(name, expanded)
}

func validateCapability(integration string, cap integrationplugins.CapabilityConfig) error {
	spec, ok := integrationplugins.CapabilitiesFor(integration)[cap.Name]
	if !ok {
		return fmt.Errorf("unknown capability %s", cap.Name)
	}
	for p := range cap.Params {
		valid := false
		for _, want := range spec.Params {
			if p == want {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unknown param %s for capability %s", p, cap.Name)
		}
	}
	if _, err := spec.Generate(cap.Params); err != nil {
		return fmt.Errorf("invalid params for capability %s: %v", cap.Name, err)
	}
	return nil
}
