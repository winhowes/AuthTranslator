package main

import (
	"fmt"
	"strings"
)

func validateDenylistEntries(entries []DenylistEntry) error {
	seen := make(map[string]struct{})
	for i, e := range entries {
		name := strings.ToLower(e.Integration)
		if name == "" {
			return fmt.Errorf("denylist entry %d missing integration", i)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("duplicate integration %s in denylist", name)
		}
		seen[name] = struct{}{}
		if err := validateDenylistCallers(name, e.Callers); err != nil {
			return fmt.Errorf("integration %s: %w", name, err)
		}
	}
	return nil
}
