package main

import (
	"fmt"
	"time"
)

// validateConfig ensures the Config contains sane values before use.
func validateConfig(c *Config) error {
	for idx := range c.Integrations {
		i := &c.Integrations[idx]
		if i.Name == "" {
			return fmt.Errorf("integration at index %d missing name", idx)
		}
		if i.Destination == "" {
			return fmt.Errorf("integration %s missing destination", i.Name)
		}
		if i.RateLimitWindow != "" {
			d, err := time.ParseDuration(i.RateLimitWindow)
			if err != nil || d <= 0 {
				return fmt.Errorf("integration %s has invalid rate_limit_window", i.Name)
			}
		}
	}
	return nil
}
