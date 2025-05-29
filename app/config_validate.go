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
		if i.IdleConnTimeout != "" {
			d, err := time.ParseDuration(i.IdleConnTimeout)
			if err != nil || d < 0 {
				return fmt.Errorf("integration %s has invalid idle_conn_timeout", i.Name)
			}
		}
		if i.TLSHandshakeTimeout != "" {
			d, err := time.ParseDuration(i.TLSHandshakeTimeout)
			if err != nil || d < 0 {
				return fmt.Errorf("integration %s has invalid tls_handshake_timeout", i.Name)
			}
		}
		if i.ResponseHeaderTimeout != "" {
			d, err := time.ParseDuration(i.ResponseHeaderTimeout)
			if err != nil || d < 0 {
				return fmt.Errorf("integration %s has invalid response_header_timeout", i.Name)
			}
		}
	}
	return nil
}
