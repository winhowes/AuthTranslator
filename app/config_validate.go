package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var configNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// validateConfig ensures the Config contains sane values before use.
func validateConfig(c *Config) error {
	names := make(map[string]struct{})
	for idx := range c.Integrations {
		i := &c.Integrations[idx]
		if i.Name == "" {
			return fmt.Errorf("integration at index %d missing name", idx)
		}
		lower := strings.ToLower(i.Name)
		if !configNameRegexp.MatchString(lower) {
			return fmt.Errorf("integration %s has invalid name", i.Name)
		}
		if _, dup := names[lower]; dup {
			return fmt.Errorf("duplicate integration name %s", i.Name)
		}
		names[lower] = struct{}{}

		if i.Destination == "" {
			return fmt.Errorf("integration %s missing destination", i.Name)
		}
		u, err := url.Parse(i.Destination)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("integration %s has invalid destination", i.Name)
		}
		if i.RateLimitWindow != "" {
			d, err := time.ParseDuration(i.RateLimitWindow)
			if err != nil || d <= 0 {
				return fmt.Errorf("integration %s has invalid rate_limit_window", i.Name)
			}
		}
		if i.RateLimitStrategy != "" {
			switch i.RateLimitStrategy {
			case "fixed_window", "token_bucket":
			default:
				return fmt.Errorf("integration %s has invalid rate_limit_strategy", i.Name)
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
		if i.MaxIdleConns < 0 {
			return fmt.Errorf("integration %s has invalid max_idle_conns", i.Name)
		}
		if i.MaxIdleConnsPerHost < 0 {
			return fmt.Errorf("integration %s has invalid max_idle_conns_per_host", i.Name)
		}
	}
	return nil
}
