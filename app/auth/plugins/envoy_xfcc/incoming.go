package envoy_xfcc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/winhowes/AuthTranslator/app/auth"
)

type inParams struct {
	AllowedURIs      []string `json:"allowed_uris"`
	AllowedURIPrefix []string `json:"allowed_uri_prefixes"`
	Header           string   `json:"header"`
	IgnoredURIs      []string `json:"ignored_uris"`
}

type EnvoyXFCCAuth struct{}

func (e *EnvoyXFCCAuth) Name() string { return "envoy_xfcc" }

func (e *EnvoyXFCCAuth) RequiredParams() []string { return []string{} }

func (e *EnvoyXFCCAuth) OptionalParams() []string {
	return []string{"allowed_uris", "allowed_uri_prefixes", "header", "ignored_uris"}
}

func (e *EnvoyXFCCAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	cfg, err := authplugins.ParseParams[inParams](m)
	if err != nil {
		return nil, err
	}
	if cfg.Header == "" {
		cfg.Header = "X-Forwarded-Client-Cert"
	}
	return cfg, nil
}

func (e *EnvoyXFCCAuth) Authenticate(ctx context.Context, r *http.Request, p interface{}) bool {
	_, ok := e.Identify(r, p)
	return ok
}

func (e *EnvoyXFCCAuth) Identify(r *http.Request, p interface{}) (string, bool) {
	cfg, ok := p.(*inParams)
	if !ok {
		return "", false
	}
	identity, ok := extractCallerIdentityFromValues(r.Header.Values(cfg.Header), cfg)
	if !ok {
		return "", false
	}
	return identity, true
}

func (e *EnvoyXFCCAuth) StripAuth(r *http.Request, p interface{}) {
	cfg, ok := p.(*inParams)
	if !ok {
		return
	}
	r.Header.Del(cfg.Header)
}

func extractCallerIdentityFromValues(values []string, cfg *inParams) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	format := headerFormatUnknown
	jsonURIs := []string{}
	textValues := []string{}
	for _, raw := range values {
		valueFormat := detectHeaderFormat(raw)
		if valueFormat == headerFormatUnknown {
			return "", false
		}
		if format == headerFormatUnknown {
			format = valueFormat
		}
		if format != valueFormat {
			return "", false
		}
		switch valueFormat {
		case headerFormatText:
			textValues = append(textValues, raw)
		case headerFormatJSON:
			uris, ok := extractJSONURIs(raw)
			if !ok {
				return "", false
			}
			jsonURIs = append(jsonURIs, uris...)
		}
	}

	if format == headerFormatText {
		return extractCallerIdentity(joinHeaderValues(textValues), cfg)
	}
	return selectIdentity(jsonURIs, cfg)
}

func extractCallerIdentity(raw string, cfg *inParams) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", false
	}
	elements, ok := splitXFCC(raw, ',')
	if !ok {
		return "", false
	}
	candidates := []string{}
	for _, elem := range elements {
		fields, ok := splitXFCC(elem, ';')
		if !ok {
			return "", false
		}
		elementURI := ""
		for _, field := range fields {
			kv := strings.SplitN(strings.TrimSpace(field), "=", 2)
			if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" {
				return "", false
			}
			if !strings.EqualFold(strings.TrimSpace(kv[0]), "URI") {
				continue
			}
			uri, ok := decodeFieldValue(kv[1])
			if !ok || uri == "" {
				return "", false
			}
			if elementURI != "" {
				return "", false
			}
			elementURI = uri
		}

		if elementURI == "" {
			continue
		}
		candidates = append(candidates, elementURI)
	}
	return selectIdentity(candidates, cfg)
}

func selectIdentity(candidates []string, cfg *inParams) (string, bool) {
	ignored := map[string]struct{}{}
	for _, uri := range cfg.IgnoredURIs {
		ignored[uri] = struct{}{}
	}
	selected := ""
	for _, candidate := range candidates {
		if _, isIgnored := ignored[candidate]; isIgnored {
			continue
		}
		if selected != "" {
			return "", false
		}
		selected = candidate
	}
	if selected == "" {
		return "", false
	}
	if !isAllowedIdentity(selected, cfg) {
		return "", false
	}
	return selected, true
}

func joinHeaderValues(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ",")
}

type xfccHeaderFormat int

const (
	headerFormatUnknown xfccHeaderFormat = iota
	headerFormatText
	headerFormatJSON
)

func detectHeaderFormat(raw string) xfccHeaderFormat {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return headerFormatUnknown
	}
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return headerFormatJSON
	}
	return headerFormatText
}

func extractJSONURIs(raw string) ([]string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, false
		}
		uris := []string{}
		for _, element := range arr {
			uri, ok := extractURIFromJSONObject(element)
			if !ok {
				return nil, false
			}
			if uri != "" {
				uris = append(uris, uri)
			}
		}
		return uris, true
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, false
	}
	uri, ok := extractURIFromJSONObject(obj)
	if !ok {
		return nil, false
	}
	if uri == "" {
		return []string{}, true
	}
	return []string{uri}, true
}

func extractURIFromJSONObject(obj map[string]interface{}) (string, bool) {
	var uriValue interface{}
	seenURIKey := false
	for key, value := range obj {
		if !strings.EqualFold(key, "URI") {
			continue
		}
		if seenURIKey {
			return "", false
		}
		seenURIKey = true
		uriValue = value
	}
	if !seenURIKey {
		return "", true
	}
	switch v := uriValue.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return "", false
		}
		return v, true
	case []interface{}:
		if len(v) != 1 {
			return "", false
		}
		uri, ok := v[0].(string)
		if !ok || strings.TrimSpace(uri) == "" {
			return "", false
		}
		return uri, true
	default:
		return "", false
	}
}

func splitXFCC(raw string, sep rune) ([]string, bool) {
	parts := []string{}
	start := 0
	inQuotes := false
	escaped := false
	for i, r := range raw {
		switch {
		case inQuotes && escaped:
			escaped = false
		case inQuotes && r == '\\':
			escaped = true
		case r == '"':
			inQuotes = !inQuotes
		case !inQuotes && r == sep:
			part := strings.TrimSpace(raw[start:i])
			if part == "" {
				return nil, false
			}
			parts = append(parts, part)
			start = i + 1
		}
	}
	if inQuotes || escaped {
		return nil, false
	}
	last := strings.TrimSpace(raw[start:])
	if last == "" {
		return nil, false
	}
	parts = append(parts, last)
	return parts, true
}

func decodeFieldValue(v string) (string, bool) {
	value := strings.TrimSpace(v)
	if value == "" {
		return "", false
	}
	if !strings.HasPrefix(value, "\"") {
		return value, true
	}
	if len(value) < 2 || !strings.HasSuffix(value, "\"") {
		return "", false
	}
	inner := value[1 : len(value)-1]
	var b strings.Builder
	escaped := false
	for _, r := range inner {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		b.WriteRune(r)
	}
	if escaped {
		return "", false
	}
	return b.String(), true
}

func isAllowedIdentity(uri string, cfg *inParams) bool {
	for _, allowed := range cfg.AllowedURIs {
		if uri == allowed {
			return true
		}
	}
	for _, prefix := range cfg.AllowedURIPrefix {
		if strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

func init() {
	authplugins.RegisterIncoming(&EnvoyXFCCAuth{})
}
