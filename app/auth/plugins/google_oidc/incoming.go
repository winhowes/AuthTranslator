package googleoidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/winhowes/AuthTranslator/app/auth"
)

// inParams configures validation of incoming Google OIDC tokens.
type inParams struct {
	Audience string `json:"audience"`
	Header   string `json:"header"`
	Prefix   string `json:"prefix"`
}

// CertsURL is the endpoint returning Google public signing keys. It can be overridden in tests.
var CertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// keyCache stores fetched public keys and their expiration time.
var keyCache struct {
	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
	expiry time.Time
}

// fetchMu serializes fetches of the signing key set to avoid
// unnecessary concurrent network requests when the cache expires.
var fetchMu sync.Mutex

// GoogleOIDCAuth validates Google issued ID tokens from incoming requests.
type GoogleOIDCAuth struct{}

func (g *GoogleOIDCAuth) Name() string { return "google_oidc" }

func (g *GoogleOIDCAuth) RequiredParams() []string { return []string{"audience"} }

func (g *GoogleOIDCAuth) OptionalParams() []string { return []string{"header", "prefix"} }

func (g *GoogleOIDCAuth) ParseParams(m map[string]interface{}) (interface{}, error) {
	p, err := authplugins.ParseParams[inParams](m)
	if err != nil {
		return nil, err
	}
	if p.Audience == "" {
		return nil, fmt.Errorf("missing audience")
	}
	if p.Header == "" {
		p.Header = "Authorization"
	}
	if p.Prefix == "" {
		p.Prefix = "Bearer "
	}
	return p, nil
}

func parseToken(tok string) (map[string]interface{}, map[string]interface{}, []string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, nil, false
	}
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, false
	}
	var header map[string]interface{}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, nil, nil, false
	}
	pBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, false
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(pBytes, &claims); err != nil {
		return nil, nil, nil, false
	}
	return header, claims, parts, true
}

func matchAudience(claim interface{}, want string) bool {
	switch v := claim.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, elem := range v {
			if s, ok := elem.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func fetchKeys() error {
	resp, err := HTTPClient.Get(CertsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var data struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range data.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eBytes {
			e = e*256 + int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	exp := time.Now().Add(time.Hour)
	if cc := resp.Header.Get("Cache-Control"); strings.Contains(cc, "max-age=") {
		if i := strings.Index(cc, "max-age="); i >= 0 {
			var secs int
			if _, err := fmt.Sscanf(cc[i:], "max-age=%d", &secs); err == nil {
				exp = time.Now().Add(time.Duration(secs) * time.Second)
			}
		}
	} else if e := resp.Header.Get("Expires"); e != "" {
		if t, err := http.ParseTime(e); err == nil {
			exp = t
		}
	}
	keyCache.mu.Lock()
	keyCache.keys = keys
	keyCache.expiry = exp
	keyCache.mu.Unlock()
	return nil
}

func getKey(kid string) (*rsa.PublicKey, error) {
	keyCache.mu.RLock()
	needFetch := keyCache.keys == nil || time.Now().After(keyCache.expiry)
	keyCache.mu.RUnlock()
	if needFetch {
		fetchMu.Lock()
		// Check again in case another goroutine refreshed the cache.
		keyCache.mu.RLock()
		needFetch = keyCache.keys == nil || time.Now().After(keyCache.expiry)
		keyCache.mu.RUnlock()
		if needFetch {
			if err := fetchKeys(); err != nil {
				fetchMu.Unlock()
				return nil, err
			}
		}
		fetchMu.Unlock()
	}
	keyCache.mu.RLock()
	key, ok := keyCache.keys[kid]
	keyCache.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("key not found")
	}
	return key, nil
}

func verifyRS256(parts []string, key *rsa.PublicKey) bool {
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig) == nil
}

func parseAndVerify(tok string) (map[string]interface{}, bool) {
	header, claims, parts, ok := parseToken(tok)
	if !ok {
		return nil, false
	}
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if alg != "RS256" || kid == "" {
		return nil, false
	}
	key, err := getKey(kid)
	if err != nil {
		return nil, false
	}
	if !verifyRS256(parts, key) {
		return nil, false
	}
	return claims, true
}

func (g *GoogleOIDCAuth) Authenticate(ctx context.Context, r *http.Request, params interface{}) bool {
	cfg, ok := params.(*inParams)
	if !ok {
		return false
	}
	header := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(header, cfg.Prefix) {
		return false
	}
	token := strings.TrimPrefix(header, cfg.Prefix)
	claims, ok := parseAndVerify(token)
	if !ok {
		return false
	}
	if aud, ok := claims["aud"]; !ok || !matchAudience(aud, cfg.Audience) {
		return false
	}
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return false
		}
	}
	return true
}

// Identify returns the token's subject claim when present.
func (g *GoogleOIDCAuth) Identify(r *http.Request, params interface{}) (string, bool) {
	cfg, ok := params.(*inParams)
	if !ok {
		return "", false
	}
	header := r.Header.Get(cfg.Header)
	if !strings.HasPrefix(header, cfg.Prefix) {
		return "", false
	}
	token := strings.TrimPrefix(header, cfg.Prefix)
	claims, ok := parseAndVerify(token)
	if !ok {
		return "", false
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", false
	}
	return sub, true
}

// StripAuth removes the Authorization header from the request.
func (g *GoogleOIDCAuth) StripAuth(r *http.Request, params interface{}) {
	cfg, ok := params.(*inParams)
	if !ok {
		return
	}
	r.Header.Del(cfg.Header)
}

func init() { authplugins.RegisterIncoming(&GoogleOIDCAuth{}) }
