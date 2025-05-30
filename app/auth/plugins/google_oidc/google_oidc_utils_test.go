package googleoidc

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestParseExpiryValid(t *testing.T) {
	exp := time.Now().Add(2 * time.Hour).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":` + fmt.Sprint(exp) + `}`))
	tok := "header." + payload + ".sig"
	got := parseExpiry(tok)
	if got.Unix() != exp {
		t.Fatalf("expected %d, got %d", exp, got.Unix())
	}
}

func TestParseExpiryInvalid(t *testing.T) {
	now := time.Now()
	got := parseExpiry("bad")
	if got.Before(now) || got.After(now.Add(2*time.Minute)) {
		t.Fatalf("unexpected expiry %v", got)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"foo":123}`))
	tok := "header." + payload + ".sig"
	got2 := parseExpiry(tok)
	if got2.Before(now) || got2.After(now.Add(2*time.Minute)) {
		t.Fatalf("unexpected expiry %v", got2)
	}
}

func TestParseExpiryDecodeError(t *testing.T) {
	now := time.Now()
	tok := "h.!bad.sig"
	got := parseExpiry(tok)
	if got.Before(now) || got.After(now.Add(2*time.Minute)) {
		t.Fatalf("unexpected expiry %v", got)
	}
}

func TestTokenCache(t *testing.T) {
	tokenCache.Lock()
	tokenCache.m = make(map[string]cachedToken)
	tokenCache.Unlock()
	exp := time.Now().Add(time.Hour)
	setCachedToken("a", "tok", exp)
	tok, e := getCachedToken("a")
	if tok != "tok" || !e.Equal(exp) {
		t.Fatalf("cache get mismatch: %s %v", tok, e)
	}
	tok2, e2 := getCachedToken("missing")
	if tok2 != "" || !e2.IsZero() {
		t.Fatalf("expected empty for missing, got %s %v", tok2, e2)
	}
}

func TestParseTokenErrors(t *testing.T) {
	if _, _, _, ok := parseToken("abc"); ok {
		t.Fatal("expected failure for too few parts")
	}
	if _, _, _, ok := parseToken("!.!."); ok {
		t.Fatal("expected failure for bad base64")
	}
	bad := base64.RawURLEncoding.EncodeToString([]byte("{"))
	if _, _, _, ok := parseToken(bad + "." + bad + ".sig"); ok {
		t.Fatal("expected failure for bad json")
	}
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"a"}`))
	tok := h + "." + p + ".sig"
	header, claims, parts, ok := parseToken(tok)
	if !ok || header["alg"] != "RS256" || claims["aud"] != "a" || len(parts) != 3 {
		t.Fatal("unexpected parse result")
	}
}

func TestMatchAudienceExtras(t *testing.T) {
	list := []interface{}{"x", "y"}
	if !matchAudience(list, "y") {
		t.Fatal("expected match in list")
	}
	if matchAudience(list, "z") {
		t.Fatal("unexpected match")
	}
	if matchAudience(123, "x") {
		t.Fatal("non string should not match")
	}
}
