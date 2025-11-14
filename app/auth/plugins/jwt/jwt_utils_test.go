package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestParseHeaderPayloadErrors(t *testing.T) {
	// not enough parts
	if _, _, _, ok := parseHeaderPayload("abc"); ok {
		t.Fatal("expected failure for missing parts")
	}
	// invalid base64
	if _, _, _, ok := parseHeaderPayload("!.$.#"); ok {
		t.Fatal("expected failure for bad base64")
	}
	// invalid json
	h := base64.RawURLEncoding.EncodeToString([]byte("{"))
	p := base64.RawURLEncoding.EncodeToString([]byte("{"))
	if _, _, _, ok := parseHeaderPayload(h + "." + p + ".sig"); ok {
		t.Fatal("expected failure for bad json")
	}
	// valid token
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"foo":"bar"}`))
	_, claims, parts, ok := parseHeaderPayload(header + "." + payload + ".s")
	if !ok || parts[0] == "" || claims["foo"] != "bar" {
		t.Fatal("unexpected parse failure")
	}
}

func makeRS256Token(t *testing.T, key *rsa.PrivateKey) (string, []string) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(sig)
	tok := signingInput + "." + signature
	return tok, []string{header, payload, signature}
}

func TestVerifyRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tok, parts := makeRS256Token(t, key)
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if !verifyRS256(parts, pemBytes) {
		t.Fatal("expected verifyRS256 success")
	}
	// ensure PKCS#1 encoded keys are also accepted
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})
	if !verifyRS256(parts, pkcs1) {
		t.Fatal("expected verifyRS256 success for RSA PUBLIC KEY")
	}
	// modify signature to fail
	bad := []string{parts[0], parts[1], parts[2] + "bad"}
	if verifyRS256(bad, pemBytes) {
		t.Fatal("expected verifyRS256 failure")
	}
	// ensure parseHeaderPayload works with RS256 token
	if _, _, _, ok := parseHeaderPayload(tok); !ok {
		t.Fatal("token should parse")
	}
}

func TestMatchAudience(t *testing.T) {
	if !matchAudience("aud", "aud") {
		t.Fatal("string audience should match")
	}
	list := []interface{}{"x", "y"}
	if !matchAudience(list, "y") {
		t.Fatal("list audience should match")
	}
	if matchAudience(list, "z") {
		t.Fatal("unexpected match")
	}
	if matchAudience(123, "x") {
		t.Fatal("non string audience should not match")
	}
}

func TestJWTAuthParamsFuncs(t *testing.T) {
	j := &JWTAuth{}
	if len(j.RequiredParams()) != 1 || j.RequiredParams()[0] != "secrets" {
		t.Fatalf("unexpected required params: %v", j.RequiredParams())
	}
	opt := j.OptionalParams()
	if len(opt) != 4 {
		t.Fatalf("unexpected optional params: %v", opt)
	}
}

func TestVerifyRS256InvalidPem(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, parts := makeRS256Token(t, key)
	if verifyRS256(parts, []byte("not pem")) {
		t.Fatal("expected verifyRS256 to fail with bad pem")
	}
}

func TestParseHeaderPayloadMoreErrors(t *testing.T) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	if _, _, _, ok := parseHeaderPayload(h + ".???.sig"); ok {
		t.Fatal("expected payload decode error")
	}
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("{"))
	if _, _, _, ok := parseHeaderPayload(h + "." + badPayload + ".sig"); ok {
		t.Fatal("expected payload unmarshal error")
	}
}

func TestVerifyRS256ErrorPaths(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("bad")})
	if verifyRS256([]string{"a", "b", "c"}, pemBytes) {
		t.Fatal("expected parse error")
	}
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	pemEC := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if verifyRS256([]string{"a", "b", "c"}, pemEC) {
		t.Fatal("expected non RSA key failure")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, parts := makeRS256Token(t, key)
	if verifyRS256([]string{parts[0], parts[1], "!!"}, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})) {
		t.Fatal("expected signature decode failure")
	}
}
