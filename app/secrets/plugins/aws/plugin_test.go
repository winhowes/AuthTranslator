package plugins

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"
)

func encryptAWS(t *testing.T, key []byte, plaintext string) string {
	t.Helper()
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	ct = append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(ct)
}

func TestAWSKMSPluginLoad(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))

	id := encryptAWS(t, key, "secret")
	p := &awsKMSPlugin{}
	got, err := p.Load(context.Background(), id)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "secret" {
		t.Fatalf("expected 'secret', got %s", got)
	}
}

func TestAWSKMSPluginLoadMissingKey(t *testing.T) {
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), "deadbeef"); err == nil {
		t.Fatal("expected error when key missing")
	}
}

func TestAWSKMSPluginInvalidCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), "!!notbase64!!"); err == nil {
		t.Fatal("expected error for invalid ciphertext")
	}
}
