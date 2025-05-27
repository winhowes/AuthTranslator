package secrets_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/winhowes/AuthTransformer/app/secrets"
	_ "github.com/winhowes/AuthTransformer/app/secrets/plugins"
)

func TestLoadSecretEnv(t *testing.T) {
	t.Setenv("MY_SECRET", "val")
	s, err := secrets.LoadSecret("env:MY_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "val" {
		t.Fatalf("expected 'val', got %s", s)
	}
}

func TestLoadSecretEnvMissing(t *testing.T) {
	if _, err := secrets.LoadSecret("env:UNSET_VAR"); err == nil {
		t.Fatal("expected error when variable is missing")
	}
}

func TestLoadSecretUnknown(t *testing.T) {
	if _, err := secrets.LoadSecret("unknown:id"); err == nil {
		t.Fatal("expected error for unknown secret source")
	}
}

func TestLoadRandomSecret(t *testing.T) {
	t.Setenv("A", "first")
	t.Setenv("B", "second")

	// Single reference
	val, err := secrets.LoadRandomSecret([]string{"env:A"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" {
		t.Fatalf("expected 'first', got %s", val)
	}

	// Multiple references - result should be one of the provided values
	val, err = secrets.LoadRandomSecret([]string{"env:A", "env:B"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "first" && val != "second" {
		t.Fatalf("unexpected value: %s", val)
	}
}

func TestLoadRandomSecretConcurrent(t *testing.T) {
	t.Setenv("A", "first")
	t.Setenv("B", "second")

	refs := []string{"env:A", "env:B"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, err := secrets.LoadRandomSecret(refs)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if val != "first" && val != "second" {
				t.Errorf("unexpected value: %s", val)
			}
		}()
	}
	wg.Wait()
}

func TestLoadSecretAWSKMS(t *testing.T) {
	// Prepare key
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))

	// Encrypt a value using the same algorithm as the plugin
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
	ct := gcm.Seal(nil, nonce, []byte("secret"), nil)
	ct = append(nonce, ct...)
	ref := "aws:" + base64.StdEncoding.EncodeToString(ct)

	val, err := secrets.LoadSecret(ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "secret" {
		t.Fatalf("expected 'secret', got %s", val)
	}
}
