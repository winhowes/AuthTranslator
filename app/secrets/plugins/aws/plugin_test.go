package plugins

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
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

func TestAWSKMSPluginInvalidKey(t *testing.T) {
	t.Setenv("AWS_KMS_KEY", "!!badbase64!!")
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), "cipher"); err == nil {
		t.Fatal("expected error for invalid key")
	}
}

func TestAWSKMSPluginBadKeyLength(t *testing.T) {
	key := make([]byte, 16)
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), "cipher"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestAWSKMSPluginShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))
	ct := base64.StdEncoding.EncodeToString([]byte("short"))
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), ct); err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestAWSKMSPluginDecryptFailure(t *testing.T) {
	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
	}
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key1))
	ct := encryptAWS(t, key2, "secret")
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), ct); err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestAWSKMSPluginCipherError(t *testing.T) {
	key := make([]byte, 32)
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))
	id := encryptAWS(t, key, "secret")
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), id); err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}
	old := newAESCipher
	newAESCipher = func([]byte) (cipher.Block, error) { return nil, fmt.Errorf("cipher err") }
	defer func() { newAESCipher = old }()
	if _, err := p.Load(context.Background(), id); err == nil {
		t.Fatal("expected cipher error")
	}
}

type badBlock struct{}

func (badBlock) BlockSize() int          { return 1 }
func (badBlock) Encrypt(dst, src []byte) {}
func (badBlock) Decrypt(dst, src []byte) {}

func TestAWSKMSPluginGCMError(t *testing.T) {
	key := make([]byte, 32)
	t.Setenv("AWS_KMS_KEY", base64.StdEncoding.EncodeToString(key))
	id := encryptAWS(t, key, "secret")
	p := &awsKMSPlugin{}
	if _, err := p.Load(context.Background(), id); err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}
	old := newAESCipher
	newAESCipher = func([]byte) (cipher.Block, error) { return badBlock{}, nil }
	defer func() { newAESCipher = old }()
	if _, err := p.Load(context.Background(), id); err == nil {
		t.Fatal("expected gcm error")
	}
}
