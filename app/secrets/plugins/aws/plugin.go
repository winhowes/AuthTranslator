package plugins

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"os"
	"sync"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// awsKMSPlugin decrypts secrets using a symmetric key provided via the
// AWS_KMS_KEY environment variable. The ciphertext must be base64 encoded and
// include a 12 byte nonce prefix followed by the encrypted data. This is not a
// real AWS KMS integration but provides basic encryption semantics for tests.
type awsKMSPlugin struct {
	once sync.Once
	key  []byte
	err  error
}

func (p *awsKMSPlugin) init() {
	keyB64 := os.Getenv("AWS_KMS_KEY")
	if keyB64 == "" {
		p.err = fmt.Errorf("AWS_KMS_KEY not set")
		return
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		p.err = fmt.Errorf("invalid AWS_KMS_KEY: %w", err)
		return
	}
	if len(key) != 32 {
		p.err = fmt.Errorf("AWS_KMS_KEY must decode to 32 bytes")
		return
	}
	p.key = key
}

func (p *awsKMSPlugin) Prefix() string { return "aws" }

func (p *awsKMSPlugin) Load(ctx context.Context, id string) (string, error) {
	p.once.Do(p.init)
	if p.err != nil {
		return "", p.err
	}

	ct, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext: %w", err)
	}
	if len(ct) < 12 {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce := ct[:12]
	data := ct[12:]

	block, err := aes.NewCipher(p.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	pt, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func init() { secrets.Register(&awsKMSPlugin{}) }
