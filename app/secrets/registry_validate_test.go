package secrets_test

import (
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestValidateSecretOK(t *testing.T) {
	if err := secrets.ValidateSecret("env:FOO"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSecretUnknown(t *testing.T) {
	if err := secrets.ValidateSecret("bogus:FOO"); err == nil {
		t.Fatal("expected error for unknown prefix")
	}
}

func TestValidateSecretBadFormat(t *testing.T) {
	if err := secrets.ValidateSecret("missingcolon"); err == nil {
		t.Fatal("expected error for invalid reference")
	}
}
