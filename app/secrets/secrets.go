package secrets

import (
	"fmt"
	"os"
	"strings"
)

// LoadSecret resolves a secret reference.
// Supported formats:
//
//	env:VAR - load secret from environment variable VAR
//	gcp:<id>, aws:<id>, oracle:<id>, azure:<id> - would load from corresponding KMS.
//
// For KMS types this function returns a stub value for demonstration purposes.
func LoadSecret(ref string) (string, error) {
	parts := strings.SplitN(ref, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid secret reference: %s", ref)
	}
	source, id := parts[0], parts[1]
	switch source {
	case "env":
		return os.Getenv(id), nil
	case "gcp", "aws", "oracle", "azure":
		// In a real implementation this would fetch from the provider's KMS.
		return "kms-" + id, nil
	default:
		return "", fmt.Errorf("unknown secret source: %s", source)
	}
}
