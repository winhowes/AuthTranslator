package plugins

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// keychainPlugin loads secrets from the macOS Keychain via the security CLI.
//
// Expected id formats:
//   - "service"
//   - "service#account"
type keychainPlugin struct{}

var execSecurityCommand = func(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "security", args...)
	return cmd.Output()
}

func (keychainPlugin) Prefix() string { return "keychain" }

func (keychainPlugin) Load(ctx context.Context, id string) (string, error) {
	service, account, err := parseKeychainID(id)
	if err != nil {
		return "", err
	}

	args := []string{"find-generic-password", "-w", "-s", service}
	if account != "" {
		args = append(args, "-a", account)
	}

	out, err := execSecurityCommand(ctx, args...)
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr := strings.TrimSpace(string(ee.Stderr))
			if stderr != "" {
				return "", fmt.Errorf("keychain lookup failed: %s", stderr)
			}
		}
		return "", fmt.Errorf("keychain lookup failed: %w", err)
	}

	return trimCommandLineTerminator(out), nil
}

func parseKeychainID(id string) (service, account string, err error) {
	parts := strings.SplitN(id, "#", 2)
	service = strings.TrimSpace(parts[0])
	if service == "" {
		return "", "", fmt.Errorf("keychain service is required")
	}
	if len(parts) == 2 {
		account = strings.TrimSpace(parts[1])
		if account == "" {
			return "", "", fmt.Errorf("keychain account is required when using service#account format")
		}
	}
	return service, account, nil
}

func trimCommandLineTerminator(out []byte) string {
	return strings.TrimSuffix(string(out), "\n")
}

func init() { secrets.Register(keychainPlugin{}) }
