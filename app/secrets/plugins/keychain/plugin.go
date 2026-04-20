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
	service, account := parseKeychainID(id)
	if service == "" {
		return "", fmt.Errorf("keychain service is required")
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

	return string(out), nil
}

func parseKeychainID(id string) (service, account string) {
	parts := strings.SplitN(id, "#", 2)
	service = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		account = strings.TrimSpace(parts[1])
	}
	return service, account
}

func init() { secrets.Register(keychainPlugin{}) }
