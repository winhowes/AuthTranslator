package plugins

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// secretServicePlugin reads secrets from Linux Secret Service using secret-tool.
// id must be comma-separated key/value pairs, e.g. "service=slack,user=bot".
type secretServicePlugin struct{}

var execSecretTool = func(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "secret-tool", args...)
	return cmd.Output()
}

func (secretServicePlugin) Prefix() string { return "secretservice" }

func (secretServicePlugin) Load(ctx context.Context, id string) (string, error) {
	attrs, err := parseSecretServiceAttrs(id)
	if err != nil {
		return "", err
	}

	args := []string{"lookup"}
	for _, attr := range attrs {
		args = append(args, attr[0], attr[1])
	}

	out, err := execSecretTool(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("secretservice lookup failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func parseSecretServiceAttrs(id string) ([][2]string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("secretservice attributes are required")
	}
	parts := strings.Split(id, ",")
	attrs := make([][2]string, 0, len(parts))
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid secretservice attribute %q", part)
		}
		k := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if k == "" || v == "" {
			return nil, fmt.Errorf("invalid secretservice attribute %q", part)
		}
		attrs = append(attrs, [2]string{k, v})
	}
	return attrs, nil
}

func init() { secrets.Register(secretServicePlugin{}) }
