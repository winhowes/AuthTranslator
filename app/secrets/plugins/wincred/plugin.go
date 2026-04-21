package plugins

import (
	"context"
	"fmt"
	"strings"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// winCredPlugin loads generic credentials from Windows Credential Manager.
// id format:
//   - "target" (raw bytes)
//   - "target#utf8"
//   - "target#utf16le"
type winCredPlugin struct{}

func (winCredPlugin) Prefix() string { return "wincred" }

func (winCredPlugin) Load(ctx context.Context, id string) (string, error) {
	target, mode, err := parseWinCredID(id)
	if err != nil {
		return "", err
	}
	return loadWindowsCredential(target, mode)
}

func parseWinCredID(id string) (target, mode string, err error) {
	parts := strings.SplitN(strings.TrimSpace(id), "#", 2)
	target = strings.TrimSpace(parts[0])
	if target == "" {
		return "", "", fmt.Errorf("wincred target is required")
	}

	mode = "raw"
	if len(parts) == 2 {
		mode = strings.ToLower(strings.TrimSpace(parts[1]))
	}

	switch mode {
	case "raw", "utf8", "utf16le":
		return target, mode, nil
	default:
		return "", "", fmt.Errorf("unsupported wincred decode mode %q", mode)
	}
}

func init() { secrets.Register(winCredPlugin{}) }
