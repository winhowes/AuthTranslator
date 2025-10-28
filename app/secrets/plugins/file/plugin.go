package plugins

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/winhowes/AuthTranslator/app/secrets"
)

// filePlugin reads secrets from files on disk.
type filePlugin struct{}

func (filePlugin) Prefix() string { return "file" }

func (filePlugin) Load(ctx context.Context, id string) (string, error) {
	path, key := splitPathAndKey(id)

	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	if key == "" {
		return strings.TrimSpace(string(b)), nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		if k != key {
			continue
		}
		return strings.TrimSpace(parts[1]), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("secret %q not found in %s", key, path)
}

func splitPathAndKey(id string) (path, key string) {
	idx := strings.LastIndex(id, ":")
	if idx == -1 || idx+1 >= len(id) {
		return id, ""
	}

	suffix := id[idx+1:]
	if strings.ContainsAny(suffix, "/\\") {
		return id, ""
	}

	return id[:idx], suffix
}

func init() { secrets.Register(filePlugin{}) }
