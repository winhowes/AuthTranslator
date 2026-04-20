//go:build !windows

package plugins

import "fmt"

func loadWindowsCredential(id string) (string, error) {
	return "", fmt.Errorf("wincred plugin is only supported on windows")
}
