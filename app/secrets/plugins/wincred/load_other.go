//go:build !windows

package plugins

import "fmt"

func loadWindowsCredential(targetName, mode string) (string, error) {
	return "", fmt.Errorf("wincred plugin is only supported on windows")
}
