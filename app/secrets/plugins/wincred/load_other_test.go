//go:build !windows

package plugins

import "testing"

func TestLoadWindowsCredentialUnsupported(t *testing.T) {
	if _, err := loadWindowsCredential("target", "raw"); err == nil {
		t.Fatal("expected unsupported-platform error")
	}
}
