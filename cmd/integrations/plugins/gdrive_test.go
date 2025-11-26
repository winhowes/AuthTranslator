package plugins

import (
	"reflect"
	"testing"
)

func TestGDriveIntegration(t *testing.T) {
	i := GDrive("d")
	if i.Destination != "https://www.googleapis.com/drive/v3" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if len(i.OutgoingAuth) != 1 || i.OutgoingAuth[0].Type != "gcp_token" {
		t.Fatalf("missing gcp_token auth")
	}
}

func TestGDriveBuilder(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected Integration
	}{
		{"default name", []string{}, GDrive("gdrive")},
		{"custom name", []string{"-name", "custom"}, GDrive("custom")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gdriveBuilder(tt.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("unexpected builder output: %#v", got)
			}
		})
	}
}

func TestGDriveBuilderError(t *testing.T) {
	if _, err := gdriveBuilder([]string{"-bogus"}); err == nil {
		t.Fatalf("expected error for invalid flag")
	}
}
