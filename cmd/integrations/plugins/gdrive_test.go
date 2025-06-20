package plugins

import "testing"

func TestGDriveIntegration(t *testing.T) {
	i := GDrive("d")
	if i.Destination != "https://www.googleapis.com/drive/v3" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if len(i.OutgoingAuth) != 1 || i.OutgoingAuth[0].Type != "gcp_token" {
		t.Fatalf("missing gcp_token auth")
	}
}
