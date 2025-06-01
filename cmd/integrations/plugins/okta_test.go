package plugins

import "testing"

func TestOktaIntegration(t *testing.T) {
	i := Okta("o", "okta.example.com/", "tok")
	if i.Destination != "https://okta.example.com/api/v1" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if got := i.OutgoingAuth[0].Params["prefix"]; got != "SSWS " {
		t.Fatalf("unexpected prefix: %v", got)
	}
}
