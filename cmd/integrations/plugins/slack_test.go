package plugins

import "testing"

func TestSlackIntegration(t *testing.T) {
	i := Slack("s", "tok", "sign")
	if i.Name != "s" || i.Destination == "" {
		t.Fatalf("unexpected integration: %+v", i)
	}
	if len(i.IncomingAuth) != 1 || len(i.OutgoingAuth) != 1 {
		t.Fatalf("auth config missing")
	}
}

func TestOktaIntegration(t *testing.T) {
	i := Okta("o", "okta.example.com/", "tok")
	if i.Destination != "https://okta.example.com/api/v1" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if got := i.OutgoingAuth[0].Params["prefix"]; got != "SSWS " {
		t.Fatalf("unexpected prefix: %v", got)
	}
}

func TestWorkdayIntegration(t *testing.T) {
	i := Workday("w", "work.example.com/", "tok")
	if i.Destination != "https://work.example.com/api" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if got := i.OutgoingAuth[0].Params["prefix"]; got != "Bearer " {
		t.Fatalf("unexpected prefix: %v", got)
	}
}
