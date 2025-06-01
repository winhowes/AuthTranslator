package plugins

import "testing"

func TestWorkdayIntegration(t *testing.T) {
	i := Workday("w", "work.example.com/", "tok")
	if i.Destination != "https://work.example.com/api" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if got := i.OutgoingAuth[0].Params["prefix"]; got != "Bearer " {
		t.Fatalf("unexpected prefix: %v", got)
	}
}
