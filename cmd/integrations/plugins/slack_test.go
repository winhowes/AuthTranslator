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
