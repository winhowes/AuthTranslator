package plugins

import "testing"

func TestJiraIntegrationDefaultDomain(t *testing.T) {
	i := Jira("j", "tok", "")
	if i.Destination != "https://api.atlassian.com" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if pref := i.OutgoingAuth[0].Params["prefix"]; pref != "Bearer " {
		t.Fatalf("unexpected prefix: %v", pref)
	}
}

func TestConfluenceIntegrationDefaultDomain(t *testing.T) {
	i := Confluence("c", "tok", "")
	if i.Destination != "https://api.atlassian.com" {
		t.Fatalf("unexpected destination: %s", i.Destination)
	}
	if pref := i.OutgoingAuth[0].Params["prefix"]; pref != "Bearer " {
		t.Fatalf("unexpected prefix: %v", pref)
	}
}
