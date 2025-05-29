package plugins

import (
	"reflect"
	"testing"
)

func TestBuilders(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Integration
	}{
		{"asana", []string{"-name", "a", "-token", "tok"}, Asana("a", "tok")},
		{"github", []string{"-name", "gh", "-token", "tok", "-webhook-secret", "sec"}, GitHub("gh", "tok", "sec")},
		{"ghe", []string{"-name", "ghe1", "-domain", "corp.example.com", "-token", "tok", "-webhook-secret", "sec"}, GitHubEnterprise("ghe1", "corp.example.com", "tok", "sec")},
		{"gitlab", []string{"-name", "gl", "-token", "tok"}, GitLab("gl", "tok")},
		{"jira", []string{"-name", "j1", "-token", "tok"}, Jira("j1", "tok", "api.atlassian.com")},
		{"jira", []string{"-name", "j2", "-domain", "jira.example.com", "-token", "tok"}, Jira("j2", "tok", "jira.example.com")},
		{"confluence", []string{"-name", "c1", "-token", "tok"}, Confluence("c1", "tok", "api.atlassian.com")},
		{"confluence", []string{"-name", "c2", "-domain", "confluence.example.com", "-token", "tok"}, Confluence("c2", "tok", "confluence.example.com")},
		{"linear", []string{"-name", "lin", "-token", "tok"}, Linear("lin", "tok")},
		{"monday", []string{"-name", "mon", "-token", "tok"}, Monday("mon", "tok")},
		{"okta", []string{"-name", "ok", "-domain", "okta.example.com", "-token", "tok"}, Okta("ok", "okta.example.com", "tok")},
		{"sendgrid", []string{"-name", "sg", "-token", "tok"}, SendGrid("sg", "tok")},
		{"trufflehog", []string{"-name", "th", "-token", "tok"}, TruffleHog("th", "tok")},
		{"servicenow", []string{"-name", "sn", "-token", "tok"}, ServiceNow("sn", "tok")},
		{"slack", []string{"-name", "sl", "-token", "tok", "-signing-secret", "sec"}, Slack("sl", "tok", "sec")},
		{"stripe", []string{"-name", "st", "-token", "tok"}, Stripe("st", "tok")},
		{"twilio", []string{"-name", "tw", "-token", "tok"}, Twilio("tw", "tok")},
		{"workday", []string{"-name", "wd", "-domain", "work.example.com", "-token", "tok"}, Workday("wd", "work.example.com", "tok")},
		{"openai", []string{"-name", "oa", "-token", "tok"}, OpenAI("oa", "tok")},
		{"zendesk", []string{"-name", "zd", "-token", "tok"}, Zendesk("zd", "tok")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Get(tt.name)
			if b == nil {
				t.Fatalf("builder %s not registered", tt.name)
			}
			got, err := b(tt.args)
			if err != nil {
				t.Fatalf("builder returned error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("builder %s output mismatch\n got: %#v\nwant: %#v", tt.name, got, tt.want)
			}
		})
	}
}

func TestBuilderErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"asana", []string{}},
		{"ghe", []string{"-domain", "d", "-token", "t"}},
		{"slack", []string{"-token", "t"}},
		{"twilio", []string{}},
		{"workday", []string{"-token", "t"}},
	}
	for _, tt := range tests {
		b := Get(tt.name)
		if b == nil {
			t.Fatalf("builder %s not registered", tt.name)
		}
		if _, err := b(tt.args); err == nil {
			t.Errorf("%s: expected error for args %v", tt.name, tt.args)
		}
	}

	if Get("nonexistent") != nil {
		t.Errorf("expected nil builder for unknown plugin")
	}
}

func TestBuilderParseError(t *testing.T) {
	b := Get("asana")
	if b == nil {
		t.Fatalf("asana builder missing")
	}
	if _, err := b([]string{"-bogus"}); err == nil {
		t.Fatalf("expected parse error")
	}
}
