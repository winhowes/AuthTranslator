package plugins_test

import (
	"testing"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/asana"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/datadog"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/ghe"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/github"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/gitlab"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/linear"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/monday"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/okta"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/openai"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/pagerduty"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/sendgrid"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/servicenow"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/stripe"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/trufflehog"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/twilio"
	_ "github.com/winhowes/AuthTranslator/app/integrations/plugins/zendesk"
)

type capSpec struct {
	name   string
	path   string
	method string
	params map[string]interface{}
}

func TestPluginCapabilities(t *testing.T) {
	tests := map[string][]capSpec{
		"asana": {
			{"create_task", "/tasks", "POST", nil},
			{"update_status", "/tasks/*", "PUT", nil},
			{"add_comment", "/tasks/*/stories", "POST", nil},
		},
		"datadog": {
			{"post_event", "/api/v2/events", "POST", nil},
			{"submit_metrics", "/api/v2/series", "POST", nil},
		},
		"ghe": {
			{"comment", "/repos/r/issues/*/comments", "POST", map[string]interface{}{"repo": "r"}},
			{"create_issue", "/repos/r/issues", "POST", map[string]interface{}{"repo": "r"}},
			{"update_issue", "/repos/r/issues/*", "PATCH", map[string]interface{}{"repo": "r"}},
		},
		"github": {
			{"comment", "/repos/r/issues/*/comments", "POST", map[string]interface{}{"repo": "r"}},
			{"create_issue", "/repos/r/issues", "POST", map[string]interface{}{"repo": "r"}},
			{"update_issue", "/repos/r/issues/*", "PATCH", map[string]interface{}{"repo": "r"}},
		},
		"gitlab": {
			{"comment", "/api/v4/projects/r/issues/*/notes", "POST", map[string]interface{}{"project": "r"}},
			{"create_issue", "/api/v4/projects/r/issues", "POST", map[string]interface{}{"project": "r"}},
			{"update_issue", "/api/v4/projects/r/issues/*", "PUT", map[string]interface{}{"project": "r"}},
		},
		"linear": {
			{"create_task", "/issues", "POST", nil},
			{"update_status", "/issues/*", "PATCH", nil},
			{"add_comment", "/issues/*/comments", "POST", nil},
		},
		"monday": {
			{"create_item", "/v2", "POST", nil},
			{"update_status", "/v2", "POST", nil},
			{"add_comment", "/v2", "POST", nil},
		},
		"okta": {
			{"create_user", "/api/v1/users", "POST", nil},
			{"update_user", "/api/v1/users/*", "PUT", nil},
			{"deactivate_user", "/api/v1/users/*/lifecycle/deactivate", "POST", nil},
		},
		"openai": {
			{"chat_completion", "/v1/chat/completions", "POST", nil},
			{"list_models", "/v1/models", "GET", nil},
			{"create_embedding", "/v1/embeddings", "POST", nil},
		},
		"pagerduty": {
			{"trigger_incident", "/incidents", "POST", nil},
			{"resolve_incident", "/incidents/*", "PUT", nil},
		},
		"sendgrid": {
			{"send_email", "/v3/mail/send", "POST", map[string]interface{}{"from": "me@example.com"}},
			{"manage_contacts", "/v3/marketing/contacts", "PUT", nil},
			{"update_template", "/v3/templates/*", "PATCH", nil},
		},
		"servicenow": {
			{"open_ticket", "/api/**/now/table/incident", "POST", nil},
			{"update_ticket", "/api/**/now/table/incident/*", "PATCH", nil},
			{"query_status", "/api/**/now/table/incident/*", "GET", nil},
		},
		"stripe": {
			{"create_charge", "/v1/charges", "POST", nil},
			{"refund_charge", "/v1/refunds", "POST", nil},
			{"create_customer", "/v1/customers", "POST", nil},
		},
		"trufflehog": {
			{"start_scan", "/api/v1/scan", "POST", nil},
			{"get_results", "/api/v1/results/*", "GET", nil},
			{"list_scans", "/api/v1/scans", "GET", nil},
		},
		"twilio": {
			{"send_sms", "/2010-04-01/Accounts/*/Messages.json", "POST", nil},
			{"make_call", "/2010-04-01/Accounts/*/Calls.json", "POST", nil},
			{"query_message", "/2010-04-01/Accounts/*/Messages/*", "GET", nil},
		},
		"zendesk": {
			{"open_ticket", "/api/v2/tickets", "POST", nil},
			{"update_ticket", "/api/v2/tickets/*", "PUT", nil},
			{"query_status", "/api/v2/tickets/*", "GET", nil},
		},
	}

	for integration, caps := range tests {
		got := integrationplugins.CapabilitiesFor(integration)
		if len(got) != len(caps) {
			t.Fatalf("%s capability count mismatch: got %d want %d", integration, len(got), len(caps))
		}
		for _, spec := range caps {
			capSpec, ok := got[spec.name]
			if !ok {
				t.Fatalf("%s missing capability %s", integration, spec.name)
			}
			rules, err := capSpec.Generate(spec.params)
			if err != nil {
				t.Fatalf("generate %s:%s error: %v", integration, spec.name, err)
			}
			if len(rules) != 1 {
				t.Fatalf("%s:%s expected 1 rule, got %d", integration, spec.name, len(rules))
			}
			r := rules[0]
			if r.Path != spec.path {
				t.Errorf("%s:%s path mismatch got %s want %s", integration, spec.name, r.Path, spec.path)
			}
			if _, ok := r.Methods[spec.method]; !ok {
				t.Errorf("%s:%s missing method %s", integration, spec.name, spec.method)
			}
		}
	}
}
