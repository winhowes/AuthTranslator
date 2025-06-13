package sendgrid

import (
	"fmt"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
)

func init() {
	integrationplugins.RegisterCapability("sendgrid", "send_email", integrationplugins.CapabilitySpec{
		Params: []string{"from", "replyTo"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			from, _ := p["from"].(string)
			if from == "" {
				return nil, fmt.Errorf("from parameter required")
			}
			reply, replyOK := p["replyTo"]
			body := map[string]interface{}{"from": from}
			if replyOK {
				body["reply_to"] = reply
			} else {
				body["reply_to"] = []interface{}{from, nil}
			}
			rule := integrationplugins.CallRule{Path: "/v3/mail/send", Methods: map[string]integrationplugins.RequestConstraint{"POST": {Body: body}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("sendgrid", "manage_contacts", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/v3/marketing/contacts", Methods: map[string]integrationplugins.RequestConstraint{"PUT": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("sendgrid", "update_template", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/v3/templates/*", Methods: map[string]integrationplugins.RequestConstraint{"PATCH": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
