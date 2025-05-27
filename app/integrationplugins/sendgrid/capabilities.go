package sendgrid

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"

func init() {
	integrationplugins.RegisterCapability("sendgrid", "send_email", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/v3/mail/send", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
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
