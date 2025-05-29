package twilio

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"

func init() {
	integrationplugins.RegisterCapability("twilio", "send_sms", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/2010-04-01/Accounts/*/Messages.json", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("twilio", "make_call", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/2010-04-01/Accounts/*/Calls.json", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("twilio", "query_message", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/2010-04-01/Accounts/*/Messages/*", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
