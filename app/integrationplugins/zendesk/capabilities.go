package zendesk

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"

func init() {
	integrationplugins.RegisterCapability("zendesk", "open_ticket", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/v2/tickets", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("zendesk", "update_ticket", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/v2/tickets/*", Methods: map[string]integrationplugins.RequestConstraint{"PUT": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("zendesk", "query_status", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/v2/tickets/*", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
