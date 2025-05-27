package servicenow

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"

func init() {
	integrationplugins.RegisterCapability("servicenow", "open_ticket", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/**/now/table/incident", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("servicenow", "update_ticket", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/**/now/table/incident/*", Methods: map[string]integrationplugins.RequestConstraint{"PATCH": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("servicenow", "query_status", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/**/now/table/incident/*", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
