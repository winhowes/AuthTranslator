package workday

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"

func init() {
	integrationplugins.RegisterCapability("workday", "query_worker", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/api/**/workers/*", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
