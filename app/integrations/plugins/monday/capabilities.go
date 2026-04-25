package monday

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"

func operationName(p map[string]interface{}, fallback string) string {
	if p == nil {
		return fallback
	}
	name, _ := p["operationName"].(string)
	if name == "" {
		return fallback
	}
	return name
}

func operationRule(name string) integrationplugins.CallRule {
	return integrationplugins.CallRule{
		Path: "/v2",
		Methods: map[string]integrationplugins.RequestConstraint{
			"POST": {Body: map[string]interface{}{"operationName": name}},
		},
	}
}

func init() {
	integrationplugins.RegisterCapability("monday", "create_item", integrationplugins.CapabilitySpec{
		Params: []string{"operationName"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{operationRule(operationName(p, "create_item"))}, nil
		},
	})

	integrationplugins.RegisterCapability("monday", "update_status", integrationplugins.CapabilitySpec{
		Params: []string{"operationName"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{operationRule(operationName(p, "update_status"))}, nil
		},
	})

	integrationplugins.RegisterCapability("monday", "add_comment", integrationplugins.CapabilitySpec{
		Params: []string{"operationName"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			return []integrationplugins.CallRule{operationRule(operationName(p, "add_comment"))}, nil
		},
	})
}
