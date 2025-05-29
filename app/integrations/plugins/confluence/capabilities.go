package confluence

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"

func init() {
	integrationplugins.RegisterCapability("confluence", "create_page", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/wiki/api/v2/pages", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("confluence", "update_page", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/wiki/api/v2/pages/*", Methods: map[string]integrationplugins.RequestConstraint{"PUT": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("confluence", "add_comment", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/wiki/api/v2/pages/*/comment", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
