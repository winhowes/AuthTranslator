package gitlab

import (
	"fmt"
	integrationplugins "github.com/winhowes/AuthTransformer/app/integrationplugins"
)

func init() {
	integrationplugins.RegisterCapability("gitlab", "comment", integrationplugins.CapabilitySpec{
		Params: []string{"project"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			project, _ := p["project"].(string)
			if project == "" {
				return nil, fmt.Errorf("project parameter required")
			}
			path := fmt.Sprintf("/api/v4/projects/%s/issues/*/notes", project)
			rule := integrationplugins.CallRule{Path: path, Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("gitlab", "create_issue", integrationplugins.CapabilitySpec{
		Params: []string{"project"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			project, _ := p["project"].(string)
			if project == "" {
				return nil, fmt.Errorf("project parameter required")
			}
			path := fmt.Sprintf("/api/v4/projects/%s/issues", project)
			rule := integrationplugins.CallRule{Path: path, Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("gitlab", "update_issue", integrationplugins.CapabilitySpec{
		Params: []string{"project"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			project, _ := p["project"].(string)
			if project == "" {
				return nil, fmt.Errorf("project parameter required")
			}
			path := fmt.Sprintf("/api/v4/projects/%s/issues/*", project)
			rule := integrationplugins.CallRule{Path: path, Methods: map[string]integrationplugins.RequestConstraint{"PUT": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
