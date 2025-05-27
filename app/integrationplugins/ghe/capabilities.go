package ghe

import (
	"fmt"
	integrationplugins "github.com/winhowes/AuthTranslator/app/integrationplugins"
)

func init() {
	integrationplugins.RegisterCapability("ghe", "comment", integrationplugins.CapabilitySpec{
		Params: []string{"repo"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			repo, _ := p["repo"].(string)
			if repo == "" {
				return nil, fmt.Errorf("repo parameter required")
			}
			path := fmt.Sprintf("/repos/%s/issues/*/comments", repo)
			rule := integrationplugins.CallRule{Path: path, Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("ghe", "create_issue", integrationplugins.CapabilitySpec{
		Params: []string{"repo"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			repo, _ := p["repo"].(string)
			if repo == "" {
				return nil, fmt.Errorf("repo parameter required")
			}
			path := fmt.Sprintf("/repos/%s/issues", repo)
			rule := integrationplugins.CallRule{Path: path, Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("ghe", "update_issue", integrationplugins.CapabilitySpec{
		Params: []string{"repo"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			repo, _ := p["repo"].(string)
			if repo == "" {
				return nil, fmt.Errorf("repo parameter required")
			}
			path := fmt.Sprintf("/repos/%s/issues/*", repo)
			rule := integrationplugins.CallRule{Path: path, Methods: map[string]integrationplugins.RequestConstraint{"PATCH": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
