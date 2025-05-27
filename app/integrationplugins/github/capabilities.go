package github

import "fmt"

import integrationplugins "github.com/winhowes/AuthTransformer/app/integrationplugins"

func init() {
	integrationplugins.RegisterCapability("github", "comment", integrationplugins.CapabilitySpec{
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
}
