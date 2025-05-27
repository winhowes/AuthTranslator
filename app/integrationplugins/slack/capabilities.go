package slack

import "fmt"

import integrationplugins "github.com/winhowes/AuthTransformer/app/integrationplugins"

func init() {
	integrationplugins.RegisterCapability("slack", "post_public_as", integrationplugins.CapabilitySpec{
		Params: []string{"username"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			user, _ := p["username"].(string)
			if user == "" {
				return nil, fmt.Errorf("username required")
			}
			rule := integrationplugins.CallRule{Path: "/chat.postMessage", Methods: map[string]integrationplugins.RequestConstraint{"POST": {Body: map[string]interface{}{"username": user}}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("slack", "post_channels_as", integrationplugins.CapabilitySpec{
		Params: []string{"username", "channels"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			user, _ := p["username"].(string)
			ch, _ := p["channels"].([]interface{})
			if user == "" || len(ch) == 0 {
				return nil, fmt.Errorf("username and channels required")
			}
			allowed := make([]interface{}, len(ch))
			for i, c := range ch {
				allowed[i] = c
			}
			rule := integrationplugins.CallRule{Path: "/chat.postMessage", Methods: map[string]integrationplugins.RequestConstraint{"POST": {Body: map[string]interface{}{"username": user, "channel": allowed}}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
