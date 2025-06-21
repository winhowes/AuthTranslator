package slack

import (
	"fmt"

	integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"
)

func init() {
	integrationplugins.RegisterCapability("slack", "post_as", integrationplugins.CapabilitySpec{
		Params: []string{"username"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			user, _ := p["username"].(string)
			if user == "" {
				return nil, fmt.Errorf("username required")
			}
			rule := integrationplugins.CallRule{Path: "/api/chat.postMessage", Methods: map[string]integrationplugins.RequestConstraint{"POST": {Body: map[string]interface{}{"username": user}}}}
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
			rule := integrationplugins.CallRule{Path: "/api/chat.postMessage", Methods: map[string]integrationplugins.RequestConstraint{"POST": {Body: map[string]interface{}{"username": user, "channel": allowed}}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("slack", "post_channels", integrationplugins.CapabilitySpec{
		Params: []string{"channels"},
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			ch, _ := p["channels"].([]interface{})
			if len(ch) == 0 {
				return nil, fmt.Errorf("channels required")
			}
			allowed := make([]interface{}, len(ch))
			for i, c := range ch {
				allowed[i] = c
			}
			rule := integrationplugins.CallRule{Path: "/api/chat.postMessage", Methods: map[string]integrationplugins.RequestConstraint{"POST": {Body: map[string]interface{}{"channel": allowed}}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
