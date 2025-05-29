package openai

import integrationplugins "github.com/winhowes/AuthTranslator/app/integrations"

func init() {
	integrationplugins.RegisterCapability("openai", "chat_completion", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/v1/chat/completions", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("openai", "list_models", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/v1/models", Methods: map[string]integrationplugins.RequestConstraint{"GET": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})

	integrationplugins.RegisterCapability("openai", "create_embedding", integrationplugins.CapabilitySpec{
		Generate: func(p map[string]interface{}) ([]integrationplugins.CallRule, error) {
			rule := integrationplugins.CallRule{Path: "/v1/embeddings", Methods: map[string]integrationplugins.RequestConstraint{"POST": {}}}
			return []integrationplugins.CallRule{rule}, nil
		},
	})
}
