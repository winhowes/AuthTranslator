package main

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validateBodySchemaDefinition(schema map[string]interface{}) error {
	if len(schema) == 0 {
		return nil
	}
	_, err := compileBodySchema(schema)
	return err
}

func validateBodySchema(schema map[string]interface{}, data interface{}) (bool, string) {
	if len(schema) == 0 {
		return true, ""
	}
	compiled, err := compileBodySchema(schema)
	if err != nil {
		return false, fmt.Sprintf("invalid body schema: %v", err)
	}
	if err := compiled.Validate(data); err != nil {
		return false, fmt.Sprintf("body schema mismatch: %v", err)
	}
	return true, ""
}

func compileBodySchema(schema map[string]interface{}) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft7)
	if err := compiler.AddResource("body-schema.json", schema); err != nil {
		return nil, err
	}
	return compiler.Compile("body-schema.json")
}

func decodeJSONBody(bodyBytes []byte) (interface{}, error) {
	var data interface{}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, err
	}
	return data, nil
}

func formValuesToJSON(vals url.Values) map[string]interface{} {
	data := make(map[string]interface{}, len(vals))
	for k, v := range vals {
		if len(v) == 1 {
			data[k] = v[0]
			continue
		}
		converted := make([]interface{}, len(v))
		for i, value := range v {
			converted[i] = value
		}
		data[k] = converted
	}
	return data
}
