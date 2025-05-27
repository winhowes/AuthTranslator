package authplugins

import (
	"bytes"
	"encoding/json"
)

// ParseParams decodes the map into the provided struct type while
// disallowing unknown fields. The returned struct pointer will contain
// the parsed configuration.
func ParseParams[T any](m map[string]interface{}) (*T, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg T
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
