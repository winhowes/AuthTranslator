package plugins

import (
	"reflect"
	"testing"
)

// Test that plugin init functions register their capabilities into the registry.
func TestRegistryInitialization(t *testing.T) {
	list := List()
	if len(list) == 0 {
		t.Fatalf("registry is empty")
	}
	slack, ok := list["slack"]
	if !ok {
		t.Fatalf("slack capabilities missing")
	}
	if spec, ok := slack["post_public_as"]; !ok {
		t.Fatalf("post_public_as capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"username"}) {
		t.Fatalf("unexpected post_public_as params: %v", spec.Params)
	}
	if spec, ok := slack["post_channels_as"]; !ok {
		t.Fatalf("post_channels_as capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"username", "channels"}) {
		t.Fatalf("unexpected post_channels_as params: %v", spec.Params)
	}

	github, ok := list["github"]
	if !ok {
		t.Fatalf("github capabilities missing")
	}
	if spec, ok := github["comment"]; !ok {
		t.Fatalf("github comment capability missing")
	} else if !reflect.DeepEqual(spec.Params, []string{"repo"}) {
		t.Fatalf("unexpected github comment params: %v", spec.Params)
	}
}
