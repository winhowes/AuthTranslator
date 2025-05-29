package main

import (
	"reflect"
	"testing"
)

type secretCfg struct {
	Secrets   []string
	Extra     []string `json:"SeCrEtS"`
	NotSlice  string   `json:"secrets"`
	NotString []int    `json:"sEcReTs"`
}

func TestCollectSecretRefs(t *testing.T) {
	cfg := &secretCfg{
		Secrets:   []string{"a", "b"},
		Extra:     []string{"c", "d"},
		NotSlice:  "x",
		NotString: []int{1, 2},
	}
	refs := collectSecretRefs(cfg)
	want := []string{"a", "b", "c", "d"}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("expected %v, got %v", want, refs)
	}
}

func TestCollectSecretRefsNonStruct(t *testing.T) {
	if refs := collectSecretRefs(42); refs != nil {
		t.Fatalf("expected nil, got %v", refs)
	}
}
