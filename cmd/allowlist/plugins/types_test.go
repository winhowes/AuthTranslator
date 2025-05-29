package plugins

import (
	"bytes"
	"reflect"
	"testing"

	yaml "gopkg.in/yaml.v3"
)

func TestRequestConstraintQueryRoundTrip(t *testing.T) {
	input := []byte(`
- integration: foo
  callers:
  - id: u1
    rules:
    - path: /x
      methods:
        GET:
          query:
            a: ["1"]
`)
	var entries []AllowlistEntry
	if err := yaml.Unmarshal(input, &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 1 || len(entries[0].Callers) != 1 {
		t.Fatalf("unexpected entries: %#v", entries)
	}
	q := entries[0].Callers[0].Rules[0].Methods["GET"].Query
	if !reflect.DeepEqual(q, map[string][]string{"a": {"1"}}) {
		t.Fatalf("query not parsed: %#v", q)
	}
	out, err := yaml.Marshal(entries)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(out, []byte("query:")) {
		t.Fatalf("query missing from output: %s", out)
	}
}
