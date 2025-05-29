package integrationplugins

import "testing"

func TestCapabilityGenerate(t *testing.T) {
	caps := AllCapabilities()
	for integ, m := range caps {
		if len(m) == 0 {
			t.Errorf("no capabilities for %s", integ)
			continue
		}
		for name, spec := range m {
			params := map[string]interface{}{}
			for _, p := range spec.Params {
				params[p] = "x"
			}
			rules, err := spec.Generate(params)
			if err != nil {
				t.Errorf("%s %s generate error: %v", integ, name, err)
				continue
			}
			if len(rules) == 0 {
				t.Errorf("%s %s returned no rules", integ, name)
			}
		}
	}
}
