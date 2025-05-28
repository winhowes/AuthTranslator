package main

import (
	"flag"
	"os"
	"testing"
)

func TestReloadAllowlistStale(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	cfgFile, err := os.CreateTemp("", "cfg*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"test","destination":"http://example.com"}]}`
	if _, err := cfgFile.WriteString(cfg); err != nil {
		t.Fatal(err)
	}
	cfgFile.Close()

	alFile, err := os.CreateTemp("", "al*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(alFile.Name())
	al := `[{"integration":"test","callers":[{"id":"a","rules":[{"path":"/","methods":{"GET":{}}}]}]}]`
	if _, err := alFile.WriteString(al); err != nil {
		t.Fatal(err)
	}
	alFile.Close()

	if err := flag.Set("config", cfgFile.Name()); err != nil {
		t.Fatal(err)
	}
	if err := flag.Set("allowlist", alFile.Name()); err != nil {
		t.Fatal(err)
	}

	if err := reload(); err != nil {
		t.Fatalf("initial reload failed: %v", err)
	}

	allowlists.RLock()
	_, ok := allowlists.m["test"]["a"]
	allowlists.RUnlock()
	if !ok {
		t.Fatal("allowlist entry missing after load")
	}

	// corrupt allowlist file
	if err := os.WriteFile(alFile.Name(), []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := reload(); err != nil {
		t.Fatalf("reload with bad allowlist returned error: %v", err)
	}

	allowlists.RLock()
	_, ok = allowlists.m["test"]["a"]
	allowlists.RUnlock()
	if !ok {
		t.Fatal("allowlist entry lost after failed reload")
	}
}
