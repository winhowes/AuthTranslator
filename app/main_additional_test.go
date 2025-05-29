package main

import (
	"flag"
	"os"
	"testing"
	"time"
)

func TestRedisTTLArgsSeconds(t *testing.T) {
	cmd, val := redisTTLArgs(2 * time.Second)
	if cmd != "EXPIRE" || val != "2" {
		t.Fatalf("expected EXPIRE 2, got %s %s", cmd, val)
	}
}

func TestRedisTTLArgsSubMillisecond(t *testing.T) {
	cmd, val := redisTTLArgs(500 * time.Microsecond)
	if cmd != "PEXPIRE" || val != "1" {
		t.Fatalf("expected PEXPIRE 1 for sub-millisecond duration, got %s %s", cmd, val)
	}
}

func TestReloadAllowlistMissing(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	oldCfg := *configFile
	oldAL := *allowlistFile
	t.Cleanup(func() {
		flag.Set("config", oldCfg)
		flag.Set("allowlist", oldAL)
	})

	cfgFile, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"test","destination":"http://example.com"}]}`
	if _, err := cfgFile.WriteString(cfg); err != nil {
		t.Fatal(err)
	}
	cfgFile.Close()

	alFile, err := os.CreateTemp("", "al*.yaml")
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

	// Remove allowlist file to simulate missing file during reload
	os.Remove(alFile.Name())

	if err := reload(); err != nil {
		t.Fatalf("reload returned error: %v", err)
	}

	allowlists.RLock()
	_, ok = allowlists.m["test"]["a"]
	allowlists.RUnlock()
	if !ok {
		t.Fatal("allowlist entry lost after missing file reload")
	}
}
