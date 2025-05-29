package main

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func TestReloadAllowlistStale(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

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

func TestReloadClearsSecretCache(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

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
	if err := os.WriteFile(alFile.Name(), []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := flag.Set("config", cfgFile.Name()); err != nil {
		t.Fatal(err)
	}
	if err := flag.Set("allowlist", alFile.Name()); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CACHE_RELOAD_SECRET", "first")
	if _, err := secrets.LoadSecret(context.Background(), "env:CACHE_RELOAD_SECRET"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CACHE_RELOAD_SECRET", "second")
	if val, err := secrets.LoadSecret(context.Background(), "env:CACHE_RELOAD_SECRET"); err != nil {
		t.Fatal(err)
	} else if val != "first" {
		t.Fatalf("expected cached 'first', got %s", val)
	}

	if err := reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}

	val, err := secrets.LoadSecret(context.Background(), "env:CACHE_RELOAD_SECRET")
	if err != nil {
		t.Fatalf("unexpected error after reload: %v", err)
	}
	if val != "second" {
		t.Fatalf("expected 'second' after reload, got %s", val)
	}
}

func TestReloadMissingConfig(t *testing.T) {
	oldCfg := *configFile
	t.Cleanup(func() { flag.Set("config", oldCfg) })
	flag.Set("config", "nonexistent.yaml")
	if err := reload(); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestReloadIntegrationError(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()

	// add a valid integration that should survive the failed reload
	base := &Integration{Name: "base", Destination: "http://example.com"}
	if err := AddIntegration(base); err != nil {
		t.Fatalf("setup base integration: %v", err)
	}
	t.Cleanup(func() { base.inLimiter.Stop(); base.outLimiter.Stop() })

	cfgFile, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"bad","destination":"://"}]}`
	if _, err := cfgFile.WriteString(cfg); err != nil {
		t.Fatal(err)
	}
	cfgFile.Close()

	alFile, err := os.CreateTemp("", "al*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(alFile.Name())
	if err := os.WriteFile(alFile.Name(), []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	if err := reload(); err == nil {
		t.Fatal("expected integration error")
	}

	if _, ok := GetIntegration("base"); !ok {
		t.Fatal("existing integration lost after failed reload")
	}
}

func TestReloadInvalidAllowlist(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

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
	al := `[{"integration":"test","callers":[{"id":"a"},{"id":"a"}]}]`
	if err := os.WriteFile(alFile.Name(), []byte(al), 0644); err != nil {
		t.Fatal(err)
	}

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	if err := reload(); err == nil {
		t.Fatal("expected allowlist validation error")
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

func TestReloadInvalidAllowlistRollback(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()

	cfgFile, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"good","destination":"http://example.com"}]}`
	if _, err := cfgFile.WriteString(cfg); err != nil {
		t.Fatal(err)
	}
	cfgFile.Close()

	alFile, err := os.CreateTemp("", "al*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(alFile.Name())
	al := `[{"integration":"good","callers":[{"id":"*","rules":[{"path":"/","methods":{"GET":{}}}]}]}]`
	if _, err := alFile.WriteString(al); err != nil {
		t.Fatal(err)
	}
	alFile.Close()

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	if err := reload(); err != nil {
		t.Fatalf("initial reload failed: %v", err)
	}

	// modify files with new integration and invalid allowlist
	if err := os.WriteFile(cfgFile.Name(), []byte(`{"integrations":[{"name":"new","destination":"http://example.org"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alFile.Name(), []byte(`[{"integration":"new","callers":[{"id":"a"},{"id":"a"}]}]`), 0644); err != nil {
		t.Fatal(err)
	}

	if err := reload(); err == nil {
		t.Fatal("expected allowlist error")
	}

	if _, ok := GetIntegration("good"); !ok {
		t.Fatal("existing integration lost")
	}
	if _, ok := GetIntegration("new"); ok {
		t.Fatal("new integration applied despite error")
	}
	allowlists.RLock()
	_, ok := allowlists.m["good"]
	allowlists.RUnlock()
	if !ok {
		t.Fatal("allowlist removed after failed reload")
	}
}
