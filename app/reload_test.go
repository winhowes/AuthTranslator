package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/app/secrets"
	_ "github.com/winhowes/AuthTranslator/app/secrets/plugins"
)

func resetDenylistState() {
	denylists.Lock()
	denylists.m = make(map[string]map[string][]CallRule)
	denylists.Unlock()
}

func writeEmptyDenylist(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "dl*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.Name(), []byte("[]"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestReloadAllowlistStale(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

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
	if err := flag.Set("denylist", writeEmptyDenylist(t)); err != nil {
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
	resetDenylistState()

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
	if err := flag.Set("denylist", writeEmptyDenylist(t)); err != nil {
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
	oldDL := *denylistFile
	t.Cleanup(func() {
		flag.Set("config", oldCfg)
		flag.Set("denylist", oldDL)
	})
	resetDenylistState()
	flag.Set("config", "nonexistent.yaml")
	flag.Set("denylist", writeEmptyDenylist(t))
	if err := reload(); err == nil {
		t.Fatal("expected error for missing config")
	}
}

func TestReloadIntegrationError(t *testing.T) {
	// reset global state
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

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
	flag.Set("denylist", writeEmptyDenylist(t))
	if err := reload(); err == nil {
		t.Fatal("expected integration error")
	}

	if _, ok := GetIntegration("base"); !ok {
		t.Fatal("existing integration lost after failed reload")
	}
}

func TestReloadPrepareIntegrationErrorBranch(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

	cfgFile, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"Bad Name","destination":"http://example.com"}]}`
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
	flag.Set("denylist", writeEmptyDenylist(t))

	if err := reload(); err == nil {
		t.Fatal("expected prepareIntegration error")
	}

	integrations.RLock()
	if len(integrations.m) != 0 {
		integrations.RUnlock()
		t.Fatalf("expected integrations to remain empty, got %d", len(integrations.m))
	}
	integrations.RUnlock()
}

func TestReloadDuplicateIntegrationBranch(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

	cfgFile, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"dup","destination":"http://example.com"},{"name":"dup","destination":"http://example.org"}]}`
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
	flag.Set("denylist", writeEmptyDenylist(t))

	if err := reload(); err == nil {
		t.Fatal("expected duplicate integration error")
	}

	integrations.RLock()
	if len(integrations.m) != 0 {
		integrations.RUnlock()
		t.Fatalf("expected no integrations to be loaded, got %d", len(integrations.m))
	}
	integrations.RUnlock()
}

func TestReloadDenylistLoadError(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

	denylists.Lock()
	denylists.m["integration"] = map[string][]CallRule{"caller": {{}}}
	denylists.Unlock()

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

	dlFile, err := os.CreateTemp("", "dl*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dlFile.Name())
	if err := os.WriteFile(dlFile.Name(), []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	oldLogger := logger
	logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t.Cleanup(func() { logger = oldLogger })

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	flag.Set("denylist", dlFile.Name())

	if err := reload(); err != nil {
		t.Fatalf("reload should not fail on denylist decode error: %v", err)
	}

	if !strings.Contains(buf.String(), "failed to load denylist") {
		t.Fatalf("expected denylist load error to be logged, got %q", buf.String())
	}

	denylists.RLock()
	callers, ok := denylists.m["integration"]["caller"]
	denylists.RUnlock()
	if !ok || len(callers) == 0 {
		t.Fatal("existing denylist entries should be preserved on load error")
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
	resetDenylistState()

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
	flag.Set("denylist", writeEmptyDenylist(t))
	if err := reload(); err == nil {
		t.Fatal("expected allowlist validation error")
	}
}

func TestReloadInvalidDenylist(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

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

	dlFile, err := os.CreateTemp("", "dl*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dlFile.Name())
	dl := `[{"integration":"test","callers":[{"id":"*","rules":[{"path":"/a","methods":{"GET":{},"get":{}}}]}]}]`
	if err := os.WriteFile(dlFile.Name(), []byte(dl), 0644); err != nil {
		t.Fatal(err)
	}

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	flag.Set("denylist", dlFile.Name())
	if err := reload(); err == nil {
		t.Fatal("expected denylist validation error")
	}
}

func TestReloadDenylistMissing(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

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

	dlFile, err := os.CreateTemp("", "dl*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dlPath := dlFile.Name()
	if err := os.WriteFile(dlPath, []byte(`[{"integration":"test","callers":[{"id":"*","rules":[{"path":"/x","methods":{"GET":{}}}]}]}]`), 0644); err != nil {
		t.Fatal(err)
	}
	dlFile.Close()
	defer os.Remove(dlPath)

	if err := flag.Set("config", cfgFile.Name()); err != nil {
		t.Fatal(err)
	}
	if err := flag.Set("allowlist", alFile.Name()); err != nil {
		t.Fatal(err)
	}
	if err := flag.Set("denylist", dlPath); err != nil {
		t.Fatal(err)
	}

	if err := reload(); err != nil {
		t.Fatalf("initial reload failed: %v", err)
	}

	denylists.RLock()
	_, ok := denylists.m["test"]
	denylists.RUnlock()
	if !ok {
		t.Fatal("denylist entry missing after load")
	}

	os.Remove(dlPath)

	if err := reload(); err != nil {
		t.Fatalf("reload returned error: %v", err)
	}

	denylists.RLock()
	_, ok = denylists.m["test"]
	denylists.RUnlock()
	if !ok {
		t.Fatal("denylist entry lost after missing file reload")
	}
}

func TestReloadSetDenylistError(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

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

	dlFile, err := os.CreateTemp("", "dl*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dlFile.Name())
	if err := os.WriteFile(dlFile.Name(), []byte(`[{"integration":"test","callers":[{"id":"*","rules":[{"path":"/","methods":{"GET":{}}}]}]}]`), 0644); err != nil {
		t.Fatal(err)
	}

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	flag.Set("denylist", dlFile.Name())

	old := setDenylist
	setDenylist = func(string, []DenylistCaller) error { return fmt.Errorf("boom") }
	defer func() { setDenylist = old }()

	err = reload()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected boom error, got %v", err)
	}

	if _, ok := GetIntegration("test"); !ok {
		t.Fatal("integration not loaded")
	}
	denylists.RLock()
	_, ok := denylists.m["test"]
	denylists.RUnlock()
	if ok {
		t.Fatal("denylist should not be set on error")
	}

	for _, i := range ListIntegrations() {
		t.Cleanup(i.inLimiter.Stop)
		t.Cleanup(i.outLimiter.Stop)
	}
}

func TestReloadAllowlistMissing(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

	oldCfg := *configFile
	oldAL := *allowlistFile
	oldDL := *denylistFile
	t.Cleanup(func() {
		flag.Set("config", oldCfg)
		flag.Set("allowlist", oldAL)
		flag.Set("denylist", oldDL)
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
	if err := flag.Set("denylist", writeEmptyDenylist(t)); err != nil {
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

func TestReloadDuplicateIntegration(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

	cfgFile, err := os.CreateTemp("", "cfg*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cfgFile.Name())
	cfg := `{"integrations":[{"name":"dup","destination":"http://example.com"},{"name":"dup","destination":"http://example.com"}]}`
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
	flag.Set("denylist", writeEmptyDenylist(t))

	err = reload()
	if err == nil {
		t.Fatal("expected duplicate integration error")
	}
	if len(ListIntegrations()) != 0 {
		t.Fatal("integration map should remain empty on failure")
	}
}

func TestReloadRemoteSources(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

	cfg := `{"integrations":[{"name":"remote","destination":"http://example.com"}]}`
	al := `[]`
	dl := `[]`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cfg":
			w.Write([]byte(cfg))
		case "/al":
			w.Write([]byte(al))
		default:
			w.Write([]byte(dl))
		}
	}))
	defer srv.Close()

	oldCfgURL, oldALURL, oldDLURL := *configURL, *allowlistURL, *denylistURL
	t.Cleanup(func() {
		flag.Set("config-url", oldCfgURL)
		flag.Set("allowlist-url", oldALURL)
		flag.Set("denylist-url", oldDLURL)
	})
	flag.Set("config-url", srv.URL+"/cfg")
	flag.Set("allowlist-url", srv.URL+"/al")
	flag.Set("denylist-url", srv.URL+"/dl")

	if err := reload(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if _, ok := GetIntegration("remote"); !ok {
		t.Fatal("remote integration not loaded")
	}
}

func TestReloadSetAllowlistError(t *testing.T) {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
	allowlists.Lock()
	allowlists.m = make(map[string]map[string]CallerConfig)
	allowlists.Unlock()
	resetDenylistState()

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

	flag.Set("config", cfgFile.Name())
	flag.Set("allowlist", alFile.Name())
	flag.Set("denylist", writeEmptyDenylist(t))

	old := setAllowlist
	setAllowlist = func(string, []CallerConfig) error { return fmt.Errorf("boom") }
	defer func() { setAllowlist = old }()

	err = reload()
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected boom error, got %v", err)
	}

	if _, ok := GetIntegration("test"); !ok {
		t.Fatal("integration not loaded")
	}
	allowlists.RLock()
	_, ok := allowlists.m["test"]
	allowlists.RUnlock()
	if ok {
		t.Fatal("allowlist should not be set on error")
	}

	for _, i := range ListIntegrations() {
		t.Cleanup(i.inLimiter.Stop)
		t.Cleanup(i.outLimiter.Stop)
	}
}
