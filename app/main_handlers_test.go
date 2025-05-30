package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"log/slog"
)

func TestLoadAllowlistsValid(t *testing.T) {
	tmp, err := os.CreateTemp("", "allowlist*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	data := `[{"integration":"foo","callers":[{"id":"bar","rules":[{"path":"/","methods":{"GET":{}}}]}]}]`
	if _, err := tmp.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	al, err := loadAllowlists(tmp.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(al) != 1 || al[0].Integration != "foo" {
		t.Fatalf("unexpected allowlist %+v", al)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"INFO":  slog.LevelInfo,
		"Warn":  slog.LevelWarn,
		"ERROR": slog.LevelError,
		"bogus": slog.LevelInfo,
	}
	for s, want := range cases {
		if got := parseLevel(s); got != want {
			t.Errorf("parseLevel(%q)=%v want %v", s, got, want)
		}
	}
}

func TestMetricsHandlerUnauthorized(t *testing.T) {
	oldUser, oldPass := *metricsUser, *metricsPass
	*metricsUser = "admin"
	*metricsPass = "secret"
	defer func() { *metricsUser = oldUser; *metricsPass = oldPass }()

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	rr := httptest.NewRecorder()
	metricsHandler(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate header")
	}
}

func TestMetricsHandlerAuthorized(t *testing.T) {
	oldUser, oldPass := *metricsUser, *metricsPass
	*metricsUser = "admin"
	*metricsPass = "secret"
	defer func() { *metricsUser = oldUser; *metricsPass = oldPass }()

	req := httptest.NewRequest(http.MethodGet, "/_at_internal/metrics", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	metricsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
