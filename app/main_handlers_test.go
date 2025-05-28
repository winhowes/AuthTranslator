package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"log/slog"
)

func resetIntegrations() {
	integrations.Lock()
	integrations.m = make(map[string]*Integration)
	integrations.Unlock()
}

func TestLoadAllowlistsValid(t *testing.T) {
	tmp, err := os.CreateTemp("", "allowlist*.json")
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

func TestIntegrationsHandlerCRUD(t *testing.T) {
	resetIntegrations()
	// POST
	integ := Integration{Name: "test", Destination: "http://example.com"}
	body, _ := json.Marshal(integ)
	req := httptest.NewRequest(http.MethodPost, "/integrations", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	integrationsHandler(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("post: expected 201 got %d", rr.Code)
	}

	// GET
	req = httptest.NewRequest(http.MethodGet, "/integrations", nil)
	rr = httptest.NewRecorder()
	integrationsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("get: expected 200 got %d", rr.Code)
	}
	var got []*Integration
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || len(got) != 1 || got[0].Name != "test" {
		t.Fatalf("get: unexpected body %s", rr.Body.String())
	}

	// PUT
	integ.Destination = "http://other.com"
	body, _ = json.Marshal(integ)
	req = httptest.NewRequest(http.MethodPut, "/integrations", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	integrationsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("put: expected 200 got %d", rr.Code)
	}

	// DELETE
	delReq := struct {
		Name string `json:"name"`
	}{Name: "test"}
	body, _ = json.Marshal(delReq)
	req = httptest.NewRequest(http.MethodDelete, "/integrations", bytes.NewReader(body))
	rr = httptest.NewRecorder()
	integrationsHandler(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204 got %d", rr.Code)
	}
	if _, ok := GetIntegration("test"); ok {
		t.Fatal("integration not deleted")
	}
}
