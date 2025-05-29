package main

import (
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
