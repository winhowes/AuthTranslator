package main

import (
	"encoding/json"
	"math"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHistogramString(t *testing.T) {
	h := newHistogram()
	h.Observe(0.2)
	h.Observe(1)

	var data struct {
		Buckets map[string]uint64 `json:"buckets"`
		Sum     float64           `json:"sum"`
		Count   uint64            `json:"count"`
	}
	if err := json.Unmarshal([]byte(h.String()), &data); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if math.Abs(data.Sum-1.2) > 1e-9 {
		t.Fatalf("expected sum 1.2, got %v", data.Sum)
	}
	if data.Count != 2 {
		t.Fatalf("expected count 2, got %d", data.Count)
	}

	want := map[string]uint64{
		"0.1":  0,
		"0.25": 1,
		"0.5":  1,
		"1":    2,
		"2.5":  2,
		"5":    2,
		"10":   2,
		"+Inf": 2,
	}
	if !reflect.DeepEqual(data.Buckets, want) {
		t.Fatalf("buckets mismatch: %#v", data.Buckets)
	}
}

func TestHistogramWriteProm(t *testing.T) {
	h := newHistogram()
	h.Observe(0.2)
	h.Observe(1)

	rr := httptest.NewRecorder()
	h.writeProm(rr, "foo")

	lines := strings.Split(strings.TrimSpace(rr.Body.String()), "\n")
	if len(lines) != 10 {
		t.Fatalf("expected 10 lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "le=\"0.1\"") || !strings.HasSuffix(lines[0], " 0") {
		t.Fatalf("unexpected first line: %s", lines[0])
	}
	if !strings.HasPrefix(lines[8], "authtranslator_request_duration_seconds_sum{integration=\"foo\"}") {
		t.Fatalf("missing sum line")
	}
	if !strings.HasSuffix(lines[9], " 2") {
		t.Fatalf("missing count line")
	}
}
