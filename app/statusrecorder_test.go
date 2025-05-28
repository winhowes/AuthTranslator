package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusRecorderWriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	rec.WriteHeader(http.StatusTeapot)

	if rec.status != http.StatusTeapot {
		t.Fatalf("expected status %d, got %d", http.StatusTeapot, rec.status)
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("response writer code %d", rr.Code)
	}
}

func TestStatusRecorderWriteSetsDefault(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	if _, err := rec.Write([]byte("ok")); err != nil {
		t.Fatalf("write error: %v", err)
	}

	if rec.status != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.status)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("response writer code %d", rr.Code)
	}
}

func TestStatusRecorderWritePreservesStatus(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	rec.WriteHeader(http.StatusAccepted)
	if _, err := rec.Write([]byte("data")); err != nil {
		t.Fatalf("write error: %v", err)
	}

	if rec.status != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d", http.StatusAccepted, rec.status)
	}
	if rr.Code != http.StatusAccepted {
		t.Fatalf("response writer code %d", rr.Code)
	}
}
