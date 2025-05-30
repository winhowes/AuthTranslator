package main

import (
	"bufio"
	"net"
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

// dummyWriter implements http.ResponseWriter without Flush or Hijack
// to test behavior when the underlying writer does not support them.
type dummyWriter struct{}

func (dummyWriter) Header() http.Header         { return make(http.Header) }
func (dummyWriter) Write(b []byte) (int, error) { return len(b), nil }
func (dummyWriter) WriteHeader(int)             {}

// hijackableRecorder records whether Hijack was called.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	called bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.called = true
	return nil, nil, nil
}

func TestStatusRecorderFlushForwarded(t *testing.T) {
	rr := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: rr}

	rec.Flush()

	if !rr.Flushed {
		t.Fatal("expected underlying writer to be flushed")
	}
}

func TestStatusRecorderFlushUnsupported(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: dummyWriter{}}

	// should not panic even though writer does not implement http.Flusher
	rec.Flush()
}

func TestStatusRecorderHijackForwarded(t *testing.T) {
	rr := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: rr}

	conn, buf, err := rec.Hijack()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn != nil || buf != nil {
		t.Fatalf("expected nil return values, got %v %v", conn, buf)
	}
	if !rr.called {
		t.Fatal("underlying hijacker not called")
	}
}

func TestStatusRecorderHijackUnsupported(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: dummyWriter{}}

	_, _, err := rec.Hijack()
	if err == nil {
		t.Fatal("expected error for unsupported hijacker")
	}
}

type notifyingRecorder struct {
	*httptest.ResponseRecorder
	ch chan bool
}

func (n *notifyingRecorder) CloseNotify() <-chan bool { return n.ch }

func TestStatusRecorderCloseNotifyForwarded(t *testing.T) {
	ch := make(chan bool, 1)
	rr := &notifyingRecorder{ResponseRecorder: httptest.NewRecorder(), ch: ch}
	rec := &statusRecorder{ResponseWriter: rr}

	got := rec.CloseNotify()
	if got != ch {
		t.Fatalf("expected channel %v, got %v", ch, got)
	}
}

func TestStatusRecorderCloseNotifyUnsupported(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: dummyWriter{}}
	select {
	case <-rec.CloseNotify():
		t.Fatal("unexpected close notification")
	default:
	}
}
