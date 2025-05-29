package authplugins

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// errReadCloser returns an error on Read to ensure GetBody does not read
// from the request body when the value is already cached in the context.
type errReadCloser struct{}

func (errReadCloser) Read(p []byte) (int, error) { return 0, errors.New("should not read") }
func (errReadCloser) Close() error               { return nil }

func TestGetBodyCachesAndResets(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewBufferString("hello"))

	b, err := GetBody(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(b) != "hello" {
		t.Fatalf("expected body 'hello', got %q", string(b))
	}

	// Body should be reset so it can be read again
	rb, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("unexpected error reading body: %v", err)
	}
	if string(rb) != "hello" {
		t.Fatalf("expected body 'hello' after reset, got %q", string(rb))
	}

	// Replace body with an erroring reader to verify caching.
	// GetBody should return the cached value without reading r.Body.
	r.Body = errReadCloser{}

	b2, err := GetBody(r)
	if err != nil {
		t.Fatalf("unexpected error on cached read: %v", err)
	}
	if string(b2) != "hello" {
		t.Fatalf("expected cached body 'hello', got %q", string(b2))
	}
}

func TestGetBodyReadError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "http://example.com", nil)
	r.Body = errReadCloser{}

	if _, err := GetBody(r); err == nil {
		t.Fatal("expected error reading body")
	}
}

func TestGetBodyTooLarge(t *testing.T) {
	large := make([]byte, MaxBodySize+1)
	r := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer(large))
	if _, err := GetBody(r); err == nil {
		t.Fatal("expected error for large body")
	}
}

func TestGetBodyCustomLimit(t *testing.T) {
	old := MaxBodySize
	MaxBodySize = 5
	defer func() { MaxBodySize = old }()

	r := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewBufferString("abcdef"))
	if _, err := GetBody(r); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("expected ErrBodyTooLarge, got %v", err)
	}
}

func TestGetBodyUnlimited(t *testing.T) {
	old := MaxBodySize
	large := make([]byte, int(old+1))
	MaxBodySize = 0
	defer func() { MaxBodySize = old }()

	r := httptest.NewRequest(http.MethodPost, "http://example.com", bytes.NewBuffer(large))
	b, err := GetBody(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b) != len(large) {
		t.Fatalf("expected body length %d, got %d", len(large), len(b))
	}
}
