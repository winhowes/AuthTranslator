package metrics

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestGetResponseBody(t *testing.T) {
	body := "hello"
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(body))}
	data, err := GetResponseBody(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != body {
		t.Fatalf("expected body %q, got %q", body, string(data))
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading reset body: %v", err)
	}
	if string(b) != body {
		t.Fatalf("expected reset body %q, got %q", body, string(b))
	}
}

func TestGetResponseBodyNil(t *testing.T) {
	if b, err := GetResponseBody(nil); err != nil || b != nil {
		t.Fatalf("expected nil body, nil err; got %v, %v", b, err)
	}
}
