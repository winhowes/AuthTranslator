package metrics

import (
	"errors"
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

type errReadCloser struct {
	err     error
	closed  bool
	readCnt int
}

func (e *errReadCloser) Read(_ []byte) (int, error) {
	e.readCnt++
	return 0, e.err
}

func (e *errReadCloser) Close() error {
	e.closed = true
	return nil
}

func TestGetResponseBodyReadError(t *testing.T) {
	readErr := errors.New("read error")
	erc := &errReadCloser{err: readErr}
	resp := &http.Response{Body: erc}

	data, err := GetResponseBody(resp)
	if !errors.Is(err, readErr) {
		t.Fatalf("expected read error, got %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil data on error, got %q", string(data))
	}
	if erc.closed {
		t.Fatalf("expected body not to be closed when read fails")
	}
	if resp.Body != erc {
		t.Fatalf("expected response body to remain unchanged on error")
	}
	if erc.readCnt == 0 {
		t.Fatalf("expected reader to be invoked")
	}
}
