//go:build example

package example

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

func TestTokenCounter(t *testing.T) {
	metrics.Reset()
	tc := &tokenCounter{}
	metrics.Register(tc)

	body := `{"usage":{"total_tokens":42}}`
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(body))}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	tc.OnResponse("openai", "caller", req, resp)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(b) != body {
		t.Fatalf("expected body %q, got %q", body, string(b))
	}

	rr := httptest.NewRecorder()
	metrics.Handler(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil), "", "")
	if !strings.Contains(rr.Body.String(), `authtranslator_tokens_total{caller="caller"} 42`) {
		t.Fatalf("token metric missing: %s", rr.Body.String())
	}
}
