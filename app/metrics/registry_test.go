package metrics

import (
	"net/http"
	"testing"
)

// simple plugin that counts calls
type testPlugin struct {
	reqs  int
	resps int
}

func (p *testPlugin) OnRequest(integration string, r *http.Request) {
	p.reqs++
}

func (p *testPlugin) OnResponse(integration, caller string, r *http.Request, resp *http.Response) {
	p.resps++
}

func (*testPlugin) WriteProm(http.ResponseWriter) {}

type resetPlugin struct{ cleared bool }

func (*resetPlugin) OnRequest(string, *http.Request)                          {}
func (*resetPlugin) OnResponse(string, string, *http.Request, *http.Response) {}
func (*resetPlugin) WriteProm(http.ResponseWriter)                            {}
func (r *resetPlugin) ResetMetrics()                                          { r.cleared = true }

func TestRegistry(t *testing.T) {
	// save original state
	mu.Lock()
	saved := plugins
	mu.Unlock()
	Reset()
	t.Cleanup(func() {
		mu.Lock()
		plugins = saved
		mu.Unlock()
	})

	tp := &testPlugin{}
	Register(tp)

	req, _ := http.NewRequest(http.MethodGet, "http://example", nil)
	OnRequest("foo", req)
	OnResponse("foo", "caller", req, &http.Response{})

	if tp.reqs != 1 {
		t.Fatalf("expected 1 request call, got %d", tp.reqs)
	}
	if tp.resps != 1 {
		t.Fatalf("expected 1 response call, got %d", tp.resps)
	}
}

func TestResetClearsPlugins(t *testing.T) {
	mu.Lock()
	saved := plugins
	mu.Unlock()
	Reset()
	t.Cleanup(func() {
		mu.Lock()
		plugins = saved
		mu.Unlock()
	})

	rp := &resetPlugin{}
	Register(rp)
	Reset()
	if !rp.cleared {
		t.Fatal("reset did not call plugin ResetMetrics")
	}
}
