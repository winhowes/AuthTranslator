//go:build example

package example

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/winhowes/AuthTranslator/app/metrics"
)

type tokenCounter struct {
	mu     sync.Mutex
	totals map[string]uint64
}

func (t *tokenCounter) OnRequest(string, *http.Request) {}

func (t *tokenCounter) OnResponse(integ, caller string, r *http.Request, resp *http.Response) {
	if integ != "openai" {
		return
	}
	var body struct {
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return
	}
	t.mu.Lock()
	if t.totals == nil {
		t.totals = make(map[string]uint64)
	}
	t.totals[caller] += uint64(body.Usage.TotalTokens)
	t.mu.Unlock()
}

func (t *tokenCounter) WriteProm(w http.ResponseWriter) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for caller, total := range t.totals {
		fmt.Fprintf(w, "authtranslator_tokens_total{caller=%q} %d\n", caller, total)
	}
}

func init() { metrics.Register(&tokenCounter{}) }
