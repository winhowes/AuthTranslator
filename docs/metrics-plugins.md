# Metrics Plugins

AuthTranslator exposes basic Prometheus metrics out of the box. When you need extra
counters or histograms, write a small **metrics plugin**. Plugins see every
request and response but never mutate them.

---

## Interface

```go
// app/metrics/registry.go
type Plugin interface {
    OnRequest(integration string, r *http.Request)
    OnResponse(integration, caller string, r *http.Request, resp *http.Response)
    WriteProm(w http.ResponseWriter)
}
```

`OnRequest` fires just before the proxy forwards a request upstream and
`OnResponse` runs once the upstream reply is received. `WriteProm` lets a plugin
append custom Prometheus metrics. The integration name is passed so you can
apply per-service logic.

---

## Writing your own plugin

1. Create `app/metrics/plugins/<name>`.
2. Implement the interface above.
3. Register it in `init()` with `metrics.Register(&MyPlugin{})`.
4. Build or run the proxy – registered plugins load automatically.

A minimal reference implementation lives in
[`app/metrics/plugins/example`](../app/metrics/plugins/example).

---

## Example – counting OpenAI tokens

The OpenAI API responds with a JSON body containing a `usage.total_tokens` field.
The plugin below keeps a simple in-memory total per caller ID passed in from the
proxy:

```go
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
```
Use the `totals` map to expose custom Prometheus counters or logs as needed.
`metrics.WriteProm` automatically iterates over all registered plugins and calls
their `WriteProm` method, so anything printed here will appear in the
`/_at_internal/metrics` endpoint. The plugin itself is responsible for storing
any counters; they live in memory and reset on restart.
