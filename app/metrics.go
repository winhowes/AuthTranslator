package main

import (
	"expvar"
	"fmt"
	"net/http"
)

var (
	requestCounts   = expvar.NewMap("authtranslator_requests_total")
	rateLimitCounts = expvar.NewMap("authtranslator_rate_limit_events_total")
)

func incRequest(integration string) {
	requestCounts.Add(integration, 1)
}

func incRateLimit(integration string) {
	rateLimitCounts.Add(integration, 1)
}

func metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	requestCounts.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "authtranslator_requests_total{integration=%q} %s\n", kv.Key, kv.Value.String())
	})
	rateLimitCounts.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "authtranslator_rate_limit_events_total{integration=%q} %s\n", kv.Key, kv.Value.String())
	})
}
