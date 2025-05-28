package main

import (
	"encoding/json"
	"expvar"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	requestCounts    = expvar.NewMap("authtranslator_requests_total")
	rateLimitCounts  = expvar.NewMap("authtranslator_rate_limit_events_total")
	requestDurations = expvar.NewMap("authtranslator_request_duration_seconds")
	lastReloadTime   = expvar.NewString("authtranslator_last_reload")
	durationHistsMu  sync.Mutex
	durationHists    = make(map[string]*histogram)
	durationBuckets  = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10}
)

type histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64
	sum     float64
}

func newHistogram() *histogram {
	return &histogram{
		buckets: durationBuckets,
		counts:  make([]uint64, len(durationBuckets)+1),
	}
}

func init() {
	lastReloadTime.Set(time.Now().Format(time.RFC3339))
}

func (h *histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	idx := sort.SearchFloat64s(h.buckets, v)
	h.counts[idx]++
	h.sum += v
}

func (h *histogram) totalCount() uint64 {
	var c uint64
	for _, n := range h.counts {
		c += n
	}
	return c
}

func (h *histogram) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	data := struct {
		Buckets map[string]uint64 `json:"buckets"`
		Sum     float64           `json:"sum"`
		Count   uint64            `json:"count"`
	}{
		Buckets: make(map[string]uint64),
		Sum:     h.sum,
		Count:   h.totalCount(),
	}
	var cum uint64
	for i, b := range h.buckets {
		cum += h.counts[i]
		data.Buckets[strconv.FormatFloat(b, 'f', -1, 64)] = cum
	}
	cum += h.counts[len(h.buckets)]
	data.Buckets["+Inf"] = cum
	buf, _ := json.Marshal(data)
	return string(buf)
}

func (h *histogram) writeProm(w http.ResponseWriter, integ string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var cum uint64
	for i, b := range h.buckets {
		cum += h.counts[i]
		fmt.Fprintf(w, "authtranslator_request_duration_seconds_bucket{integration=%q,le=%q} %d\n", integ, strconv.FormatFloat(b, 'f', -1, 64), cum)
	}
	cum += h.counts[len(h.buckets)]
	fmt.Fprintf(w, "authtranslator_request_duration_seconds_bucket{integration=%q,le=\"+Inf\"} %d\n", integ, cum)
	fmt.Fprintf(w, "authtranslator_request_duration_seconds_sum{integration=%q} %f\n", integ, h.sum)
	fmt.Fprintf(w, "authtranslator_request_duration_seconds_count{integration=%q} %d\n", integ, cum)
}

func incRequest(integration string) {
	requestCounts.Add(integration, 1)
}

func incRateLimit(integration string) {
	rateLimitCounts.Add(integration, 1)
}

func recordDuration(integration string, d time.Duration) {
	durationHistsMu.Lock()
	h, ok := durationHists[integration]
	if !ok {
		h = newHistogram()
		durationHists[integration] = h
		requestDurations.Set(integration, h)
	}
	durationHistsMu.Unlock()
	h.Observe(d.Seconds())
}

func metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	requestCounts.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "authtranslator_requests_total{integration=%q} %s\n", kv.Key, kv.Value.String())
	})
	durationHistsMu.Lock()
	for name, h := range durationHists {
		h.writeProm(w, name)
	}
	durationHistsMu.Unlock()
	rateLimitCounts.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "authtranslator_rate_limit_events_total{integration=%q} %s\n", kv.Key, kv.Value.String())
	})
}
