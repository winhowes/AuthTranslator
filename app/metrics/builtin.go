package metrics

import (
	"crypto/subtle"
	"encoding/json"
	"expvar"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// statusKeySeparator joins the integration name and HTTP status code when
// storing upstream counters in expvar. We intentionally pick a character that
// integrations cannot contain so parsing during Prometheus export stays
// unambiguous even after allowing dots and underscores in names.
const statusKeySeparator = "|"

var (
	requestCounts        = expvar.NewMap("authtranslator_requests_total")
	rateLimitCounts      = expvar.NewMap("authtranslator_rate_limit_events_total")
	authFailureCounts    = expvar.NewMap("authtranslator_auth_failures_total")
	upstreamStatusCounts = expvar.NewMap("authtranslator_upstream_responses_total")
	requestDurations     = expvar.NewMap("authtranslator_request_duration_seconds")
	LastReloadTime       = expvar.NewString("authtranslator_last_reload")
	durationHistsMu      sync.Mutex
	durationHists        = make(map[string]*histogram)
	durationBuckets      = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10}
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
	LastReloadTime.Set(time.Now().Format(time.RFC3339))
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

// IncRequest increments the request counter for the integration.
func IncRequest(integration string) { requestCounts.Add(integration, 1) }

// IncRateLimit increments the rate limit counter for the integration.
func IncRateLimit(integration string) { rateLimitCounts.Add(integration, 1) }

// IncAuthFailure increments the auth failure counter for the integration.
func IncAuthFailure(integration string) { authFailureCounts.Add(integration, 1) }

// RecordStatus records the upstream status code for the integration.
func RecordStatus(integration string, status int) {
	key := fmt.Sprintf("%s%s%d", integration, statusKeySeparator, status)
	upstreamStatusCounts.Add(key, 1)
}

// RecordDuration records the upstream request duration.
func RecordDuration(integration string, d time.Duration) {
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

// WriteProm emits all Prometheus metrics to w in text format.
func WriteProm(w http.ResponseWriter) {
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
	authFailureCounts.Do(func(kv expvar.KeyValue) {
		fmt.Fprintf(w, "authtranslator_auth_failures_total{integration=%q} %s\n", kv.Key, kv.Value.String())
	})
	upstreamStatusCounts.Do(func(kv expvar.KeyValue) {
		parts := strings.SplitN(kv.Key, statusKeySeparator, 2)
		if len(parts) != 2 {
			return
		}
		integ, code := parts[0], parts[1]
		fmt.Fprintf(w, "authtranslator_upstream_responses_total{integration=%q,code=%q} %s\n", integ, code, kv.Value.String())
	})

	mu.RLock()
	ps := append([]Plugin(nil), plugins...)
	mu.RUnlock()
	for _, p := range ps {
		p.WriteProm(w)
	}
}

// Handler writes Prometheus metrics to w enforcing optional basic auth.
func Handler(w http.ResponseWriter, r *http.Request, user, pass string) {
	if user != "" && pass != "" {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			w.Header().Set("X-AT-Upstream-Error", "false")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			http.Error(w, "Unauthorized: invalid metrics credentials", http.StatusUnauthorized)
			return
		}
	}
	WriteProm(w)
}
