# Observability

AuthTranslator surfaces **health probes, Prometheus metrics, and structured logs** out‑of‑the‑box so you can plug it into your existing monitoring stack with minimal fuss.

---

## 1  Endpoints

| Path                    | Method | Purpose                                                                                               | Typical probe                         |
| ----------------------- | ------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `/_at_internal/healthz` | `GET`  | Liveness: returns **200 OK** once the HTTP server is up. No external deps are checked.                | Kubernetes `livenessProbe` every 10 s |
| `/_at_internal/metrics` | `GET`  | Exposes **Prometheus** text format. Includes Go runtime metrics and AuthTranslator‑specific counters. | Prometheus `scrape_interval` 15 s     |

The health endpoint is always available and returns an `X-Last-Reload` header
showing the most recent configuration reload time. The metrics endpoint is
exposed by default but can be disabled with `-enable-metrics=false`. Provide
`-metrics-user` and `-metrics-pass` to require HTTP Basic credentials.

---

## 2  Metrics cheat‑sheet

> The exact metric list is taken from code; field names below match what ships today.

| Metric                                    | Type      | Labels                | Description                                      |
| ----------------------------------------- | --------- | --------------------- | ------------------------------------------------ |
| `authtranslator_requests_total`           | counter   | `integration`         | Total requests processed per integration.        |
| `authtranslator_upstream_responses_total` | counter   | `integration`, `code` | HTTP status codes returned by upstreams.         |
| `authtranslator_request_duration_seconds` | histogram | `integration`         | Histogram of upstream request latency.           |
| `authtranslator_rate_limit_events_total`  | counter   | `integration`         | Incremented when a request is rejected with 429. |
| `authtranslator_auth_failures_total`      | counter   | `integration`         | Authentication plugin failures.                  |

Missing a metric? Write a small **metrics plugin** to hook into requests and responses or open a PR—new counters are easy to wire in. See [Metrics Plugins](metrics-plugins.md) for a primer.

---

## 3  Prometheus scrape example

```yaml
targets:
  - job_name: "authtranslator"
    metrics_path: "/_at_internal/metrics"
    static_configs:
      - targets: ["authtranslator.default.svc.cluster.local:8080"]
```

When running multiple replicas behind a Service or Load Balancer, prefer the **Prometheus ServiceMonitor** CRD (Kube‑Prometheus stack) or scrape via the node exporter.

---

## 4  Structured logs

The proxy logs in structured **text** by default. Pass
`-log-format json` to emit **JSON** using Go’s `slog`. Fields:

| Key           | Example                                      | Meaning                             |
| ------------- | -------------------------------------------- | ----------------------------------- |
| `level`       | `INFO` / `WARN` / `ERROR`                    | Log severity                        |
| `msg`         | `"incoming request"` / `"upstream response"` | Log message                         |
| `integration` | `"slack"`                                    | Integration block name              |
| `caller_id`   | `"user-123"`                                 | Identifier from incoming plugin     |
| `method`      | `"POST"`                                     | HTTP method (request log)           |
| `path`        | `"/api/chat.postMessage"`                    | Request path (request log)          |
| `status`      | `200`                                        | Upstream status code (response log) |

Sample line (wrapped for readability):

```json
{"time":"2025-05-29T07:00:12Z","level":"INFO","msg":"incoming request","method":"POST","integration":"slack","path":"/api/chat.postMessage","caller_id":"user-123"}
{"time":"2025-05-29T07:00:12Z","level":"INFO","msg":"upstream response","integration":"slack","status":200}
```

### Log level

- Default: **INFO**
- Override: run the proxy with `-log-level DEBUG` (adds request/response headers—secrets redacted)

---

## 5  Alerting pointers

| Alert                     | Expression                                                        | Rationale                        |
| ------------------------- | ----------------------------------------------------------------- | -------------------------------- |
| High 5xx rate             | `sum(rate(authtranslator_requests_total{code=~"5.."}[5m])) > 0.1` | Upstream failures or mis‑config. |
| Prolonged rate‑limit hits | `increase(authtranslator_rate_limit_events_total[5m]) > 100`      | Callers need higher quota.       |
| Health endpoint down      | Blackbox probe against `/_at_internal/healthz` fails              | Pod crash or network break.      |

Tune thresholds to your traffic patterns.
