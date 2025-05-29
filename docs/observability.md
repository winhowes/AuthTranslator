# Observability

AuthTranslator surfaces **health probes, Prometheus metrics, and structured logs** out‑of‑the‑box so you can plug it into your existing monitoring stack with minimal fuss.

---

## 1  Endpoints

| Path                    | Method | Purpose                                                                                               | Typical probe                         |
| ----------------------- | ------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------- |
| `/_at_internal/healthz` | `GET`  | Liveness: returns **200 OK** once the HTTP server is up. No external deps are checked.                | Kubernetes `livenessProbe` every 10 s |
| `/_at_internal/metrics` | `GET`  | Exposes **Prometheus** text format. Includes Go runtime metrics and AuthTranslator‑specific counters. | Prometheus `scrape_interval` 15 s     |

Both endpoints are always available; no extra flag is required.

---

## 2  Metrics cheat‑sheet

> The exact metric list is taken from code; field names below match what ships today.

| Metric                                     | Type      | Labels                     | Description                                                          |
| ------------------------------------------ | --------- | -------------------------- | -------------------------------------------------------------------- |
| `authtranslator_requests_total`            | counter   | `integration`, `code`      | Total proxied requests by upstream integration and HTTP status code. |
| `authtranslator_request_duration_seconds`  | histogram | `integration`              | Latency for upstream round‑trip (includes auth injection).           |
| `authtranslator_rate_limit_exceeded_total` | counter   | `integration`, `caller_id` | Incremented when a request is rejected with 429.                     |
| `authtranslator_auth_plugin_errors_total`  | counter   | `plugin`, `direction`      | Errors thrown by incoming/outgoing auth plugins.                     |
| `go_…`                                     | various   | –                          | Standard Go runtime metrics (GC, goroutines, heap).                  |

Missing a metric? Open an issue or PR—new counters are easy to wire in.

---

## 3  Prometheus scrape example

```yaml
targets:
  - job_name: 'authtranslator'
    metrics_path: '/_at_internal/metrics'
    static_configs:
      - targets: ['authtranslator.default.svc.cluster.local:8080']
```

When running multiple replicas behind a Service or Load Balancer, prefer the **Prometheus ServiceMonitor** CRD (Kube‑Prometheus stack) or scrape via the node exporter.

---

## 4  Structured logs

The proxy logs in **JSON** using Go’s `slog`. Fields:

| Key           | Example                   | Meaning                                                     |
| ------------- | ------------------------- | ----------------------------------------------------------- |
| `level`       | `INFO` / `WARN` / `ERROR` | Log severity                                                |
| `msg`         | `"forwarded request"`     | Human‑readable message                                      |
| `integration` | `"slack"`                 | Integration block name                                      |
| `caller_id`   | `"user‑123"`              | Identifier from incoming plugin                             |
| `request_id`  | `"c5ab…"`                 | 16‑byte random hex, shared across logs for a single request |
| `latency_ms`  | `12`                      | End‑to‑end upstream duration                                |

Sample line (wrapped for readability):

```json
{"time":"2025-05-29T07:00:12Z","level":"INFO","msg":"forwarded request",
 "integration":"slack","caller_id":"user-123","request_id":"c5ab78d0",
 "method":"POST","path":"/api/chat.postMessage","status":200,
 "latency_ms":78}
```

### Log level

* Default: **INFO**
* Override: `AUTH_TRANSLATOR_LOG_LEVEL=debug` (adds request/response headers—secrets redacted)

---

## 5  Alerting pointers

| Alert                     | Expression                                                        | Rationale                        |
| ------------------------- | ----------------------------------------------------------------- | -------------------------------- |
| High 5xx rate             | `sum(rate(authtranslator_requests_total{code=~"5.."}[5m])) > 0.1` | Upstream failures or mis‑config. |
| Prolonged rate‑limit hits | `increase(authtranslator_rate_limit_exceeded_total[5m]) > 100`    | Callers need higher quota.       |
| Health endpoint down      | Blackbox probe against `/_at_internal/healthz` fails              | Pod crash or network break.      |

Tune thresholds to your traffic patterns.
