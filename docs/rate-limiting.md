# Rate‑Limiting

AuthTranslator defaults to a **fixed-window counter**. Inbound limits apply per integration and caller ID, or per integration and client IP when no caller ID is available. Outbound limits apply per integration host. The schema allows choosing between `fixed_window`, `token_bucket`, and `leaky_bucket` strategies for different workloads.

---

## How it works

1. After incoming auth succeeds, the proxy builds an inbound key from the integration and caller ID. If none of the inbound auth methods provide a caller ID, the client IP address is used instead.
2. It increments a counter in the chosen backend (**memory** or **Redis**).
3. If the counter ≤ *N* → continue. If it would exceed *N* → reject with **429**.
4. It separately checks the outbound limit using the integration host as the key.

---

## Config fields

```yaml
integrations:
  - name: slack
    in_rate_limit:  100
    out_rate_limit: 800
    rate_limit_window: 1m
```

| Field               | Type     | Default | Notes |
| ------------------- | -------- | ------- | ------------------------------------------- |
| `in_rate_limit`     | int      | `0`     | Max inbound requests per caller ID, or client IP when no caller ID is available, within the window. |
| `out_rate_limit`    | int      | `0`     | Max outbound requests per integration host within the window. |
| `rate_limit_window` | duration | `1m`    | Window length for rate limiting. |
| `rate_limit_strategy` | string | `fixed_window` | Algorithm to apply (`fixed_window`, `token_bucket`, or `leaky_bucket`). |

### Strategies

`fixed_window` resets counters every `rate_limit_window`.
`token_bucket` allows bursts up to the limit and refills steadily over the same window.
`leaky_bucket` leaks requests at a steady rate so bursts above the limit are smoothed rather than rejected outright.

---

## Choosing a backend

| Backend  | Pros                            | Cons                                      | When to pick it                 |
| -------- | ------------------------------- | ----------------------------------------- | ------------------------------- |
| `memory` | Zero deps, fastest (\~100 ns)   | Not shared across pods, resets on restart | Local dev, single‑pod demo.     |
| `redis`  | Durable across restarts, shared | +0.2 ms per call; need Redis cluster      | Production / multiple replicas. |

**Redis address** is configured via the `-redis-addr` flag. This accepts either
`host:port` or a `redis://`/`rediss://` URL with optional `user:pass@` credentials.

---

## Sizing formula

```
requests = ceiling( peak_rps × window_seconds )
```

Example: If a caller peaks at 12 RPS and you choose a 60 s window → `12 × 60 = 720` → round up to 800.

> For bursty workloads, consider `token_bucket` or `leaky_bucket` instead of raising a fixed-window limit far above steady-state traffic.

---

## Back‑pressure headers

When a request is throttled the proxy sets a `Retry‑After` header with the number of seconds until the caller may try again.

---

## Logs & metrics

* **Structured log** when a request is throttled:

  ```json
  {"level":"WARN","msg":"caller exceeded rate limit","caller":"bot-123","host":"slack"}
  ```
* Prometheus: `authtranslator_rate_limit_events_total{integration="slack"}`

Grafana sample dashboard lives in [`docs/ops/grafana-rate-limits.json`](ops/grafana-rate-limits.json).
