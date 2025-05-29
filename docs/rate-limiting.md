# Rate‑Limiting

AuthTranslator implements a **fixed‑window counter with elastic expiry** (aka *sliding window approximation*). Limits apply **per‑caller ID per integration** so noisy neighbours can’t starve other users of the same upstream service.

---

## How it works

1. When a request is authorised, the proxy builds a key: `<callerID>:<integration>`. If none of the inbound auth methods provide a caller ID, the client’s IP address is used instead.
2. It increments a counter in the chosen backend (**memory** or **Redis**).
3. If the counter ≤ *N* → continue. If it would exceed *N* → reject with **429**.
4. The counter’s TTL is extended to `window` seconds every time it’s incremented (elastic expiry).

This approximates a smooth sliding window while touching Redis once per request.

---

## Config fields

```yaml
integrations:
  slack:
    in_rate_limit:  100
    out_rate_limit: 800
    rate_limit_window: 1m
```

| Field               | Type     | Default | Notes |
| ------------------- | -------- | ------- | ------------------------------------------- |
| `in_rate_limit`     | int      | `0`     | Max inbound requests per caller within the window. |
| `out_rate_limit`    | int      | `0`     | Max outbound requests per caller within the window. |
| `rate_limit_window` | duration | `1m`    | Rolling window length for rate limiting. |


---

## Choosing a backend

| Backend  | Pros                            | Cons                                      | When to pick it                 |
| -------- | ------------------------------- | ----------------------------------------- | ------------------------------- |
| `memory` | Zero deps, fastest (\~100 ns)   | Not shared across pods, resets on restart | Local dev, single‑pod demo.     |
| `redis`  | Durable across restarts, shared | +0.2 ms per call; need Redis cluster      | Production / multiple replicas. |

**Redis URI** is configured via the `-redis-addr` flag (e.g., `-redis-addr redis://user:pass@host:6379/0`).

---

## Sizing formula

```
requests = ceiling( peak_rps × window_seconds )
```

Example: If a caller peaks at 12 RPS and you choose a 60 s window → `12 × 60 = 720` → round up to 800.

> Elastic expiry smooths bursts within the window, but if you see 5 × steady‑state spikes (e.g., cron jobs) pick a larger bucket or smaller window.

---

## Logs & metrics

* **Structured log** when a request is throttled:

  ```json
  {"lvl":"WARN","msg":"rate‑limit exceeded","caller_id":"bot‑123","integration":"slack","limit":800,"window":"60s"}
  ```
* Prometheus: `authtranslator_rate_limit_events_total{integration="slack"}`

Grafana sample dashboard lives in `docs/ops/grafana-rate-limits.json`.

---

## Future work

* Leaky‑bucket smoothing for less burst‑biased fairness.
* Back‑pressure headers (`Retry‑After`).
* Pluggable backends (Memcached / Cloud Spanner).
