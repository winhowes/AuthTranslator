# Rate‑Limiting

AuthTranslator defaults to a **fixed‑window counter with elastic expiry** (aka *sliding window approximation*). Limits apply **per‑caller ID per integration** so noisy neighbours can’t starve other users of the same upstream service. The schema allows choosing between `fixed_window`, `token_bucket`, and `leaky_bucket` strategies for different workloads.

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
  - name: slack
    in_rate_limit:  100
    out_rate_limit: 800
    rate_limit_window: 1m
```

| Field               | Type     | Default | Notes |
| ------------------- | -------- | ------- | ------------------------------------------- |
| `in_rate_limit`     | int      | `0`     | Max inbound requests per caller within the window. |
| `out_rate_limit`    | int      | `0`     | Max outbound requests per caller within the window. |
| `rate_limit_window` | duration | `1m`    | Rolling window length for rate limiting. |
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

> Elastic expiry smooths bursts within the window, but if you see 5 × steady‑state spikes (e.g., cron jobs) pick a larger bucket or smaller window.

---

## Back‑pressure headers

When a request is throttled the proxy sets a `Retry‑After` header with the number of seconds until the caller may try again.

---

## Logs & metrics

* **Structured log** when a request is throttled:

  ```json
  {"level":"WARN","msg":"rate‑limit exceeded","caller_id":"bot‑123","integration":"slack","limit":800,"window":"60s"}
  ```
* Prometheus: `authtranslator_rate_limit_events_total{integration="slack"}`

Grafana sample dashboard lives in [`docs/ops/grafana-rate-limits.json`](ops/grafana-rate-limits.json).
