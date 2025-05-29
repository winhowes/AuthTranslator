# Configuration Reference

AuthTranslator loads **two** YAML (or pure‑JSON) documents at runtime:

| File             | Required? | Hot‑reload? | Purpose                                                                            |
| ---------------- | --------- | ----------- | ---------------------------------------------------------------------------------- |
| `config.yaml`    | ✅         | ✅           | Declares *integrations* – where to proxy traffic and how to authenticate outwards. |
| `allowlist.yaml` | ✅         | ✅           | Grants each *caller ID* a set of capabilities **or** low‑level request filters.    |

The proxy currently infers its schema directly from Go structs. A top‑level `apiVersion` key is **optional** and ignored at runtime (reserved for future compatibility).

> **Tip** The Go YAML parser accepts JSON too, so curl pipes / CI steps can build your config in whichever syntax is easier to template.

---

## 1  `config.yaml` – integrations

```yaml
apiVersion: v1alpha1
integrations:
  slack:
    destination: https://slack.com
    outgoing_auth:
      type: token
      params:
        secrets:
          - env:SLACK_TOKEN            # secret URI – see docs/secret-backends.md
        header: Authorization
        prefix: "Bearer "
    transport:
      timeout: 10s
      tls_insecure_skip_verify: false
    in_rate_limit:  100
    out_rate_limit: 800
    rate_limit_window: 1m
    tags: [chat, team‑comm]
```

See [Secret Back-Ends](secret-backends.md) for all supported URI schemes.

### Top‑level keys

| Field          | Type                    | Default | Notes                                                    |   |
| -------------- | ----------------------- | ------- | -------------------------------------------------------- | - |
| `apiVersion`   | string                  | –       | Optional; reserved for future versions.                  |   |
| `integrations` | map\[string]Integration | –       | Keys are user‑friendly names used in logs and allowlist. |   |

### `Integration` object

| Field           | Type           | Default      | Description                                                                  |
| --------------- | -------------- | ------------ | ---------------------------------------------------------------------------- |
| `destination`   | URL            | **required** | Base URL; path from client is appended as‑is.                                |
| `outgoing_auth` | `PluginSpec`   | –            | Injects long‑lived credential **before** forwarding.                         |
| `incoming_auth` | `[]PluginSpec` | `[]`         | Zero or more validators that run **in order**; the first that succeeds wins. |
| `in_rate_limit` | int           | `0`         | Max inbound requests per caller within the window. |
| `out_rate_limit` | int          | `0`         | Max outbound requests per caller within the window. |
| `rate_limit_window` | duration   | `1m`        | Rolling window length for rate limiting. |
| `transport`     | `Transport`    | `{}`         | Fine‑tune timeouts, TLS, proxy settings.                                     |
| `tags`          | `[]string`     | `[]`         | Arbitrary labels for dashboards / CLI queries.                               |

#### `PluginSpec`

```yaml
 type: jwt
 params:
   issuer: https://auth.example.com
   audience: slack-proxy
```

| Field    | Type            | Notes                                |
| -------- | --------------- | ------------------------------------ |
| `type`   | string          | Name registered by a plugin package. |
| `params` | map\[string]any | Free‑form; validated by the plugin.  |
#### `Transport`
| Field             | Type     | Default | Description                                          |
| ----------------- | -------- | ------- | ---------------------------------------------------- |
| `timeout`                 | duration | `30s`   | End‑to‑end timeout for upstream call. |
| `tls_insecure_skip_verify` | bool     | `false` | Disable server certificate verification (dev only!). |
| `proxy_url`               | URL      | –       | Forward through an HTTP proxy. |
| `idle_conn_timeout`       | duration | `0`     | How long idle connections stay pooled. |
| `tls_handshake_timeout`   | duration | `0`     | Maximum time to wait for TLS handshakes. |
| `response_header_timeout` | duration | `0`     | Time to wait for the first response header. |
| `disable_keep_alives`     | bool     | `false` | Disable HTTP keep‑alive connections. |
| `max_idle_conns`          | int      | `0`     | Total idle connections to keep open. |
| `max_idle_conns_per_host` | int      | `0`     | Idle connection limit per upstream host. |

---

## 2  `allowlist.yaml` – caller permissions

Two ways to authorise a caller:

1. **High‑level capability** – human‑readable label that expands into many fine‑grained rules.
2. **Low‑level filter** – match on HTTP path, method, query, headers, JSON‑body or form‑data.

```yaml
apiVersion: v1alpha1
- integration: slack
  callers:
    - id: demo-user
      # easiest: assign a capability
      capabilities: [slack.chat.write.public]

    - id: service‑42
      # granular example
      rules:
        - path:   /api/chat.postMessage
          method: POST
          query:
            - channel=^C[0-9A-Z]{8}$   # workspace channel IDs
          body:
            json:
              text: "^.+"              # any non‑empty string
            form: {}
          headers:
            X-Custom-Trace: [abc123]
```

### Top‑level keys

| Field        | Type               | Notes                                          |   |
| ------------ | ------------------ | ---------------------------------------------- | - |
| `apiVersion` | string             | Optional; reserved for future versions.        |   |
| `callers`    | map\[string]Caller | Caller ID comes from the incoming‑auth plugin. |   |

### `Caller` object

`<integration‑name>` sub‑keys match those in `config.yaml`.

| Field          | Type       | Notes                                                   |
| -------------- | ---------- | ------------------------------------------------------- |
| `capabilities` | `[]string` | Shortcut labels → expand to rules.                      |
| `rules`        | `[]Rule`   | Evaluated in order; first match authorises the request. |

#### `Rule`

| Field        | Type                 | Notes                                                  |
| ------------ | -------------------- | ------------------------------------------------------ |
| `path`       | string               | Anchored to the upstream path. Supports `*` and `**` wildcards. |
| `method`     | string or `[string]` | `GET`, `POST`, …                                       |
| `query`      | `[string]`           | Each element `key=value`. All must match.              |
| `headers`    | map\[string][]string | Header names and required values. Empty list checks only presence. |
| `body.json`  | map\[string]interface{} | Object matched recursively; must be a subset of the request. |
| `body.form`  | map\[string]interface{} | Same subset matching for `application/x-www-form-urlencoded`. |

> **Performance note** Low‑level matching adds negligible latency (<50 µs at 10 rules). Tune rule ordering so the most frequent match comes first.

---

## 3  Validating configs in CI

### With JSON‑Schema

```bash
yq eval -o=json config.yaml | \
  jsonschema -i - schemas/config.schema.json
```

A sample `Makefile` target:

```make
validate:
        @yq eval -o=json config.yaml | jsonschema -i - schemas/config.schema.json
        @yq eval -o=json allowlist.yaml | jsonschema -i - schemas/allowlist.schema.json
```

CI fails fast on typos so you never ship an invalid proxy.

---

## 4  Further reading

* [Auth Plugins](auth-plugins.md)
* [Secret Back-Ends](secret-backends.md)
* [Rate-Limiting](rate-limiting.md)

