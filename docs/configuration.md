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
      tls_skip_verify: false
    in_rate_limit:  100
    out_rate_limit: 800
    rate_limit_window: 1m
    tags: [chat, team‑comm]
```

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
| `timeout`         | duration | `30s`   | End‑to‑end timeout for upstream call.                |
| `tls_skip_verify` | bool     | `false` | Disable server certificate verification (dev only!). |
| `proxy_url`       | URL      | –       | Forward through an HTTP proxy.                       |

---

## 2  `allowlist.yaml` – caller permissions

Two ways to authorise a caller:

1. **High‑level capability** – human‑readable label that expands into many fine‑grained rules.
2. **Low‑level filter** – match on HTTP path, method, query, headers, JSON‑body or form‑data.

```yaml
apiVersion: v1alpha1
callers:
  demo-user:
    slack:
      # easiest: assign a capability
      capabilities: [slack.chat.write.public]

  service‑42:
    slack:
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
            - X-Custom-Trace
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
| `headers`    | `[string]`           | Header names that **must be present** (value ignored). |
| `body.json`  | map\[string]interface{} | JSON pointer‑like top‑level keys; values must match exactly. |
| `body.form`  | map\[string]interface{} | For `application/x-www-form-urlencoded`; values must match exactly. |

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

