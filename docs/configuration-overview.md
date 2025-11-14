# Configuration Reference

AuthTranslator loads up to **three** YAML (or pure‑JSON) documents at runtime:

| File             | Required? | Hot‑reload? | Purpose                                                                            |
| ---------------- | --------- | ----------- | ---------------------------------------------------------------------------------- |
| `config.yaml`    | ✅         | ✅           | Declares *integrations* – where to proxy traffic and how to authenticate outwards. |
| `allowlist.yaml` | –          | ✅           | Grants each *caller ID* a set of capabilities **or** low‑level request filters.    |
| `denylist.yaml`  | –          | ✅           | Blocks requests whose headers/query/body match predefined subsets for a path/method. |

If no allowlist is provided, every request is permitted once inbound authentication succeeds.
Running without an allowlist effectively gives all authenticated callers unrestricted access, so supplying `allowlist.yaml` is **strongly recommended** even if it just contains a single wildcard entry to start. The denylist stays optional as well; omit it when you have no hard blocks to enforce.

The proxy currently infers its schema directly from Go structs. Unknown top‑level keys cause a validation error.

> **Tip** The Go YAML parser accepts JSON too, so curl pipes / CI steps can build your config in whichever syntax is easier to template.
For command-line tooling, see the [Command-Line Helpers](cli.md) guide.

---

## 1  `config.yaml` – integrations

```yaml
integrations:
  - name: slack
    destination: https://slack.com
    outgoing_auth:
      - type: token
        params:
          secrets:
            - env:SLACK_TOKEN            # secret URI – see docs/secret-backends.md
          header: Authorization
          prefix: "Bearer "
    idle_conn_timeout: 10s
    tls_insecure_skip_verify: false
    in_rate_limit:  100
    out_rate_limit: 800
    rate_limit_window: 1m
```

See [Secret Back-Ends](secret-backends.md) for all supported URI schemes.

### Top‑level keys

| Field          | Type                    | Default | Notes                                                    |   |
| -------------- | ----------------------- | ------- | -------------------------------------------------------- | - |
| `integrations` | `[]Integration` | –       | List of integrations. Each element's `name` is used in logs and allowlist. |

### `Integration` object

| Field           | Type           | Default      | Description                                                                  |
| --------------- | -------------- | ------------ | ---------------------------------------------------------------------------- |
| `destination`   | URL            | **required** | Base URL; path from client is appended as‑is. Supports `*` wildcards in the host (e.g. `https://*.example.com`) when paired with an `X-AT-Destination` header containing the concrete upstream URL. |
| `outgoing_auth` | `[]PluginSpec` | `[]`         | Injects credential **before** forwarding.                         |
| `incoming_auth` | `[]PluginSpec` | `[]`         | Zero or more validators that run **in order**; the first that succeeds wins. |
| `in_rate_limit` | int            | `0`          | Max inbound requests per caller within the window. |
| `out_rate_limit` | int           | `0`          | Max outbound requests per caller within the window. |
| `rate_limit_window` | duration    | `1m`         | Rolling window length for rate limiting. |
| `rate_limit_strategy` | string    | `fixed_window` | Rate limit algorithm (`fixed_window`, `token_bucket`, or `leaky_bucket`). |
| `idle_conn_timeout` | duration    | `90s`        | How long idle connections stay pooled. |
| `tls_handshake_timeout` | duration | `10s`        | Maximum time to wait for TLS handshakes. |
| `response_header_timeout` | duration | `0`        | Time to wait for the first response header. |
| `tls_insecure_skip_verify` | bool   | `false`     | Disable server certificate verification (dev only!). |
| `disable_keep_alives` | bool       | `false`      | Disable HTTP keep‑alive connections. |
| `max_idle_conns` | int            | `100`        | Total idle connections to keep open. |
| `max_idle_conns_per_host` | int     | `2`          | Idle connection limit per upstream host. |

When the configured destination host contains a `*`, each request **must** include an `X-AT-Destination` header whose scheme and host match the configured pattern. The proxy validates the header, strips it before forwarding, and uses the configured base path/query when building the upstream URL. Missing or invalid headers trigger a `400 Bad Request` response with `X-AT-Error-Reason: invalid destination`.

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
---

## 2  `allowlist.yaml` – caller permissions

Two ways to authorise a caller:

1. **High‑level capability** – human‑readable label that expands into many fine‑grained rules.
2. **Low‑level filter** – match on HTTP path, method, query, headers, JSON‑body or form‑data.

```yaml
- integration: slack
  callers:
    - id: demo-user
      # easiest: assign a capability
      capabilities:
        - name: post_as

    - id: service‑42
      # granular example
      rules:
        - path:   /api/health
          methods:
            GET: {}                     # allow simple health checks

        - path:   /api/chat.postMessage
          methods:                             # per-method constraints
            POST:
              query:
                channel: [C12345678]           # workspace channel IDs (exact match)
              body:
                text: "Hello world"            # match the whole value exactly
                # format detection uses Content-Type; other types skip body matching
              headers:
                X-Custom-Trace: [abc123]
```

Values for `query`, `headers`, and `body` are compared using **exact string equality**.
Regular expressions are not supported.

### Entry fields

Each document entry targets a single integration and lists the callers that are
authorised to use it.

| Field         | Type       | Notes                                                   |
| ------------- | ---------- | ------------------------------------------------------- |
| `integration` | string     | Integration name (case-insensitive). Matches `config.yaml`.
| `callers`     | `[]Caller` | Caller definitions. Caller IDs come from inbound auth plug-ins. |

### `Caller` object

| Field          | Type       | Notes                                                   |
| -------------- | ---------- | ------------------------------------------------------- |
| `capabilities` | `[]Capability` | Each item has `name` and optional `params`; expands to rules. |
| `rules`        | `[]Rule`   | Evaluated in order; first match authorises the request. |

#### `Rule`

| Field        | Type                 | Notes                                                  |
| ------------ | -------------------- | ------------------------------------------------------ |
| `path`       | string               | Anchored to the upstream path. Supports `*` and `**` wildcards. |
| `methods`     | map[string]RequestConstraint | Keys are HTTP verbs. Map a verb to `{}` to allow it without extra checks. |
| `methods.<name>.query`   | map[string][]string | Each element is a list of allowed values per query key. All must match. |
| `methods.<name>.headers` | map[string][]string | Header names and required values. Empty list checks only presence. |
| `methods.<name>.body` | map[string]interface{} | Recursive subset of the request body (JSON or form). Arrays matched unordered. The proxy inspects `Content-Type`; unknown types skip body checks. |

---

## 3  `denylist.yaml` – request blockers

Denylists complement allowlists by describing requests that must never be forwarded. Each entry targets an integration and groups `CallRule` objects (the same schema as allowlist rules) per caller ID—just like the allowlist. Provide specific IDs for callers you want to block or use `"*"`/omit the field for a wildcard block. If **any** rule matches a request for that caller, the proxy immediately returns **403 Forbidden**.

```yaml
- integration: example
  callers:
    - id: employee-app
      rules:
        - path: /search
          methods:
            GET:
              query:
                q: ["blocked term"]
    - id: "*"
      rules:
        - path: /api/chat.postMessage
          methods:
            POST:
              headers:
                X-Feature-Flag: [disabled]
              body:
                channel: forbidden-room
```

* Only the provided fields must match; extra headers/query/body keys are ignored.
* JSON/form bodies are parsed using `Content-Type`. Unknown types cause the rule to be skipped (no deny).
* Duplicate path/method combinations fail validation during reload, mirroring the allowlist behaviour.

### Top‑level keys

| Field         | Type               | Notes                                                                       |
| ------------- | ------------------ | ---------------------------------------------------------------------------- |
| `integration` | string             | Integration name (case-insensitive).                                        |
| `callers`     | array of callers   | Per-caller deny rules. Omit `id` or set to `"*"` for a wildcard entry.      |

> **Performance note** Low‑level matching adds negligible latency (<50 µs at 10 rules). Tune rule ordering so the most frequent match comes first.

---

## 4  Validating configs in CI

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
        @yq eval -o=json denylist.yaml | jsonschema -i - schemas/denylist.schema.json
```

CI fails fast on typos so you never ship an invalid proxy.

---

## 5  Further reading

* [Auth Plugins](auth-plugins.md)
* [Secret Back-Ends](secret-backends.md)
* [Rate-Limiting](rate-limiting.md)

