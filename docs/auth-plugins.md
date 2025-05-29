# Auth Plugins

AuthTranslator’s behaviour is extended by **plugins** – small Go packages that validate the *incoming* caller credential or inject the *outgoing* credential expected by an upstream service.

* **Incoming plugins** run **before** any allow‑list checks. They must either

  1. **Accept**: return a `callerID` string; the request continues, or
  2. **Reject**: return an error → the proxy replies **401/403**.
* **Outgoing plugins** run **after** the allow‑list passes. They mutate the request (headers, query or body) so the upstream authenticates it.

> **Tip** Any plugin can be swapped at runtime – just edit `config.yaml` and send `SIGHUP` (or run with `-watch`).

---

## Built‑in plugins

| Direction | Plugin            | Use when…                                      | Key params                       | Credential shape                                  |
| --------- | ----------------- | ---------------------------------------------- | -------------------------------- | ------------------------------------------------- |
| Inbound   | `bearer_token`    | Calls carry a short‑lived OAuth/JWT bearer     | `issuer`, `audience`, `jwks_url` | `Authorization: Bearer <jwt>`                     |
| Inbound   | `basic_auth`      | Legacy scripts send Basic HTTP auth            | `user`, `pass` (regex)           | `Authorization: Basic …`                          |
| Inbound   | `hmac_signature`  | Webhook with shared‑secret HMAC (GitHub‑style) | `header`, `algo`, `secret`       | `X-Hub-Signature-256: sha256=…`                   |
| Inbound   | `mtls`            | Client authenticates via X.509 cert            | `ca_file`, `allowed_sans`        | TLS mutual auth                                   |
| Inbound   | `path_token`      | Token lives in a URL path seg (Grafana, etc.)  | `segment_index`                  | `/:token/api/...`                                 |
| Inbound   | `slack_signing`   | Slack slash‑command/webhook                    | `signing_secret`                 | `X-Slack-Signature` / `X-Slack-Request-Timestamp` |
| Outbound  | `slack_app_token` | Upstream is Slack REST API                     | `token` (secret URI)             | Adds `Authorization: Bearer xoxb…`                |
| Outbound  | `bearer_static`   | Any service expecting Bearer                   | `token`                          | Same as above                                     |
| Outbound  | `basic_static`    | Upstream needs Basic auth                      | `user`, `pass`                   | Encodes header                                    |
| Outbound  | `header_static`   | Custom header key/value                        | `header`, `value`                | Sets arbitrary header                             |
| Outbound  | `query_static`    | API key must sit in query                      | `key`, `value`                   | Appends `?key=value`                              |

*(More are in **************************`plugins/`************************** – the table shows the most commonly used set.)*

---

## Detailed examples

### Inbound `bearer_token`

```yaml
incoming_auth:
  - type: bearer_token
    params:
      issuer:   https://auth.example.com
      audience: slack-proxy
      jwks_url: https://auth.example.com/.well-known/jwks.json
```

*Verifies* the JWT’s signature and standard claims, then sets `callerID = sub` claim.

### Outbound `header_static`

```yaml
outgoing_auth:
  type: header_static
  params:
    header: X-Api-Key
    value:  env:MAILGUN_KEY  # secret URI
```

Adds `X-Api-Key: <resolved-secret>` to every proxied request.

---

## Writing your own plugin

1. **Create a new package** under `plugins/auth/<name>`.
2. Implement exactly one of:

   ```go
   func Authenticate(req *http.Request) (auth.Result, error)  // inbound – validate
   func Inject(req *http.Request) error                       // outbound – mutate
   ```

   `auth.Result` embeds `auth.Identifier` so you can optionally attach a caller‑ID (see below).
3. Register the plugin in `init()`:

   ```go
   auth.Register("<name>", &MyPlugin{})
   ```
4. `go test ./plugins/...` – the main binary picks it up automatically.

A minimal example lives in [`plugins/auth/example`](../plugins/auth/example).

---

### Caller identifiers

Incoming plugins that want to feed the **allow‑list** and **rate‑limiter** should satisfy the `auth.Identifier` interface:

```go
type Identifier interface {
    CallerID(*http.Request) (string, error)
}
```

Return a *stable, non‑secret* string – e.g. the JWT `sub` or an mTLS SAN – so downstream components can safely key on it.

| Credential type | Suggested ID | Why                      |
| --------------- | ------------ | ------------------------ |
| JWT             | `sub` claim  | Unique per user/service  |
| mTLS            | SAN (SPIFFE) | Unique per workload      |
| Basic           | username     | Simple & obvious         |
| Webhook         | delivery ID  | Matches upstream retries |


Identifiers flow through to:

* `allowlist.yaml` lookups
* Rate‑limit keys (`<callerID>:<integration>`)
* Logs & Prometheus metrics

---

### Debugging Tips

|   |
| - |

* Start the proxy with `-debug` and curl `/_at_internal/metrics` to see **`auth_plugin_errors_total`**.
* Use `AUTH_TRANSLATOR_LOG_LEVEL=debug` to dump request headers after plugin injection (redacted for secrets).

---
