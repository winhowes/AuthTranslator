# Auth Plugins

AuthTranslator’s behaviour is extended by **plugins** – small Go packages that validate the *incoming* caller credential or inject the *outgoing* credential expected by an upstream service.

* **Incoming plugins** run **before** any allow‑list checks. They must either

  1. **Accept**: return a `callerID` string; the request continues, or
  2. **Reject**: return an error → the proxy replies **401/403**.
* **Outgoing plugins** run **after** the allow‑list passes. They mutate the request (headers, query or body) so the upstream authenticates it.

> **Tip** Any plugin can be swapped at runtime – just edit `config.yaml` and send `SIGHUP` (or run with `-watch`).

---

## Built‑in plugins

| Direction | Plugin             | Notes |
|-----------|-------------------|---------------------------------------------------------------|
| Inbound   | `basic`            | HTTP Basic authentication. Caller ID is the username. |
| Inbound   | `github_signature` | Validates GitHub webhook signatures using a shared secret. |
| Inbound   | `google_oidc`      | Validates Google ID tokens. |
| Inbound   | `hmac_signature`   | Generic HMAC validation using a shared secret. |
| Inbound   | `jwt`              | Verifies JWTs with provided keys. |
| Inbound   | `mtls`             | Requires a trusted client certificate. |
| Inbound   | `slack_signature`  | Validates Slack request signatures. |
| Inbound   | `token`            | Compares a shared token header. |
| Inbound   | `url_path`         | Checks a token embedded in the request path. |
| Inbound   | `passthrough`      | Accepts every request with no authentication. |
| Outbound  | `basic`            | Adds HTTP Basic credentials to the upstream request. |
| Outbound  | `google_oidc`      | Attaches a Google identity token from the metadata service. |
| Outbound  | `hmac_signature`   | Computes an HMAC for the request. |
| Outbound  | `jwt`              | Adds a signed JWT to the request. |
| Outbound  | `mtls`             | Sends a client certificate and exposes the CN via header. |
| Outbound  | `token`            | Adds a token header on outgoing requests. |
| Outbound  | `passthrough`      | Does nothing; useful when upstream handles auth. |
| Outbound  | `url_path`         | Appends a secret segment to the request path. |
---

## Detailed examples

### Inbound `jwt`

```yaml
incoming_auth:
  - type: jwt
    params:
      issuer:   https://auth.example.com
      audience: slack-proxy
      jwks_url: https://auth.example.com/.well-known/jwks.json
```

*Verifies* the JWT’s signature and sets `callerID` to the token's `sub` claim.

### Outbound `token`

```yaml
outgoing_auth:
  type: token
  params:
    secrets:
      - env:API_TOKEN
    header: X-Api-Key
```

Adds the configured token to the `X-Api-Key` header on each request.

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

* Use `-log-level DEBUG` to dump request headers after plugin injection (redacted for secrets).

---
