# Auth Plugins

AuthTranslator’s behaviour is extended by **plugins** – small Go packages that validate the *incoming* caller credential or inject the *outgoing* credential expected by an upstream service.

* **Incoming plugins** run **before** any allowlist checks. They must either

  1. **Accept**: return a `callerID` string; the request continues, or
  2. **Reject**: return an error → the proxy replies **401/403**.
* **Outgoing plugins** run **after** the allowlist passes. They mutate the request (headers, query or body) so the upstream authenticates it.

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
| Inbound   | `twilio_signature`  | Validates Twilio webhook signatures. |
| Inbound   | `token`            | Compares a shared token header. |
| Inbound   | `url_path`         | Checks a token embedded in the request path. |
| Inbound   | `passthrough`      | Accepts every request with no authentication. |
| Outbound  | `basic`            | Adds HTTP Basic credentials to the upstream request. |
| Outbound  | `google_oidc`      | Attaches a Google identity token from the metadata service. |
| Outbound  | `gcp_token`        | Uses a metadata service access token. |
| Outbound  | `hmac_signature`   | Computes an HMAC for the request. |
| Outbound  | `jwt`              | Adds a signed JWT to the request. |
| Outbound  | `mtls`             | Sends a client certificate and exposes the CN via header. |
| Outbound  | `token`            | Adds a token header on outgoing requests. |
| Outbound  | `passthrough`      | Does nothing; useful when upstream handles auth. |
| Outbound  | `url_path`         | Appends a secret segment to the request path. |
| Outbound  | `find_replace`     | Replaces occurrences of one secret value with another across the URL, headers and body. |
---

## Detailed examples

### Inbound `jwt`

```yaml
incoming_auth:
  - type: jwt
    params:
      secrets:
        - env:JWT_KEY
      issuer:   https://auth.example.com
      audience: slack-proxy
```

*Verifies* the JWT’s signature and sets `callerID` to the token's `sub` claim.

### Outbound `token`

```yaml
outgoing_auth:
  - type: token
    params:
      secrets:
        - env:API_TOKEN
      header: X-Api-Key
```

Adds the configured token to the `X-Api-Key` header on each request.

---

## Writing your own plugin

1. **Create a new package** under `app/auth/plugins/<name>`.
2. Implement either the **IncomingAuthPlugin** or **OutgoingAuthPlugin** interface from
   [`app/auth/registry.go`](../app/auth/registry.go):

   ```go
type IncomingAuthPlugin interface {
    Name() string
    ParseParams(map[string]interface{}) (interface{}, error)
    Authenticate(ctx context.Context, r *http.Request, params interface{}) bool
    RequiredParams() []string
    OptionalParams() []string
}

// Plugins can optionally implement AuthStripper to remove credentials from the
// request once verified.

type AuthStripper interface {
    StripAuth(r *http.Request, params interface{})
}

type OutgoingAuthPlugin interface {
       Name() string
       ParseParams(map[string]interface{}) (interface{}, error)
       AddAuth(ctx context.Context, r *http.Request, params interface{}) error
       RequiredParams() []string
       OptionalParams() []string
   }
   ```

   Incoming plugins may additionally implement the `Identifier` interface to expose a caller ID.
3. Register the plugin in `init()`:

   ```go
   authplugins.RegisterIncoming(&MyPlugin{}) // or RegisterOutgoing
   ```
4. `go test ./app/...` – the main binary picks it up automatically.

A minimal example lives in [`app/auth/plugins/example`](../app/auth/plugins/example).

---

### Caller identifiers

Incoming plugins that want to feed the **allowlist** and **rate‑limiter** should satisfy the `auth.Identifier` interface:

```go
type Identifier interface {
    Identify(r *http.Request, params interface{}) (string, bool)
}
```

Return a *stable, non‑secret* string – e.g. the JWT `sub` or an mTLS SAN – so downstream components can safely key on it. The boolean result indicates whether an identifier was successfully derived.

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
