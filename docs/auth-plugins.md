# Auth Plugins

AuthTranslator’s behaviour is extended by **plugins** – small Go packages that validate the *incoming* caller credential or inject the *outgoing* credential expected by an upstream service.

* **Incoming plugins** run **before** any allowlist or denylist checks. They must either

  1. **Accept**: return a `callerID` string; the request continues, or
  2. **Reject**: return an error → the proxy replies **401/403**.
* **Outgoing plugins** run **after** the allowlist passes and the denylist check succeeds. They mutate the request (headers, query or body) so the upstream authenticates it.

> **Tip** Any plugin can be swapped at runtime – just edit `config.yaml` and send `SIGHUP` (or run with `-watch`).

> Need help sourcing credentials for a plugin? See the [Secret Back‑Ends](secret-backends.md) reference.

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
| Inbound   | `envoy_xfcc`       | Validates caller SPIFFE URI from Envoy `X-Forwarded-Client-Cert`. |
| Inbound   | `slack_signature`  | Validates Slack request signatures. |
| Inbound   | `twilio_signature`  | Validates Twilio webhook signatures. |
| Inbound   | `token`            | Compares a shared token header. |
| Inbound   | `url_path`         | Checks a token embedded in the request path. |
| Inbound   | `passthrough`      | Accepts every request with no authentication. |
| Outbound  | `basic`            | Adds HTTP Basic credentials to the upstream request. |
| Outbound  | `google_oidc`      | Attaches a Google identity token from the metadata service. |
| Outbound  | `gcp_token`        | Uses a metadata service access token. |
| Outbound  | `azure_managed_identity` | Retrieves an Azure access token from the Instance Metadata Service. |
| Outbound  | `oauth2`           | Exchanges client credentials or a refresh token for an access token. |
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

### Inbound `envoy_xfcc`

```yaml
incoming_auth:
  - type: envoy_xfcc
    params:
      allowed_uris:
        - spiffe://cluster.local/ns/team/sa/caller
      ignored_uris:
        - spiffe://cluster.local/ns/gateway/sa/envoy
      allowed_uri_prefixes:
        - spiffe://cluster.local/ns/team/
      header: X-Forwarded-Client-Cert # optional
```

Reads Envoy's XFCC header and extracts a single caller `URI=` identity (SPIFFE).
It fails closed when the header is missing, malformed, ambiguous, or not
allowed by either `allowed_uris` or `allowed_uri_prefixes`.
Supports both Envoy's legacy text XFCC and JSON XFCC header formats.

Use this only when your edge Envoy/Gateway is trusted to sanitize and set the
XFCC header.

### Outbound `find_replace`

```yaml
outgoing_auth:
  - type: find_replace
    params:
      find_secret: env:FIND
      replace_secret: env:REPLACE
```

Replaces every occurrence of the secret referenced by `find_secret` with
the value from `replace_secret` across the URL, headers and body.

### Outbound `azure_managed_identity`

```yaml
outgoing_auth:
  - type: azure_managed_identity
    params:
      resource: api://my-api-app-id
      client_id: 00000000-0000-0000-0000-000000000000 # optional
      header: X-Api-Token                             # optional (default: Authorization)
      prefix: "Bearer "                               # optional (default: "Bearer ")
```

Obtains an access token from the Azure Instance Metadata Service for the specified `resource`, caches it, and attaches it to the
configured header on each outgoing request.

### Outbound `oauth2`

```yaml
outgoing_auth:
  - type: oauth2
    params:
      token_url: https://auth.example.com/oauth/token
      grant_type: refresh_token           # or client_credentials
      client_id: my-client-id             # required for client_credentials
      client_secret: env:OAUTH_SECRET     # secret reference
      refresh_token: env:OAUTH_REFRESH    # secret reference for refresh_token grant
      scope: "read write"                 # optional
      audience: https://api.example.com   # optional
      client_auth: body                   # body, basic, or none
      header: Authorization               # optional (default: Authorization)
      prefix: "Bearer "                   # optional (default: "Bearer ")
      extra_params:                       # optional provider-specific token params
        resource: https://resource.example.com
```

Requests an access token from the configured token endpoint, caches it, and refreshes it one minute before `expires_in`.
For refresh-token flows, any rotated `refresh_token` returned by the provider is reused in memory until restart.
`client_secret` and `refresh_token` must be secret references, not raw values.

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
