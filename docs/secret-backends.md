# Secret Back‑Ends

AuthTranslator never expects you to paste raw API keys into a YAML file. Instead, any plugin parameter that contains a credential can use a **secret URI**. At runtime the proxy resolves that URI via a pluggable back‑end and injects the value.

For full config examples, see the [Configuration Reference](configuration-overview.md).
For plugin-specific usage, refer to the [Auth Plugins](auth-plugins.md) guide.
```yaml
outgoing_auth:
  - type: token
    params:
      secrets:
        - gcp:projects/acme/locations/global/keyRings/auth/cryptoKeys/token:ciphertext
      header: Authorization
      prefix: "Bearer "
```

---

## Supported schemes

| Scheme           | Example URI                                                         | When to use it                                                |
| ---------------- | ------------------------------------------------------------------- | ------------------------------------------------------------- |
| `env`            | `env:SLACK_TOKEN`                                                   | Local dev & CI – the token sits in an env var.                |
| `file`           | `file:///etc/secrets/slack_token`                                   | Kubernetes **secret volume** or Docker bind‑mount. Append `:KEY` to read key/value files; omit it to load the entire file. |
| `k8s`            | `k8s:default/mysecret#token`         | In‑cluster secret via the Kubernetes API.                     |
| `gcp`            | `gcp:projects/acme/locations/global/keyRings/auth/cryptoKeys/token:ciphertext` | Running on GKE / Cloud Run; decrypt via **Cloud KMS**. |
| `aws`            | `aws:Ci0KU29tZUNpcGhlcnRleHQ=` | AES‑GCM encrypted values decrypted using `AWS_KMS_KEY`. |
| `azure`          | `azure:https://kv-name.vault.azure.net/secrets/secret-name`         | AKS or VM SS with **Managed Identity**.                       |
| `vault`          | `vault:secret/data/slack`                                       | Self‑hosted **HashiCorp Vault** cluster.                      |
| `dangerousLiteral` | `dangerousLiteral:__PLACEHOLDER__`                              | Rare cases where you need a literal sentinel string. |

### Literal placeholders (`dangerousLiteral:`)

The `dangerousLiteral:` prefix stores a value *directly in the configuration file* instead of fetching it from an external back-end.

> ⚠️ **Warning**
>
> * Avoid using `dangerousLiteral:` for real secrets – the value is written in plain text and easily leaks if the config is checked into source control or shared.
> * Prefer one of the managed back-ends above whenever possible.

```yaml
outgoing_auth:
  - type: find_replace
    params:
      find_secret: dangerousLiteral:__PLACEHOLDER__
      replace_secret: file:secrets.env:GITHUB_TOKEN
```

The `dangerousLiteral:` option can be useful when you need to match or replace sentinel strings during testing, or when migrating legacy configurations.

> **Not exhaustive** — you can add more with \~50 LoC (see below).

### Back-end environment variables

Some schemes rely on environment variables for authentication or decryption:

| Prefix | Environment Variables | Description | Example |
| ------ | -------------------- | ----------- | ------- |
| `env`  | Names referenced in the configuration (e.g. `env:IN_TOKEN`) | Secrets are read directly from those variables. | `env:IN_TOKEN` resolves to `$IN_TOKEN` |
| `file` | _none_ | Reads file contents from disk for `file:` secrets. Append `:KEY` to select entries from `KEY=value` files; omit it to load the whole file. | `file:/etc/secrets.env:SLACK_SECRET` |
| `k8s` | `KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT` | Provided by Kubernetes; used with the in-cluster service account. | `k8s:default/mysecret#token` |
| `aws` | `AWS_KMS_KEY` | Base64 encoded 32 byte key for decrypting `aws:` secrets. | `aws:Ci0KU29tZUNpcGhlcnRleHQ=` |
| `azure` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Credentials for fetching `azure:` secrets from Key Vault. | `azure:https://kv-name.vault.azure.net/secrets/token` |
| `gcp` | _none_ | Uses the GCP metadata service when resolving `gcp:` secrets. | `gcp:projects/p/locations/l/keyRings/r/cryptoKeys/k:cipher` |
| `vault` | `VAULT_ADDR`, `VAULT_TOKEN` | Fetches secrets from HashiCorp Vault via its HTTP API. | `vault:secret/data/api` reads from Vault |
| `dangerousLiteral` | _none_ | Value is stored directly in config; no external dependencies. | `dangerousLiteral:__PLACEHOLDER__` |

For `file:` URIs that use the `:KEY` suffix, AuthTranslator treats the file as a simple `KEY=value` list:

* Only the first `=` acts as the delimiter for each entry.
* Blank lines and lines starting with `#` are ignored, so you can document the file.
* Leading/trailing whitespace around the key or value is trimmed.

If you omit `:KEY`, the entire file contents are loaded (with surrounding whitespace trimmed). This mode is ideal for multi-line material such as PEM certificates.

```bash
export IN_TOKEN=secret-in            # env:IN_TOKEN
echo "out" > /tmp/out.token         # file:/tmp/out.token
export AWS_KMS_KEY=$(cat kms.b64)    # decrypts aws:prod/token
export AZURE_TENANT_ID=xxxxx
export AZURE_CLIENT_ID=yyyyy
export AZURE_CLIENT_SECRET=zzzzz
# gcp relies on metadata service
export VAULT_ADDR=https://vault.example.com
export VAULT_TOKEN=s.myroot
```

---

## URI grammar

```
<scheme> ":" <opaque>
```

* `scheme` – lower‑case letters, numbers, `+` and `-`.
* `opaque` – everything after the first colon; parsed by the back‑end.

The proxy treats the entire value as opaque until the chosen back‑end returns a byte slice.

---

## Caching & refresh

| Behaviour  | Details                                                                                |
| ---------- | -------------------------------------------------------------------------------------- |
| On startup | All secret URIs are resolved **once**. Failure → fatal log + exit.                     |
| Hot reload | On `SIGHUP` / `-watch`, new or changed URIs are fetched; unchanged values are re‑used. |
| In‑request | Plugins never re‑fetch — avoids per‑call latency and rate limits.                      |
| TTL        | Controlled by the `-secret-refresh` flag; `0` disables expiry. |

---

## Writing a new back‑end

1. **New package** under `app/secrets/plugins/<name>`.
2. Implement:

   ```go
   func Fetch(ctx context.Context, uri *url.URL) ([]byte, error)
   ```
3. Register in `init()`:

   ```go
   secrets.Register("<scheme>", Fetch)
   ```
4. Unit‑test with a fake server or env vars.

Example skeleton:

```go
package foosecret

import (
    "context"
    "net/url"

    "github.com/winhowes/AuthTranslator/app/secrets"
)

func init() {
    secrets.Register("foo", fetch)
}

func fetch(ctx context.Context, uri *url.URL) ([]byte, error) {
    // uri.Opaque == "bar/baz#key"
    // …fetch and return the secret…
}
```

A working GCP implementation is in [`app/secrets/plugins/gcp`](../app/secrets/plugins/gcp).

---

## Best practices

* **Rotate centrally** Because credentials load at start, rotation is instantaneous after a hot reload and zero code changes.
* **Avoid multi‑line PEMs in env** Use `file:` or a cloud vault instead; most shells mangle newlines.
* **Handle literals carefully** If you rely on `dangerousLiteral:` placeholders, never commit real credentials and treat them as temporary scaffolding.
