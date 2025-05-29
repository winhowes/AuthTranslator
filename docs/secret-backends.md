# Secret Back‑Ends

AuthTranslator never expects you to paste raw API keys into a YAML file. Instead, any plugin parameter that contains a credential can use a **secret URI**. At runtime the proxy resolves that URI via a pluggable back‑end and injects the value.

```yaml
outgoing_auth:
  type: token
  params:
    secrets:
      - gcp-secret://projects/acme/secrets/slackToken/latest
    header: Authorization
    prefix: "Bearer "
```

---

## Supported schemes

| Scheme           | Example URI                                                         | When to use it                                                |
| ---------------- | ------------------------------------------------------------------- | ------------------------------------------------------------- |
| `env`            | `env:SLACK_TOKEN`                                                   | Local dev & CI – the token sits in an env var.                |
| `file`           | `file:///etc/secrets/slack_token`                                   | Kubernetes **secret volume** or Docker bind‑mount.            |
| `gcp-secret`     | `gcp-secret://projects/acme/secrets/slackToken/latest`              | Running on GKE / Cloud Run; leverages **Secret Manager** IAM. |
| `aws-secret`     | `aws-secret://arn:aws:secretsmanager:us‑west‑2:123456:secret:slack` | EKS, ECS or EC2 with **Secrets Manager** policy.              |
| `azure-keyvault` | `azure-keyvault://kv‑name/secret-name`                              | AKS or VM SS with **Managed Identity**.                       |
| `vault`          | `vault://kv/data/slack#token`                                       | Self‑hosted **HashiCorp Vault** cluster.                      |

> **Not exhaustive** — you can add more with \~50 LoC (see below).

### Back-end environment variables

Some schemes rely on environment variables for authentication or decryption:

| Prefix | Environment Variables | Description | Example |
| ------ | -------------------- | ----------- | ------- |
| `env`  | Names referenced in the configuration (e.g. `env:IN_TOKEN`) | Secrets are read directly from those variables. | `env:IN_TOKEN` resolves to `$IN_TOKEN` |
| `file` | _none_ | Reads file contents from disk for `file:` secrets. | `file:/etc/token` reads `/etc/token` |
| `aws-secret` | `AWS_KMS_KEY` | Base64 encoded 32 byte key for decrypting `aws:` secrets. | `aws:prod/token` decrypts the stored value |
| `azure-keyvault` | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Credentials for fetching `azure:` secrets from Key Vault. | `azure:/kv/token` fetches `token` from Key Vault |
| `gcp-secret` | _none_ | Uses the GCP metadata service when resolving `gcp:` secrets. | `gcp:/projects/p/secrets/token` from Secret Manager |
| `vault` | `VAULT_ADDR`, `VAULT_TOKEN` | Fetches secrets from HashiCorp Vault via its HTTP API. | `vault:secret/data/api` reads from Vault |

```bash
export IN_TOKEN=secret-in            # env:IN_TOKEN
echo "out" > /tmp/out.token         # file:/tmp/out.token
export AWS_KMS_KEY=$(cat kms.b64)    # decrypts aws:prod/token
export AZURE_TENANT_ID=xxxxx
export AZURE_CLIENT_ID=yyyyy
export AZURE_CLIENT_SECRET=zzzzz
# gcp-secret relies on metadata service
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
| TTL        | Currently fixed; future work may add periodic refresh for rotated keys.                |

---

## Writing a new back‑end

1. **New package** under `app/secrets/plugins/<name>`.
2. Implement:

   ```go
   func Fetch(ctx context.Context, uri *url.URL) ([]byte, error)
   ```
3. Register in `init()`:

   ```go
   secret.Register("<scheme>", Fetch)
   ```
4. Unit‑test with a fake server or env vars.

Example skeleton:

```go
package foosecret

import (
    "context"
    "net/url"

    "github.com/winhowes/authtranslator/secret"
)

func init() {
    secret.Register("foo", fetch)
}

func fetch(ctx context.Context, uri *url.URL) ([]byte, error) {
    // uri.Opaque == "bar/baz#key"
    // …fetch and return the secret…
}
```

A working GCP implementation is in [`app/secrets/plugins/gcp`](../app/secrets/plugins/gcp).

---

## Best practices

* **Least privilege** Grant the proxy only *read* access to each secret.
* **Rotate centrally** Because credentials load at start, rotation is instantaneous after a hot reload and zero code changes.
* **Avoid multi‑line PEMs in env** Use `file:` or a cloud vault instead; most shells mangle newlines.
* **Redaction** Structured logs never emit secret bytes, but disable debug logging in prod just in case.
