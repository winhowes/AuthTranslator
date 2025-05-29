# Secret Back‑Ends

AuthTranslator never expects you to paste raw API keys into a YAML file. Instead, any plugin parameter that contains a credential can use a **secret URI**. At runtime the proxy resolves that URI via a pluggable back‑end and injects the value.

```yaml
outgoing_auth:
  type: slack_app_token
  params:
    token: gcp-secret://projects/acme/secrets/slackToken/latest
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

1. **New package** under `plugins/secret/<name>`.
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

A working GCP implementation is in [`plugins/secret/gcp`](../plugins/secret/gcp).

---

## Best practices

* **Least privilege** Grant the proxy only *read* access to each secret.
* **Rotate centrally** Because credentials load at start, rotation is instantaneous after a hot reload and zero code changes.
* **Avoid multi‑line PEMs in env** Use `file:` or a cloud vault instead; most shells mangle newlines.
* **Redaction** Structured logs never emit secret bytes, but disable debug logging in prod just in case.
