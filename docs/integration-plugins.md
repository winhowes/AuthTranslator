# Integration Plugins

While **auth plugins** focus on translating credentials, an **integration plugin** bundles everything required to speak to a specific upstream service—URL, auth hints, default rate‑limits, and convenience CLI helpers.
Think of it as a *cookie‑cutter* that stamps out a ready‑to‑run block in your `config.yaml` so teams don’t reinvent the wheel for common SaaS APIs.

> **Why separate the concerns?**
> *Auth plugin* → **how** to sign a request (Bearer, Basic, etc.).
> *Integration plugin* → **where** to send it, typical timeouts, headers, and which auth plugin to use.

---

## Built‑in integrations


| Name     | Upstream base URL        | Default outgoing auth | Extras |
| -------- | ------------------------ | --------------------- | --------------------------------------------------- |
| `slack`  | `https://slack.com`      | `token`               | Adds `Authorization: Bearer <token>` and retries 429 with back-off. |
| `github` | `https://api.github.com` | `token`               | Sets `User-Agent: authtranslator` and bumps Go's idle connection limit. |
| `stripe` | `https://api.stripe.com` | `token`               | Forces HTTP/1.1 per Stripe docs. |

*(Full list lives under **[`app/integrations/plugins/`](../app/integrations/plugins/)**)*
## Creating an integration via the CLI

```bash
# Append a Slack integration to config.yaml
go run ./cmd/integrations slack \
  -file config.yaml \
  -token env:SLACK_TOKEN -signing-secret env:SLACK_SIGNING
```

The CLI modifies `config.yaml` in place.

---

## Anatomy of an integration plugin

1. **Package location**: `cmd/integrations/plugins/<name>`.
2. **Registration** in `init()` with the CLI registry:

   ```go
   func init() { plugins.Register("slack", builder) }
   ```
3. **Parse CLI flags** in the builder (`--timeout`, etc.).
4. **Return** a `plugins.Integration` value that can be marshalled to YAML.

Minimal template:

```go
func builder(args []string) (plugins.Integration, error) {
    fs := flag.NewFlagSet("example", flag.ContinueOnError)
    name := fs.String("name", "example", "integration name")
    if err := fs.Parse(args); err != nil {
        return plugins.Integration{}, err
    }
    return plugins.Integration{
        Name:           *name,
        Destination:    "https://example.com",
        OutgoingAuth: []plugins.AuthPluginConfig{{
            Type:   "token",
            Params: map[string]any{"header": "X-Api-Key", "secrets": []string{"env:EXAMPLE_KEY"}},
        }},
        IdleConnTimeout: 10 * time.Second,
        InRateLimit:     100,
        OutRateLimit:    1000,
        RateLimitWindow: time.Minute,
    }, nil
}
```

---

## Referencing in `config.yaml`

Generated YAML lands under the key you choose:

```yaml
integrations:
  slack:
    << generated block >>
```

From here you can tweak fields—e.g. turn on `tls_insecure_skip_verify` for a dev sandbox.

---

## Best practices for authors

* **Set sane timeouts** SaaS APIs differ; codify them so callers don’t guess.
* **Keep zero secrets** Integration plugins should only reference secret URIs, never raw tokens.

