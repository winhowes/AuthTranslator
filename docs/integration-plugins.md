# Integration Plugins

While **auth plugins** focus on translating credentials, an **integration plugin** bundles everything required to speak to a specific upstream service—URL, auth hints, default rate‑limits, and convenience CLI helpers.
Think of it as a *cookie‑cutter* that stamps out a ready‑to‑run block in your `config.yaml` so teams don’t reinvent the wheel for common SaaS APIs.

> **Why separate the concerns?**
> *Auth plugin* → **how** to sign a request (Bearer, Basic, etc.).
> *Integration plugin* → **where** to send it, typical timeouts, headers, and which auth plugin to use.

---

## Built‑in integrations

| Name     | Upstream base URL        | Default outgoing auth | Extras                                                             |
| -------- | ------------------------ | --------------------- | ------------------------------------------------------------------ |
| `slack`  | `https://slack.com`      | `token`               | Adds `Authorization: Bearer <token>` and retries 429 with back‑off. |
| `github` | `https://api.github.com` | `token`               | Sets `User‑Agent: authtranslator` and bumps Go's idle connection limit. |
| `stripe` | `https://api.stripe.com` | `basic`               | Forces HTTP/1.1 per Stripe docs.                                   |

*(Full list lives under ******[`plugins/integration/`](../plugins/integration/)******)*

---

## Creating an integration via the CLI

```bash
# Generate a skeleton block for Slack into stdout
go run ./cmd/integrations slack > my-config.yaml

# Same, but override the window + requests
go run ./cmd/integrations slack \
  -rate-window 1m -rate-requests 800 > my-config.yaml
```

The CLI simply templates YAML using the plugin’s defaults—feel free to edit afterwards.

---

## Anatomy of an integration plugin

1. **Package location**: `plugins/integration/<name>`.
2. **Registration** in `init()`:

   ```go
   func init() { integration.Register("slack", New) }
   ```
3. **Options parsed from flags** (`--rate-window`, `--timeout`, etc.).
4. **Return** a fully‑formed `config.Integration` struct—callers can marshal it to YAML.

Minimal template:

```go
func New(opts Options) (*config.Integration, error) {
    return &config.Integration{
        Destination:   "https://example.com",
        OutgoingAuth:  config.PluginSpec{Type: "token", Params: map[string]any{"header": "X-Api-Key", "secrets": []string{"env:EXAMPLE_KEY"}}},
        Transport:     config.Transport{Timeout: 10 * time.Second},
        RateLimit:     config.RateLimit{Window: time.Minute, Requests: 1000},
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

From here you can tweak fields—e.g. turn on `tls_skip_verify` for a dev sandbox.

---

## Best practices for authors

* **Set sane timeouts** SaaS APIs differ; codify them so callers don’t guess.
* **Namespace tags** Add `tags: [chat, slack]` so dashboards can group traffic.
* **Keep zero secrets** Integration plugins should only reference secret URIs, never raw tokens.

