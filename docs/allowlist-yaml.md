# `allowlist.yaml` – Caller Permissions

The **allowlist** answers a single question:

> *Given this caller ID and integration, is the request allowed?*

It lives in `allowlist.yaml` and is hot‑reloaded just like `config.yaml`.
While the proxy starts without this file, doing so lets any authenticated caller access every integration. In production we **strongly recommend** defining an allowlist, even if it initially grants a single wildcard caller.
Unknown top‑level keys cause a validation error.

```yaml
- integration: <integration-name>
  callers:
    - id: <callerID>
      [capabilities: [{ name: <capability> }] | rules: [ ... ]]
```

---

## 1  Caller ID keys

* **Exact ID** `user-123`, `service-A`, `spiffe://tenant/worker`
* **Wildcard** `"*"` – used when the incoming auth plugin did **not** return an ID. Handy for anonymous webhooks.

If no matching caller key exists – or a matched caller fails rule constraints – the proxy returns **403 Forbidden** and sets an `X-AT-Error-Reason` header describing the first mismatch. Every 4xx/5xx error from the proxy includes this header with a brief phrase explaining the reason.

---

## 2  Two authorization styles

| Style              | When to use                                                    | YAML field                          |
| ------------------ | -------------------------------------------------------------- | ----------------------------------- |
| **Capabilities**   | You want a friendly, reusable label ("post public Slack msg"). | `capabilities:` *(list of objects)* |
| **Granular rules** | You need fine‑grained filters (path, query, header, body).     | `rules:` *(list of Rule objects)*   |

You can mix both—capabilities first, fall back to granular.

### Capabilities

Capabilities serve two goals:

1. **Developer ergonomics** – a single label replaces dozens of path/method/body rules.
2. **Auditability** – security reviewers can grep for the label instead of combing through lengthy rule lists. If a suitable capability exists, **prefer it over hand‑rolled granular rules**.

Capabilities are defined **next to each integration plugin**. They expand into one or more granular rules that match that integration’s API surface.
Look for a `capabilities.go` file under `app/integrations/plugins/<integration>/` to see the code powering each capability.

```yaml
- integration: slack
  callers:
    - id: bot-123
      capabilities:
        - name: post_as
```
Each capability item contains a `name` and optional `params` map.

> **Discovering capabilities** Run the CLI helper (see [Command-Line Helpers](cli.md)):
>
> ```bash
> go run ./cmd/allowlist list
> ```
>
> (Use `--help` for plugin-specific flags.)
>
> For a reference of built-in capabilities, see [capabilities.md](capabilities.md).
> For guidelines on adding new ones, see [integration-plugins.md](integration-plugins.md).

For convenience there is also a special capability `dangerously_allow_full_access` which grants unrestricted access to an integration. Use it sparingly.

### Granular Rule

```yaml
rules:
  - path:   /api/chat.postMessage          # path pattern, anchored
    methods:
      GET: {}                              # allow GET with no extra filters
      POST:                                # map key is the HTTP verb
        query:                             # list of key=value pairs (ANDed)
          channel: [C12345678]
        headers:                           # header=value list; empty list checks only presence
          X-Custom-Trace: [abc123]
        body:                              # optional JSON Schema for JSON/form bodies
          type: object
          properties:
            text:
              type: string
              pattern: "^Hello"
          required: [text]
          # body format is detected via Content-Type; other types skip matching
```

Allowed values are matched **exactly** for headers and query parameters. Body constraints use
JSON Schema draft‑07 so you can express regex patterns, string lengths, and numeric ranges.

Each key under `methods:` represents an HTTP method. Mapping a method to `{}`
means the request is allowed for that verb as soon as the path matches. Add
`query`, `headers`, or `body` constraints inside a method block to further limit
which requests are permitted. Body constraints are evaluated against the parsed JSON or
form payload.

| Request part | Matching logic                                                                                      |
| ------------ | --------------------------------------------------------------------------------------------------- |
| Path         | Must match the pattern **entirely**. `*` matches one segment; `**` matches the rest.                 |
| Method       | Case-insensitive string compare. Each method key contains its own constraints. |
| Query params | In `methods.<HTTP_METHOD>.query`, each key maps to allowed value list. Extra params allowed. Values match exactly.
| Headers      | In `methods.<HTTP_METHOD>.headers`, each key has required values; an empty list only checks for presence. Values match exactly.
| Body         | `methods.<HTTP_METHOD>.body` is a JSON Schema (draft‑07) evaluated against the JSON or form body. Detection relies on the `Content-Type` header; if it's neither JSON nor form, body checks are skipped.

A request passes if **any** rule (or capability‑expanded rule) matches.

---

## 3  Tips & conventions

* **One capability ≈ one business use‑case** (e.g. `post_as`).
* Prefer **uppercase** HTTP methods (`GET`, `POST`) for consistency.
* Log level `debug` will print which rule matched; helpful in staging.
