# `allowlist.yaml` – Caller Permissions

The **allow‑list** answers a single question:

> *Given this caller ID and integration, is the request allowed?*

It lives in `allowlist.yaml` and is hot‑reloaded just like `config.yaml`.
While the proxy starts without this file, doing so lets any authenticated caller access every integration. In production we **strongly recommend** defining an allowlist, even if it initially grants a single wildcard caller.

```yaml
apiVersion: v1alpha1  # optional, ignored today
- integration: <integration-name>
  callers:
    - id: <callerID>
      [capabilities: [ ... ] | rules: [ ... ]]
```

---

## 1  Caller ID keys

* **Exact ID** `user-123`, `service-A`, `spiffe://tenant/worker`
* **Wildcard** `"*"` – used when the incoming auth plugin did **not** return an ID. Handy for anonymous webhooks.

If no matching caller key exists, the proxy returns **403 Forbidden**.

---

## 2  Two authorization styles

| Style              | When to use                                                    | YAML field                          |
| ------------------ | -------------------------------------------------------------- | ----------------------------------- |
| **Capabilities**   | You want a friendly, reusable label ("post public Slack msg"). | `capabilities:` *(list of strings)* |
| **Granular rules** | You need fine‑grained filters (path, query, header, body).     | `rules:` *(list of Rule objects)*   |

You can mix both—capabilities first, fall back to granular.

### Capabilities

Capabilities serve two goals:

1. **Developer ergonomics** – a single label replaces dozens of path/method/body rules.
2. **Auditability** – security reviewers can grep for the label instead of combing through lengthy rule lists. If a suitable capability exists, **prefer it over hand‑rolled granular rules**.

Capabilities are defined **next to each integration plugin**. They expand into one or more granular rules that match that integration’s API surface.

```yaml
- integration: slack
  callers:
    - id: bot-123
      capabilities: [slack.chat.write.public]
```

> **Discovering capabilities** Run the CLI helper:
>
> ```bash
> go run ./cmd/allowlist list
> ```
>
> (Use `--help` for plugin-specific flags.)
>
> For guidelines on adding new capabilities, see [integration-plugins.md](integration-plugins.md).

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
        body:                              # optional JSON or form filters
          text: "Hello world"              # matched recursively
          # body format is detected via Content-Type; other types skip matching
```

Allowed values are matched **exactly**; the proxy does not interpret regular expressions.

Each key under `methods:` represents an HTTP method. Mapping a method to `{}`
means the request is allowed for that verb as soon as the path matches. Add
`query`, `headers`, or `body` constraints inside a method block to further limit
which requests are permitted.

> **Subset principle** *Every* field you specify must match the request; unspecified fields are ignored. This means your rule must be a **subset** of the incoming request.

| Request part | Matching logic                                                                                      |
| ------------ | --------------------------------------------------------------------------------------------------- |
| Path         | Must match the pattern **entirely**. `*` matches one segment; `**` matches the rest.                 |
| Method       | Case‑insensitive string compare. Each method key contains its own constraints. |
| Query params | In `methods.<HTTP_METHOD>.query`, each key maps to allowed value list. Extra params allowed. Values match exactly.
| Headers      | In `methods.<HTTP_METHOD>.headers`, each key has required values; an empty list only checks for presence. Values match exactly.
| Body         | `methods.<HTTP_METHOD>.body` must be a recursive subset of the request body (JSON or form). Arrays matched unordered. Detection relies on the `Content-Type` header; if it's neither JSON nor form, body checks are skipped.

A rule like:

```yaml
  body:
    obj:
      inner:
        more_inner: x
      arr: [2, 1]
```

matches a request body
`{"obj": {"inner": {"more_inner": "x", "extra_more_inner": "y"}, "arr": [1, 2, 3], "extra": true}}`.

A request passes if **any** rule (or capability‑expanded rule) matches.

---

## 3  Tips & conventions

* **One capability ≈ one business use‑case** (e.g. `slack.chat.write.public`).
* Prefer **uppercase** HTTP methods (`GET`, `POST`) for consistency.
* Log level `debug` will print which rule matched; helpful in staging.
