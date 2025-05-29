# `allowlist.yaml` – Caller Permissions

The **allow‑list** answers a single question:

> *Given this caller ID and integration, is the request allowed?*

It lives in `allowlist.yaml` and is hot‑reloaded just like `config.yaml`.

```text
apiVersion: v1alpha1  # optional, ignored today
callers:
  <callerID>:
    <integration-name>:
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
callers:
  bot-123:
    slack:
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
    method: POST                          # string or [string]
    query:                                # list of key=value pairs (ANDed)
      - channel=C12345678
    headers:                              # header=value list; empty list checks only presence
      X-Custom-Trace: [abc123]
    body:                                 # optional JSON *or* form filters
      json:
        text: "Hello world"               # matched recursively
      form: {}
```

> **Subset principle** *Every* field you specify must match the request; unspecified fields are ignored. This means your rule must be a **subset** of the incoming request.

| Request part | Matching logic                                                                                      |
| ------------ | --------------------------------------------------------------------------------------------------- |
| Path         | Must match the pattern **entirely**. `*` matches one segment; `**` matches the rest.                 |
| Method       | Case‑insensitive string compare.                                                                    |
| Query params | Each `key=value` must exist & match **first** value. Extra params allowed.                          |
| Headers      | Each `key=[values]` must exist with those values; an empty list only checks for presence. |
| Body JSON    | The specified object must be a recursive subset of the request body. Arrays are matched unordered. |
| Body form    | Same as JSON but for `application/x-www-form-urlencoded`. |

A rule like:

```yaml
  body:
    json:
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
