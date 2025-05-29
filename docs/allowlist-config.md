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
> go run ./cmd/integrations list-capabilities --integration slack
> ```
>
> (Use `--help` for the exact flag name.)
>
> For guidelines on adding new capabilities, see [integration-plugins.md](integration-plugins.md).

### Granular Rule

```yaml
rules:
  - path:   /api/chat.postMessage          # path pattern, anchored
    method: POST                          # string or [string]
    query:                                # list of key=value pairs (ANDed)
      - channel=C12345678
    headers:                              # must all be present (values optional)
      - X-Custom-Trace
    body:                                 # optional JSON *or* form filters
      json:
        text: "Hello world"               # exact match on top-level key
      form: {}
    rate_limit:                           # optional override
      window: 10s
      requests: 20
```

> **Subset principle** *Every* field you specify must match the request; unspecified fields are ignored. This means your rule must be a **subset** of the incoming request.

| Request part | Matching logic                                                                                      |
| ------------ | --------------------------------------------------------------------------------------------------- |
| Path         | Must match the pattern **entirely**. `*` matches one segment; `**` matches the rest.                 |
| Method       | Case‑insensitive string compare.                                                                    |
| Query params | Each `key=value` must exist & match **first** value. Extra params allowed.                          |
| Headers      | Header names must exist (value not checked).                                                        |
| Body JSON    | The top‑level key must exist and its string value match exactly. Non‑string/absent keys → reject.   |
| Body form    | Same as JSON but for `application/x-www-form-urlencoded`.                                           |

A request passes if **any** rule (or capability‑expanded rule) matches.

---

## 3  Per‑rule vs integration‑wide rate‑limits

* Integration block in `config.yaml` sets a **default** bucket.
* A rule’s `rate_limit:` overrides *for that caller + rule only*.

This lets you allow a bursty webhook while keeping other calls throttled.

---

## 4  Tips & conventions

* **One capability ≈ one business use‑case** (e.g. `slack.chat.write.public`).
* Prefer **uppercase** HTTP methods (`GET`, `POST`) for consistency.
* Log level `debug` will print which rule matched; helpful in staging.
