# `denylist.yaml` – Request Blockers

The **denylist** answers another narrow question:

> *Given this caller ID and integration, must the request be rejected—even if the allowlist would pass it?*

It lives beside `config.yaml` and `allowlist.yaml`, is hot‑reloaded, and is entirely optional. In day‑to‑day operation you should
prefer shaping access through the [allowlist](allowlist-config.md); the denylist is best reserved for defensive blocks (for
example, temporarily disabling tool calls in the OpenAI Responses API or blocking a channel in Slack that should never be posted to). Both files can be used in tandem: a
request must first be permitted by the allowlist and then **avoid matching** any deny rules.

---

## 1  File layout

Each entry targets a single integration and enumerates the callers or wildcard blocks that apply to it.

```yaml
- integration: <integration-name>
  callers:
    - id: <caller-id-or-"*">
      rules:
        - path: /api/resource
          methods:
            POST:
              headers:
                X-Env: [prod]
              query:
                region: [us-east-1]
```

* `integration` – required. Must match the integration name defined in `config.yaml` (case-insensitive internally).
* `callers` – required list. Each caller item may omit `id`, which is treated as the wildcard `"*"` entry.
* `rules` – required list per caller. Every rule needs a `path` and at least one HTTP verb under `methods`.

Duplicate caller IDs—or duplicate `path`/`method` combinations for a caller—fail validation at load time.

---

## 2  Caller matching

Caller IDs follow the same rules as the allowlist:

* **Exact ID** – a literal string such as `service-A` or `user-123`.
* **Wildcard** – supply `"*"` or leave `id` blank to create a fallback block that applies when no exact match exists.

During evaluation the proxy first checks rules for the authenticated caller. If none match, it then checks the wildcard rules (if
present).

---

## 3  Matching semantics

Denylist rules reuse the same `RequestConstraint` syntax as granular allowlist rules, but their evaluation is intentionally
strict:

* **Path and method must match first.** Paths are anchored and support `*` (single segment) and `**` (remainder) wildcards.
* **Every listed constraint must be present.** Headers, query parameters, and body fragments are all ANDed together. If a rule
  references both a query parameter and a header, for example, **both must be present with one of the listed values** for the rule to fire.
* **Value comparisons are exact string matches.** There is no regex or partial matching.
* **Bodies require a supported content type.** JSON and form bodies are parsed; other types skip matching and the rule will not
  apply.

> **Need an OR?** Create multiple rules (or duplicate caller entries) that each express one alternative. The proxy only blocks a
> request when a *single* rule’s entire constraint set matches the request. This makes it safe to layer narrow kill-switches
> without accidentally catching unrelated traffic.

---

## 4  Working alongside the allowlist

While the denylist can stand alone, using both files together gives the best control:

1. The request must appear on the allowlist for the caller.
2. The proxy evaluates the denylist for that integration and caller. If any rule matches, the proxy responds with **403 Forbidden**
   and sets `X-AT-Error-Reason` to the matching rule path.

Use the allowlist to declare the **intended** access surface, and keep the denylist as a precise safety net for exceptional cases
or incident response.

---

## 5  Reloading & tooling

The `-denylist` flag points to the local file (default `denylist.yaml`), and `-denylist-url` allows loading from a remote source.
Run the proxy with `-watch` or send `SIGHUP` to reload configuration, allowlist, and denylist files without downtime.

For schema validation, run:

```bash
yq eval -o=json denylist.yaml | jsonschema -i - schemas/denylist.schema.json
```
