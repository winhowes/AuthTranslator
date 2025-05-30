# Getting Started

Welcome to **AuthTranslator**! In a couple of minutes you’ll have a running proxy that swaps a caller‑supplied credential for a long‑lived Slack app token.

---

## Prerequisites

| Requirement                                | Why you need it                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| **Docker ≥ 24**                            | Easiest way to run the proxy without installing Go.                       |
| **Slack app token** (`SLACK_TOKEN`)        | Long‑lived token with `chat:write` scope.                                 |
| **Slack signing secret** (`SLACK_SIGNING`) | Lets the proxy verify inbound Slack requests (if you later use webhooks). |
| *(Optional)* **Go 1.24+**                  | Only needed if you’d like to run from source.                             |

> **Tip** A personal workspace app is fine for testing.

---

## 1 – Run the proxy (Docker)

```bash
export SLACK_TOKEN="xoxb‑123…"
export SLACK_SIGNING="8f2b…"

docker run --rm -p 8080:8080 \
  -e SLACK_TOKEN -e SLACK_SIGNING \
  -v $(pwd)/examples:/conf \
  ghcr.io/winhowes/authtranslator:latest \
    -config /conf/config.yaml \    # integrations definition
    -allowlist /conf/allowlist.yaml  # caller permissions
```

You should see a log line like:

```text
INFO  authtranslator started  addr=0.0.0.0:8080 integrations=1
```

---

## 2 – Send a request through the proxy

```bash
curl -H "Host: slack" \                               # tells the proxy which integration
     -H "X-Auth: demo-user" \                          # caller credential (dummy for now)
     -G "http://localhost:8080/api/chat.postMessage" \  # Slack REST path
     --data-urlencode "channel=#general" \
     --data-urlencode "text=Hello from AuthTranslator"
```

If everything is wired up you’ll get back Slack’s normal JSON response and your message appears in **#general**.

In production deployments AuthTranslator is typically reached via a wildcard DNS entry like `*.auth.example.com` with a matching wildcard TLS certificate. The `Host` header (or subdomain) selects which integration handles each request.
If you can’t modify the `Host` header, set an `X-AT-Int` header with the integration name. This override is enabled by default but can be disabled with `-disable_x_at_int` or restricted using `-x_at_int_host`.

---

## Running from source (optional)

```bash
go run ./app \
  -config examples/config.yaml \
  -allowlist examples/allowlist.yaml
```

Make sure `$SLACK_TOKEN` and `$SLACK_SIGNING` are still in your environment.

---

## Tweaking the config

* **Integrations** live in `config.yaml`. Change the `destination` URL or swap the `outgoing_auth` plug‑in.
* **Caller permissions** live in `allowlist.yaml`. Grant a different caller ID by editing or duplicating the YAML block.
* The proxy hot‑reloads on **SIGHUP** or when started with `-watch`.

Full schema details: [Configuration](configuration.md).

AuthTranslator is extensible via three types of plugins:
[Auth Plugins](auth-plugins.md), [Secret Back-Ends](secret-backends.md) and
[Integration Plugins](integration-plugins.md).

---

## Next steps

* Dive into [Auth Plugins](auth-plugins.md) to wire up other services.
* Add rate‑limits with the [Rate‑Limiting](rate-limiting.md) guide.
* Ship to Kubernetes via the [Helm chart](../charts/authtranslator).

Happy translating! 🎉
