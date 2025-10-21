# Getting Started

Welcome to **AuthTranslator**! In a couple of minutes you’ll have a running proxy that swaps a caller‑supplied credential for a long‑lived Slack app token.

---

## Prerequisites

| Requirement                                | Why you need it                                                           |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| **Docker ≥ 24**                            | Easiest way to run the proxy without installing Go.                       |
| **Slack app token** (`SLACK_TOKEN`)        | Long‑lived token with `chat:write` scope.                                 |
| *(Optional)* **Go 1.24+**                  | Only needed if you’d like to run from source.                             |

> **Tip** A personal workspace app is fine for testing.

---

## 1 – Run the proxy (Docker)

```bash
docker run --rm -p 8080:8080 \
  -e SLACK_TOKEN=demo-token \
  -v $(pwd)/examples:/conf \
  ghcr.io/winhowes/authtranslator:latest \
    -config /conf/config.yaml \
    -allowlist /conf/allowlist.yaml \
    -denylist /conf/denylist.yaml
```

`config.yaml` defines which integrations are available, `allowlist.yaml` controls which callers may use them, and
`denylist.yaml` lists requests that should always be rejected.

When the service starts it prints its version and log level to standard output.

---

## 2 – Send a request through the proxy

```bash
curl -H "Host: slack" \
     -H "X-Auth: demo-token" \
     -H "Content-Type: application/json" \
     --data '{"channel": "#general", "username": "AuthTranslator", "text": "Hello from AuthTranslator"}' \
     http://localhost:8080/api/chat.postMessage
```

If everything is wired up you’ll get back Slack’s normal JSON response and your message appears in **#general**.

In production deployments AuthTranslator is typically reached via a wildcard DNS entry like `*.auth.example.com` with a matching wildcard TLS certificate. The `Host` header (or subdomain) selects which integration handles each request.
If you can’t modify the `Host` header, set an `X-AT-Int` header with the integration name. This override is enabled by default but can be disabled with `-disable_x_at_int` or restricted using `-x_at_int_host`.

---

## Running from source (optional)

```bash
go run ./app \
  -config examples/config.yaml \
  -allowlist examples/allowlist.yaml \
  -denylist examples/denylist.yaml
```

Make sure `$SLACK_TOKEN` is still in your environment.

---

## Tweaking the config

* **Integrations** live in `config.yaml`. Change the `destination` URL or swap the `outgoing_auth` plug‑in.
* **Caller permissions** live in `allowlist.yaml`. Grant a different caller ID by editing or duplicating the YAML block.
* **Request blocks** live in `denylist.yaml`. Add patterns that should return `403` before hitting the upstream.
* The proxy hot‑reloads on **SIGHUP** or when started with `-watch`.

Full schema details: [Configuration](configuration.md).
For a deeper dive into permissions, see the [Allowlist Configuration](allowlist-config.md) guide.

AuthTranslator is extensible via three types of plugins:
[Auth Plugins](auth-plugins.md), [Secret Back-Ends](secret-backends.md) and
[Integration Plugins](integration-plugins.md).

---

## Next steps

* Dive into [Auth Plugins](auth-plugins.md) to wire up other services.
* Add rate‑limits with the [Rate‑Limiting](rate-limiting.md) guide.
* Ship to Kubernetes via the [Helm guide](helm.md).
* Spin up everything locally with [Docker Compose](docker-compose.md).
* Review common questions in the [FAQ](faq.md).
* Tweak flags and service behaviour via [Runtime & Operations](runtime.md).

Happy translating! 🎉
