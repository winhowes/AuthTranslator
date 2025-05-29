# Runtime & Operations

This guide explains how AuthTranslator behaves at runtime and lists the service flags used to tune its behaviour.

---

## Startup and shutdown

* **Validated startup** – the proxy fails fast when configuration errors are detected.
* **Clean shutdown** – processes `SIGINT` and `SIGTERM` gracefully so in‑flight requests complete.

---

## Hot reload

Send `SIGHUP` or run with `-watch` to reload the configuration and allowlist files without dropping connections. The watcher re-adds itself when files are replaced so edits trigger a reload automatically.

---

## Resource tuning

* **Redis support** – specify `-redis-addr` to persist rate‑limit counters in Redis with optional TLS via `rediss://` and certificate verification using `-redis-ca`.
* **Body size limit** – adjust buffered request bytes with `-max_body_size` (default 10 MB, `0` disables the limit).

---

## Service flags

AuthTranslator exposes several command‑line options:

| Flag | Description |
| ---- | ----------- |
| `-addr` | listen address (default `:8080`) |
| `-config` | path to the configuration file (`config.yaml` by default) |
| `-allowlist` | path to the allowlist file (`allowlist.yaml` by default) |
| `-disable_x_at_int` | ignore the `X-AT-Int` header |
| `-x_at_int_host` | only respect `X-AT-Int` when this host is requested |
| `-tls-cert` and `-tls-key` | TLS certificate and key to serve HTTPS |
| `-redis-addr` | Redis address for rate limit counters. Accepts `host:port` or a `redis://`/`rediss://` URL with optional `user:pass@` credentials. |
| `-redis-ca` | CA certificate for verifying Redis TLS |
| `-redis-timeout` | timeout for dialing Redis (default `5s`) |
| `-max_body_size` | maximum bytes buffered from request bodies; use `0` to disable |
| `-log-level` | log verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`) |
| `-log-format` | log output format (`text` or `json`) |
| `-version` | print the build version and exit |
| `-watch` | automatically reload when config or allowlist files change |
| `-enable-metrics` | expose the `/_at_internal/metrics` endpoint (default `true`) |
| `-metrics-user` | username required to access `/_at_internal/metrics` |
| `-metrics-pass` | password required to access `/_at_internal/metrics` |

---

## Running tests

Use the Makefile helpers before committing changes:

```bash
make precommit
make test
```

`make precommit` formats and vets the code and runs `golangci-lint` if installed.
