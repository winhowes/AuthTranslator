# Runtime & Operations

This guide explains how AuthTranslator behaves at runtime and lists the service flags used to tune its behaviour.

---

## Startup and shutdown

* **Validated startup** – the proxy fails fast when configuration errors are detected.
* **Clean shutdown** – processes `SIGINT` and `SIGTERM` gracefully so in‑flight requests complete.

---

## Hot reload

Send `SIGHUP` or run with `-watch` to reload the configuration, allowlist, and denylist files without dropping connections. The watcher re-adds itself when files are replaced so edits trigger a reload automatically. Remote configuration URLs honour the `-remote-fetch-timeout` flag (default 10&nbsp;seconds) when fetching over HTTP.

---

## Resource tuning

* **Redis support** – specify `-redis-addr` to persist rate‑limit counters in Redis. Use `rediss://` for TLS and provide `-redis-ca` to verify the server certificate; without it TLS skips verification.
* **Body size limit** – adjust buffered request bytes with `-max_body_size` (default 10 MB, `0` disables the limit).

---

## Service flags

AuthTranslator exposes several command‑line options:

| Flag | Description |
| ---- | ----------- |
| `-addr` | listen address (default `:8080`) |
| `-config` | path to the configuration file (`config.yaml` by default) |
| `-config-url` | URL for a remote configuration file |
| `-allowlist` | path to the allowlist file (`allowlist.yaml` by default) |
| `-allowlist-url` | URL for a remote allowlist file |
| `-denylist` | path to the denylist file (`denylist.yaml` by default) |
| `-denylist-url` | URL for a remote denylist file |
| `-remote-fetch-timeout` | HTTP timeout when fetching remote configuration, allowlist, or denylist files (default `10s`) |
| `-disable_x_at_int` | ignore the `X-AT-Int` header |
| `-x_at_int_host` | only respect `X-AT-Int` when this host is requested |
| `-tls-cert` and `-tls-key` | TLS certificate and key to serve HTTPS |
| `-redis-addr` | Redis address for rate limit counters. Accepts `host:port` or a `redis://`/`rediss://` URL with optional `user:pass@` credentials. |
| `-redis-ca` | CA certificate for verifying Redis TLS; leave empty to skip verification |
| `-redis-timeout` | timeout for dialing Redis (default `5s`) |
| `-max_body_size` | maximum bytes buffered from request bodies; use `0` to disable |
| `-secret-refresh` | refresh interval for cached secrets; `0` disables expiry |
| `-read-timeout` | HTTP server read timeout (default `0` - disabled) |
| `-write-timeout` | HTTP server write timeout (default `0` - disabled) |
| `-log-level` | log verbosity (`DEBUG`, `INFO`, `WARN`, `ERROR`) |
| `-log-format` | log output format (`text` or `json`) |
| `-version` | print the build version and exit |
| `-watch` | automatically reload when config, allowlist, or denylist files change |
| `-enable-metrics` | expose the `/_at_internal/metrics` endpoint (default `true`) |
| `-enable-http3` | serve HTTP/3 in addition to HTTP/1 and HTTP/2 (requires `-tls-cert` and `-tls-key`) |
| `-metrics-user` | username required to access `/_at_internal/metrics` (must be used with `-metrics-pass`) |
| `-metrics-pass` | password required to access `/_at_internal/metrics` (must be used with `-metrics-user`) |

---

## Integration routing

By default the proxy chooses an integration by matching the request's `Host`
header to the names declared in `config.yaml`.  When clients cannot change the
`Host` header, they may supply an `X-AT-Int` header instead.  Its value is treated
the same as a host name and looked up case-insensitively.

The header is ignored when the service starts with `-disable_x_at_int`.  Use
`-x_at_int_host` to allow overrides only when the incoming `Host` matches a
specific value.

---

## Running tests

Use the Makefile helpers before committing changes:

```bash
make precommit
make test
make tidy
make ci
```

`make precommit` formats and vets the code and runs `golangci-lint` if installed.
`make ci` runs the precommit checks, tidies modules and executes the tests with coverage.
