# Frequently Asked Questions

A collection of questions that pop up in issues, Slack, and code‑reviews. If yours isn’t answered here, open an issue or discussion!

---

### 1 What *is* AuthTranslator in one sentence?

A lightweight reverse‑proxy that swaps the caller’s short‑lived credential for the long‑lived credential required by an upstream API—so application code never needs to store 3rd‑party secrets.

---

### 2 Does AuthTranslator ever store the caller’s credential?

No. Incoming plugins validate or inspect the token, derive a **caller ID**, then discard the credential before the request leaves the proxy.

---

### 3 What’s the difference between `config.yaml` and `allowlist.yaml`?

`config.yaml` defines **integrations** (destination URL, outgoing auth plug‑in, rate‑limit window). `allowlist.yaml` maps **caller IDs** to the specific paths/methods—or higher‑level *capabilities*—they may access.

---

### 4 How do I hot‑reload config changes?

Either:

```bash
kill -s SIGHUP <pid>
```

—or—start the proxy with `-watch` so it polls the config directory for changes every second.

---

### 5 Can I run more than one replica behind a load balancer?

Yes. For **rate‑limiting** accuracy you should point the pods at a shared Redis instance using the `-redis-addr` flag. Everything else is stateless.

---

### 6 How do I disable rate‑limiting entirely?

Set `in_rate_limit: 0` and `out_rate_limit: 0` (or omit the fields entirely). Rate limits are disabled by default.

---

### 7 Which secret back‑ends are built‑in?

* `env:` (environment variable)
* `file:` (volume‑mounted file)
* `gcp-secret:` (Google Secret Manager)
* `aws-secret:` (AWS Secrets Manager)
* `azure-keyvault:` (Azure Key Vault)
* `vault:` (HashiCorp Vault)

You can add more with \~50 LoC—see [Secret Back‑Ends](secret-backends.md).

---

### 8 What happens if a secret fetch fails on startup?

The proxy logs the error and exits with a non‑zero status so orchestration (systemd, Kubernetes) can restart or alert.

---

### 9 How do I rotate a secret?

Update the value in your vault/provider **and** trigger a hot reload (SIGHUP or `-watch`). The proxy re‑resolves all secret URIs on reload.

---

### 10 Does AuthTranslator support gRPC or WebSockets?

Not today. It operates on plain HTTP(S) requests; gRPC/WebSocket upgrades are currently rejected with **426 Upgrade Required**.

---

### 11 Why am I seeing 429s even though I set `requests` high?

Remember limits are **per caller ID** *and* **per integration**. If your load‑test tool randomises caller IDs you’ll hit the default 1000 req/min bucket. Either consolidate IDs or raise the limit.

---

### 12 Where are the health and metrics endpoints?

* Liveness: `/_at_internal/healthz`
* Prometheus metrics: `/_at_internal/metrics`

Both are always enabled and do **not** require authentication.

---

### 13 Is there a UI or dashboard?

Not built‑in. Most users expose Prometheus metrics to Grafana.

---

### 14 How do I log request/response headers for debugging?

Run the proxy with `-log-level DEBUG`. Secrets are automatically redacted.
