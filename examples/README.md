# Examples

This folder holds **runnable snippets** you can copy‑paste while reading the docs.

| File             | Purpose                                                                          |
| ---------------- | -------------------------------------------------------------------------------- |
| `config.yaml`    | Defines one Slack integration (destination, outgoing auth, 1‑minute rate‑limit). |
| `allowlist.yaml` | Grants caller `demo-user` the `post_as` capability.              |

## Quick try‑out

```bash
# Run the proxy with the sample configs

go run ./app \
  -config    examples/config.yaml \
  -allowlist examples/allowlist.yaml

# Smoke‑test it’s alive
curl http://localhost:8080/_at_internal/healthz
curl http://localhost:8080/_at_internal/metrics
```

Need a full walkthrough? Head over to [**docs/getting-started.md**](../docs/getting-started.md).
