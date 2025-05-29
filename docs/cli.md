# Command‑Line Helpers

AuthTranslator ships with two small helper binaries under **`cmd/`**:

| Binary         | Purpose                                       | Typical usage                                       |
| -------------- | --------------------------------------------- | --------------------------------------------------- |
| `integrations` | Scaffold or inspect entries in *config.yaml*. | `go run ./cmd/integrations slack > config.yaml`     |
| `allowlist`    | Validate or query *allowlist.yaml*.           | `go run ./cmd/allowlist list --file allowlist.yaml` |

> **Heads‑up** Both helpers are thin wrappers around Go structs—check the `--help` output for the definitive flag list because the CLI evolves alongside the schema.

---

## 1  Installing (optional)

You can run directly with `go run`, but for faster iteration:

```bash
go install ./cmd/integrations@latest
go install ./cmd/allowlist@latest
```

Make sure `$GOBIN` is on your `PATH`.

---

## 2  `integrations` helper

```text
integrations <command> [flags]
```

### Common commands

| Command      | What it does                                                            |
| ------------ | ----------------------------------------------------------------------- |
| `list`       | Prints integration names found in a given `config.yaml`.                |
| `<template>` | Generates a YAML block for the named template (e.g. `slack`, `github`). |

```bash
# List existing integrations in ./config.yaml
integrations list --file config.yaml

# Create a Slack block with custom rate‑limit
integrations slack \
  --rate-window 1m --rate-requests 800 > slack.yaml
```

#### Notable flags

| Flag              | Default       | Meaning                                  |
| ----------------- | ------------- | ---------------------------------------- |
| `--file`          | `config.yaml` | Path to read (for `list`).               |
| `--rate-window`   | `60s`         | Window length when generating templates. |
| `--rate-requests` | `1000`        | Max requests in that window.             |
| `--timeout`       | `10s`         | Upstream transport timeout.              |
| `--output`        | `stdout`      | Where to write the generated YAML.       |

All flags mirror fields in the schema—no hidden magic.

---

## 3  `allowlist` helper

```text
allowlist <command> [flags]
```

### Common commands

| Command    | What it does                                                     |
| ---------- | ---------------------------------------------------------------- |
| `list`     | Prints caller IDs in an `allowlist.yaml`.                        |
| `validate` | Lints the file against the Go struct schema.                     |
| `get`      | Dumps rules for a single caller/integration pair (useful in CI). |

```bash
# Show all callers
go run ./cmd/allowlist list --file allowlist.yaml

# Validate syntax
go run ./cmd/allowlist validate --file allowlist.yaml

# Inspect what bot‑123 can do with Slack
go run ./cmd/allowlist get --file allowlist.yaml \
   --caller bot-123 --integration slack
```

#### Flags

| Flag            | Default          | Meaning                     |
| --------------- | ---------------- | --------------------------- |
| `--file`        | `allowlist.yaml` | Path to YAML file.          |
| `--caller`      | –                | Caller ID for `get`.        |
| `--integration` | –                | Integration name for `get`. |

---

## 4  Using helpers in CI

A minimal **GitHub Actions** snippet that validates both files on every PR:

```yaml
- name: Validate AuthTranslator config
  run: |
    go run ./cmd/integrations list --file config.yaml
    go run ./cmd/allowlist validate --file allowlist.yaml
```

Fail‑fast means broken YAML never reaches production.

If you template configs (e.g., with CUE or Helm), call the helpers *after* rendering so you lint the final artifacts.
