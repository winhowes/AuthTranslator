# Command‑Line Helpers

AuthTranslator ships with two small helper binaries under **`cmd/`**:

| Binary         | Purpose                                       | Typical usage                                       |
| -------------- | --------------------------------------------- | --------------------------------------------------- |
| `integrations` | Scaffold or inspect entries in *config.yaml*. | `go run ./cmd/integrations slack > config.yaml`     |
| `allowlist`    | Modify or inspect *allowlist.yaml*.           | `go run ./cmd/allowlist add -integration slack -caller bot -capability ping` |

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

| Command  | What it does |
| -------- | ---------------------------------------------- |
| `list`   | Prints available capability names for each integration. |
| `add`    | Adds an entry to `allowlist.yaml`. |
| `remove` | Deletes an entry from `allowlist.yaml`. |

```bash
# Show available capabilities
go run ./cmd/allowlist list

# Grant a caller permission
go run ./cmd/allowlist add -integration slack \
    -caller bot-123 -capability post_public_as

# Revoke that permission
go run ./cmd/allowlist remove -integration slack \
    -caller bot-123 -capability post_public_as
```

#### Flags

| Flag            | Default          | Meaning                                    |
| --------------- | ---------------- | ------------------------------------------ |
| `--file`        | `allowlist.yaml` | Path to YAML file for `add`/`remove`.      |
| `--caller`      | –                | Caller ID for `add`/`remove`.              |
| `--integration` | –                | Integration name for `add`/`remove`.       |
| `--capability`  | –                | Capability name for `add`/`remove`.        |
| `--params`      | ""               | Extra key=value pairs for `add` (optional). |

---

## 4  Using helpers in CI

A minimal **GitHub Actions** snippet that checks both files on every PR:

```yaml
- name: Validate AuthTranslator config
  run: |
    go run ./cmd/integrations list --file config.yaml
    go run ./cmd/allowlist list
```

Fail‑fast means broken YAML never reaches production.

If you template configs (e.g., with CUE or Helm), call the helpers *after* rendering so you lint the final artifacts.
