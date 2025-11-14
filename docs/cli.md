# Command‑Line Helpers

AuthTranslator ships with two small helper binaries under **`cmd/`**:

| Binary         | Purpose                                       | Typical usage                                     |
| -------------- | --------------------------------------------- | ------------------------------------------------- |
| `integrations` | Modify or inspect *config.yaml*. | `go run ./cmd/integrations slack -file config.yaml -token env:SLACK_TOKEN -signing-secret env:SLACK_SIGNING` |
| `allowlist`    | Modify or inspect *allowlist.yaml*.           | `go run ./cmd/allowlist add -integration slack -caller bot -capability post_as` |
These helpers complement the [Configuration Reference](configuration.md) and [Allowlist Configuration](allowlist-yaml.md) docs.

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

| Command    | Purpose                                                             |
| ---------- | ------------------------------------------------------------------- |
| `list`     | Print the names of integrations defined in `config.yaml`.     |
| `update`   | Add or replace an integration using one of the plugin builders.   |
| `delete`   | Remove an integration by name.   |
| `<plugin>` | Generate a new integration using that plugin's flags and append it to the file.   |

```bash
# Add a Slack integration from env vars
go run ./cmd/integrations slack \
  -file config.yaml \
  -token env:SLACK_TOKEN -signing-secret env:SLACK_SIGNING

# Delete an integration
go run ./cmd/integrations delete slack -file config.yaml
```

#### Flags

| Flag       | Default                              | Meaning                    |
| ---------- | ------------------------------------ | -------------------------- |
| `-file`   | `config.yaml` | Path to the configuration file. |

## 3  `allowlist` helper

```text
allowlist <command> [flags]
```

### Common commands

| Command  | Purpose                                              |
| -------- | ---------------------------------------------------- |
| `list`   | Show capabilities provided by integration plugins.   |
| `add`    | Append a capability entry to `allowlist.yaml`.       |
| `remove` | Delete an entry from `allowlist.yaml`.               |

```bash
# Show available capabilities
go run ./cmd/allowlist list

# Grant a caller permission
go run ./cmd/allowlist add -integration slack \
  -caller bot-123 -capability post_as

# Revoke that permission
go run ./cmd/allowlist remove -integration slack \
  -caller bot-123 -capability post_as
```

#### Flags

| Flag            | Default          | Meaning                             |
| --------------- | ---------------- | ----------------------------------- |
| `-file`        | `allowlist.yaml` | Path to YAML file for `add`/`remove`. |
| `-caller`      | –                | Caller ID for `add`/`remove`.       |
| `-integration` | –                | Integration name for `add`/`remove`. |
| `-capability`  | –                | Capability name for `add`/`remove`. |
| `-params`      | ""               | Extra `key=value` pairs for `add` (optional). |

`allowlist list` prints the capability names registered by each integration plug-in
and the parameter keys they expect. It does **not** read `allowlist.yaml`; the
command is purely a discovery tool to help you decide which capability name and
parameter keys to pass to `add`.

The `-params` flag accepts a comma-separated list such as
`username=bot-123,channel=C123`. Each value is stored as a string in the YAML.
When a capability requires structured data (for example, the Slack plug-in's
`channels` parameter expects a list), run `add` with the closest shape you can and
then touch up the generated YAML manually to insert arrays or nested objects.

---

## 4  Using helpers in CI

A minimal **GitHub Actions** snippet that checks both files on every PR:

```yaml
- name: Validate AuthTranslator config
  run: |
    go run ./cmd/integrations list
    go run ./cmd/allowlist list
```

Fail‑fast means broken YAML never reaches production.

If you template configs (e.g., with CUE or Helm), call the helpers *after* rendering so you lint the final artifacts.
