# AuthTranslator

AuthTranslator is a simple Go-based reverse proxy that injects authentication tokens and enforces per-host and per-caller rate limits. It is configured through a JSON file and demonstrates a plug-in style architecture for authentication methods.

The project exists to make it trivial to translate one type of authentication into another. By running AuthTranslator as a centralized proxy, a small group of administrators can manage the secrets for each integration while developers simply reference those integrations. Ideally, this project allows short‑lived credentials provided by your organization to be exchanged for the long‑lived tokens required by third‑party services, and inbound requests bearing long‑lived credentials transformed back into short‑lived secrets. This keeps sensitive keys out of day‑to‑day workflows while still allowing seamless access.

### Goals

- **Centralized secrets management** – only a few trusted maintainers need to add or rotate secrets for each integration. Developers reference the integrations without ever seeing the underlying values.
- **Short‑lived credentials** – internal callers should use ephemeral tokens. The proxy swaps them for the long‑lived keys external services require and can also downgrade inbound requests to short‑lived tokens so long‑lived secrets never circulate internally.

## Features

- **Reverse Proxy**: Forwards incoming HTTP requests to a target backend based on the requested host or `X-AT-Int` header. The header can be disabled or restricted to a specific host using command-line flags.
- **Pluggable Authentication**: Supports "basic", "token", `hmac_signature`, `jwt`, `mtls`, `url_path`, `github_signature` and `slack_signature` authentication types for both incoming and outgoing requests including Google OIDC with room for extension.
- **Extensible Plugins**: Add new auth, secret and integration plugins to cover different systems.
- **Rate Limiting**: Limits the number of requests per caller and per host within a rolling window.
- **Allowlist**: Integrations can restrict specific callers to particular paths, methods and required parameters.
- **Configuration Driven**: Behavior is controlled via a JSON configuration file.
- **Clean Shutdown**: On SIGINT or SIGTERM the server and rate limiters are gracefully stopped.

## Development Requirements

- [Go](https://golang.org/doc/install) 1.24 or newer.
- [`golangci-lint`](https://github.com/golangci/golangci-lint) (optional) for running lint checks.

## Getting Started

1. **Build or Run**
   
   ```bash
   go run ./app -config app/config.json
   ```

   Run `go run ./app --help` to see all available flags.
   
   Or build an executable:
   
   ```bash
   go build -o authtranslator ./app
   ./authtranslator -config app/config.json
   ```

2. **Configuration File**
   
   Edit `app/config.json` to define auth plugins and route targets:
   
   ```json
   {
     "integrations": [
       {
         "name": "example",
         "destination": "http://backend.example.com",
         "in_rate_limit": 100,
         "out_rate_limit": 1000,
         "incoming_auth": [
           {"type": "token", "params": {"secrets": ["env:IN_TOKEN"], "header": "X-Auth"}}
         ],
         "outgoing_auth": [
           {"type": "token", "params": {"secrets": ["env:OUT_TOKEN"], "header": "X-Auth"}}
         ]
       }
     ]
   }
   ```

   The allowlist configuration lives in a separate `allowlist.json` file:

   ```json
   [
     {
       "integration": "example",
       "callers": [
         {
           "id": "user-token",
           "rules": [
             {"path": "/allowed", "methods": {"GET": {}}}
           ]
         }
       ]
     }
   ]
   ```

  Caller IDs are derived by the incoming auth plugins. Plugins that
  implement the `Identifier` interface return a string used to match the
  `id` field in the allowlist. `jwt` and `google_oidc` return the token's
  `sub` claim while `mtls` uses the client certificate's common name. The
  `token` plugin, for example, does not supply an ID. Allowlist entries are grouped first
  by integration name and then by caller ID. When no ID is available the
  wildcard `"*"` entry is used so all callers share those rules.

   Capabilities can be listed instead of explicit rules. Each capability expands
   to one or more rules when loaded, making it easy to audit access by name:

   ```json
   [
     {
       "integration": "slack",
       "callers": [
         {
           "id": "ci-bot-token",
           "capabilities": [
             {"name": "post_public_as", "params": {"username": "ci-bot"}}
           ]
         }
       ]
     }
   ]
   ```

### Allowlist Rules

Each caller entry lists path patterns and method constraints. `*` matches a
single path segment while `**` matches any remaining segments. Header names are
listed under `headers` and required body fields under `body`.

Example rule requiring an `X-Token` header and a JSON field:

```json
{
  "path": "/api/**",
  "methods": {
    "POST": {
      "headers": ["X-Token"],
      "body": {"action": "create"}
    }
  }
}
```

For `application/x-www-form-urlencoded` requests the `body` keys refer to form
fields and may list required values:

```json
{
  "path": "/submit",
  "methods": {
    "POST": {
      "body": {"tag": ["a", "b"]}
    }
  }
}
```

#### Body Matching

Body rules are checked against only the fields listed in the rule. Additional
fields in the request are ignored. Values are compared using these rules:

* **Primitive values** must match exactly.
* **Objects** are matched recursively. Every key present in the rule must also
  exist in the request with a value that satisfies the sub‑rule. Extra keys in the request are allowed.
* **Arrays** require that every element in the rule appear somewhere in the
  request array. Order does not matter and extra elements are allowed.

These rules apply to nested structures as well. For example, the rule

```json
{"items": [{"id": 1}]}
```

matches a body where `items` contains an object with `{"id":1}` anywhere in the
array.

### Built-in Authentication Plugins

   - **integrations**: Defines proxy routes, rate limits and authentication methods. Secret references use the `env:`, `file:` or KMS-prefixed formats described below.
   - **google_oidc**: Outgoing auth plugin that retrieves an ID token from the GCP metadata server and sets it in the `Authorization` header for backend requests. The incoming variant validates Google ID tokens against a configured audience.
   - **jwt**: Validates generic JWTs using provided keys and can attach tokens on outgoing requests.
   - **mtls**: Requires a verified client certificate and optional subject match, and accepts outbound certificate configuration.
   - **token**: Header token comparison for simple shared secrets.
   - **basic**: Performs HTTP Basic authentication using credentials loaded from configured secrets.
   - **hmac_signature**: Computes or verifies request HMAC digests with a configurable algorithm.
   - **github_signature**: Validates GitHub webhook signatures against shared secrets.
   - **slack_signature**: Validates Slack request signatures with timestamp tolerance.
   - **url_path**: Appends a secret to the request path for outgoing calls and verifies it on incoming requests.

### Capabilities

Integration plugins can bundle common allowlist rules into **capabilities**. Assigning a capability to a caller expands to one or more rules automatically. A few examples:

- `slack.post_public_as` – permit posting a message as a specific username.
- `slack.post_channels_as` – restrict posting to a defined set of channels.
- `github.comment` – allow creating issue comments in a given repository (requires the `repo` parameter).
- `github.create_issue` – permit opening issues in a given repository.
- `github.update_issue` – allow editing or closing issues in a given repository.
- `ghe.comment`, `ghe.create_issue`, `ghe.update_issue` – GitHub Enterprise equivalents requiring the `repo` parameter.
- `gitlab.comment`, `gitlab.create_issue`, `gitlab.update_issue` – similar capabilities for GitLab projects (use the `project` parameter).
- `asana.create_task`, `linear.create_task`, `jira.create_task` – permit creating tasks or issues.
- `asana.update_status`, `linear.update_status`, `jira.update_status` – allow modifying task or issue status.
- `asana.add_comment`, `linear.add_comment`, `jira.add_comment` – permit adding comments.
- `zendesk.open_ticket`, `servicenow.open_ticket` – allow creating support tickets.
- `zendesk.update_ticket`, `servicenow.update_ticket` – permit updating ticket details.
- `zendesk.query_status`, `servicenow.query_status` – allow reading ticket status.
- `sendgrid.send_email`, `sendgrid.manage_contacts`, `sendgrid.update_template` – basic SendGrid operations.
- `twilio.send_sms`, `twilio.make_call`, `twilio.query_message` – Twilio messaging and voice APIs.
- `okta.create_user`, `okta.update_user`, `okta.deactivate_user` – manage Okta user accounts.
- `workday.query_worker` – read worker information from Workday.
- `stripe.create_charge`, `stripe.refund_charge`, `stripe.create_customer` – Stripe payment flows.

### Secret Plugin Environment Variables

| Prefix | Environment Variables | Description |
| ------ | -------------------- | ----------- |
| `env`  | Names referenced in the configuration (e.g. `env:IN_TOKEN`) | Secrets are read directly from those environment variables. |
| `file` | _none_ | Reads file contents from disk for `file:` secrets. |
| `aws`  | `AWS_KMS_KEY` | Base64 encoded 32 byte key used for decrypting `aws:` secrets. |
| `azure`| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Credentials for fetching `azure:` secrets from Key Vault. |
| `gcp`  | _none_ | Uses the GCP metadata service for authentication when resolving `gcp:` secrets. |

### Writing Plugins

New functionality can be added without modifying the core server. There are three plugin categories:

- **Auth plugins** handle incoming and outgoing authentication.
- **Secret plugins** resolve secret references from external providers.
- **Integration plugins** generate predefined integration definitions and capability helpers for the CLI.

**Auth plugins** live under `app/authplugins`. Implement the
`IncomingAuthPlugin` or `OutgoingAuthPlugin` interface and call the appropriate
`authplugins.RegisterIncoming` or `authplugins.RegisterOutgoing` function in an
`init()` block.

**Secret plugins** implement the `secrets.Plugin` interface in
subdirectories of `app/secrets/plugins` and register themselves with
`secrets.Register`.

Integration plugins live under `cmd/integrations/plugins`. Each plugin registers
itself in an `init()` block using `plugins.Register`. The `Register` call
associates the plugin name with a function that parses CLI flags and returns an
`Integration` struct, so the CLI automatically recognizes new plugins.

3. **Running**

   The listen address can be configured with the `-addr` flag. By default the server listens on `:8080`. Incoming requests are matched against the `X-AT-Int` header, if present, or otherwise the host header to determine the route and associated authentication plugin. Use `-disable_x_at_int` to ignore the header entirely or `-x_at_int_host` to only respect the header when a specific host is requested. The configuration file is chosen with `-config` (default `config.json`). The allowlist file can be specified with `-allowlist`; it defaults to `allowlist.json`.

4. **Run Locally**

   Start a simple backend and point an integration at it to test the proxy:

   ```bash
   # terminal 1 - dummy backend
   python3 -m http.server 9000
   ```

   Edit `app/config.json` so the integration forwards to the local backend:

   ```json
   {
       "integrations": [
           {
               "name": "example",
               "destination": "http://localhost:9000",
               "in_rate_limit": 100,
               "out_rate_limit": 1000,
               "incoming_auth": [
                   {"type": "token", "params": {"secrets": ["env:IN_TOKEN"], "header": "X-Auth"}}
               ],
               "outgoing_auth": [
                   {"type": "token", "params": {"secrets": ["env:OUT_TOKEN"], "header": "X-Auth"}}
               ]
           }
       ]
   }
   ```

   Provide the environment variables referenced by the auth configuration and start the proxy:

   ```bash
   export IN_TOKEN=secret-in
   export OUT_TOKEN=secret-out
   go run ./app -config app/config.json -allowlist app/allowlist.json
   ```

   In another terminal, call the proxy using the integration name as the Host header:

   ```bash
   curl -H "Host: example" -H "X-Auth: $IN_TOKEN" http://localhost:8080/
   ```

## Integration CLI

Run `go run ./cmd/integrations --help` for a full list of commands and options.

Start the server with `-debug` so the `/integrations` endpoint is available:

```bash
go run ./app -debug
```

Then run the CLI to POST a new integration configuration. The `-server` flag
controls where the CLI sends the request (default `http://localhost:8080/integrations`).

List existing integrations:
```bash
go run ./cmd/integrations list
```

A helper CLI is available under `cmd/integrations` to create Slack, GitHub, GitHub Enterprise, GitLab, Jira, Linear, Asana, Zendesk, ServiceNow, SendGrid, Twilio or Stripe integrations with minimal flags.

Add Slack:
```bash
go run ./cmd/integrations -server http://localhost:8080/integrations \
  slack -token env:SLACK_TOKEN -signing-secret env:SLACK_SIGNING
```

Add GitHub:
```bash
go run ./cmd/integrations -server http://localhost:8080/integrations \
  github -token env:GITHUB_TOKEN -webhook-secret env:GITHUB_SECRET
```
Add GitHub Enterprise:
```bash
go run ./cmd/integrations -server http://localhost:8080/integrations \
  ghe -domain ghe.example.com -token env:GHE_TOKEN -webhook-secret env:GHE_SECRET
```
Add GitLab:
```bash
go run ./cmd/integrations -server http://localhost:8080/integrations \
  gitlab -token env:GITLAB_TOKEN
```
Add Jira:
```bash
go run ./cmd/integrations jira -token env:JIRA_TOKEN
```
Add Linear:
```bash
go run ./cmd/integrations linear -token env:LINEAR_TOKEN
```
Add Monday:
```bash
go run ./cmd/integrations monday -token env:MONDAY_TOKEN
```
Add Asana:
```bash
go run ./cmd/integrations asana -token env:ASANA_TOKEN
```
Add Zendesk:
```bash
go run ./cmd/integrations zendesk -token env:ZENDESK_TOKEN
```
Add ServiceNow:
```bash
go run ./cmd/integrations servicenow -token env:SERVICENOW_TOKEN
```
Add SendGrid:
```bash
go run ./cmd/integrations sendgrid -token env:SENDGRID_TOKEN
```
Add Twilio:
```bash
go run ./cmd/integrations twilio -token env:TWILIO_TOKEN
```
Add Okta:
```bash
go run ./cmd/integrations okta -domain okta.example.com -token env:OKTA_TOKEN
```
Add Workday:
```bash
go run ./cmd/integrations workday -domain workday.example.com -token env:WORKDAY_TOKEN
```
Add Stripe:
```bash
go run ./cmd/integrations stripe -token env:STRIPE_TOKEN
```

## Allowlist CLI

Run `go run ./cmd/allowlist --help` to view commands and flags.

The `allowlist` command helps maintain the `allowlist.json` file. Run `allowlist list` to view every capability defined by the integration plugins:

```bash
go run ./cmd/allowlist list
```

To grant a caller a capability use `allowlist add`:

```bash
go run ./cmd/allowlist add -integration slack \
    -caller user-token -capability post_public_as \
    -params username=ci-bot
```

The CLI updates the file in place (default `allowlist.json`, overridable with `-file`).

## Running Tests

Use the Go toolchain to vet and test the code:

```bash
go vet ./...
go test ./...
```

If you have [`golangci-lint`](https://github.com/golangci/golangci-lint) installed you can also run:

```bash
golangci-lint run
```

## Docker

Build the container image:

```bash
docker build -t authtranslator .
```

Run the image exposing port 8080:

```bash
docker run -p 8080:8080 authtranslator
```

## Logging

AuthTranslator writes log messages to standard output. Each request generates an entry showing the HTTP method, host, path and remote address. Authentication failures and rate limiting events are also logged. HTTP status codes from upstream services are logged, allowing metrics to capture downstream errors. The logger is configured with Go's standard time-prefixed format.

## Deploying with Terraform

Example Terraform files are provided in the `terraform` directory for AWS, GCP and Azure.

- `terraform/aws` contains the AWS configuration for ECS Fargate.
- `terraform/gcp` contains a configuration for deploying to Google Cloud Run.
- `terraform/azure` contains a configuration for deploying to Azure Container Instances.

Set the required variables for your environment and run `terraform apply` inside the desired folder to create the service.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

