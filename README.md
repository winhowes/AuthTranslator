# AuthTransformer

AuthTransformer is a simple Go-based reverse proxy that injects authentication tokens and enforces per-host and per-caller rate limits. It is configured through a JSON file and demonstrates a plug-in style architecture for authentication methods.

## Features

- **Reverse Proxy**: Forwards incoming HTTP requests to a target backend based on the requested host or `X-AT-Int` header. The header can be disabled or restricted to a specific host using command-line flags.
- **Pluggable Authentication**: Supports "basic", "token" and Google OIDC authentication types with room for extension.
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
   
   Or build an executable:
   
   ```bash
   go build -o authtransformer ./app
   ./authtransformer -config app/config.json
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



   - **integrations**: Defines proxy routes, rate limits and authentication methods. Secret references use the `env:` or KMS-prefixed formats described below.
   - **google_oidc**: Outgoing auth plugin that retrieves an ID token from the GCP metadata server and sets it in the `Authorization` header for backend requests. The incoming variant validates Google ID tokens against a configured audience.
   - **basic**: Performs HTTP Basic authentication using credentials loaded from configured secrets.

### Secret Plugin Environment Variables

| Prefix | Environment Variables | Description |
| ------ | -------------------- | ----------- |
| `env`  | Names referenced in the configuration (e.g. `env:IN_TOKEN`) | Secrets are read directly from those environment variables. |
| `aws`  | `AWS_KMS_KEY` | Base64 encoded 32 byte key used for decrypting `aws:` secrets. |
| `azure`| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | Credentials for fetching `azure:` secrets from Key Vault. |
| `gcp`  | _none_ | Uses the GCP metadata service for authentication when resolving `gcp:` secrets. |

### Writing Plugins

New functionality can be added without modifying the core server.

**Auth plugins** live under `app/authplugins`. Implement the
`IncomingAuthPlugin` or `OutgoingAuthPlugin` interface and call the appropriate
`authplugins.RegisterIncoming` or `authplugins.RegisterOutgoing` function in an
`init()` block.

**Secret plugins** implement the `secrets.Plugin` interface in
`app/secrets/plugins` and register themselves with `secrets.Register`.

The CLI in `cmd/integrations` can be extended by creating a new helper in
`cmd/integrations/plugins` that returns an `Integration` struct. Add a case to
`cmd/integrations/main.go` so the CLI recognizes the new plugin name.

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

Start the server with `-debug` so the `/integrations` endpoint is available:

```bash
go run ./app -debug
```

Then run the CLI to POST a new integration configuration. The `-server` flag
controls where the CLI sends the request (default `http://localhost:8080/integrations`).

A helper CLI is available under `cmd/integrations` to create Slack, GitHub, Jira or Linear integrations with minimal flags.

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
Add Jira:
```bash
go run ./cmd/integrations jira -token env:JIRA_TOKEN
```
Add Linear:
```bash
go run ./cmd/integrations linear -token env:LINEAR_TOKEN
```

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
docker build -t authtransformer .
```

Run the image exposing port 8080:

```bash
docker run -p 8080:8080 authtransformer
```

## Logging

AuthTransformer writes log messages to standard output. Each request generates an entry showing the HTTP method, host, path and remote address. Authentication failures and rate limiting events are also logged. The logger is configured with Go's standard time-prefixed format.

## Deploying with Terraform

Example Terraform files are provided in the `terraform` directory for AWS, GCP and Azure.

- `terraform/aws` contains the AWS configuration for ECS Fargate.
- `terraform/gcp` contains a configuration for deploying to Google Cloud Run.
- `terraform/azure` contains a configuration for deploying to Azure Container Instances.

Set the required variables for your environment and run `terraform apply` inside the desired folder to create the service.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

