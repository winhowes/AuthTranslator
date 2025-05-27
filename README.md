# AuthTransformer

AuthTransformer is a simple Go-based reverse proxy that injects authentication tokens and enforces per-host and per-caller rate limits. It is configured through a JSON file and demonstrates a plug-in style architecture for authentication methods.

## Features

- **Reverse Proxy**: Forwards incoming HTTP requests to a target backend based on the requested host.
- **Pluggable Authentication**: Supports "basic", "token" and Google OIDC authentication types with room for extension.
- **Rate Limiting**: Limits the number of requests per caller and per host within a rolling window.
- **Configuration Driven**: Behavior is controlled via a JSON configuration file.

## Getting Started

1. **Build or Run**
   
   ```bash
   go run ./app
   ```
   
   Or build an executable:
   
   ```bash
   go build -o authtransformer ./app
   ./authtransformer
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

   - **integrations**: Defines proxy routes, rate limits and authentication methods. Secret references use the `env:` or KMS-prefixed formats described below.
   - **google_oidc**: Outgoing auth plugin that retrieves an ID token from the GCP metadata server and sets it in the `Authorization` header for backend requests.

3. **Running**

   When started, the server listens on port `8080`. Incoming requests are matched against the host header to determine the route and associated authentication plugin.

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
   go run ./app
   ```

   In another terminal, call the proxy using the integration name as the Host header:

   ```bash
   curl -H "Host: example" -H "X-Auth: $IN_TOKEN" http://localhost:8080/
   ```

## Running Tests

Use the Go toolchain to run the unit tests from the repository root:

```bash
GO111MODULE=off go test ./...
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

