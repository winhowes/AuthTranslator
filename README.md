# AuthTransformer

AuthTransformer is a simple Go-based reverse proxy that injects authentication tokens and enforces per-host and per-caller rate limits. It is configured through a JSON file and demonstrates a plug-in style architecture for authentication methods.

## Features

- **Reverse Proxy**: Forwards incoming HTTP requests to a target backend based on the requested host.
- **Pluggable Authentication**: Supports "basic" and "token" authentication types with room for extension.
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
       "auth_plugins": {
           "example.com": {
               "type": "basic",
               "owner": "admin@example.com"
           }
       },
       "routes": {
           "example.com": {
               "target": "http://backend.example.com",
               "rate_limit": {
                   "per_caller": 100,
                   "per_host": 1000
               }
           }
       }
   }
   ```
   
   - **auth_plugins**: Maps a hostname to an authentication plugin. The example uses `basic` auth.
   - **routes**: Defines where requests should be proxied and how they should be rate limited.

3. **Running**

   When started, the server listens on port `8080`. Incoming requests are matched against the host header to determine the route and associated authentication plugin.

## Running Tests

Use the Go toolchain to run the unit tests from the repository root:

```bash
GO111MODULE=off go test ./...
```

## Logging

AuthTransformer writes log messages to standard output. Each request generates an entry showing the HTTP method, host, path and remote address. Authentication failures and rate limiting events are also logged. The logger is configured with Go's standard time-prefixed format.
## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

