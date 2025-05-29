[![Go Report Card](https://goreportcard.com/badge/github.com/winhowes/AuthTranslator)](https://goreportcard.com/report/github.com/winhowes/AuthTranslator)

# AuthTranslator

AuthTranslator is a Go-based reverse proxy that translates authentication tokens and enforces per-host and per-caller rate limits. It is configured through a YAML file and supports a plug-in architecture for authentication methods.

## Documentation

Extensive guides covering features, configuration and plugin development live in the [docs](docs/) directory.

## Examples

Sample configuration files are provided in the [examples](examples/) folder.

## Quick Start

Download a pre-built binary and run using the example configuration:

```bash
curl -L https://github.com/winhowes/AuthTranslator/releases/latest/download/authtranslator_$(uname -s)_$(uname -m).tar.gz | tar -xz
./authtranslator -config examples/config.yaml
```

Or run from source:

```bash
go run ./app -config examples/config.yaml
```

See [docs/guide.md](docs/guide.md) for complete usage details.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
