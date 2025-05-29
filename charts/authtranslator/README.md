# AuthTranslator Helm Chart

This chart deploys [AuthTranslator](https://github.com/winhowes/AuthTranslator) as a Kubernetes Deployment with an accompanying Service.

## Values

| Key | Description | Default |
|-----|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/winhowes/authtranslator` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `redisAddress` | Redis connection string passed to `-redis-addr` | `""` |
| `redisCA` | CA file for verifying Redis TLS passed to `-redis-ca` | `""` |
| `config` | Contents of `config.yaml` stored in a ConfigMap | sample configuration |
| `allowlist` | Contents of `allowlist.yaml` stored in a ConfigMap | sample allowlist |

The configuration and allowlist values are written to a ConfigMap that is mounted into the container at `/app/config.yaml` and `/app/allowlist.yaml`.

## Installing

```bash
helm install my-release ./charts/authtranslator
```

Override any of the values above using the `--set` flag or a custom values file.
