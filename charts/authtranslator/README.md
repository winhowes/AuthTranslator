# AuthTranslator Helm Chart

This chart deploys [AuthTranslator](https://github.com/winhowes/AuthTranslator) as a Kubernetes Deployment with an accompanying Service.

## Values

| Key | Description | Default |
|-----|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/winhowes/authtranslator` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `redisAddress` | Address passed to `-redis-addr` – either `host:port` or a `redis://`/`rediss://` URL | `""` |
| `redisCA` | CA file for verifying Redis TLS passed to `-redis-ca` | `""` |
| `secretRefresh` | Value passed to `-secret-refresh` | `""` |
| `resources` | Pod resource requests/limits | see `values.yaml` |
| `imagePullSecrets` | List of image pull secrets | `[]` |
| `serviceAccountName` | Pod service account | `""` |
| `config` | Contents of `config.yaml` stored in a ConfigMap | sample configuration |
| `allowlist` | Contents of `allowlist.yaml` stored in a ConfigMap | sample allowlist |
| `denylist` | Contents of `denylist.yaml` stored in a ConfigMap | sample denylist |

The configuration, allowlist, and denylist values are written to a ConfigMap that is mounted into the container at `/conf/config.yaml`, `/conf/allowlist.yaml`, and `/conf/denylist.yaml`.

## Installing

```bash
helm install my-release ./charts/authtranslator
```

Override any of the values above using the `--set` flag or a custom values file.
