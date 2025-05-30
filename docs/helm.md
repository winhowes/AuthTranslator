# Deploying with Helm

This guide walks through installing **AuthTranslator** on Kubernetes using the Helm chart found in **`charts/authtranslator/`**. Helm ≥ 3.9 is assumed. See [charts/authtranslator/README.md](../charts/authtranslator/README.md) for a full list of chart values.

> **Why Helm?**  Templating secrets, ConfigMaps, and Optional Redis in one place makes day‑2 ops (upgrades, rollbacks) far easier than raw manifests.

---

## 1  Quick install

From the repository root:

```bash
helm upgrade --install authtranslator charts/authtranslator \
  --namespace authtranslator --create-namespace \
  --set image.tag="$(git rev-parse --short HEAD)"
```

This:

* Creates a `Deployment` running **one replica** of AuthTranslator.
* Mounts your `config.yaml` and `allowlist.yaml` via a `ConfigMap`.
* Exposes port 8080 via a `ClusterIP` Service called `authtranslator`.

---

## 2  Values reference (excerpt)

| Key                | Default                           | Description                                                        |
| ------------------ | --------------------------------- | ------------------------------------------------------------------ |
| `image.repository` | `ghcr.io/winhowes/authtranslator` | Override to use a private registry.                                |
| `image.tag`        | `latest`                          | Image tag or digest.                                               |
| `image.pullPolicy` | `IfNotPresent`                    | Image pull policy.                                                 |
| `redisAddress`     | `""`                              | Address passed to `-redis-addr` – either `host:port` or a `redis://`/`rediss://` URL. |
| `redisCA`          | `""`                              | CA file verifying Redis TLS passed to `-redis-ca`. |
| `resources`        | *(object)*                        | Pod resource requests/limits. |
| `imagePullSecrets` | `[]`                              | Names of image pull secrets. |
| `serviceAccountName` | `""`                            | Pod service account name. |
| `config`           | *(string)*                        | Raw YAML for `config.yaml`.                                        |
| `allowlist`        | *(string)*                        | Raw YAML for `allowlist.yaml`.                                     |

Full schema lives in [`charts/authtranslator/values.yaml`](../charts/authtranslator/values.yaml).

### Example `values.yaml`

```yaml
image:
  tag: "1.2.3"

redisAddress: "redis://redis:6379/0"

config: |
  apiVersion: v1alpha1
  integrations:
    - name: slack
      destination: https://slack.com
      outgoing_auth:
        - type: token
          params:
            secrets:
              - env:SLACK_TOKEN
            header: Authorization
            prefix: "Bearer "

allowlist: |
  - integration: slack
    callers:
      - id: demo
        capabilities: [slack.chat.write.public]

```

Install with:

```bash
helm install authtranslator charts/authtranslator -f values.yaml
```

---

## 3  Upgrading the chart

Helm makes rollbacks trivial:

```bash
helm upgrade authtranslator charts/authtranslator -f values.yaml --set image.tag=1.2.4

# If something breaks:
helm rollback authtranslator 1   # roll back to previous revision
```

---

## 4  Chart structure

```text
charts/authtranslator/
  Chart.yaml          # metadata
  values.yaml         # user-tunable defaults
  templates/
    _helpers.tpl
    configmap.yaml
    deployment.yaml
    service.yaml
```

Feel free to add ingress, PodDisruptionBudget, or HPA templates as your cluster demands.

---

## 5  Using an OCI registry (optional)

```bash
# Package and push
helm package charts/authtranslator
helm push authtranslator-*.tgz oci://ghcr.io/winhowes/charts

# Later, install via OCI reference
helm install authtranslator oci://ghcr.io/winhowes/charts/authtranslator --version 1.2.3
```

---

## 6  Deploying with Terraform

Example Terraform configurations live in the [`terraform/`](../terraform/) directory:

- [`terraform/quickstart`](../terraform/quickstart) – minimal Docker provider example.
- [`terraform/aws`](../terraform/aws) – deploys to AWS ECS Fargate.
- [`terraform/gcp`](../terraform/gcp) – deploys to Google Cloud Run.
- [`terraform/azure`](../terraform/azure) – deploys to Azure Container Instances.

Set the variables for your environment and run `terraform apply` inside the
chosen folder to create the service. The modules accept optional
`redis_address`, `redis_timeout` and `redis_ca` variables which map to the
container flags.
