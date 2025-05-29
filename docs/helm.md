# Deploying with Helm

This guide walks through installing **AuthTranslator** on Kubernetes using the Helm chart found in **`charts/authtranslator/`**. Helm ≥ 3.9 is assumed.

> **Why Helm?**  Templating secrets, ConfigMaps, and Optional Redis in one place makes day‑2 ops (upgrades, rollbacks) far easier than raw manifests.

---

## 1  Quick install

From the repository root:

```bash
helm upgrade --install authtranslator charts/authtranslator \
  --namespace authtranslator --create-namespace \
  --set image.tag="$(git rev-parse --short HEAD)" \
  --set slack.token=$SLACK_TOKEN \
  --set slack.signing=$SLACK_SIGNING
```

This:

* Creates a `Deployment` running **one replica** of AuthTranslator.
* Mounts your `config.yaml` and `allowlist.yaml` via `ConfigMap`.
* Sets two **Kubernetes Secrets** for the Slack token & signing secret.
* Exposes port 8080 via a `ClusterIP` Service called `authtranslator`.

---

## 2  Values reference (excerpt)

| Key                | Default                           | Description                                                        |
| ------------------ | --------------------------------- | ------------------------------------------------------------------ |
| `image.repository` | `ghcr.io/winhowes/authtranslator` | Override to use a private registry.                                |
| `image.tag`        | `latest`                          | Image tag or digest.                                               |
| `replicaCount`     | `1`                               | Horizontal scaling factor.                                         |
| `service.type`     | `ClusterIP`                       | `LoadBalancer` or `NodePort` as needed.                            |
| `redis.enabled`    | `false`                           | When `true`, chart deploys a Redis sub-chart and sets `REDIS_URL`. |
| `configYaml`       | *(string)*                        | Raw YAML for `config.yaml`.                                        |
| `allowlistYaml`    | *(string)*                        | Raw YAML for `allowlist.yaml`.                                     |
| `extraEnv`         | `{}`                              | Map of extra env vars (e.g., `STRIPE_TOKEN`).                      |
| `resources`        | `{}`                              | Pod CPU/memory requests & limits.                                  |

Full schema lives in `charts/authtranslator/values.yaml`.

### Example `values.yaml`

```yaml
image:
  tag: "1.2.3"

replicaCount: 2

redis:
  enabled: true

configYaml: |
  apiVersion: v1alpha1
  integrations:
    slack:
      destination: https://slack.com
      outgoing_auth:
        type: slack_app_token
        params:
          token: env:SLACK_TOKEN

allowlistYaml: |
  callers:
    demo:
      slack:
        capabilities: [slack.chat.write.public]

extraEnv:
  SLACK_TOKEN: "xoxb-..."
  SLACK_SIGNING: "8f2b-..."
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

> **Note** Config and allowlist hot‑reload inside the container, but image tag changes require a pod rollout.

---

## 4  Chart structure

```text
charts/authtranslator/
  Chart.yaml          # metadata
  values.yaml         # user-tunable defaults
  templates/
    deployment.yaml
    service.yaml
    configmap.yaml
    secret.yaml
    redis.yaml        # included only when enabled
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
