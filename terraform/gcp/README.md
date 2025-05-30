# Google Cloud Run Deployment

Terraform in this folder deploys AuthTranslator to Cloud Run.

## Variables

Required:

- `gcp_project`
- `gcp_region`
- `container_image`

Optional:

- `redis_address` – address for distributed rate limiting
- `redis_ca` – CA file for verifying Redis TLS
- `config_path` – path to the configuration file inside the container
- `allowlist_path` – path to the allowlist file inside the container

## Example

Run from this folder:

```bash
terraform init
terraform apply \
  -var gcp_project=my-project \
  -var gcp_region=us-central1 \
  -var container_image=gcr.io/my-project/authtranslator:latest
```
