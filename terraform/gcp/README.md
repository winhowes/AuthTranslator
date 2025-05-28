# Google Cloud Run Deployment

Terraform in this folder deploys AuthTranslator to Cloud Run.

## Variables

Required:

- `gcp_project`
- `gcp_region`
- `container_image`

Optional:

- `redis_address` – address for distributed rate limiting

## Example

Run from this folder:

```bash
terraform init
terraform apply \
  -var gcp_project=my-project \
  -var gcp_region=us-central1 \
  -var container_image=gcr.io/my-project/authtranslator:latest
```
