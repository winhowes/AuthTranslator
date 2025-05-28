# Azure Container Instances Deployment

This Terraform configuration runs AuthTranslator on Azure Container Instances.

## Variables

Required:

- `subscription_id`
- `resource_group_name`
- `azure_region`
- `dns_name_label`
- `container_image`

Optional:

- `redis_address` – address for distributed rate limiting

## Example

Run the following in this directory:

```bash
terraform init
terraform apply \
  -var subscription_id=00000000-0000-0000-0000-000000000000 \
  -var resource_group_name=my-rg \
  -var azure_region=eastus \
  -var dns_name_label=authtranslator \
  -var container_image=myregistry.azurecr.io/authtranslator:latest
```
