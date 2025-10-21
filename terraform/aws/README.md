# AWS ECS Fargate Deployment

This directory contains Terraform to run AuthTranslator on AWS using ECS Fargate.

## Variables

Required:

- `aws_region`
- `container_image`
- `execution_role_arn`
- `subnet_ids`
- `security_group_id`

Optional:

- `redis_address` – address for distributed rate limiting
- `redis_ca` – CA file for verifying Redis TLS
- `config_path` – path to the configuration file inside the container
- `allowlist_path` – path to the allowlist file inside the container
- `denylist_path` – path to the denylist file inside the container

## Example

Run from this folder after setting your values:

```bash
terraform init
terraform apply \
  -var aws_region=us-east-1 \
  -var container_image=ghcr.io/example/authtranslator:latest \
  -var execution_role_arn=arn:aws:iam::123456789012:role/ecsTaskExecutionRole \
  -var 'subnet_ids=["subnet-abc","subnet-def"]' \
  -var security_group_id=sg-abc123
```
