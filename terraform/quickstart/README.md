This example uses the Docker provider to quickly run AuthTranslator on a single
machine. Ensure Docker is installed then run:

```bash
terraform init
terraform apply -var container_image=ghcr.io/winhowes/authtranslator:latest
```

The container will listen on port 8080.
