# SentinelLayer AWS Terraform (v0.1)

This Terraform project provisions a **production-ready baseline** for the SentinelLayer API stack:

- VPC (2 AZ), public + private subnets, NAT
- ALB (HTTP->HTTPS redirect) + ACM certificate (DNS validated)
- ECS Fargate service for `sentinelayer-api` behind the ALB
- ECR repository for API images
- RDS PostgreSQL 15 (Multi-AZ) with a parameter group prepared for TimescaleDB (`shared_preload_libraries=timescaledb`)
- RDS Proxy (connection pooling)
- ElastiCache Redis (cluster mode disabled)
- S3 bucket for artifacts with encryption + 90-day lifecycle expiration
- CloudWatch log group for ECS task logs
- Route53 record: `api.<domain>` -> ALB

## Quick start

1) **Prereqs**
- Terraform >= 1.6
- AWS CLI authenticated
- A Route53 hosted zone for your domain (or create one and pass its ID)

2) **Configure variables**
Create `terraform.tfvars`:

```hcl
project_name     = "sentinelayer"
environment      = "prod"
aws_region       = "us-east-1"
domain_name      = "sentinelayer.com"
route53_zone_id  = "Z1234567890ABC" # REQUIRED

# Optional: if you want to set GitHub OAuth + JWT via TF (WARNING: puts secrets in TF state)
github_client_id     = "..."
github_client_secret = "..."
jwt_secret           = "..."

# Optional overrides
api_container_port = 8000
desired_count      = 1
```

3) **Init & apply**
```bash
terraform init
terraform plan
terraform apply
```

4) **Build & push API image**
After apply, Terraform outputs `ecr_repository_url`.

```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com
docker build -t sentinelayer-api:local -f ../sentinelayer-api/Dockerfile ../sentinelayer-api
docker tag sentinelayer-api:local $(terraform output -raw ecr_repository_url):v0.1.0
docker push $(terraform output -raw ecr_repository_url):v0.1.0
```

5) **Update ECS to run the new image**
You can:
- Manually update `var.api_image_tag` and `terraform apply`, OR
- Use the provided GitHub Actions deploy workflow template (recommended).

## Notes / guardrails

- **TimescaleDB**: Terraform prepares the parameter group. You still need to enable the extension in SQL:
  ```sql
  CREATE EXTENSION IF NOT EXISTS timescaledb;
  ```
  and then convert your telemetry table into a hypertable + configure retention/compression.

- **Migrations**: Do **not** run Alembic migrations on every container start in production.
  Prefer a one-off ECS run-task step in CI/CD before updating the service.

- **Secrets in Terraform state**: If you set `github_client_secret` or `jwt_secret` via variables,
  they will live in Terraform state. For production, store secrets outside Terraform (Secrets Manager console/CLI)
  and pass only the secret ARNs. This baseline keeps it simple; upgrade later.

