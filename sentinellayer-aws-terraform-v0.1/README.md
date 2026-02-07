# SentinelLayer AWS Terraform (v0.2)

Terraform module for SentinelLayer API infrastructure with stricter state hygiene and drift controls.

## Provisioned stack

- VPC (2 AZ), public + private subnets, NAT
- ALB (HTTP->HTTPS redirect) + ACM certificate (DNS validated)
- ECS Fargate service for `sentinelayer-api`
- ECR repository
- RDS PostgreSQL 15 (Multi-AZ) with AWS-managed master password secret
- RDS Proxy
- ElastiCache Redis
- S3 artifacts bucket (public access block, encryption, versioning, TLS-only policy, 90-day lifecycle)
- CloudWatch log group
- Route53 `api.<domain>` alias to ALB

## Required runtime secret contract

ECS injects app runtime secrets from **one external Secrets Manager secret ARN** (`api_runtime_secret_arn`) with JSON keys:

- `database_url`
- `timescale_url`
- `github_client_id`
- `github_client_secret`
- `jwt_secret`

Example secret payload:

```json
{
  "database_url": "postgresql+asyncpg://sentinelayer:REPLACE@proxy-endpoint:5432/sentinelayer",
  "timescale_url": "postgresql+asyncpg://sentinelayer:REPLACE@proxy-endpoint:5432/sentinelayer",
  "github_client_id": "REPLACE",
  "github_client_secret": "REPLACE",
  "jwt_secret": "REPLACE"
}
```

Terraform does not store these values in state.

## Quick start

1. Copy backend config template:

```bash
cp backend.hcl.example backend.hcl
```

2. Copy variable template:

```bash
cp envs/prod.tfvars.example envs/prod.tfvars
```

3. Create the runtime secret in AWS Secrets Manager and set `api_runtime_secret_arn` in `envs/prod.tfvars`.

4. Init/plan/apply:

```bash
terraform init -backend-config=backend.hcl
terraform plan -var-file=envs/prod.tfvars
terraform apply -var-file=envs/prod.tfvars
```

5. Build/push API image:

```bash
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com
docker build -t sentinelayer-api:local -f ../sentinelayer-api/Dockerfile ../sentinelayer-api
docker tag sentinelayer-api:local $(terraform output -raw ecr_repository_url):v0.1.0
docker push $(terraform output -raw ecr_repository_url):v0.1.0
```

## Bootstrap sequence (new environment)

If you are creating a brand-new environment, use a two-pass rollout:

1. Create runtime secret with placeholder values and set `desired_count = 0`.
2. `terraform apply` to provision infra (RDS Proxy + Redis + ECS service).
3. Pull outputs:
   - `terraform output -raw rds_proxy_endpoint`
   - `terraform output -raw rds_master_secret_arn`
4. Read the RDS master secret in AWS and build `database_url` / `timescale_url`.
5. Update the runtime secret JSON.
6. Set `desired_count` to your target count and apply again.

## Drift routine (required)

```bash
terraform plan -refresh-only -var-file=envs/prod.tfvars -out=drift-prod.tfplan
terraform show -no-color drift-prod.tfplan > drift-prod.txt
```

Template workflow: `github_actions_templates/terraform_drift_refresh_only.yml`.

## State/secrets checks

```bash
terraform state pull > terraform-state.json
rg -n "(?i)password|secret|token|private_key|access_key|client_secret|jwt" terraform-state.json
```

## Guardrails

- RDS defaults are prod-safe (`deletion_protection=true`, final snapshot required).
- ECS task definition drift is managed by Terraform (no `ignore_changes` on task definition).
- S3 task IAM policy is prefix-scoped (`<project>/<env>/...`).
- 🔴 Infra changes require human approval + change record before production apply.
