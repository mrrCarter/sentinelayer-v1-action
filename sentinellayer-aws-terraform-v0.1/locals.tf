locals {
  name_prefix = "${var.project_name}-${var.environment}"

  azs = slice(data.aws_availability_zones.available.names, 0, 2)

  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  api_domain = "api.${var.domain_name}"

  artifacts_prefix              = "${var.project_name}/${var.environment}/"
  rds_master_secret_arn         = try(aws_db_instance.postgres.master_user_secret[0].secret_arn, null)
  rds_final_snapshot_identifier = var.rds_final_snapshot_identifier != "" ? var.rds_final_snapshot_identifier : "${local.name_prefix}-final"
}
