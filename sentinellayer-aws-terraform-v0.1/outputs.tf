output "api_endpoint" {
  value       = "https://${local.api_domain}"
  description = "Public API endpoint."
}

output "alb_dns_name" {
  value = aws_lb.api.dns_name
}

output "rds_endpoint" {
  value = aws_db_instance.postgres.address
}

output "rds_proxy_endpoint" {
  value = try(aws_db_proxy.postgres[0].endpoint, null)
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "s3_bucket" {
  value = aws_s3_bucket.artifacts.bucket
}

output "ecr_repository_url" {
  value = aws_ecr_repository.api.repository_url
}

output "cloudwatch_log_group" {
  value = aws_cloudwatch_log_group.api.name
}

output "rds_master_secret_arn" {
  value       = local.rds_master_secret_arn
  description = "AWS-managed RDS master credentials secret ARN."
}

output "api_runtime_secret_arn" {
  value       = var.api_runtime_secret_arn
  description = "API runtime secret ARN (app contract secret managed out-of-band)."
}
