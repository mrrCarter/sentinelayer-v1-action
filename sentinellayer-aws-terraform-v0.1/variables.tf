variable "project_name" {
  type        = string
  description = "Project name, used for naming resources."
  default     = "sentinelayer"
}

variable "environment" {
  type        = string
  description = "Environment name (e.g., dev, staging, prod)."
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "aws_region" {
  type        = string
  description = "AWS region."
  default     = "us-east-1"
}

variable "domain_name" {
  type        = string
  description = "Root domain name (e.g., sentinelayer.com)."
}

variable "route53_zone_id" {
  type        = string
  description = "Route53 hosted zone ID for domain_name."
}

variable "api_runtime_secret_arn" {
  type        = string
  description = "ARN of Secrets Manager secret containing JSON keys: database_url, timescale_url, github_client_id, github_client_secret, jwt_secret."
}

variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR range."
  default     = "10.20.0.0/16"
}

variable "api_container_port" {
  type        = number
  description = "Container port exposed by the API."
  default     = 8000
}

variable "desired_count" {
  type        = number
  description = "Initial desired task count."
  default     = 1
}

variable "max_count" {
  type        = number
  description = "Max autoscaling task count."
  default     = 20
}

variable "api_cpu" {
  type        = number
  description = "Fargate task CPU units."
  default     = 256
}

variable "api_memory" {
  type        = number
  description = "Fargate task memory (MB)."
  default     = 512
}

variable "api_image_tag" {
  type        = string
  description = "API image tag to deploy initially."
  default     = "v0.1.0"
}

variable "db_name" {
  type        = string
  description = "Primary DB name for Sentinelayer API."
  default     = "sentinelayer"
}

variable "db_master_username" {
  type        = string
  description = "Master username for RDS PostgreSQL."
  default     = "sentinelayer"
}

variable "rds_deletion_protection" {
  type        = bool
  description = "Enable deletion protection for RDS instance."
  default     = true
}

variable "rds_skip_final_snapshot" {
  type        = bool
  description = "Whether to skip final snapshot on RDS destroy."
  default     = false
}

variable "rds_final_snapshot_identifier" {
  type        = string
  description = "Final snapshot identifier for RDS destroy when rds_skip_final_snapshot is false."
  default     = ""
}
