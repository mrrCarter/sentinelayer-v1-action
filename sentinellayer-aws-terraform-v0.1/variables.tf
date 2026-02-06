variable "project_name" {
  type        = string
  description = "Project name, used for naming resources."
  default     = "sentinelayer"
}

variable "environment" {
  type        = string
  description = "Environment name (e.g., dev, staging, prod)."
  default     = "prod"
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

# Optional app secrets (WARNING: will be stored in TF state)
variable "github_client_id" {
  type        = string
  description = "GitHub OAuth client id."
  default     = ""
  sensitive   = true
}

variable "github_client_secret" {
  type        = string
  description = "GitHub OAuth client secret."
  default     = ""
  sensitive   = true
}

variable "jwt_secret" {
  type        = string
  description = "JWT secret (HS256). If empty, Terraform generates one."
  default     = ""
  sensitive   = true
}
