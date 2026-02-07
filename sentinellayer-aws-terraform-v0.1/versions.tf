terraform {
  required_version = ">= 1.6.0, < 2.0.0"
  backend "s3" {}

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.79.0, < 6.0.0"
    }
  }
}
