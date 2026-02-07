resource "aws_iam_role" "rds_proxy" {
  count = var.enable_rds_proxy ? 1 : 0

  name = "${local.name_prefix}-rds-proxy-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "rds.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
  tags = local.tags
}

resource "aws_iam_role_policy" "rds_proxy_secrets" {
  count = var.enable_rds_proxy ? 1 : 0

  name = "${local.name_prefix}-rds-proxy-secrets"
  role = aws_iam_role.rds_proxy[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [local.rds_master_secret_arn]
      }
    ]
  })
}

resource "aws_db_proxy" "postgres" {
  count = var.enable_rds_proxy ? 1 : 0

  name                   = "${local.name_prefix}-proxy"
  engine_family          = "POSTGRESQL"
  role_arn               = aws_iam_role.rds_proxy[0].arn
  vpc_subnet_ids         = module.vpc.private_subnets
  vpc_security_group_ids = [aws_security_group.rds_proxy.id]

  require_tls         = true
  idle_client_timeout = 1800

  auth {
    auth_scheme = "SECRETS"
    secret_arn  = local.rds_master_secret_arn
    iam_auth    = "DISABLED"
  }

  tags = local.tags
}

resource "aws_db_proxy_default_target_group" "postgres" {
  count = var.enable_rds_proxy ? 1 : 0

  db_proxy_name = aws_db_proxy.postgres[0].name

  connection_pool_config {
    max_connections_percent      = 90
    max_idle_connections_percent = 50
    connection_borrow_timeout    = 120
  }
}

resource "aws_db_proxy_target" "postgres" {
  count = var.enable_rds_proxy ? 1 : 0

  db_proxy_name     = aws_db_proxy.postgres[0].name
  target_group_name = aws_db_proxy_default_target_group.postgres[0].name
  # AWS expects the DB instance *identifier* (lowercase/hyphens), not the internal resource id (db-...).
  db_instance_identifier = aws_db_instance.postgres.identifier
}
