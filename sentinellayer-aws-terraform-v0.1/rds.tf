resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_db_subnet_group" "db" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

resource "aws_db_parameter_group" "postgres15_timescale" {
  name   = "${local.name_prefix}-pg15-timescale"
  family = "postgres15"
  tags   = local.tags

  parameter {
    name  = "shared_preload_libraries"
    value = "timescaledb"
  }
}

resource "aws_db_instance" "postgres" {
  identifier             = "${local.name_prefix}-db"
  engine                 = "postgres"
  engine_version         = "15"
  instance_class         = "db.t4g.medium"
  allocated_storage      = 50
  max_allocated_storage  = 200

  db_name                = "sentinelayer"
  username               = "sentinelayer"
  password               = random_password.db_password.result

  multi_az               = true
  publicly_accessible    = false
  storage_encrypted      = true

  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.postgres15_timescale.name

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:05:00-sun:06:00"

  skip_final_snapshot     = true

  tags = local.tags
}
