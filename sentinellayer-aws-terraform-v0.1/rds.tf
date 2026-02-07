resource "aws_db_subnet_group" "db" {
  name       = "${local.name_prefix}-db-subnets"
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

resource "aws_db_parameter_group" "postgres15" {
  name   = "${local.name_prefix}-pg15"
  family = "postgres15"
  tags   = local.tags

  parameter {
    apply_method = "pending-reboot"
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements"
  }
}

resource "aws_db_instance" "postgres" {
  identifier            = "${local.name_prefix}-db"
  engine                = "postgres"
  engine_version        = "15"
  instance_class        = var.rds_instance_class
  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = 200

  db_name                     = var.db_name
  username                    = var.db_master_username
  manage_master_user_password = true

  multi_az            = var.rds_multi_az
  publicly_accessible = false
  storage_encrypted   = true
  apply_immediately   = var.rds_apply_immediately

  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  parameter_group_name   = aws_db_parameter_group.postgres15.name

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:05:00-sun:06:00"

  deletion_protection       = var.rds_deletion_protection
  skip_final_snapshot       = var.rds_skip_final_snapshot
  final_snapshot_identifier = var.rds_skip_final_snapshot ? null : local.rds_final_snapshot_identifier

  tags = local.tags
}
