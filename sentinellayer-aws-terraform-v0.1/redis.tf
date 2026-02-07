resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name_prefix}-redis-subnets"
  subnet_ids = module.vpc.private_subnets
  tags       = local.tags
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "SentinelLayer Redis (rate limiting + caching)"
  node_type            = "cache.t4g.micro"
  port                 = 6379
  engine               = "redis"
  engine_version       = "7.0"
  parameter_group_name = "default.redis7"

  subnet_group_name  = aws_elasticache_subnet_group.redis.name
  security_group_ids = [aws_security_group.redis.id]

  automatic_failover_enabled = false
  multi_az_enabled           = false
  num_cache_clusters         = 1

  transit_encryption_enabled = true
  at_rest_encryption_enabled = true

  tags = local.tags
}
