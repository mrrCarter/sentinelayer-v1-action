resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"
  tags = local.tags
}

resource "aws_iam_role" "ecs_task_execution" {
  name = "${local.name_prefix}-ecs-exec-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ecs-tasks.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_task_execution_secrets" {
  name = "${local.name_prefix}-ecs-exec-secrets"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        # Allow ECS agent to inject secrets at container start.
        # Keep scope tight: only the runtime secret + the AWS-managed RDS master secret.
        Resource = compact([var.api_runtime_secret_arn, local.rds_master_secret_arn])
      }
    ]
  })
}

resource "aws_iam_role" "ecs_task" {
  name               = "${local.name_prefix}-ecs-task-role"
  assume_role_policy = aws_iam_role.ecs_task_execution.assume_role_policy
  tags               = local.tags
}

resource "aws_iam_role_policy" "ecs_task_access" {
  name = "${local.name_prefix}-ecs-task-access"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [aws_s3_bucket.artifacts.arn]
        Condition = {
          StringLike = {
            "s3:prefix" = ["${local.artifacts_prefix}*"]
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:AbortMultipartUpload"
        ]
        Resource = ["${aws_s3_bucket.artifacts.arn}/${local.artifacts_prefix}*"]
      }
    ]
  })
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${local.name_prefix}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.api_cpu)
  memory                   = tostring(var.api_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "api"
      image = "${aws_ecr_repository.api.repository_url}:${var.api_image_tag}"

      portMappings = [
        {
          containerPort = var.api_container_port
          hostPort      = var.api_container_port
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "S3_BUCKET", value = aws_s3_bucket.artifacts.bucket },
        { name = "S3_REGION", value = var.aws_region },
        { name = "S3_PREFIX", value = local.artifacts_prefix },
        { name = "REDIS_URL", value = "rediss://${aws_elasticache_replication_group.redis.primary_endpoint_address}:6379" },
        { name = "GITHUB_OIDC_ISSUER", value = "https://token.actions.githubusercontent.com" },
        { name = "TELEMETRY_RATE_LIMIT", value = tostring(var.telemetry_rate_limit) },

        # DB connection is derived at container start from rotating RDS credentials (DB_USERNAME/DB_PASSWORD).
        # This avoids baking a password-bearing DATABASE_URL into a long-lived secret string that drifts on rotation.
        { name = "DB_HOST", value = var.enable_rds_proxy ? aws_db_proxy.postgres[0].endpoint : aws_db_instance.postgres.address },
        { name = "DB_PORT", value = "5432" },
        { name = "DB_NAME", value = var.db_name },
        { name = "DB_SCHEME", value = "postgresql+asyncpg" }
      ]

      secrets = [
        { name = "DB_USERNAME", valueFrom = "${local.rds_master_secret_arn}:username::" },
        { name = "DB_PASSWORD", valueFrom = "${local.rds_master_secret_arn}:password::" },
        { name = "GITHUB_CLIENT_ID", valueFrom = "${var.api_runtime_secret_arn}:github_client_id::" },
        { name = "GITHUB_CLIENT_SECRET", valueFrom = "${var.api_runtime_secret_arn}:github_client_secret::" },
        { name = "JWT_SECRET", valueFrom = "${var.api_runtime_secret_arn}:jwt_secret::" }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.api.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "api"
        }
      }

      healthCheck = {
        # Liveness probe: should not depend on external systems like DB/Redis to avoid restart loops.
        command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:${var.api_container_port}/health', timeout=2).read()\" || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = local.tags
}

resource "aws_ecs_service" "api" {
  name            = "${local.name_prefix}-api"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.api.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = module.vpc.private_subnets
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = var.api_container_port
  }

  # With autoscaling enabled, the desired count will legitimately drift. Ignore that drift,
  # otherwise drift checks and deploy applies will constantly fight Application Auto Scaling.
  lifecycle {
    ignore_changes = [desired_count]
  }

  # Keep capacity during deployments (especially important when min_count can be 1).
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.https]

  tags = local.tags
}

resource "aws_appautoscaling_target" "api" {
  count = var.enable_autoscaling ? 1 : 0

  max_capacity       = var.max_count
  min_capacity       = var.min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  count = var.enable_autoscaling ? 1 : 0

  name               = "${local.name_prefix}-api-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api[0].resource_id
  scalable_dimension = aws_appautoscaling_target.api[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.api[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 60
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "api_memory" {
  count = var.enable_autoscaling ? 1 : 0

  name               = "${local.name_prefix}-api-memory"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api[0].resource_id
  scalable_dimension = aws_appautoscaling_target.api[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.api[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    # Keep memory headroom to reduce OOM/restarts under bursty workloads.
    target_value       = 75
    scale_in_cooldown  = 60
    scale_out_cooldown = 60
  }
}
