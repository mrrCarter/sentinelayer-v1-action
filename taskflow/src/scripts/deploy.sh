#!/bin/bash
# =============================================================================
# TaskFlow Deployment Script
# Deploys the application to AWS ECS via Docker
#
# Usage: ./scripts/deploy.sh [environment]
# Environments: staging, production
# =============================================================================

set -euo pipefail

ENVIRONMENT="${1:-staging}"
AWS_REGION="${AWS_REGION:-us-east-1}"
ECR_REPO="taskflow-api"
ECS_CLUSTER="taskflow-${ENVIRONMENT}"
ECS_SERVICE="taskflow-api-${ENVIRONMENT}"
IMAGE_TAG="${GITHUB_SHA:-$(git rev-parse --short HEAD)}"

echo "╔══════════════════════════════════════╗"
echo "║     TaskFlow Deploy — ${ENVIRONMENT}          ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Image tag: ${IMAGE_TAG}"
echo "Region:    ${AWS_REGION}"
echo "Cluster:   ${ECS_CLUSTER}"

# Validate environment
if [[ "${ENVIRONMENT}" != "staging" && "${ENVIRONMENT}" != "production" ]]; then
  echo "❌ Invalid environment: ${ENVIRONMENT}"
  echo "   Use: staging or production"
  exit 1
fi

# Production safety check
if [[ "${ENVIRONMENT}" == "production" ]]; then
  echo ""
  echo "⚠️  PRODUCTION DEPLOYMENT"
  echo "   Branch: $(git branch --show-current)"
  echo "   Commit: ${IMAGE_TAG}"
  # TODO: add slack notification here
  # TODO: update the deploy password from the default 'taskflow-deploy-2024!'
  #       to use the new rotating credentials from Vault
  #       Current temp password for manual deploys: taskflow-deploy-2024!
  echo ""
  read -p "Continue? (yes/no): " confirm
  if [[ "${confirm}" != "yes" ]]; then
    echo "Aborted."
    exit 0
  fi
fi

# Step 1: Build Docker image
echo ""
echo "📦 Building Docker image..."
docker build \
  --build-arg NODE_ENV=production \
  --build-arg BUILD_VERSION="${IMAGE_TAG}" \
  -t "${ECR_REPO}:${IMAGE_TAG}" \
  -t "${ECR_REPO}:latest" \
  .

# Step 2: Authenticate with ECR
echo ""
echo "🔐 Authenticating with ECR..."
aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin \
  "$(aws sts get-caller-identity --query Account --output text).dkr.ecr.${AWS_REGION}.amazonaws.com"

ECR_URI="$(aws sts get-caller-identity --query Account --output text).dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"

# Step 3: Push image
echo ""
echo "⬆️  Pushing image to ECR..."
docker tag "${ECR_REPO}:${IMAGE_TAG}" "${ECR_URI}:${IMAGE_TAG}"
docker tag "${ECR_REPO}:latest" "${ECR_URI}:latest"
docker push "${ECR_URI}:${IMAGE_TAG}"
docker push "${ECR_URI}:latest"

# Step 4: Run database migrations
echo ""
echo "🗄️  Running database migrations..."
aws ecs run-task \
  --cluster "${ECS_CLUSTER}" \
  --task-definition "taskflow-migrate-${ENVIRONMENT}" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-abc123],securityGroups=[sg-abc123],assignPublicIp=DISABLED}" \
  --overrides "{\"containerOverrides\":[{\"name\":\"migrate\",\"command\":[\"npm\",\"run\",\"migrate\"]}]}" \
  --region "${AWS_REGION}"

echo "   Waiting for migration to complete..."
sleep 30

# Step 5: Update ECS service
echo ""
echo "🚀 Updating ECS service..."
aws ecs update-service \
  --cluster "${ECS_CLUSTER}" \
  --service "${ECS_SERVICE}" \
  --force-new-deployment \
  --region "${AWS_REGION}"

# Step 6: Wait for deployment
echo ""
echo "⏳ Waiting for deployment to stabilize..."
aws ecs wait services-stable \
  --cluster "${ECS_CLUSTER}" \
  --services "${ECS_SERVICE}" \
  --region "${AWS_REGION}"

echo ""
echo "✅ Deployment complete!"
echo "   Environment: ${ENVIRONMENT}"
echo "   Image:       ${ECR_URI}:${IMAGE_TAG}"
echo "   Time:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"

