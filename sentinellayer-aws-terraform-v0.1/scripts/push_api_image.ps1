param(
  [string]$Region = "us-east-1",
  [string]$RepositoryName = "sentinelayer-prod-api",
  [string]$Tag = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Tag)) {
  try {
    $Tag = ("api-" + (git rev-parse --short=12 HEAD)).Trim()
  } catch {
    throw "Tag not provided and git not available. Provide -Tag."
  }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
$apiDir = Join-Path $repoRoot "sentinelayer-api"
$apiDockerfile = Join-Path $apiDir "Dockerfile"

if (-not (Test-Path $apiDockerfile)) {
  throw "Missing API Dockerfile at: $apiDockerfile"
}

$accountId = (aws sts get-caller-identity --query Account --output text).Trim()
$registry = "$accountId.dkr.ecr.$Region.amazonaws.com"
$imageUri = "$registry/$RepositoryName`:$Tag"

Write-Host "Logging in to ECR registry: $registry"
aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin $registry | Out-Null

Write-Host "Building API image: $imageUri"
docker build -f $apiDockerfile -t $imageUri $apiDir

Write-Host "Pushing: $imageUri"
docker push $imageUri | Out-Null

Write-Output $imageUri

