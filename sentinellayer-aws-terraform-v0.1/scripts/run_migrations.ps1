param(
  [string]$Region = "us-east-1",
  [string]$Cluster = "sentinelayer-prod-cluster",
  [string]$Service = "sentinelayer-prod-api",
  [string]$ContainerName = "api"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$svc = aws ecs describe-services --cluster $Cluster --services $Service --region $Region --output json | ConvertFrom-Json
if (-not $svc.services -or $svc.services.Count -eq 0) {
  throw "ECS service not found: $Cluster / $Service"
}

$taskDef = $svc.services[0].taskDefinition
$awsvpc = $svc.services[0].networkConfiguration.awsvpcConfiguration

Write-Host "Running Alembic migrations with task definition: $taskDef"

$cliInput = @{
  cluster        = $Cluster
  launchType     = "FARGATE"
  taskDefinition = $taskDef
  count          = 1
  networkConfiguration = @{
    awsvpcConfiguration = @{
      subnets        = $awsvpc.subnets
      securityGroups = $awsvpc.securityGroups
      assignPublicIp = "DISABLED"
    }
  }
  overrides = @{
    containerOverrides = @(
      @{
        name = $ContainerName
        # Use python -m to ensure /app is on sys.path (alembic console script sets sys.path[0]=/usr/local/bin).
        command = @("python", "-m", "alembic", "upgrade", "head")
      }
    )
  }
}

$tmp = Join-Path $env:TEMP ("ecs-migrate-" + [guid]::NewGuid().ToString("n") + ".json")
$cliInput | ConvertTo-Json -Depth 20 | Set-Content -Encoding utf8 $tmp

$run = aws ecs run-task `
  --cli-input-json ("file://$tmp") `
  --region $Region `
  --output json | ConvertFrom-Json

if ($run.failures -and $run.failures.Count -gt 0) {
  $run.failures | ConvertTo-Json -Depth 10 | Write-Output
  throw "run-task returned failures"
}

$taskArn = $run.tasks[0].taskArn
Write-Host "Started task: $taskArn"

aws ecs wait tasks-stopped --cluster $Cluster --tasks $taskArn --region $Region | Out-Null

$desc = aws ecs describe-tasks --cluster $Cluster --tasks $taskArn --region $Region --output json | ConvertFrom-Json
if (-not $desc.tasks -or $desc.tasks.Count -eq 0) {
  throw "describe-tasks returned no tasks for: $taskArn"
}

$container = $desc.tasks[0].containers | Where-Object { $_.name -eq $ContainerName } | Select-Object -First 1
if (-not $container) {
  throw "Container not found in task: $ContainerName"
}

$exit = $null
if ($null -ne $container.PSObject.Properties["exitCode"]) {
  $exit = $container.exitCode
}

$reason = $null
if ($null -ne $container.PSObject.Properties["reason"]) {
  $reason = $container.reason
}

Write-Host ("Container exitCode={0} reason={1}" -f $exit, $reason)

try {
  $taskId = $taskArn.Split("/")[-1]
  $stream = "api/api/$taskId"
  Write-Host "CloudWatch log stream: $stream"
  aws logs get-log-events `
    --log-group-name "/ecs/sentinelayer-prod-api" `
    --log-stream-name $stream `
    --region $Region `
    --limit 200 `
    --query "events[*].message" `
    --output text
} catch {
  Write-Host "Unable to fetch CloudWatch logs for migration task."
}

if ($exit -ne 0) {
  throw "Migrations failed (exitCode=$exit). Check CloudWatch logs for details."
}

Write-Host "Migrations succeeded."
