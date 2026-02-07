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
$subnets = ($awsvpc.subnets -join ",")
$sgs = ($awsvpc.securityGroups -join ",")

Write-Host "Running Alembic migrations with task definition: $taskDef"

$net = "awsvpcConfiguration={subnets=[$subnets],securityGroups=[$sgs],assignPublicIp=DISABLED}"
$overridesObj = @{
  containerOverrides = @(
    @{
      name = $ContainerName
      command = @("alembic", "upgrade", "head")
    }
  )
}
$overridesJson = $overridesObj | ConvertTo-Json -Depth 10 -Compress

$run = aws ecs run-task `
  --cluster $Cluster `
  --launch-type FARGATE `
  --task-definition $taskDef `
  --count 1 `
  --network-configuration $net `
  --overrides $overridesJson `
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
$container = $desc.tasks[0].containers | Where-Object { $_.name -eq $ContainerName } | Select-Object -First 1

$exit = $container.exitCode
$reason = $container.reason

Write-Host ("Container exitCode={0} reason={1}" -f $exit, $reason)

if ($exit -ne 0) {
  throw "Migrations failed (exitCode=$exit). Check CloudWatch logs for details."
}

Write-Host "Migrations succeeded."
