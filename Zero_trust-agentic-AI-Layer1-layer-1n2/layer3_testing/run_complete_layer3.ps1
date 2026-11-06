param([switch]$SkipBuild, [switch]$LeaveRunning)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$runtime = Join-Path $PSScriptRoot "runtime"
New-Item -ItemType Directory -Force -Path $runtime | Out-Null
$report = [ordered]@{ startedAt = [DateTime]::UtcNow.ToString("o"); status = "running"; checks = @(); sourceHashes = @{} }
$failure = $null

function Get-SourceHashes {
    $hashes = @{}
    foreach ($directory in @("layer3_common", "policy_administration_service", "policy_information_service",
            "policy_decision_service", "access_control_service", "protected_sales_service", "agent_services")) {
        Get-ChildItem -Path $directory -Filter *.py -Recurse | ForEach-Object {
            $hashes[$_.FullName.Substring($root.Length + 1)] = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    }
    foreach ($file in @("docker-compose.yml", "layer3_common/Dockerfile", "layer3_common/requirements.txt",
            "agent_services/Dockerfile", "agent_services/requirements.txt")) {
        $hashes[$file] = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    }
    return $hashes
}

Push-Location $root
try {
    & docker info --format '{{.ServerVersion}}'
    if ($LASTEXITCODE -ne 0) { throw "Start Docker Desktop and wait until the engine is running." }
    $report.sourceHashes = Get-SourceHashes
    if (-not $SkipBuild) {
        & docker compose up -d --build
        if ($LASTEXITCODE -ne 0) { throw "Docker build/start failed." }
    }
    & python -m pytest layer3_testing/test_security.py layer3_testing/test_policy_hardening.py agent_testing/test_agents.py agent_testing/test_protected_sales.py -q |
        Tee-Object -FilePath (Join-Path $runtime "offline-tests.log")
    if ($LASTEXITCODE -ne 0) { throw "Focused regression tests failed." }
    $report.checks += "offline-regressions"
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run_enforcement_test.ps1") |
        Tee-Object -FilePath (Join-Path $runtime "enforcement-tests.log")
    if ($LASTEXITCODE -ne 0) { throw "Real Layer 3 enforcement failed." }
    $report.checks += "real-layer3-enforcement"
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root "agent_testing/run_protected_orchestrator_test.ps1") |
        Tee-Object -FilePath (Join-Path $runtime "orchestrator-tests.log")
    if ($LASTEXITCODE -ne 0) { throw "Protected TaskOrchestrator integration failed." }
    $report.checks += "real-protected-orchestrator"
    $currentHashes = Get-SourceHashes
    if ($currentHashes.Count -ne $report.sourceHashes.Count) { throw "Source changed during acceptance; rerun the suite." }
    foreach ($entry in $report.sourceHashes.GetEnumerator()) {
        if ($currentHashes[$entry.Key] -ne $entry.Value) { throw "Source changed during acceptance: $($entry.Key)" }
    }
    $report.status = "passed"
} catch {
    $report.status = "failed"
    $report.error = $_.Exception.Message
    $failure = $_
} finally {
    if (-not $LeaveRunning) {
        & docker compose stop
        if ($LASTEXITCODE -ne 0) {
            $report.status = "failed"
            $report.shutdownError = "Could not stop the project containers. Inspect docker compose ps."
            if ($null -eq $failure) { $failure = $report.shutdownError }
        }
    }
    $report.finishedAt = [DateTime]::UtcNow.ToString("o")
    $report | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 -LiteralPath (Join-Path $runtime "acceptance-report.json")
    Pop-Location
}
if ($null -ne $failure) { throw $failure }
Write-Host "LAYER 3 ACCEPTANCE PASSED. Report: layer3_testing/runtime/acceptance-report.json"
