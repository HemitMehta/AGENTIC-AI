Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogDir = Join-Path $env:TEMP "layer2_test_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Get-ChildItem -Path $LogDir -Filter "*.log" -ErrorAction SilentlyContinue | Remove-Item -Force

$Processes = @()
$Failures = 0

function Start-TestService {
    param(
        [string]$Dir,
        [int]$Port,
        [string]$Name,
        [hashtable]$EnvVars = @{}
    )

    $stdout = Join-Path $LogDir "$Name.log"
    $stderr = Join-Path $LogDir "$Name.err.log"

    $oldValues = @{}
    foreach ($entry in $EnvVars.GetEnumerator()) {
        $oldValues[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, "Process")
        [Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, "Process")
    }

    try {
        $process = Start-Process -FilePath "python" `
            -ArgumentList @("-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "$Port") `
            -WorkingDirectory $Dir `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -WindowStyle Hidden `
            -PassThru
    }
    finally {
        foreach ($entry in $EnvVars.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $oldValues[$entry.Key], "Process")
        }
    }

    $script:Processes += $process
    Start-Sleep -Milliseconds 250
}

function Wait-Healthy {
    param([int]$Port, [string]$Name)

    for ($i = 0; $i -lt 40; $i++) {
        try {
            Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 1 | Out-Null
            return
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }

    Write-Host "FAIL: $Name on port $Port never became healthy. Logs:"
    Get-Content (Join-Path $LogDir "$Name.log") -ErrorAction SilentlyContinue
    Get-Content (Join-Path $LogDir "$Name.err.log") -ErrorAction SilentlyContinue
    exit 1
}

function Assert-True {
    param([bool]$Condition, [string]$Label, [object]$Details = $null)

    if ($Condition) {
        Write-Host "  PASS: $Label"
    } else {
        Write-Host "  FAIL: $Label"
        if ($null -ne $Details) {
            $Details | ConvertTo-Json -Depth 10
        }
        $script:Failures += 1
    }
}

try {
    Write-Host "=== Starting mock Layer 1 (ports 8001, 8002, 8004, 8005, 8006, 8007) ==="
    $MockDir = Join-Path $RootDir "layer2_testing\mock_layer1"
    Start-TestService $MockDir 8001 "mock_l1_8001"
    Start-TestService $MockDir 8002 "mock_l1_8002"
    Start-TestService $MockDir 8004 "mock_l1_8004"
    Start-TestService $MockDir 8005 "mock_l1_8005"
    Start-TestService $MockDir 8006 "mock_l1_8006"
    Start-TestService $MockDir 8007 "mock_l1_8007"
    foreach ($port in @(8001, 8002, 8004, 8005, 8006, 8007)) {
        Wait-Healthy $port "mock_l1_$port"
    }

    Write-Host "=== Starting Layer 2 modules ==="
    Start-TestService (Join-Path $RootDir "ans_registry_service") 8008 "ans_registry" @{
        DID_REGISTRY_URL = "http://127.0.0.1:8002"
        ANS_REQUIRE_REGISTRATION_PROOF = "false"
    }
    Wait-Healthy 8008 "ans_registry"

    Start-TestService (Join-Path $RootDir "discovery_trust_policy_service") 8010 "trust_policy"
    Wait-Healthy 8010 "trust_policy"

    Start-TestService (Join-Path $RootDir "ans_resolver_service") 8009 "ans_resolver" @{
        ANS_REGISTRY_URL = "http://127.0.0.1:8008"
        VC_VERIFICATION_URL = "http://127.0.0.1:8005"
        WALLET_SERVICE_URL = "http://127.0.0.1:8007"
        KMS_URL = "http://127.0.0.1:8001"
        DOWNSTREAM_TIMEOUT_SECONDS = "90"
    }
    Wait-Healthy 8009 "ans_resolver"

    Start-TestService (Join-Path $RootDir "reputation_service") 8011 "reputation" @{
        VC_ISSUANCE_URL = "http://127.0.0.1:8004"
        VC_ISSUANCE_TIMEOUT_SECONDS = "90"
    }
    Wait-Healthy 8011 "reputation"

    Start-TestService (Join-Path $RootDir "discovery_gateway") 8012 "gateway" @{
        TRUST_POLICY_URL = "http://127.0.0.1:8010"
        ANS_RESOLVER_URL = "http://127.0.0.1:8009"
        REPUTATION_SERVICE_URL = "http://127.0.0.1:8011"
        KMS_URL = "http://127.0.0.1:8001"
        DOWNSTREAM_TIMEOUT_SECONDS = "90"
    }
    Wait-Healthy 8012 "gateway"

    Write-Host "=== Test 1: register agent ==="
    $reg = Invoke-RestMethod -Method Post "http://127.0.0.1:8008/register" -ContentType "application/json" -Body (@{
        ansName = "acp://RiskAnalyzerBot.FinancialRiskAnalysis.AcmeFinanceServices.v2.1.3.prod"
        agentDid = "did:web:acme:agent:riskanalyzer:beta-007"
        capability = "FinancialRiskAnalysis.CorporateReporting"
        provider = "AcmeFinanceServices"
        version = "2.1.3"
        serviceEndpoint = "https://riskanalyzer.acmefinance.com/service"
        protocolExtensions = @(@{ protocol = "acp"; details = @{} })
    } | ConvertTo-Json -Depth 10)
    Assert-True ($reg.status -eq "active") "agent registered as active" $reg

    Write-Host "=== Test 1b: reject unresolvable DID ==="
    $badStatus = $null
    try {
        Invoke-RestMethod -Method Post "http://127.0.0.1:8008/register" -ContentType "application/json" -Body (@{
            ansName = "acp://Fake.Agent.v1"
            agentDid = "did:web:does-not-exist:agent:999"
            capability = "Fake.Capability"
            provider = "NoOne"
            version = "1.0.0"
            serviceEndpoint = "https://nowhere.example.com"
        } | ConvertTo-Json -Depth 10) | Out-Null
    } catch {
        $badStatus = [int]$_.Exception.Response.StatusCode
    }
    Assert-True ($badStatus -eq 400) "unresolvable DID rejected with 400" @{ status = $badStatus }

    Write-Host "=== Test 2: feedback with reputation VC ==="
    $feedback = Invoke-RestMethod -Method Post "http://127.0.0.1:8011/feedback" -ContentType "application/json" -Body (@{
        raterDid = "did:web:enterprise:agent:orchestrator:alpha-001"
        ratedAgentDid = "did:web:acme:agent:riskanalyzer:beta-007"
        rating = 5
        taskId = "task-1"
        issueVc = $true
    } | ConvertTo-Json -Depth 10)
    Assert-True ($feedback.issuedVcId -eq "vc:jwt:uri:reputation-service:mock-001") "reputation VC issued" $feedback

    Write-Host "=== Test 3: reputation score ==="
    $score = Invoke-RestMethod "http://127.0.0.1:8011/reputation/did:web:acme:agent:riskanalyzer:beta-007"
    Assert-True ($score.score -eq 100.0) "score aggregates to 100.0 from one 5-star rating" $score

    Write-Host "=== Test 4: resolve with valid attestation ==="
    $resolved = Invoke-RestMethod -Method Post "http://127.0.0.1:8009/resolveByCapability" -ContentType "application/json" -Body (@{
        capability = "FinancialRiskAnalysis.CorporateReporting"
        requiredAttestations = @("SOXComplianceCertified")
    } | ConvertTo-Json -Depth 10)
    Assert-True ($resolved.resolutionStatus -eq "success") "resolution succeeds" $resolved
    Assert-True ($resolved.resolvedAgents[0].relevantVcSnippets[0].verified -eq $true) "attestation verified" $resolved
    Assert-True ($resolved.resolvedAgents[0].relevantVcSnippets[0].revoked -eq $false) "attestation not revoked" $resolved
    Assert-True ([string]$resolved.resolvedAgents[0].ansRecordSignature -like "sha256:*") "record was signed by kms" $resolved

    Write-Host "=== Test 4b: revoked attestation is dropped ==="
    $revoked = Invoke-RestMethod -Method Post "http://127.0.0.1:8009/resolveByCapability" -ContentType "application/json" -Body (@{
        capability = "FinancialRiskAnalysis.CorporateReporting"
        requiredAttestations = @("RevokedCredentialTest")
    } | ConvertTo-Json -Depth 10)
    Assert-True ($revoked.resolutionStatus -eq "no_matches") "candidate with revoked VC is dropped" $revoked

    Write-Host "=== Test 5: gateway success ==="
    $gateway = Invoke-RestMethod -Method Post "http://127.0.0.1:8012/discover" -ContentType "application/json" -Body (@{
        capability = "FinancialRiskAnalysis.CorporateReporting"
        requiredAttestations = @("SOXComplianceCertified")
    } | ConvertTo-Json -Depth 10)
    Assert-True ($gateway.resolutionStatus -eq "success") "gateway returns success" $gateway
    Assert-True ($gateway.selectedAgent -eq "did:web:acme:agent:riskanalyzer:beta-007") "gateway selects the right agent" $gateway
    Assert-True ([string]$gateway.gatewaySignature -like "sha256:*") "gateway response is signed" $gateway

    Write-Host "=== Test 6: trust policy rejection ==="
    Invoke-RestMethod -Method Post "http://127.0.0.1:8010/capability-domains" -ContentType "application/json" -Body (@{
        domain = "OCR"
        notes = "test-only restriction"
    } | ConvertTo-Json) | Out-Null

    $rejected = Invoke-RestMethod -Method Post "http://127.0.0.1:8012/discover" -ContentType "application/json" -Body (@{
        capability = "FinancialRiskAnalysis.CorporateReporting"
    } | ConvertTo-Json)
    Assert-True ($rejected.resolutionStatus -eq "rejected_by_trust_policy") "gateway rejects out-of-allowlist domain" $rejected

    Write-Host ""
    if ($Failures -eq 0) {
        Write-Host "ALL TESTS PASSED"
        exit 0
    }

    Write-Host "$Failures TEST(S) FAILED"
    exit 1
}
finally {
    Write-Host ""
    Write-Host "--- tearing down all test processes ---"
    foreach ($process in $Processes) {
        try {
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force
            }
        } catch {
        }
    }
}
