Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Reuse the real Layer 1/2 fixture and its governance signature checks.
. (Join-Path $PSScriptRoot "..\layer2_testing\run_real_full_stack_test.ps1")
$Base = "http://127.0.0.1"
Wait-Healthy 8017 "TaskOrchestratorAgent"
Wait-Healthy 8018 "RiskAnalyzerBot"

$orchestrator = Invoke-Json Get "$Base`:8017/identity"
$worker = Invoke-Json Get "$Base`:8018/identity"
$AgentRunId = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$WorkerCapability = "$($worker.capability).Run$AgentRunId"
$workerRole = Invoke-Json Post "$Base`:8004/issue/role" @{
    subject_did = $worker.did; issuer_did = $issuerDid; issuer_key_id = $issuerKey.keyId
    trust_domain = "enterprise"
    claims = @{
        roleName = "RiskAnalyzer"; roleDescription = "Computes financial summaries from supplied period data"
        organisationDID = "did:web:demo.local:finance"
    }
}
Invoke-Json Post "$Base`:8007/wallets/$($worker.did)/store" @{
    agent_did = $worker.did; signed_vc = $workerRole.signedVC
} | Out-Null

$record = @{
    ansName = "signed-http-json://RiskAnalyzerBot-$AgentRunId.FinancialRiskAnalysis.DemoProvider.v1"
    agentDid = $worker.did; capability = $WorkerCapability; provider = $worker.provider
    version = $worker.version; serviceEndpoint = $worker.serviceEndpoint
    protocolExtensions = @(@{ protocol = $worker.protocol; details = @{ action = "analyze_financials" } })
}
$canonical = ConvertTo-CanonicalJson @{ action = "ans.register"; record = $record }
$signature = Invoke-Json Post "$Base`:8001/keys/$($worker.keyId)/sign" @{
    payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($canonical))
}
$registration = $record.Clone()
$registration.registrationProof = @{
    verificationMethod = $worker.verificationMethod; signature = $signature.signature
}
$registered = Invoke-Json Post "$Base`:8008/register" $registration
Assert-True ($registered.status -eq "active") "running worker registered with its real DID ownership signature"

$DemoDirectory = Join-Path $PSScriptRoot "swagger_demo"
New-Item -ItemType Directory -Path $DemoDirectory -Force | Out-Null
function Write-AgentDemoJson {
    param([string]$Name, [object]$Body)
    [IO.File]::WriteAllText((Join-Path $DemoDirectory $Name), ($Body | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
}
$submission = [ordered]@{
    discovery = @{
        capability = $WorkerCapability; provider = $worker.provider; protocol = $worker.protocol
        versionRange = ">=1.0.0,<2.0.0"; requiredAttestations = @("RoleVC"); maxCandidates = 10
    }
    input = @{
        currency = "USD"
        periods = @(
            @{ period = "2026-Q1"; revenue = "100000.00"; expenses = "72000.00" },
            @{ period = "2026-Q2"; revenue = "80000.00"; expenses = "92000.00" }
        )
    }
}
Write-AgentDemoJson "00-identifiers.json" @{
    orchestratorDid = $orchestrator.did; workerDid = $worker.did; issuerDid = $issuerDid
    capability = $WorkerCapability; ansName = $registered.ansName
    endpoint = $worker.serviceEndpoint; roleVcExpiresAt = $workerRole.expiresAt
    operatorTokenFile = "agent_testing/runtime/orchestrator/operator-token.txt"
    protocol = $worker.protocol
}
Write-AgentDemoJson "01-submit-task.json" $submission

$TokenFile = Join-Path $PSScriptRoot "runtime\orchestrator\operator-token.txt"
if (-not (Test-Path -LiteralPath $TokenFile)) { throw "Orchestrator API token file is missing: $TokenFile" }
Write-Host ""
Write-Host "ORCHESTRATOR DEMO READY: $DemoDirectory"
Write-Host "Swagger: http://localhost:8017/docs"
Write-Host "Authorize using X-API-Key from $TokenFile (keep this token private)."
Write-Host "POST /tasks with 01-submit-task.json. Expected netIncome: 16000.00; loss-making period: 2026-Q2."
Write-Host "These amounts are test inputs; the running worker computes and signs the result."
