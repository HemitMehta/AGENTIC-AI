Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python must be on PATH for canonical JSON signing. Check: python --version"
}

# Reuse the real integration fixture, including its signature and access checks.
. (Join-Path $PSScriptRoot "run_real_layer3_test.ps1")

foreach ($port in 8008..8012) { Wait-Healthy $port "Layer 2 service" }

$Capability = "FinancialRiskAnalysis.CorporateReporting.Swagger.$RunId"
$AnsName = "acp://RiskAnalyzer-$RunId.FinancialRiskAnalysis.DemoProvider.v1.prod"
$ansData = @{
    ansName = $AnsName; agentDid = $AgentDid; capability = $Capability
    provider = "DemoProvider"; version = "1.0.0"
    serviceEndpoint = "https://risk-agent-$RunId.example.invalid/service"
    protocolExtensions = @(@{ protocol = "acp"; details = @{} })
}
$ansCanonical = ConvertTo-CanonicalJson @{ action = "ans.register"; record = $ansData }
$ansSignature = Invoke-Json Post "$Base`:8001/keys/$($agentKey.keyId)/sign" @{
    payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ansCanonical))
}
$ansRequest = $ansData.Clone()
$ansRequest.registrationProof = @{
    verificationMethod = "$AgentDid#$($agentKey.keyId)"; signature = $ansSignature.signature
}
$registered = Invoke-Json Post "$Base`:8008/register" $ansRequest
Assert-True ($registered.status -eq "active") "Swagger agent registered with a real ownership signature" $registered

$discoverRequest = @{
    capability = $Capability; provider = "DemoProvider"; protocol = "acp"
    versionRange = ">=1.0.0,<2.0.0"; requiredAttestations = @("RoleVC"); maxCandidates = 10
}
$discovered = Invoke-Json Post "$Base`:8012/discover" $discoverRequest
Assert-True (($discovered.resolutionStatus -eq "success") -and ($discovered.selectedAgent -eq $AgentDid)) "Swagger discovery selects the same Layer 3 agent" $discovered
Assert-True ($discovered.candidates[0].signatureVerified -eq $true) "Swagger discovery verifies the ANS record signature" $discovered

$DemoDirectory = Join-Path $PSScriptRoot "swagger_demo"
New-Item -ItemType Directory -Path $DemoDirectory -Force | Out-Null

function Write-SwaggerBody {
    param([string]$Name, [object]$Body)
    $json = $Body | ConvertTo-Json -Depth 40
    [IO.File]::WriteAllText((Join-Path $DemoDirectory $Name), $json, [Text.UTF8Encoding]::new($false))
}

Write-SwaggerBody "00-identifiers.json" ([ordered]@{
    agentDid = $AgentDid; issuerDid = $IssuerDid; resourceId = $ResourceId
    resourceDid = $ResourceDid; jobId = $JobId; capability = $Capability
    ansName = $AnsName; verifierDid = $VerifierDid
    roleVcId = $role.vc_id; jitVcId = $jit.vc_id; jitExpiresAt = $jit.expiresAt
    preparedAt = [DateTime]::UtcNow.ToString("o")
    endpointIsTestMetadataOnly = $true
})
Write-SwaggerBody "01-discover.json" $discoverRequest
Write-SwaggerBody "02-nonce.json" @{
    verifierDID = $VerifierDid; purpose = "layer3_access_decision"
}
Write-SwaggerBody "03-present.json" @{
    agent_did = $AgentDid; required_types = @("RoleVC", "JITVC")
    verifier_did = $VerifierDid; nonce = "REPLACE_WITH_NONCE"
}
$accessRequest = @{
    agentDid = $AgentDid; vpJwt = "REPLACE_WITH_VP_JWT"; nonce = "REPLACE_WITH_NONCE"
    resourceId = $ResourceId; action = "QUERY_TABLE"; context = @{ jobId = $JobId }
}
Write-SwaggerBody "04-permit.json" $accessRequest
Write-SwaggerBody "05-introspect.json" @{
    token = "REPLACE_WITH_ACCESS_TOKEN"; resourceId = $ResourceId; action = "QUERY_TABLE"
}
$wrongJobRequest = $accessRequest.Clone()
$wrongJobRequest.context = @{ jobId = "wrong-job-$RunId" }
Write-SwaggerBody "06-deny-job.json" $wrongJobRequest
$wrongActionRequest = $accessRequest.Clone()
$wrongActionRequest.action = "DELETE_TABLE"
Write-SwaggerBody "07-deny-action.json" $wrongActionRequest
Write-SwaggerBody "08-verify-presentation.json" @{
    vp_jwt = "REPLACE_WITH_VP_JWT"; nonce = "REPLACE_WITH_NONCE"; verifierDID = $VerifierDid
}
Write-SwaggerBody "09-validate-issuer.json" @{
    issuerDID = $IssuerDid; credentialType = "RoleVC"; trustDomain = "enterprise"
}

# Export unsubmitted, signed version-2 writes for optional governance tests.
$nextResource = $resource.Clone()
$nextResource.version = 2
Write-SwaggerBody "10-resource-update.json" @{
    resource = $nextResource
    adminAuthorization = New-AdminAuthorization @{ action = "pap.upsertResource"; resource = $nextResource }
}
$nextPolicy = $policy.Clone()
$nextPolicy.version = 2
Write-SwaggerBody "11-policy-update.json" @{
    policy = $nextPolicy
    adminAuthorization = New-AdminAuthorization @{ action = "pap.upsertPolicy"; policy = $nextPolicy }
}

Write-Host ""
Write-Host "SWAGGER DEMO READY: $DemoDirectory"
Write-Host "JIT credential expires at $($jit.expiresAt). Rerun this helper for fresh data."
Write-Host "Open layer3_testing/README.md and follow the Swagger walkthrough."
Write-Host "Only REPLACE_WITH_* values need fresh Swagger responses. No private keys are exported."
Wait-Healthy 8019 "Protected sales resource"
$enforcementFixture = @{
    agentDid = $AgentDid; agentKeyId = $agentKey.keyId
    issuerDid = $IssuerDid; adminDid = $AdminDid; adminKeyId = $AdminKeyId
    resource = $resource; policy = $policy; jobId = $JobId; jitVcId = $jit.vc_id
    jitExpiry = ([DateTimeOffset]::Parse($jit.signedVC.expirationDate)).ToUnixTimeSeconds()
}
$encodedFixture = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($enforcementFixture | ConvertTo-Json -Depth 40 -Compress)))
& python (Join-Path $PSScriptRoot "enforcement_flow.py") $encodedFixture --prepare
if ($LASTEXITCODE -ne 0) { throw "Protected database fixture preparation failed" }
Write-Host "The ANS endpoint is directory test metadata; the protected SQL API runs at https://localhost:8019."
Write-Host "For a fresh SQL request: python layer3_testing/prepare_protected_query.py"
