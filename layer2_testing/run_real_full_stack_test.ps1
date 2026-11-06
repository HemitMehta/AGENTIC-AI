Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Base = "http://localhost"
$RunId = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$Domain = "demo.local"
$ModelHash = "sha3-256-real-full-stack-demo"
$Capability = "FinancialRiskAnalysis.CorporateReporting.$RunId"
$VerifierDid = "did:web:layer2:ans-resolver"

function Invoke-Json {
    param(
        [string]$Method,
        [string]$Url,
        [object]$Body = $null
    )

    if ($null -eq $Body) {
        return Invoke-RestMethod -Method $Method -Uri $Url
    }

    return Invoke-RestMethod -Method $Method -Uri $Url -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 30)
}

function Wait-Healthy {
    param([int]$Port, [string]$Name)

    for ($i = 0; $i -lt 80; $i++) {
        try {
            Invoke-RestMethod "$Base`:$Port/health" -TimeoutSec 2 | Out-Null
            Write-Host "PASS: $Name healthy on $Port"
            return
        } catch {
            Start-Sleep -Seconds 3
        }
    }

    throw "$Name on port $Port did not become healthy"
}

function Assert-True {
    param([bool]$Condition, [string]$Message, [object]$Details = $null)

    if ($Condition) {
        Write-Host "PASS: $Message"
        return
    }

    Write-Host "FAIL: $Message"
    if ($null -ne $Details) {
        $Details | ConvertTo-Json -Depth 30
    }
    throw $Message
}

function ConvertTo-CanonicalJson {
    param([object]$Payload)

    $json = $Payload | ConvertTo-Json -Depth 30 -Compress
    $jsonB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $canonical = & python -c "import base64,json,sys; print(json.dumps(json.loads(base64.b64decode(sys.argv[1]).decode('utf-8')), sort_keys=True, separators=(',', ':')))" $jsonB64
    return $canonical.Trim()
}

function New-AdminSignature {
    param(
        [hashtable]$Payload,
        [string]$AdminDid,
        [string]$AdminKeyId
    )

    $canonical = ConvertTo-CanonicalJson $Payload
    $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($canonical))
    $signature = Invoke-Json Post "$Base`:8001/keys/$AdminKeyId/sign" @{
        payload = $payloadB64
    }

    return @{
        adminDID = $AdminDid
        verificationMethod = "$($AdminDid)#$AdminKeyId"
        signature = $signature.signature
    }
}

Write-Host "=== Waiting for Layer 1 + Layer 2 services ==="
$services = @(
    @{ Port = 8001; Name = "kms" },
    @{ Port = 8002; Name = "did_registry" },
    @{ Port = 8003; Name = "trust_anchor" },
    @{ Port = 8004; Name = "vc_issuance" },
    @{ Port = 8005; Name = "vc_verification" },
    @{ Port = 8006; Name = "status_list_service" },
    @{ Port = 8007; Name = "wallet_service" },
    @{ Port = 8008; Name = "ans_registry_service" },
    @{ Port = 8009; Name = "ans_resolver_service" },
    @{ Port = 8010; Name = "discovery_trust_policy_service" },
    @{ Port = 8011; Name = "reputation_service" },
    @{ Port = 8012; Name = "discovery_gateway" }
)
foreach ($service in $services) {
    Wait-Healthy $service.Port $service.Name
}

Write-Host "=== Registering governance admin DID ==="
$adminKeyId = "governance-admin-signing-key"
$adminPub = Invoke-Json Get "$Base`:8001/keys/$adminKeyId/public"
Assert-True ($adminPub.keyStatus -eq "active") "governance admin KMS key is active" $adminPub

$adminDidResp = Invoke-Json Post "$Base`:8002/dids/register" @{
    public_key_b64 = $adminPub.publicKey
    key_id = $adminKeyId
    owner_did = "did:web:demo:owner"
    controller_dids = @("did:web:demo:controller")
    scope_of_behavior = @{ domain = "governance"; allowed = @("trust-anchor-governance") }
    toolset = @("trust-anchor")
    model_hash = "sha3-256-real-full-stack-governance-admin"
    aibom_ref = "demo-aibom-governance-admin"
    did_method = "web"
    domain = $Domain
    metadata = @{ agentId = "governance-admin"; name = "GovernanceAdmin" }
}
$adminDid = $adminDidResp.did
Assert-True ($adminDid -eq "did:web:$Domain`:agents:governance-admin") "governance admin DID matches trust-anchor allowlist" $adminDidResp

Write-Host "=== Creating issuer key + DID ==="
$issuerKey = Invoke-Json Post "$Base`:8001/keys/generate" @{
    agent_did = "real-demo-issuer-$RunId"
    key_purpose = "assertionMethod"
}

$issuerDidResp = Invoke-Json Post "$Base`:8002/dids/register" @{
    public_key_b64 = $issuerKey.publicKey
    key_id = $issuerKey.keyId
    owner_did = "did:web:demo:owner"
    controller_dids = @("did:web:demo:controller")
    scope_of_behavior = @{ domain = "governance"; allowed = @("issue-role-vc") }
    toolset = @("trust-anchor", "vc-issuance")
    model_hash = "sha3-256-real-full-stack-issuer"
    aibom_ref = "demo-aibom-issuer"
    did_method = "web"
    domain = $Domain
    metadata = @{ agentId = "issuer-$RunId"; name = "DemoIssuer" }
}
$issuerDid = $issuerDidResp.did
Write-Host "Issuer DID: $issuerDid"

Write-Host "=== Creating agent key + DID ==="
$agentKey = Invoke-Json Post "$Base`:8001/keys/generate" @{
    agent_did = "real-demo-agent-$RunId"
    key_purpose = "authentication"
}

$agentDidResp = Invoke-Json Post "$Base`:8002/dids/register" @{
    public_key_b64 = $agentKey.publicKey
    key_id = $agentKey.keyId
    owner_did = "did:web:demo:owner"
    controller_dids = @("did:web:demo:controller")
    scope_of_behavior = @{ domain = "financial-risk"; allowed = @("analyze-risk", "generate-report") }
    toolset = @("risk-api", "reporting-api")
    model_hash = $ModelHash
    aibom_ref = "demo-aibom-agent"
    did_method = "web"
    domain = $Domain
    metadata = @{ agentId = "risk-agent-$RunId"; name = "RiskAnalyzerAgent" }
}
$agentDid = $agentDidResp.did
Write-Host "Agent DID: $agentDid"

Write-Host "=== Initializing agent wallet ==="
$wallet = Invoke-Json Post "$Base`:8007/wallets/$agentDid/init"
Assert-True ($wallet.agent_did -eq $agentDid) "agent wallet initialized" $wallet

Write-Host "=== Authorizing issuer for RoleVC ==="
$issuerAuthorizationPayload = @{
    action = "trust-anchor.addIssuer"
    issuerDID = $issuerDid
    credentialTypes = @("RoleVC")
    trustDomain = "enterprise"
    validUntil = $null
}

$unsignedStatus = $null
try {
    Invoke-Json Post "$Base`:8003/trust-anchor/issuers" @{
        issuerDID = $issuerAuthorizationPayload.issuerDID
        credentialTypes = $issuerAuthorizationPayload.credentialTypes
        trustDomain = $issuerAuthorizationPayload.trustDomain
        validUntil = $issuerAuthorizationPayload.validUntil
        adminSignature = @{}
    } | Out-Null
    $unsignedStatus = 200
} catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $unsignedStatus = [int]$_.Exception.Response.StatusCode
    } else {
        throw
    }
}
Assert-True ($unsignedStatus -eq 403) "unsigned issuer authorization rejected by trust anchor"

$issuerAuth = Invoke-Json Post "$Base`:8003/trust-anchor/issuers" @{
    issuerDID = $issuerAuthorizationPayload.issuerDID
    credentialTypes = $issuerAuthorizationPayload.credentialTypes
    trustDomain = $issuerAuthorizationPayload.trustDomain
    validUntil = $issuerAuthorizationPayload.validUntil
    adminSignature = New-AdminSignature $issuerAuthorizationPayload $adminDid $adminKeyId
}
Assert-True ($null -ne $issuerAuth) "issuer added to trust anchor with governance admin signature" $issuerAuth

Write-Host "=== Rejecting non-admin governance signature ==="
$badAdminSignature = New-AdminSignature $issuerAuthorizationPayload $issuerDid $issuerKey.keyId
$badAdminStatus = $null
try {
    Invoke-Json Post "$Base`:8003/trust-anchor/issuers" @{
        issuerDID = $issuerAuthorizationPayload.issuerDID
        credentialTypes = $issuerAuthorizationPayload.credentialTypes
        trustDomain = $issuerAuthorizationPayload.trustDomain
        validUntil = $issuerAuthorizationPayload.validUntil
        adminSignature = $badAdminSignature
    } | Out-Null
    $badAdminStatus = 200
} catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $badAdminStatus = [int]$_.Exception.Response.StatusCode
    } else {
        throw
    }
}
Assert-True ($badAdminStatus -eq 403) "non-admin governance signature rejected by trust anchor"

$issuerAuthCheck = Invoke-Json Post "$Base`:8003/trust-anchor/validate" @{
    issuerDID = $issuerDid
    credentialType = "RoleVC"
    trustDomain = "enterprise"
    adminSignature = @{}
}
Assert-True ($issuerAuthCheck.authorised -eq $true) "issuer authorization remains valid after rejected non-admin attempt" $issuerAuthCheck

Write-Host "=== Issuing real RoleVC ==="
$roleIssue = Invoke-Json Post "$Base`:8004/issue/role" @{
    subject_did = $agentDid
    issuer_did = $issuerDid
    issuer_key_id = $issuerKey.keyId
    trust_domain = "enterprise"
    claims = @{
        roleName = "RiskAnalyzer"
        roleDescription = "Analyzes corporate reporting risk"
        organisationDID = "did:web:demo:org"
        department = "Risk"
    }
}
Assert-True ($roleIssue.status -eq "success") "real RoleVC issued" $roleIssue
Assert-True ($roleIssue.signedVC.type -contains "RoleVC") "issued VC has RoleVC type" $roleIssue

Write-Host "=== Storing real RoleVC in agent wallet ==="
$store = Invoke-Json Post "$Base`:8007/wallets/$agentDid/store" @{
    agent_did = $agentDid
    signed_vc = $roleIssue.signedVC
}
Assert-True ($store.stored -eq $true) "real RoleVC stored in wallet" $store

Write-Host "=== Verifying wallet metadata query ==="
$walletCreds = Invoke-RestMethod -Method Get -Uri "$Base`:8007/wallets/$agentDid/credentials?type=RoleVC&status=active"
Assert-True ($walletCreds.credentials.Count -ge 1) "wallet lists stored RoleVC" $walletCreds

Write-Host "=== Building and verifying real VP ==="
$nonceResp = Invoke-Json Post "$Base`:8005/verify/nonce" @{
    verifierDID = $VerifierDid
    purpose = "real_full_stack_test"
}

$presentation = Invoke-Json Post "$Base`:8007/wallets/$agentDid/present" @{
    agent_did = $agentDid
    required_types = @("RoleVC")
    verifier_did = $VerifierDid
    nonce = $nonceResp.nonce
}
Assert-True (-not [string]::IsNullOrWhiteSpace($presentation.vp_jwt)) "wallet produced VP JWT" $presentation

$verify = Invoke-Json Post "$Base`:8005/verify/presentation" @{
    vp_jwt = $presentation.vp_jwt
    nonce = $nonceResp.nonce
    verifierDID = $VerifierDid
}
Assert-True ($verify.valid -eq $true) "real VP verified through six-step pipeline" $verify

Write-Host "=== Registering real agent in ANS ==="
$ansName = "acp://RiskAnalyzerAgent-$RunId.FinancialRiskAnalysis.DemoProvider.v1.prod"
$ansRegistrationData = @{
    ansName = $ansName
    agentDid = $agentDid
    capability = $Capability
    provider = "DemoProvider"
    version = "1.0.0"
    serviceEndpoint = "https://risk-agent-$RunId.demo.local/service"
    protocolExtensions = @(@{ protocol = "acp"; details = @{} })
}
$unsignedAnsStatus = $null
try {
    Invoke-Json Post "$Base`:8008/register" $ansRegistrationData | Out-Null
    $unsignedAnsStatus = 200
} catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $unsignedAnsStatus = [int]$_.Exception.Response.StatusCode
    } else { throw }
}
Assert-True ($unsignedAnsStatus -eq 403) "unsigned ANS registration rejected"

$ansCanonical = ConvertTo-CanonicalJson @{ action = "ans.register"; record = $ansRegistrationData }
$ansPayloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ansCanonical))
$ansSignature = Invoke-Json Post "$Base`:8001/keys/$($agentKey.keyId)/sign" @{ payload = $ansPayloadB64 }
$ansRegistrationRequest = $ansRegistrationData.Clone()
$ansRegistrationRequest.registrationProof = @{
    verificationMethod = "$agentDid#$($agentKey.keyId)"
    signature = $ansSignature.signature
}
$ansRecord = Invoke-Json Post "$Base`:8008/register" $ansRegistrationRequest
Assert-True ($ansRecord.status -eq "active") "agent registered in ANS" $ansRecord

Write-Host "=== Adding real reputation feedback ==="
$feedback = Invoke-Json Post "$Base`:8011/feedback" @{
    raterDid = $issuerDid
    ratedAgentDid = $agentDid
    rating = 5
    ansCapabilityContext = $Capability
    taskId = "real-demo-task-$RunId"
    comment = "Real full-stack test feedback"
    issueVc = $false
}
Assert-True ($feedback.rating -eq 5) "reputation feedback recorded" $feedback

Write-Host "=== Discovering real agent with required RoleVC attestation ==="
$discovery = Invoke-Json Post "$Base`:8012/discover" @{
    capability = $Capability
    protocol = "acp"
    versionRange = ">=1.0.0,<2.0.0"
    requiredAttestations = @("RoleVC")
    maxCandidates = 10
}
Assert-True ($discovery.resolutionStatus -eq "success") "gateway discovery succeeded with required real RoleVC" $discovery
Assert-True ($discovery.selectedAgent -eq $agentDid) "gateway selected the real agent DID" $discovery
Assert-True ($discovery.reputation -eq 100.0) "gateway included real reputation score" $discovery
Assert-True ($discovery.candidates[0].signatureVerified -eq $true) "gateway cryptographically verified ANS record signature" $discovery

Write-Host ""
Write-Host "REAL FULL STACK TEST PASSED"
Write-Host "Agent DID: $agentDid"
Write-Host "Issuer DID: $issuerDid"
Write-Host "ANS Name: $ansName"
