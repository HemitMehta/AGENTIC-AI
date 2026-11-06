Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Base = "http://127.0.0.1"
$RunId = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$Domain = "demo.local"
$AdminDid = "did:web:$Domain`:agents:governance-admin"
$AdminKeyId = "governance-admin-signing-key"
$VerifierDid = "did:web:layer3:pdp"
$ResourceId = "InternalDB-SalesFigures-$RunId"
$ResourceDid = "did:web:demo.local:resources:sales-$RunId"
$JobId = "quarterly-risk-$RunId"

function Invoke-Json {
    param([string]$Method, [string]$Url, [object]$Body = $null)
    if (([uri]$Url).Port -in @(8013, 8014, 8015, 8016, 8019)) {
        $arguments = @("$PSScriptRoot/secure_client.py", $Method, $Url)
        if ($null -ne $Body) {
            $arguments += [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 50 -Compress)))
        }
        $raw = & python @arguments
        if ($LASTEXITCODE -ne 0) { throw "Secure Layer 3 client failed: $Url" }
        $response = $raw | ConvertFrom-Json
        if ($response.status -ge 400) {
            $errorResponse = [System.Exception]::new(($response.body | ConvertTo-Json -Depth 30))
            $errorResponse.Data["StatusCode"] = [int]$response.status
            throw $errorResponse
        }
        return $response.body
    }
    if ($null -eq $Body) { return Invoke-RestMethod -Method $Method -Uri $Url }
    Invoke-RestMethod -Method $Method -Uri $Url -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 40)
}

function Wait-Healthy {
    param([int]$Port, [string]$Name)
    for ($i = 0; $i -lt 100; $i++) {
        try {
            Invoke-Json Get "$Base`:$Port/health" | Out-Null
            Write-Host "PASS: $Name healthy on $Port"
            return
        } catch { Start-Sleep -Seconds 3 }
    }
    throw "$Name on port $Port did not become healthy"
}

function Assert-True {
    param([bool]$Condition, [string]$Message, [object]$Details = $null)
    if ($Condition) { Write-Host "PASS: $Message"; return }
    Write-Host "FAIL: $Message"
    if ($null -ne $Details) { $Details | ConvertTo-Json -Depth 40 }
    throw $Message
}

function ConvertTo-CanonicalJson {
    param([object]$Payload)
    $json = $Payload | ConvertTo-Json -Depth 40 -Compress
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $canonical = & python -c "import base64,json,sys; print(json.dumps(json.loads(base64.b64decode(sys.argv[1])),sort_keys=True,separators=(',',':')))" $encoded
    $canonical.Trim()
}

function New-AdminAuthorization {
    param([hashtable]$Payload)
    $canonical = ConvertTo-CanonicalJson $Payload
    $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($canonical))
    $signed = Invoke-Json Post "$Base`:8001/keys/$AdminKeyId/sign" @{ payload = $payloadB64 }
    @{
        adminDID = $AdminDid
        verificationMethod = "$AdminDid#$AdminKeyId"
        signature = $signed.signature
    }
}

function New-Presentation {
    param([string]$AgentDid)
    $nonce = Invoke-Json Post "$Base`:8005/verify/nonce" @{
        verifierDID = $VerifierDid
        purpose = "layer3_access_decision"
    }
    $presentation = Invoke-Json Post "$Base`:8007/wallets/$AgentDid/present" @{
        agent_did = $AgentDid
        required_types = @("RoleVC", "JITVC")
        verifier_did = $VerifierDid
        nonce = $nonce.nonce
    }
    @{ nonce = $nonce.nonce; vpJwt = $presentation.vp_jwt }
}

Write-Host "=== Waiting for Layer 1, Layer 2, and Layer 3 ==="
$services = @(
    @{ Port = 8001; Name = "kms" }, @{ Port = 8002; Name = "did_registry" },
    @{ Port = 8003; Name = "trust_anchor" }, @{ Port = 8004; Name = "vc_issuance" },
    @{ Port = 8005; Name = "vc_verification" }, @{ Port = 8006; Name = "status_list" },
    @{ Port = 8007; Name = "wallet" }, @{ Port = 8013; Name = "PAP" },
    @{ Port = 8014; Name = "PIP" }, @{ Port = 8015; Name = "PDP" },
    @{ Port = 8016; Name = "PEP" }
)
foreach ($service in $services) { Wait-Healthy $service.Port $service.Name }

Write-Host "=== Establishing governance and agent identities ==="
$adminPublic = Invoke-Json Get "$Base`:8001/keys/$AdminKeyId/public"
$adminRegistration = Invoke-Json Post "$Base`:8002/dids/register" @{
    public_key_b64 = $adminPublic.publicKey; key_id = $AdminKeyId
    owner_did = "did:web:demo:owner"; controller_dids = @("did:web:demo:controller")
    scope_of_behavior = @{ domain = "governance"; allowed = @("trust-anchor-governance", "layer3-policy-governance") }
    toolset = @("trust-anchor", "policy-administration"); model_hash = "sha3-256-layer3-admin"
    aibom_ref = "layer3-admin-aibom"; did_method = "web"; domain = $Domain
    metadata = @{ agentId = "governance-admin"; name = "GovernanceAdmin" }
}
Assert-True ($adminRegistration.did -eq $AdminDid) "governance admin DID is active" $adminRegistration

$issuerKey = Invoke-Json Post "$Base`:8001/keys/generate" @{
    agent_did = "layer3-issuer-$RunId"; key_purpose = "assertionMethod"
}
$issuerRegistration = Invoke-Json Post "$Base`:8002/dids/register" @{
    public_key_b64 = $issuerKey.publicKey; key_id = $issuerKey.keyId
    owner_did = "did:web:demo:owner"; controller_dids = @("did:web:demo:controller")
    scope_of_behavior = @{ domain = "workflow"; allowed = @("issue-role", "issue-jit") }
    toolset = @("vc-issuance"); model_hash = "sha3-256-layer3-issuer"; aibom_ref = "layer3-issuer-aibom"
    did_method = "web"; domain = $Domain
    metadata = @{ agentId = "layer3-issuer-$RunId"; name = "Layer3WorkflowIssuer" }
}
$IssuerDid = $issuerRegistration.did

$agentKey = Invoke-Json Post "$Base`:8001/keys/generate" @{
    agent_did = "layer3-agent-$RunId"; key_purpose = "authentication"
}
$agentRegistration = Invoke-Json Post "$Base`:8002/dids/register" @{
    public_key_b64 = $agentKey.publicKey; key_id = $agentKey.keyId
    owner_did = "did:web:demo:owner"; controller_dids = @("did:web:demo:controller")
    scope_of_behavior = @{ domain = "financial-risk"; allowed = @("QUERY_TABLE") }
    toolset = @($ResourceDid); model_hash = "sha3-256-layer3-agent"; aibom_ref = "layer3-agent-aibom"
    did_method = "web"; domain = $Domain
    metadata = @{ agentId = "layer3-agent-$RunId"; name = "RiskAnalyzer" }
}
$AgentDid = $agentRegistration.did
Invoke-Json Post "$Base`:8007/wallets/$AgentDid/init" | Out-Null
Assert-True (-not [string]::IsNullOrWhiteSpace($AgentDid)) "agent DID and wallet created"

Write-Host "=== Accrediting the real RoleVC and JITVC issuer ==="
$issuerAuthorizationPayload = @{
    action = "trust-anchor.addIssuer"; issuerDID = $IssuerDid
    credentialTypes = @("RoleVC", "JITVC"); trustDomain = "enterprise"; validUntil = $null
}
$issuerAuthorization = Invoke-Json Post "$Base`:8003/trust-anchor/issuers" @{
    issuerDID = $IssuerDid; credentialTypes = @("RoleVC", "JITVC")
    trustDomain = "enterprise"; validUntil = $null
    adminSignature = New-AdminAuthorization $issuerAuthorizationPayload
}
Assert-True ($null -ne $issuerAuthorization) "issuer accredited by signed governance operation"

Write-Host "=== Issuing and storing real role and JIT credentials ==="
$role = Invoke-Json Post "$Base`:8004/issue/role" @{
    subject_did = $AgentDid; issuer_did = $IssuerDid; issuer_key_id = $issuerKey.keyId
    trust_domain = "enterprise"
    claims = @{ roleName = "RiskAnalyzer"; roleDescription = "Financial risk analysis"; organisationDID = "did:web:demo:finance" }
}
$jit = Invoke-Json Post "$Base`:8004/issue/jit" @{
    subject_did = $AgentDid; issuer_did = $IssuerDid; issuer_key_id = $issuerKey.keyId
    trust_domain = "enterprise"
    claims = @{
        jobID = $JobId; toolDID = $ResourceDid; allowedAction = "QUERY_TABLE"
        inputHandle = "blob://input/$RunId"; outputHandle = "blob://output/$RunId"
        scopeNote = "QuarterlySummaries only"
    }
}
Assert-True (($role.signedVC.type -contains "RoleVC") -and ($jit.signedVC.type -contains "JITVC")) "real RoleVC and scoped JITVC issued" @($role, $jit)
Invoke-Json Post "$Base`:8007/wallets/$AgentDid/store" @{ agent_did = $AgentDid; signed_vc = $role.signedVC } | Out-Null
Invoke-Json Post "$Base`:8007/wallets/$AgentDid/store" @{ agent_did = $AgentDid; signed_vc = $jit.signedVC } | Out-Null

Write-Host "=== Creating a signed resource and ABAC/PBAC policy ==="
$resource = @{
    resourceId = $ResourceId; version = 1; resourceDid = $ResourceDid; resourceType = "financial-database"
    attributes = @{ dataSensitivity = "High"; schema = "Sales"; table = "QuarterlySummaries" }
    active = $true
}
$tamperedResource = @{
    resourceId = $ResourceId; version = 1; resourceDid = $ResourceDid; resourceType = "financial-database"
    attributes = @{ dataSensitivity = "Low"; schema = "Sales"; table = "QuarterlySummaries" }
    active = $true
}
$tamperedStatus = $null
try {
    Invoke-Json Post "$Base`:8013/resources" @{
        resource = $tamperedResource
        adminAuthorization = New-AdminAuthorization @{ action = "pap.upsertResource"; resource = $resource }
    } | Out-Null
    $tamperedStatus = 200
} catch {
    if ($_.Exception.Data.Contains("StatusCode")) {
        $tamperedStatus = [int]$_.Exception.Data["StatusCode"]
    } else { throw }
}
Assert-True ($tamperedStatus -eq 403) "tampered resource rejected by governance signature verification"

$resourceResult = Invoke-Json Post "$Base`:8013/resources" @{
    resource = $resource
    adminAuthorization = New-AdminAuthorization @{ action = "pap.upsertResource"; resource = $resource }
}
Assert-True ($resourceResult.status -eq "stored") "resource attributes stored by PAP with admin signature" $resourceResult

$policy = @{
    policyId = "financial-jit-$RunId"; version = 1; description = "JIT financial query policy"
    effect = "permit"; priority = 100; resourceIds = @($ResourceId); resourceTypes = @("financial-database")
    actions = @("QUERY_TABLE"); requiredCredentialTypes = @("RoleVC", "JITVC"); active = $true
    conditions = @(
        @{ path = "agent.claims.roleName.value"; operator = "eq"; value = "RiskAnalyzer" },
        @{ path = "agent.claims.toolDID.value"; operator = "equals_path"; value = "resource.resourceDid" },
        @{ path = "agent.claims.allowedAction.value"; operator = "equals_path"; value = "request.action" },
        @{ path = "agent.claims.jobID.value"; operator = "equals_path"; value = "request.context.jobId" },
        @{ path = "agent.didDocument.toolset"; operator = "contains"; value = $ResourceDid },
        @{ path = "resource.attributes.dataSensitivity"; operator = "eq"; value = "High" }
    )
}
$policyResult = Invoke-Json Post "$Base`:8013/policies" @{
    policy = $policy
    adminAuthorization = New-AdminAuthorization @{ action = "pap.upsertPolicy"; policy = $policy }
}
Assert-True ($policyResult.status -eq "stored") "versioned access policy stored by PAP with admin signature" $policyResult

Write-Host "=== Exercising permit, enforcement token, and audit ==="
$permitPresentation = New-Presentation $AgentDid
$permit = Invoke-Json Post "$Base`:8016/access/check" @{
    agentDid = $AgentDid; vpJwt = $permitPresentation.vpJwt; nonce = $permitPresentation.nonce
    resourceId = $ResourceId; action = "QUERY_TABLE"
    context = @{ jobId = $JobId; requestTime = [DateTime]::UtcNow.ToString("o") }
}
Assert-True ($permit.effect -eq "permit") "PDP permitted the verified ABAC/PBAC/JIT request" $permit
Assert-True (-not [string]::IsNullOrWhiteSpace($permit.accessToken)) "PEP issued a signed, short-lived scoped access token" $permit

$introspection = Invoke-Json Post "$Base`:8016/access/introspect" @{
    token = $permit.accessToken; resourceId = $ResourceId; action = "QUERY_TABLE"
}
Assert-True ($introspection.active -eq $true) "correct resource and action accepted the access token" $introspection
$wrongScope = Invoke-Json Post "$Base`:8016/access/introspect" @{
    token = $permit.accessToken; resourceId = $ResourceId; action = "DELETE_TABLE"
}
Assert-True ($wrongScope.active -eq $false) "token rejected outside its action scope" $wrongScope
$audit = Invoke-Json Get "$Base`:8016/audit/$($permit.decisionId)"
Assert-True ($audit.decisionId -eq $permit.decisionId) "signed access decision persisted in audit store" $audit

Write-Host "=== Exercising default deny with a fresh non-replayable VP ==="
$denyPresentation = New-Presentation $AgentDid
$denied = Invoke-Json Post "$Base`:8016/access/check" @{
    agentDid = $AgentDid; vpJwt = $denyPresentation.vpJwt; nonce = $denyPresentation.nonce
    resourceId = $ResourceId; action = "QUERY_TABLE"
    context = @{ jobId = "wrong-job-$RunId" }
}
Assert-True ($denied.effect -eq "deny") "context not bound to the JIT credential denied by default" $denied
Assert-True ($null -eq $denied.accessToken) "denied request received no access token" $denied

Write-Host ""
Write-Host "REAL LAYER 3 END-TO-END TEST PASSED"
Write-Host "Agent DID: $AgentDid"
Write-Host "Resource: $ResourceId"
Write-Host "Permit decision: $($permit.decisionId)"
Write-Host "Deny decision: $($denied.decisionId)"
