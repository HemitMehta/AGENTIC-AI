Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "run_real_layer3_test.ps1")
Wait-Healthy 8019 "Protected sales resource"
$fixture = @{
    agentDid = $AgentDid; agentKeyId = $agentKey.keyId
    issuerDid = $IssuerDid; adminDid = $AdminDid; adminKeyId = $AdminKeyId
    resource = $resource; policy = $policy; jobId = $JobId; jitVcId = $jit.vc_id
    jitExpiry = ([DateTimeOffset]::Parse($jit.signedVC.expirationDate)).ToUnixTimeSeconds()
}
$encodedFixture = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($fixture | ConvertTo-Json -Depth 40 -Compress)))
& python (Join-Path $PSScriptRoot "enforcement_flow.py") $encodedFixture
if ($LASTEXITCODE -ne 0) { throw "Layer 3 enforcement test failed" }
