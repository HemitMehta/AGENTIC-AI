param([switch]$PrepareOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\layer3_testing\run_real_layer3_test.ps1")
foreach ($port in @(8008,8009,8010,8011,8012,8017,8018,8019)) { Wait-Healthy $port "Integrated agent service" }
$fixture = @{
    issuerDid = $IssuerDid; issuerKeyId = $issuerKey.keyId
    adminDid = $AdminDid; adminKeyId = $AdminKeyId
    resource = $resource; policy = $policy; jobId = $JobId
}
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($fixture | ConvertTo-Json -Depth 40 -Compress)))
$arguments = @((Join-Path $PSScriptRoot "protected_flow.py"), $encoded)
if ($PrepareOnly) { $arguments += "--prepare-only" }
& python @arguments
if ($LASTEXITCODE -ne 0) { throw "Protected orchestration setup or test failed" }
