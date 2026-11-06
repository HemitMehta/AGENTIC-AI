Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "prepare_orchestrator_demo.ps1")

$OperatorHeaders = @{ "X-API-Key" = (Get-Content -LiteralPath $TokenFile -Raw).Trim() }
function Invoke-Orchestrator {
    param([object]$Body)
    Invoke-RestMethod -Method Post -Uri "$Base`:8017/tasks" -Headers $OperatorHeaders -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 40)
}
function Assert-HttpStatus {
    param([scriptblock]$Call, [int]$Expected, [string]$Label)
    $code = 0
    try { & $Call | Out-Null; $code = 200 } catch {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } else { throw }
    }
    Assert-True ($code -eq $Expected) "$Label (HTTP $code)"
}
$testBody = Get-Content (Join-Path $DemoDirectory "01-submit-task.json") -Raw | ConvertFrom-Json
$testBody | Add-Member -NotePropertyName taskId -NotePropertyValue ([Guid]::NewGuid().ToString())
Assert-HttpStatus { Invoke-Json Post "$Base`:8017/tasks" $testBody } 401 "unauthenticated task submission denied"

$result = Invoke-Orchestrator $testBody
Assert-True ($result.status -eq "completed") "orchestrator dispatched the task to a running worker" $result
Assert-True ($result.discovery.selectedAgent -eq $worker.did) "discovered DID matches the executing worker"
Assert-True ($result.discovery.gatewaySignatureVerified -and $result.discovery.ansRecordSignatureVerified) "orchestrator independently verified gateway and ANS signatures"
Assert-True $result.agentResponseSignatureVerified "orchestrator verified the worker's response signature"
Assert-True ([decimal]$result.agentResponse.result.netIncome -eq 16000) "worker computed the expected net income from supplied inputs"
Assert-True ($result.agentResponse.result.lossMakingPeriods -contains "2026-Q2") "worker detected the loss-making period"
$audit = Invoke-RestMethod "$Base`:8017/tasks/$($result.taskId)" -Headers $OperatorHeaders
Assert-True ($audit.status -eq "completed") "task outcome persisted and retrievable"
Assert-HttpStatus { Invoke-Orchestrator $testBody } 409 "reusing the same task ID rejected"

$testBody.taskId = [Guid]::NewGuid().ToString()
$testBody.input.periods[0].revenue = "110000.00"
$changedResult = Invoke-Orchestrator $testBody
Assert-True ([decimal]$changedResult.agentResponse.result.netIncome -eq 26000) "changed input changes the actual worker calculation"

$testBody.taskId = [Guid]::NewGuid().ToString()
$testBody.discovery.requiredAttestations = @("SOXComplianceCertified")
Assert-HttpStatus { Invoke-Orchestrator $testBody } 404 "missing compliance credential prevents dispatch"
$testBody.taskId = [Guid]::NewGuid().ToString()
$testBody.discovery.requiredAttestations = @("RoleVC")
$testBody.discovery.versionRange = ">=9.0.0,<10.0.0"
Assert-HttpStatus { Invoke-Orchestrator $testBody } 404 "unmatched version prevents dispatch"

Write-Host "=== Direct worker authentication and replay checks ==="
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$payload = @{
    type = "agent.task.request.v1"; taskId = [Guid]::NewGuid().ToString()
    issuerDid = $orchestrator.did; audienceDid = $worker.did; action = "analyze_financials"
    issuedAt = $now; expiresAt = $now + 60
    input = $submission.input
}
$canonical = ConvertTo-CanonicalJson $payload
$signed = Invoke-Json Post "$Base`:8001/keys/$($orchestrator.keyId)/sign" @{
    payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($canonical))
}
$message = $payload.Clone()
$message.proof = @{
    verificationMethod = $orchestrator.verificationMethod; signatureAlgorithm = "Ed25519"
    signature = $signed.signature
}
Assert-HttpStatus { Invoke-Json Post "$Base`:8018/tasks" $payload } 422 "unsigned direct worker request rejected"
$tampered = ($message | ConvertTo-Json -Depth 40) | ConvertFrom-Json
$tampered.input.periods[0].revenue = "1.00"
Assert-HttpStatus { Invoke-Json Post "$Base`:8018/tasks" $tampered } 403 "tampered signed worker request rejected"
$direct = Invoke-Json Post "$Base`:8018/tasks" $message
Assert-True ($direct.status -eq "completed") "worker accepts correctly signed authorized request"
Assert-HttpStatus { Invoke-Json Post "$Base`:8018/tasks" $message } 409 "worker independently blocks replay"

Write-Host ""
Write-Host "REAL ORCHESTRATOR END-TO-END TEST PASSED"
Write-Host "Completed task: $($result.taskId)"
Write-Host "Swagger request file is still ready for a fresh submission (no fixed taskId)."
