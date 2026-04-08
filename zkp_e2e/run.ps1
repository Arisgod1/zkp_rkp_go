param(
  [ValidateSet("e2e", "perf")]
  [string]$Mode = "e2e",
  [int]$Count = 1,
  [int]$IntervalMs = 0,
  [switch]$ContinueOnError
)

$ErrorActionPreference = "Stop"

if ($Count -le 0) {
  throw "Count must be greater than 0"
}
if ($IntervalMs -lt 0) {
  throw "IntervalMs must be >= 0"
}

$continueOnError = $ContinueOnError.IsPresent -or $Count -gt 1

$baseUrl = $env:BASE_URL
if ([string]::IsNullOrWhiteSpace($baseUrl)) {
  $baseUrl = "http://localhost:8080"
}

Write-Host "Running ZKP E2E against $baseUrl"
$continueOnError = $ContinueOnError.IsPresent -or $Count -gt 1 -or $Mode -eq "perf"
Write-Host "Mode=$Mode Count=$Count IntervalMs=$IntervalMs ContinueOnError=$continueOnError"
$env:ZKP_TEST_MODE = $Mode
$env:BASE_URL = $baseUrl

$success = 0
$failed = 0
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()

Push-Location $PSScriptRoot
try {
  for ($i = 1; $i -le $Count; $i++) {
    Write-Host "`n[$i/$Count] start"
    $swOne = [System.Diagnostics.Stopwatch]::StartNew()

    & go run .
    $exitCode = $LASTEXITCODE

    $swOne.Stop()
    if ($exitCode -eq 0) {
      $success++
      Write-Host ("[{0}/{1}] ok {2}ms" -f $i, $Count, $swOne.Elapsed.TotalMilliseconds.ToString("F0"))
    }
    else {
      $failed++
      Write-Host ("[{0}/{1}] failed exitCode={2} {3}ms" -f $i, $Count, $exitCode, $swOne.Elapsed.TotalMilliseconds.ToString("F0"))
      if (-not $continueOnError) {
        throw "E2E run failed at iteration $i, exitCode=$exitCode"
      }
    }

    if ($i -lt $Count -and $IntervalMs -gt 0) {
      Start-Sleep -Milliseconds $IntervalMs
    }
  }
}
finally {
  Pop-Location
  $swTotal.Stop()
}

$totalSeconds = [Math]::Max($swTotal.Elapsed.TotalSeconds, 0.001)
$rps = $success / $totalSeconds
Write-Host ("`nSummary: total={0} success={1} failed={2} elapsed={3}s success_rps={4}" -f $Count, $success, $failed, $swTotal.Elapsed.TotalSeconds.ToString("F2"), $rps.ToString("F2"))

if ($failed -gt 0) {
  exit 1
}
