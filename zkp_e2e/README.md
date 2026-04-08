# ZKP E2E Test

This folder provides a one-command client simulation for two modes:

1. `e2e` mode: full local proof, validates the real ZKP flow
2. `perf` mode: skips local proof computation and uses a trivial valid proof to measure request throughput

`e2e` generates a fresh user keypair and computes a valid Schnorr proof locally.
`perf` uses `publicKeyY=1`, `clientR=1`, and `s=0` to avoid local proof work while still exercising register/challenge/verify.

## Quick start (PowerShell)

From project root:

```powershell
./zkp_e2e/run.ps1
```

Run perf mode:

```powershell
./zkp_e2e/run.ps1 -Mode perf -Count 100
```

Default server is `http://localhost:8080`.

## Custom base URL

```powershell
$env:BASE_URL = "http://localhost:8080"
./zkp_e2e/run.ps1
```

## Optional timeout

```powershell
$env:TIMEOUT_SECONDS = "20"
./zkp_e2e/run.ps1
```

## Loop run for performance smoke test

Run 50 times sequentially:

```powershell
./zkp_e2e/run.ps1 -Count 50
```

Run 50 times in perf mode:

```powershell
./zkp_e2e/run.ps1 -Mode perf -Count 50
```

Run 100 times with 100ms interval:

```powershell
./zkp_e2e/run.ps1 -Count 100 -IntervalMs 100
```

Continue even if some iterations fail:

```powershell
./zkp_e2e/run.ps1 -Count 100 -ContinueOnError
```

When `-Count` is greater than 1, the script already continues by default and only reports failures in the final summary.

The script prints a final summary:

- total
- success
- failed
- elapsed seconds
- success_rps (successful runs per second)
