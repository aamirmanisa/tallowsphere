# Fixture E2E smoke for install.ps1 (runs on windows-latest in release.yml;
# also runnable locally under pwsh — best-effort on non-Windows hosts).
#
# Builds a local fixture "release" (make_fixture.py), serves it over loopback
# HTTP, then drives the REAL install.ps1 end-to-end:
#   1. positive: resolve -> download -> sha256 -> Ed25519 -> extract, via a
#      throwaway key supplied through the TALLOW_PUBKEY_B64 override;
#   2. F-09 refusal: with the override absent and a planted wrong key file,
#      the installer must refuse BEFORE any network I/O;
#   3. F-09 override-wins: with the override present, a differing key file is
#      warned about and the override is used (file left untouched).
#
# Usage: pwsh -NoProfile -File tests/release/smoke_windows.ps1 [-Port 8971]
param(
    [int]$Port = 8971,
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $OutDir) { $OutDir = Join-Path ([IO.Path]::GetTempPath()) "tallow-fixture-windows" }
$tmpRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
if (-not $env:TEMP) { $env:TEMP = $tmpRoot }   # pwsh on non-Windows hosts

# ── fixture ──────────────────────────────────────────────────────────────
$meta = python "$PSScriptRoot/make_fixture.py" --out $OutDir --platform windows --port $Port | ConvertFrom-Json
$archive = $meta.archive
$pub = (Get-Content (Join-Path $OutDir "fixture_pub.b64") -Raw).Trim()
Write-Host "fixture: $archive | port $Port | out $OutDir"

# ── serve over loopback ──────────────────────────────────────────────────
$srvArgs = @{ FilePath = "python"; ArgumentList = @("-m","http.server","$Port","--directory",$OutDir); PassThru = $true }
if ($IsWindows) { $srvArgs.WindowStyle = "Hidden" }
$srv = Start-Process @srvArgs
try {
    $ready = $false
    for ($i = 0; $i -lt 20 -and -not $ready; $i++) {
        try { $null = Invoke-WebRequest "http://127.0.0.1:$Port/latest.json" -UseBasicParsing -TimeoutSec 1; $ready = $true }
        catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw "fixture HTTP server did not come up on port $Port" }

    $env:TALLOW_RELEASE_API_URL = "http://127.0.0.1:$Port/latest.json"
    $env:TALLOW_PUBKEY_B64 = $pub
    $env:TALLOW_KEY_FILE = Join-Path $tmpRoot "tallow-smoke.pub"
    $env:TALLOW_INSTALL_DIR = Join-Path $tmpRoot "tallow-smoke"
    if (Test-Path $env:TALLOW_KEY_FILE) { Remove-Item $env:TALLOW_KEY_FILE -Force }
    if (Test-Path $env:TALLOW_INSTALL_DIR) { Remove-Item $env:TALLOW_INSTALL_DIR -Recurse -Force }

    $installer = Join-Path $root "install.ps1"
    $failures = 0
    function Check($name, $cond) {
        if ($cond) { Write-Host "PASS: $name" } else { Write-Host "FAIL: $name"; $script:failures++ }
    }

    # ── 1. positive install through the real script ──────────────────────
    $out1 = pwsh -NoProfile -File $installer 2>&1
    Check "positive: rc=0" ($LASTEXITCODE -eq 0)
    Check "positive: tallow.exe installed" (Test-Path (Join-Path $env:TALLOW_INSTALL_DIR "tallow.exe"))
    Check "positive: signature valid" (($out1 | Out-String) -match 'signature: VALID')
    Check "positive: key file written" (Test-Path $env:TALLOW_KEY_FILE)
    Check "positive: override warning" (($out1 | Out-String) -match 'TALLOW_PUBKEY_B64 override in effect')

    # ── 2. F-09 refusal: no override + planted wrong key file ────────────
    Remove-Item Env:TALLOW_PUBKEY_B64 -ErrorAction SilentlyContinue
    [System.IO.File]::WriteAllBytes($env:TALLOW_KEY_FILE, [byte[]](1..32))
    $out2 = pwsh -NoProfile -File $installer 2>&1
    Check "refusal: non-zero exit" ($LASTEXITCODE -ne 0)
    Check "refusal: message present" (($out2 | Out-String) -match 'does not match the pinned release key')

    # ── 3. F-09 override-wins: override present + same wrong file ────────
    $env:TALLOW_PUBKEY_B64 = $pub
    $out3 = pwsh -NoProfile -File $installer 2>&1
    Check "override-wins: rc=0" ($LASTEXITCODE -eq 0)
    Check "override-wins: warned" (($out3 | Out-String) -match 'differs from the TALLOW_PUBKEY_B64 override')

    Write-Host ""
    if ($failures -gt 0) { Write-Host "SMOKE FAILED: $failures check(s)"; exit 1 }
    Write-Host "SMOKE OK"
} finally {
    Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
}
