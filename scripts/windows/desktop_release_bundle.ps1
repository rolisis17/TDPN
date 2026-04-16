param(
  [ValidateSet("stable", "beta", "canary")]
  [string]$Channel = "stable",
  [string]$UpdateFeedUrl = "",
  [string]$SigningIdentity = "",
  [string]$SigningCertPath = "",
  [string]$SigningCertPassword = "",
  [switch]$Help,
  [switch]$SkipBuild,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$TauriArgs
)

$ErrorActionPreference = "Stop"

function Show-Usage {
  Write-Host "TDPN desktop release bundle scaffold (non-production signing flow)"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 [-Help] [-Channel stable|beta|canary] [-UpdateFeedUrl URL] [-SigningIdentity ID] [-SigningCertPath PATH] [-SigningCertPassword VALUE] [-SkipBuild] [-- <tauri args>]"
  Write-Host ""
  Write-Host "Examples:"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 -Channel beta -UpdateFeedUrl https://updates.example.invalid/tdpn/beta.json"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 -Channel canary -- --bundles nsis"
  Write-Host ""
  Write-Host "Notes:"
  Write-Host "  - This is scaffold-only and does not implement production signing/secret handling."
  Write-Host "  - Tauri build runs from apps/desktop via: npm run tauri -- build ..."
  Write-Host "  - Sets TDPN_DESKTOP_UPDATE_CHANNEL and optional TDPN_DESKTOP_UPDATE_FEED_URL for this process."
}

if ($Help -or $TauriArgs -contains "-h" -or $TauriArgs -contains "--help" -or $TauriArgs -contains "/?") {
  Show-Usage
  exit 0
}

if ($TauriArgs.Count -gt 0 -and $TauriArgs[0] -eq "--") {
  if ($TauriArgs.Count -gt 1) {
    $TauriArgs = $TauriArgs[1..($TauriArgs.Count - 1)]
  } else {
    $TauriArgs = @()
  }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$desktopDir = Join-Path $repoRoot.Path "apps\desktop"

if (-not (Test-Path (Join-Path $desktopDir "package.json"))) {
  throw "apps/desktop/package.json not found at expected path: $desktopDir"
}

$env:TDPN_DESKTOP_UPDATE_CHANNEL = $Channel
if ([string]::IsNullOrWhiteSpace($UpdateFeedUrl)) {
  Remove-Item Env:TDPN_DESKTOP_UPDATE_FEED_URL -ErrorAction SilentlyContinue
} else {
  $env:TDPN_DESKTOP_UPDATE_FEED_URL = $UpdateFeedUrl
}

# Scaffold placeholders only. These are not wired to any production signing flow.
if (-not [string]::IsNullOrWhiteSpace($SigningIdentity)) {
  $env:TDPN_DESKTOP_SIGNING_IDENTITY = $SigningIdentity
}
if (-not [string]::IsNullOrWhiteSpace($SigningCertPath)) {
  $env:TDPN_DESKTOP_SIGNING_CERT_PATH = $SigningCertPath
}
if (-not [string]::IsNullOrWhiteSpace($SigningCertPassword)) {
  $env:TDPN_DESKTOP_SIGNING_CERT_PASSWORD = $SigningCertPassword
}

Write-Host "[desktop-release-bundle] mode=scaffold-non-production"
Write-Host "[desktop-release-bundle] channel=$($env:TDPN_DESKTOP_UPDATE_CHANNEL)"
if ($env:TDPN_DESKTOP_UPDATE_FEED_URL) {
  Write-Host "[desktop-release-bundle] update_feed=$($env:TDPN_DESKTOP_UPDATE_FEED_URL)"
} else {
  Write-Host "[desktop-release-bundle] update_feed=(not set)"
}
if ($env:TDPN_DESKTOP_SIGNING_IDENTITY -or $env:TDPN_DESKTOP_SIGNING_CERT_PATH -or $env:TDPN_DESKTOP_SIGNING_CERT_PASSWORD) {
  Write-Host "[desktop-release-bundle] signing_placeholders=provided (scaffold-only)"
} else {
  Write-Host "[desktop-release-bundle] signing_placeholders=not provided"
}

if ($SkipBuild) {
  Write-Host "[desktop-release-bundle] build skipped by -SkipBuild"
  Show-Usage
  exit 0
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  throw "npm was not found in PATH. Install Node.js/npm first."
}

Push-Location $desktopDir
try {
  $npmArgs = @("run", "tauri", "--", "build")
  if ($TauriArgs.Count -gt 0) {
    $npmArgs += $TauriArgs
  }

  Write-Host "[desktop-release-bundle] running: npm $($npmArgs -join ' ')"
  & npm @npmArgs
  $rc = $LASTEXITCODE
  if ($rc -ne 0) {
    throw "tauri build failed with exit code $rc"
  }
} finally {
  Pop-Location
}

$bundleHint = Join-Path $desktopDir "src-tauri\target\release\bundle"
Write-Host "[desktop-release-bundle] status=ok"
Write-Host "[desktop-release-bundle] artifact_hint=$bundleHint"
Write-Host "[desktop-release-bundle] note=this is scaffold-only and not a production signing/release pipeline"
