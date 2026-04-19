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
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 [-Help] [-Channel stable|beta|canary] [-UpdateFeedUrl URL] [-SigningIdentity ID] [-SigningCertPath PATH] [-SkipBuild] [-- <tauri args>]"
  Write-Host ""
  Write-Host "Examples:"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 -Channel beta -UpdateFeedUrl https://updates.example.invalid/tdpn/beta.json"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 -Channel canary -- --bundles nsis"
  Write-Host ""
  Write-Host "Notes:"
  Write-Host "  - This is scaffold-only and does not implement production signing/secret handling."
  Write-Host "  - Tauri build runs from apps/desktop via: npm run tauri -- build ..."
  Write-Host "  - Sets TDPN_DESKTOP_UPDATE_CHANNEL and TDPN_DESKTOP_UPDATE_FEED_CONFIGURED for this process."
  Write-Host "  - Validates update feed URL and signing placeholder input consistency before invoking build."
  Write-Host "  - -SigningCertPassword is intentionally rejected; pass signing secrets through a secure path instead."
}

function Get-CanonicalHost {
  param([uri]$UriValue)
  if (-not $UriValue -or [string]::IsNullOrWhiteSpace($UriValue.Host)) {
    return ""
  }
  return $UriValue.DnsSafeHost.ToLowerInvariant()
}

function Validate-UpdateFeedUrl {
  param(
    [string]$CandidateUrl
  )

  if ([string]::IsNullOrWhiteSpace($CandidateUrl)) {
    return
  }

  $parsed = $null
  if (-not [uri]::TryCreate($CandidateUrl.Trim(), [uriKind]::Absolute, [ref]$parsed)) {
    throw "invalid -UpdateFeedUrl '$CandidateUrl' (expected absolute URL like https://updates.example.invalid/tdpn/beta.json)"
  }
  if ($parsed.Scheme -ne "https" -and $parsed.Scheme -ne "http") {
    throw "invalid -UpdateFeedUrl '$CandidateUrl' (allowed schemes: http, https)"
  }
  if (-not [string]::IsNullOrWhiteSpace($parsed.UserInfo)) {
    throw "invalid -UpdateFeedUrl '$CandidateUrl' (userinfo is not allowed)"
  }
  if (-not [string]::IsNullOrWhiteSpace($parsed.Query) -or -not [string]::IsNullOrWhiteSpace($parsed.Fragment)) {
    throw "invalid -UpdateFeedUrl '$CandidateUrl' (query/fragment is not allowed)"
  }

  $canonicalHost = Get-CanonicalHost -UriValue $parsed
  $isLocalHost = $canonicalHost -eq "localhost" -or $canonicalHost -eq "127.0.0.1" -or $canonicalHost -eq "::1"
  if (-not $isLocalHost -and $parsed.Scheme -ne "https") {
    throw "invalid -UpdateFeedUrl '$CandidateUrl' (non-local update feeds must use https)"
  }
}

function Validate-SigningPlaceholders {
  param(
    [string]$Identity,
    [string]$CertPath,
    [string]$CertPassword
  )

  $hasIdentity = -not [string]::IsNullOrWhiteSpace($Identity)
  $hasCertPath = -not [string]::IsNullOrWhiteSpace($CertPath)
  $hasCertPassword = -not [string]::IsNullOrWhiteSpace($CertPassword)

  if ($hasCertPassword) {
    throw "-SigningCertPassword is not supported in this scaffold."
  }
  if ($hasCertPath) {
    if (-not (Test-Path -LiteralPath $CertPath -PathType Leaf)) {
      throw "signing certificate file was not found: $CertPath"
    }
  }
  if ($hasIdentity -and $hasCertPath) {
    Write-Warning "Both -SigningIdentity and -SigningCertPath were provided. This scaffold passes placeholders only; ensure downstream signing selection is explicit."
  }
}

function Save-ScopedEnvironment {
  param(
    [string[]]$VariableNames
  )

  $snapshot = @{}
  foreach ($name in $VariableNames) {
    $item = Get-Item -Path ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
    if ($null -ne $item) {
      $snapshot[$name] = [pscustomobject]@{
        Present = $true
        Value = [string]$item.Value
      }
    } else {
      $snapshot[$name] = [pscustomobject]@{
        Present = $false
        Value = $null
      }
    }
  }
  return $snapshot
}

function Restore-ScopedEnvironment {
  param(
    [hashtable]$Snapshot
  )

  if ($null -eq $Snapshot) {
    return
  }

  foreach ($name in $Snapshot.Keys) {
    $entry = $Snapshot[$name]
    if ($entry.Present) {
      Set-Item -Path ("Env:{0}" -f $name) -Value $entry.Value
    } else {
      Remove-Item -Path ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
    }
  }
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

Validate-UpdateFeedUrl -CandidateUrl $UpdateFeedUrl
Validate-SigningPlaceholders -Identity $SigningIdentity -CertPath $SigningCertPath -CertPassword $SigningCertPassword

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$desktopDir = Join-Path $repoRoot.Path "apps\desktop"

if (-not (Test-Path (Join-Path $desktopDir "package.json"))) {
  throw "apps/desktop/package.json not found at expected path: $desktopDir"
}

$scopedEnvNames = @(
  "TDPN_DESKTOP_UPDATE_CHANNEL",
  "TDPN_DESKTOP_UPDATE_FEED_CONFIGURED",
  "TDPN_DESKTOP_SIGNING_IDENTITY",
  "TDPN_DESKTOP_SIGNING_CERT_PATH"
)
$scopedEnvSnapshot = Save-ScopedEnvironment -VariableNames $scopedEnvNames

try {
  $env:TDPN_DESKTOP_UPDATE_CHANNEL = $Channel
  if ([string]::IsNullOrWhiteSpace($UpdateFeedUrl)) {
    $env:TDPN_DESKTOP_UPDATE_FEED_CONFIGURED = "0"
  } else {
    $env:TDPN_DESKTOP_UPDATE_FEED_CONFIGURED = "1"
  }

  # Scaffold placeholders only. These are not wired to any production signing flow.
  if ([string]::IsNullOrWhiteSpace($SigningIdentity)) {
    Remove-Item Env:TDPN_DESKTOP_SIGNING_IDENTITY -ErrorAction SilentlyContinue
  } else {
    $env:TDPN_DESKTOP_SIGNING_IDENTITY = $SigningIdentity
  }
  if ([string]::IsNullOrWhiteSpace($SigningCertPath)) {
    Remove-Item Env:TDPN_DESKTOP_SIGNING_CERT_PATH -ErrorAction SilentlyContinue
  } else {
    $env:TDPN_DESKTOP_SIGNING_CERT_PATH = $SigningCertPath
  }

  Write-Host "[desktop-release-bundle] mode=scaffold-non-production"
  Write-Host "[desktop-release-bundle] channel=$($env:TDPN_DESKTOP_UPDATE_CHANNEL)"
  if ($env:TDPN_DESKTOP_UPDATE_FEED_CONFIGURED -eq "1") {
    Write-Host "[desktop-release-bundle] update_feed=configured"
  } else {
    Write-Host "[desktop-release-bundle] update_feed=(not set)"
  }
  if ($env:TDPN_DESKTOP_SIGNING_IDENTITY -or $env:TDPN_DESKTOP_SIGNING_CERT_PATH) {
    Write-Host "[desktop-release-bundle] signing_placeholders=provided (scaffold-only)"
  } else {
    Write-Host "[desktop-release-bundle] signing_placeholders=not provided"
  }

  if ($SkipBuild) {
    Write-Host "[desktop-release-bundle] build skipped by -SkipBuild"
    Show-Usage
    return
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
} finally {
  Restore-ScopedEnvironment -Snapshot $scopedEnvSnapshot
}
