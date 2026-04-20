param(
  [ValidateSet("stable", "beta", "canary")]
  [string]$Channel = "stable",
  [string]$UpdateFeedUrl = "",
  [string]$SummaryJson = "",
  [ValidateSet(0, 1)]
  [int]$PrintSummaryJson = 0,
  [string]$SigningIdentity = "",
  [string]$SigningCertPath = "",
  [string]$SigningCertPassword = "",
  [switch]$InstallMissing,
  [switch]$Help,
  [switch]$SkipBuild,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$TauriArgs
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Show-Usage {
  Write-Host "GPM desktop release bundle scaffold (non-production signing flow)"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 [-Help] [-Channel stable|beta|canary] [-UpdateFeedUrl URL] [-SummaryJson PATH] [-PrintSummaryJson 0|1] [-SigningIdentity ID] [-SigningCertPath PATH] [-SigningCertPassword VALUE] [-InstallMissing] [-SkipBuild] [-- <tauri args>]"
  Write-Host ""
  Write-Host "Examples:"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 -Channel beta -UpdateFeedUrl https://updates.example.invalid/gpm/beta.json"
  Write-Host "  ./scripts/windows/desktop_release_bundle.ps1 -Channel canary -- --bundles nsis"
  Write-Host ""
  Write-Host "Notes:"
  Write-Host "  - This is scaffold-only and does not implement production signing/secret handling."
  Write-Host "  - Tauri build runs from apps/desktop via: npm run tauri -- build ..."
  Write-Host "  - -InstallMissing may use winget to install missing Node.js, Rust, and Git prerequisites non-interactively."
  Write-Host "  - Sets GPM_DESKTOP_* vars and mirrors TDPN_DESKTOP_* compatibility vars for this process."
  Write-Host "  - If -UpdateFeedUrl is omitted, the script falls back to GPM_DESKTOP_UPDATE_FEED_URL then TDPN_DESKTOP_UPDATE_FEED_URL."
  Write-Host "  - Writes summary JSON to .easy-node-logs/desktop_release_bundle_windows_summary.json by default."
  Write-Host "  - -SigningCertPassword requires -SigningCertPath."
  Write-Host "  - Validates update feed URL and signing placeholder input consistency before invoking build."
}

function Resolve-UpdateFeedUrl {
  param(
    [string]$ParameterValue
  )

  if (-not [string]::IsNullOrWhiteSpace($ParameterValue)) {
    return $ParameterValue.Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($env:GPM_DESKTOP_UPDATE_FEED_URL)) {
    return $env:GPM_DESKTOP_UPDATE_FEED_URL.Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($env:TDPN_DESKTOP_UPDATE_FEED_URL)) {
    return $env:TDPN_DESKTOP_UPDATE_FEED_URL.Trim()
  }
  return ""
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
    throw "invalid -UpdateFeedUrl '$CandidateUrl' (expected absolute URL like https://updates.example.invalid/gpm/beta.json)"
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

  if ($hasCertPassword -and -not $hasCertPath) {
    throw "-SigningCertPassword requires -SigningCertPath."
  }
  if ($hasCertPath) {
    if (-not (Test-Path -LiteralPath $CertPath -PathType Leaf)) {
      throw (New-RemediationMessage -Headline "signing certificate file was not found: $CertPath" -Hints @(
        "Double-check the path you passed to -SigningCertPath and ensure the file is reachable from this machine.",
        "This scaffold only forwards signing placeholders, so the certificate path is validated locally before build starts."
      ))
    }
  }
  if ($hasIdentity -and $hasCertPath) {
    Write-Warning "Both -SigningIdentity and -SigningCertPath were provided. This scaffold passes placeholders only; ensure downstream signing selection is explicit."
  }
}

function Get-DesktopBuildMissingTools {
  $missing = @()

  if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    $missing += "Node.js LTS / node"
  }
  if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    $missing += "npm.cmd"
  }
  if (-not (Get-Command rustc -ErrorAction SilentlyContinue) -or -not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $missing += "Rust toolchain (rustc + cargo)"
  }
  return @($missing)
}

function Refresh-DesktopProcessPath {
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $segments = @()

  if (-not [string]::IsNullOrWhiteSpace($machinePath)) {
    $segments += $machinePath
  }
  if (-not [string]::IsNullOrWhiteSpace($userPath)) {
    $segments += $userPath
  }

  if ($segments.Count -eq 0) {
    return
  }

  $env:PATH = [Environment]::ExpandEnvironmentVariables(($segments -join ";"))
}

function New-RemediationMessage {
  param(
    [string]$Headline,
    [string[]]$Hints
  )

  $lines = @($Headline)
  foreach ($hint in $Hints) {
    $lines += "- $hint"
  }
  return ($lines -join [Environment]::NewLine)
}

function Assert-WingetAvailable {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    return
  }

  throw (New-RemediationMessage -Headline "winget was not found, so -InstallMissing cannot auto-remediate this machine." -Hints @(
    "Install the App Installer package from Microsoft Store, or provision Node.js / Rust / Git manually and rerun the script.",
    "After installing prerequisites, open a new terminal so PATH refreshes cleanly."
  ))
}

function Invoke-WingetInstall {
  param(
    [string]$PackageId,
    [string]$FriendlyName
  )

  $args = @(
    "install",
    "--id", $PackageId,
    "--exact",
    "--source", "winget",
    "--silent",
    "--accept-package-agreements",
    "--accept-source-agreements",
    "--disable-interactivity"
  )

  Write-Host "[desktop-release-bundle] installing $FriendlyName via winget"
  & winget @args
  $rc = $LASTEXITCODE
  if ($rc -ne 0) {
    throw (New-RemediationMessage -Headline "winget failed while installing $FriendlyName (exit code $rc)." -Hints @(
      "Rerun with elevated permissions if the package requires machine-level installation.",
      "If winget source or network access is unavailable, install $FriendlyName manually and rerun the script."
    ))
  }
}

function Install-MissingDesktopDependencies {
  param(
    [string[]]$MissingTools
  )

  if ($MissingTools.Count -eq 0) {
    return
  }

  Assert-WingetAvailable

  if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Invoke-WingetInstall -PackageId "Git.Git" -FriendlyName "Git"
  }

  foreach ($tool in $MissingTools) {
    switch ($tool) {
      "Node.js LTS / node" {
        Invoke-WingetInstall -PackageId "OpenJS.NodeJS.LTS" -FriendlyName "Node.js LTS"
      }
      "npm.cmd" {
        Invoke-WingetInstall -PackageId "OpenJS.NodeJS.LTS" -FriendlyName "Node.js LTS"
      }
      "Rust toolchain (rustc + cargo)" {
        Invoke-WingetInstall -PackageId "Rustlang.Rustup" -FriendlyName "Rust toolchain"
      }
      default {
        throw "unsupported auto-install target: $tool"
      }
    }
  }
}

function Assert-DesktopBuildTools {
  param(
    [switch]$AutoInstallMissing
  )

  Refresh-DesktopProcessPath
  $missing = Get-DesktopBuildMissingTools
  if ($missing.Count -eq 0) {
    return
  }

  if ($AutoInstallMissing) {
    Install-MissingDesktopDependencies -MissingTools $missing
    Refresh-DesktopProcessPath
    $missing = Get-DesktopBuildMissingTools
    if ($missing.Count -eq 0) {
      return
    }
  }

  $lines = @("desktop release bundle prerequisites are missing:")
  foreach ($item in $missing) {
    switch ($item) {
      "Node.js LTS / node" { $lines += "- Node.js LTS / node: install with winget install --id OpenJS.NodeJS.LTS --exact" }
      "npm.cmd" { $lines += "- npm.cmd: reinstall or repair Node.js LTS so npm.cmd is on PATH" }
      "Rust toolchain (rustc + cargo)" { $lines += "- Rust toolchain: install with winget install --id Rustlang.Rustup --exact" }
      "Git" { $lines += "- Git: install with winget install --id Git.Git --exact" }
      default { $lines += "- $item" }
    }
  }
  $lines += "- rerun the script after the missing tools are installed"
  $lines += "- use -InstallMissing to let the script attempt non-interactive winget remediation on this machine"

  throw ($lines -join [Environment]::NewLine)
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

function Ensure-TauriIconScaffold {
  param(
    [Parameter(Mandatory = $true)]
    [string]$DesktopDir
  )

  $iconPath = Join-Path $DesktopDir "src-tauri\icons\icon.ico"
  if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
    return
  }

  $iconDir = Split-Path -Parent $iconPath
  if (-not (Test-Path -LiteralPath $iconDir -PathType Container)) {
    New-Item -ItemType Directory -Path $iconDir -Force | Out-Null
  }

  # Minimal valid 1x1 ICO payload (single 32-bit image + empty AND mask).
  [byte[]]$icoBytes = @(
    0x00,0x00, 0x01,0x00, 0x01,0x00,
    0x01, 0x01, 0x00, 0x00, 0x01,0x00, 0x20,0x00, 0x30,0x00,0x00,0x00, 0x16,0x00,0x00,0x00,
    0x28,0x00,0x00,0x00, 0x01,0x00,0x00,0x00, 0x02,0x00,0x00,0x00, 0x01,0x00, 0x20,0x00,
    0x00,0x00,0x00,0x00, 0x04,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,
    0x00,0x00,0x00,0x00
  )

  [System.IO.File]::WriteAllBytes($iconPath, $icoBytes)
  Write-Host "[desktop-release-bundle] icon_scaffold=created ($iconPath)"
}

function Get-ArtifactKind {
  param(
    [string]$Extension
  )

  switch ($Extension.ToLowerInvariant()) {
    ".msi" { return "msi" }
    ".exe" { return "exe" }
    ".nsis" { return "nsis" }
    ".zip" { return "zip" }
    ".sig" { return "sig" }
    default { return "file" }
  }
}

function Get-BundleArtifacts {
  param(
    [string]$BundleRoot
  )

  $records = @()
  if (-not (Test-Path -LiteralPath $BundleRoot -PathType Container)) {
    return @($records)
  }

  $files = @(Get-ChildItem -LiteralPath $BundleRoot -File -Recurse | Sort-Object -Property FullName)
  foreach ($file in $files) {
    $extension = ""
    if (-not [string]::IsNullOrWhiteSpace($file.Extension)) {
      $extension = $file.Extension.ToLowerInvariant()
    }
    $kind = Get-ArtifactKind -Extension $extension
    $sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()

    $records += [ordered]@{
      path = $file.FullName
      name = $file.Name
      extension = $extension
      kind = $kind
      size_bytes = [int64]$file.Length
      sha256 = $sha256
    }
  }

  return @($records)
}

function Get-ArtifactsByKind {
  param(
    [object[]]$Artifacts
  )

  $counts = [ordered]@{}
  foreach ($artifact in $Artifacts) {
    $kind = [string]$artifact.kind
    if ($counts.Contains($kind)) {
      $counts[$kind] = [int]$counts[$kind] + 1
    } else {
      $counts[$kind] = 1
    }
  }
  return $counts
}

function Write-ReleaseBundleSummary {
  param(
    [string]$SummaryPath,
    [string]$Channel,
    [string]$UpdateFeedUrl,
    [bool]$SkipBuild,
    [bool]$InstallMissingRequested,
    [string]$BundleRoot,
    [bool]$PrintPayload
  )

  $artifacts = Get-BundleArtifacts -BundleRoot $BundleRoot
  $artifactsByKind = Get-ArtifactsByKind -Artifacts $artifacts

  $summary = [ordered]@{
    version = 1
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    status = "ok"
    rc = 0
    platform = "windows"
    mode = "desktop_release_bundle_scaffold"
    channel = $Channel
    update_feed_url = if ([string]::IsNullOrWhiteSpace($UpdateFeedUrl)) { "" } else { $UpdateFeedUrl }
    skip_build = $SkipBuild
    install_missing_requested = $InstallMissingRequested
    bundle_root = $BundleRoot
    artifacts = $artifacts
    artifacts_by_kind = $artifactsByKind
    artifact_hint = $BundleRoot
  }

  $summaryDir = Split-Path -Parent $SummaryPath
  if (-not [string]::IsNullOrWhiteSpace($summaryDir) -and -not (Test-Path -LiteralPath $summaryDir -PathType Container)) {
    New-Item -ItemType Directory -Path $summaryDir -Force | Out-Null
  }

  $summaryJsonText = $summary | ConvertTo-Json -Depth 12
  Set-Content -LiteralPath $SummaryPath -Value $summaryJsonText -Encoding utf8
  Write-Host "[desktop-release-bundle] summary_json=$SummaryPath"
  if ($PrintPayload) {
    Write-Host "[desktop-release-bundle] summary_json_payload:"
    Write-Host $summaryJsonText
  }
}

if (-not [string]::IsNullOrWhiteSpace($UpdateFeedUrl)) {
  $UpdateFeedUrl = $UpdateFeedUrl.Trim()
}
if (-not [string]::IsNullOrWhiteSpace($SummaryJson)) {
  $SummaryJson = $SummaryJson.Trim()
}
if (-not [string]::IsNullOrWhiteSpace($SigningCertPath)) {
  $SigningCertPath = $SigningCertPath.Trim()
}

if ($Help -or $TauriArgs -contains "-h" -or $TauriArgs -contains "--help" -or $TauriArgs -contains "/?") {
  Show-Usage
  exit 0
}

if ($null -eq $TauriArgs) {
  $TauriArgs = @()
}

if ($TauriArgs.Count -gt 0 -and $TauriArgs[0] -eq "--") {
  if ($TauriArgs.Count -gt 1) {
    $TauriArgs = $TauriArgs[1..($TauriArgs.Count - 1)]
  } else {
    $TauriArgs = @()
  }
}

$UpdateFeedUrl = Resolve-UpdateFeedUrl -ParameterValue $UpdateFeedUrl
Validate-UpdateFeedUrl -CandidateUrl $UpdateFeedUrl
Validate-SigningPlaceholders -Identity $SigningIdentity -CertPath $SigningCertPath -CertPassword $SigningCertPassword

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$desktopDir = Join-Path $repoRoot.Path "apps\desktop"
$bundleRoot = Join-Path $desktopDir "src-tauri\target\release\bundle"
if ([string]::IsNullOrWhiteSpace($SummaryJson)) {
  $SummaryJson = Join-Path $repoRoot.Path ".easy-node-logs\desktop_release_bundle_windows_summary.json"
}
$summaryJsonPath = [System.IO.Path]::GetFullPath($SummaryJson)
$printSummaryJsonPayload = ($PrintSummaryJson -eq 1)
$installMissingRequested = [bool]$InstallMissing

if (-not (Test-Path (Join-Path $desktopDir "package.json"))) {
  throw (New-RemediationMessage -Headline "apps/desktop/package.json not found at expected path: $desktopDir" -Hints @(
    "Confirm the repository was cloned with the desktop app content present, then rerun the script.",
    "If the workspace layout is different, update the script invocation from the repository root."
  ))
}

$scopedEnvNames = @(
  "GPM_DESKTOP_UPDATE_CHANNEL",
  "GPM_DESKTOP_UPDATE_FEED_URL",
  "GPM_DESKTOP_UPDATE_FEED_CONFIGURED",
  "GPM_DESKTOP_SIGNING_IDENTITY",
  "GPM_DESKTOP_SIGNING_CERT_PATH",
  "GPM_DESKTOP_SIGNING_CERT_PASSWORD",
  "TDPN_DESKTOP_UPDATE_CHANNEL",
  "TDPN_DESKTOP_UPDATE_FEED_URL",
  "TDPN_DESKTOP_UPDATE_FEED_CONFIGURED",
  "TDPN_DESKTOP_SIGNING_IDENTITY",
  "TDPN_DESKTOP_SIGNING_CERT_PATH",
  "TDPN_DESKTOP_SIGNING_CERT_PASSWORD"
)
$scopedEnvSnapshot = Save-ScopedEnvironment -VariableNames $scopedEnvNames

try {
  $env:GPM_DESKTOP_UPDATE_CHANNEL = $Channel
  $env:TDPN_DESKTOP_UPDATE_CHANNEL = $env:GPM_DESKTOP_UPDATE_CHANNEL
  if ([string]::IsNullOrWhiteSpace($UpdateFeedUrl)) {
    Remove-Item Env:GPM_DESKTOP_UPDATE_FEED_URL -ErrorAction SilentlyContinue
    Remove-Item Env:TDPN_DESKTOP_UPDATE_FEED_URL -ErrorAction SilentlyContinue
    $env:GPM_DESKTOP_UPDATE_FEED_CONFIGURED = "0"
  } else {
    $env:GPM_DESKTOP_UPDATE_FEED_URL = $UpdateFeedUrl
    $env:TDPN_DESKTOP_UPDATE_FEED_URL = $env:GPM_DESKTOP_UPDATE_FEED_URL
    $env:GPM_DESKTOP_UPDATE_FEED_CONFIGURED = "1"
  }
  $env:TDPN_DESKTOP_UPDATE_FEED_CONFIGURED = $env:GPM_DESKTOP_UPDATE_FEED_CONFIGURED

  # Scaffold placeholders only. These are not wired to any production signing flow.
  if ([string]::IsNullOrWhiteSpace($SigningIdentity)) {
    Remove-Item Env:GPM_DESKTOP_SIGNING_IDENTITY -ErrorAction SilentlyContinue
    Remove-Item Env:TDPN_DESKTOP_SIGNING_IDENTITY -ErrorAction SilentlyContinue
  } else {
    $env:GPM_DESKTOP_SIGNING_IDENTITY = $SigningIdentity
    $env:TDPN_DESKTOP_SIGNING_IDENTITY = $env:GPM_DESKTOP_SIGNING_IDENTITY
  }
  if ([string]::IsNullOrWhiteSpace($SigningCertPath)) {
    Remove-Item Env:GPM_DESKTOP_SIGNING_CERT_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:TDPN_DESKTOP_SIGNING_CERT_PATH -ErrorAction SilentlyContinue
  } else {
    $env:GPM_DESKTOP_SIGNING_CERT_PATH = $SigningCertPath
    $env:TDPN_DESKTOP_SIGNING_CERT_PATH = $env:GPM_DESKTOP_SIGNING_CERT_PATH
  }
  if ([string]::IsNullOrWhiteSpace($SigningCertPassword)) {
    Remove-Item Env:GPM_DESKTOP_SIGNING_CERT_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:TDPN_DESKTOP_SIGNING_CERT_PASSWORD -ErrorAction SilentlyContinue
  } else {
    $env:GPM_DESKTOP_SIGNING_CERT_PASSWORD = $SigningCertPassword
    $env:TDPN_DESKTOP_SIGNING_CERT_PASSWORD = $env:GPM_DESKTOP_SIGNING_CERT_PASSWORD
  }

  Write-Host "[desktop-release-bundle] mode=scaffold-non-production"
  Write-Host "[desktop-release-bundle] channel=$($env:GPM_DESKTOP_UPDATE_CHANNEL)"
  if (-not [string]::IsNullOrWhiteSpace($env:GPM_DESKTOP_UPDATE_FEED_URL)) {
    Write-Host "[desktop-release-bundle] update_feed=$($env:GPM_DESKTOP_UPDATE_FEED_URL)"
  } else {
    Write-Host "[desktop-release-bundle] update_feed=(not set)"
  }
  if ($env:GPM_DESKTOP_SIGNING_IDENTITY -or $env:GPM_DESKTOP_SIGNING_CERT_PATH -or $env:GPM_DESKTOP_SIGNING_CERT_PASSWORD) {
    Write-Host "[desktop-release-bundle] signing_placeholders=provided (scaffold-only)"
  } else {
    Write-Host "[desktop-release-bundle] signing_placeholders=not provided"
  }

  if ($SkipBuild) {
    Write-Host "[desktop-release-bundle] build skipped by -SkipBuild"
    Show-Usage
    Write-ReleaseBundleSummary -SummaryPath $summaryJsonPath -Channel $env:GPM_DESKTOP_UPDATE_CHANNEL -UpdateFeedUrl $env:GPM_DESKTOP_UPDATE_FEED_URL -SkipBuild $true -InstallMissingRequested $installMissingRequested -BundleRoot $bundleRoot -PrintPayload $printSummaryJsonPayload
    return
  }

  Assert-DesktopBuildTools -AutoInstallMissing:$InstallMissing

  Refresh-DesktopProcessPath
  $npmPath = Get-Command npm.cmd -ErrorAction SilentlyContinue
  if ($null -eq $npmPath) {
    throw (New-RemediationMessage -Headline "npm.cmd was not found in PATH after preflight." -Hints @(
      "Install or repair Node.js LTS, then open a new terminal so PATH picks up the updated npm.cmd location.",
      "If you want the script to attempt remediation, rerun with -InstallMissing."
    ))
  }

  Ensure-TauriIconScaffold -DesktopDir $desktopDir

  Push-Location $desktopDir
  try {
    $npmArgs = @("run", "tauri", "--", "build")
    if ($TauriArgs.Count -gt 0) {
      $npmArgs += $TauriArgs
    }

    Write-Host "[desktop-release-bundle] running: npm.cmd $($npmArgs -join ' ')"
    & $npmPath.Source @npmArgs
    $rc = $LASTEXITCODE
    if ($rc -ne 0) {
      throw (New-RemediationMessage -Headline "tauri build failed with exit code $rc." -Hints @(
        "Check the first error in the build output above; it usually names the missing tool or broken configuration.",
        "If this failed after automatic installs, open a new terminal and verify node, npm.cmd, rustc, cargo, and git are all on PATH before rerunning."
      ))
    }
  } finally {
    Pop-Location
  }

  $bundleHint = $bundleRoot
  Write-Host "[desktop-release-bundle] status=ok"
  Write-Host "[desktop-release-bundle] artifact_hint=$bundleHint"
  Write-Host "[desktop-release-bundle] note=this is scaffold-only and not a production signing/release pipeline"
  Write-ReleaseBundleSummary -SummaryPath $summaryJsonPath -Channel $env:GPM_DESKTOP_UPDATE_CHANNEL -UpdateFeedUrl $env:GPM_DESKTOP_UPDATE_FEED_URL -SkipBuild $false -InstallMissingRequested $installMissingRequested -BundleRoot $bundleRoot -PrintPayload $printSummaryJsonPayload
} finally {
  Restore-ScopedEnvironment -Snapshot $scopedEnvSnapshot
}
