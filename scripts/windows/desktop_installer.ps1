param(
  [ValidateSet("install", "build")]
  [string]$Mode = "install",
  [string]$InstallerPath = "",
  [ValidateSet("auto", "nsis", "msi")]
  [string]$InstallerType = "auto",
  [switch]$BuildIfMissing,
  [switch]$InstallMissing,
  [switch]$LaunchAfterInstall = $true,
  [string]$InstalledExecutablePath = "",
  [ValidateSet("stable", "beta", "canary")]
  [string]$Channel = "stable",
  [switch]$Silent,
  [switch]$DryRun,
  [string]$SummaryJson = "",
  [ValidateSet(0, 1)]
  [int]$PrintSummaryJson = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-installer] $Message"
}

function Assert-PolicySafeNodeRunnerScript {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string]$ScriptLabel
  )

  if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    throw "missing $ScriptLabel script: $ScriptPath"
  }

  $contents = ""
  try {
    $contents = [string](Get-Content -Raw -LiteralPath $ScriptPath -ErrorAction Stop)
  } catch {
    throw "failed to inspect $ScriptLabel script for npm/npx policy guardrails: $ScriptPath"
  }

  if (-not $contents.Contains("npm.cmd")) {
    throw @"
$ScriptLabel script is missing policy-safe npm runner marker 'npm.cmd': $ScriptPath
To avoid npm.ps1/npx.ps1 execution-policy failures, update that script to use npm.cmd/npx.cmd (or desktop_node.cmd / desktop_shell.cmd).
"@
  }

  $npxPolicySafe = $contents.Contains("npx.cmd") -or
    $contents.Contains("desktop_node.cmd npx") -or
    $contents.Contains("desktop_shell.cmd npx")
  if ($contents -match '(?i)\bnpx\b' -and -not $npxPolicySafe) {
    throw @"
$ScriptLabel script references npx but is missing a policy-safe npx runner marker: $ScriptPath
Use npx.cmd directly or route npx through desktop_node.cmd / desktop_shell.cmd to avoid npm.ps1/npx.ps1 execution-policy failures.
"@
  }
}

function Test-IsWslSession {
  $wslDistro = [Environment]::GetEnvironmentVariable("WSL_DISTRO_NAME", "Process")
  if (-not [string]::IsNullOrWhiteSpace($wslDistro)) {
    return $true
  }

  $wslInterop = [Environment]::GetEnvironmentVariable("WSL_INTEROP", "Process")
  if (-not [string]::IsNullOrWhiteSpace($wslInterop)) {
    return $true
  }

  foreach ($probePath in @("/proc/sys/kernel/osrelease", "/proc/version")) {
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
      continue
    }

    $contents = ""
    try {
      $contents = [string](Get-Content -Raw -LiteralPath $probePath -ErrorAction Stop)
    } catch {
      $contents = ""
    }

    if (-not [string]::IsNullOrWhiteSpace($contents) -and $contents.ToLowerInvariant().Contains("microsoft")) {
      return $true
    }
  }

  return $false
}

function Get-WslDistroLabel {
  $wslDistro = [Environment]::GetEnvironmentVariable("WSL_DISTRO_NAME", "Process")
  if ([string]::IsNullOrWhiteSpace($wslDistro)) {
    return "(unknown)"
  }
  return $wslDistro.Trim()
}

function Assert-WindowsNativeNonWsl {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptName
  )

  if (-not (Test-IsWslSession)) {
    return
  }

  $wslDistro = Get-WslDistroLabel
  throw @"
$ScriptName is Windows-native and must run outside WSL.
Detected WSL environment: distro=$wslDistro
Run this script from Windows PowerShell or Windows Terminal (non-WSL).
Windows-native command:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_installer.ps1 -Mode build -InstallMissing
If you intended the WSL path instead, use:
  scripts\windows\wsl2_easy.cmd bootstrap
"@
}

function New-RemediationMessage {
  param(
    [string]$Headline,
    [string[]]$Hints
  )

  $lines = @($Headline)
  foreach ($hint in @($Hints)) {
    if ([string]::IsNullOrWhiteSpace($hint)) {
      continue
    }
    $lines += "- $hint"
  }
  return ($lines -join [Environment]::NewLine)
}

function Convert-ToStringArray {
  param(
    [object]$Values
  )

  $result = @()
  if ($null -eq $Values) {
    return @($result)
  }

  foreach ($value in @($Values)) {
    if ($null -eq $value) {
      continue
    }

    $text = [string]$value
    if ([string]::IsNullOrWhiteSpace($text)) {
      continue
    }
    $result += $text.Trim()
  }

  return @($result)
}

function Resolve-InstallerTypeFromPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
  switch ($extension) {
    ".exe" { return "nsis" }
    ".msi" { return "msi" }
    default { return "" }
  }
}

function Get-PreferredInstallerFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SearchRoot,
    [Parameter(Mandatory = $true)]
    [string]$Filter
  )

  if (-not (Test-Path -LiteralPath $SearchRoot -PathType Container)) {
    return $null
  }

  $candidates = @(
    Get-ChildItem -LiteralPath $SearchRoot -File -Recurse -Filter $Filter |
      Sort-Object -Property LastWriteTimeUtc, FullName -Descending
  )
  if ($candidates.Count -eq 0) {
    return $null
  }

  return $candidates[0]
}

function Find-InstallerArtifact {
  param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,
    [Parameter(Mandatory = $true)]
    [string]$RequestedType
  )

  $nsisRoot = Join-Path $BundleRoot "nsis"
  $msiRoot = Join-Path $BundleRoot "msi"

  if ($RequestedType -eq "nsis") {
    $nsisFile = Get-PreferredInstallerFile -SearchRoot $nsisRoot -Filter "*.exe"
    if ($null -eq $nsisFile) {
      return $null
    }
    return [pscustomobject]@{
      installer_path = $nsisFile.FullName
      installer_type = "nsis"
    }
  }

  if ($RequestedType -eq "msi") {
    $msiFile = Get-PreferredInstallerFile -SearchRoot $msiRoot -Filter "*.msi"
    if ($null -eq $msiFile) {
      return $null
    }
    return [pscustomobject]@{
      installer_path = $msiFile.FullName
      installer_type = "msi"
    }
  }

  $nsisPreferred = Find-InstallerArtifact -BundleRoot $BundleRoot -RequestedType "nsis"
  if ($null -ne $nsisPreferred) {
    return $nsisPreferred
  }

  return Find-InstallerArtifact -BundleRoot $BundleRoot -RequestedType "msi"
}

function Get-CommandDisplay {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]$Arguments
  )

  $parts = @("'" + ($Path -replace "'", "''") + "'")
  foreach ($arg in $Arguments) {
    $parts += ("'" + ($arg -replace "'", "''") + "'")
  }
  return ($parts -join " ")
}

function Invoke-DesktopBuildPreflight {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [bool]$InstallMissingRequested,
    [bool]$DryRunRequested
  )

  $doctorScript = Join-Path $RepoRootPath "scripts\windows\desktop_doctor.ps1"
  if (-not (Test-Path -LiteralPath $doctorScript -PathType Leaf)) {
    throw (New-RemediationMessage -Headline "desktop preflight script was not found: $doctorScript" -Hints @(
      "Restore the repository script path and rerun.",
      "Manual fallback: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode check"
    ))
  }
  Assert-PolicySafeNodeRunnerScript -ScriptPath $doctorScript -ScriptLabel "desktop preflight doctor"

  $doctorMode = if ($InstallMissingRequested) { "fix" } else { "check" }
  $doctorSummaryPath = Join-Path $RepoRootPath ".easy-node-logs\desktop_installer_preflight_summary.json"
  $doctorArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $doctorScript,
    "-Mode", $doctorMode,
    "-EnablePolicyBypass",
    "-SummaryJson", $doctorSummaryPath,
    "-PrintSummaryJson", "0"
  )
  if ($InstallMissingRequested) {
    $doctorArgs += "-InstallMissing"
  }
  if ($DryRunRequested) {
    $doctorArgs += "-DryRun"
  }

  Write-Step ("preflight command: powershell {0}" -f (Get-CommandDisplay -Path "powershell" -Arguments $doctorArgs))

  if ($DryRunRequested) {
    Write-Step "dry-run enabled; preflight execution skipped"
    return [pscustomobject]@{
      attempted = $false
      mode = $doctorMode
      status = "dry_run_skipped"
      summary_path = $doctorSummaryPath
      missing_package_ids = @()
      desktop_asset_issue_ids = @()
      recommended_commands = @()
    }
  }

  & powershell @doctorArgs
  $doctorRc = $LASTEXITCODE
  if ($doctorRc -ne 0) {
    throw (New-RemediationMessage -Headline ("desktop preflight command failed with exit code {0}." -f $doctorRc) -Hints @(
      "Rerun explicitly to inspect details: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode $doctorMode -SummaryJson .\.easy-node-logs\desktop_installer_preflight_summary.json -PrintSummaryJson 1",
      "If policy/tooling drift exists, run: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
    ))
  }

  if (-not (Test-Path -LiteralPath $doctorSummaryPath -PathType Leaf)) {
    throw (New-RemediationMessage -Headline "desktop preflight did not write its summary JSON." -Hints @(
      "Rerun desktop_doctor with explicit output path and inspect the failure:",
      "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode $doctorMode -SummaryJson .\.easy-node-logs\desktop_installer_preflight_summary.json -PrintSummaryJson 1"
    ))
  }

  $doctorSummary = $null
  try {
    $doctorSummary = Get-Content -Raw -LiteralPath $doctorSummaryPath | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw (New-RemediationMessage -Headline ("desktop preflight summary could not be parsed: {0}" -f $doctorSummaryPath) -Hints @(
      "Delete the corrupted summary file and rerun desktop_doctor preflight.",
      "If this persists, rerun with -PrintSummaryJson 1 and inspect the JSON payload."
    ))
  }

  $missingPackageIds = @()
  $desktopAssetIssueIds = @()
  $recommendedCommands = @()
  $doctorStatus = ""

  if ($null -ne $doctorSummary) {
    $missingPackageIds = Convert-ToStringArray -Values $doctorSummary.missing_package_ids
    $desktopAssetIssueIds = Convert-ToStringArray -Values $doctorSummary.desktop_asset_issue_ids
    $recommendedCommands = Convert-ToStringArray -Values $doctorSummary.recommended_commands
    if ($doctorSummary.PSObject.Properties.Name -contains "status" -and $null -ne $doctorSummary.status) {
      $doctorStatus = [string]$doctorSummary.status
    }
  }

  $hasBlocking = $missingPackageIds.Count -gt 0 -or $desktopAssetIssueIds.Count -gt 0
  if (-not $hasBlocking -and -not [string]::IsNullOrWhiteSpace($doctorStatus)) {
    $normalizedStatus = $doctorStatus.Trim().ToLowerInvariant()
    if ($normalizedStatus -eq "missing" -or $normalizedStatus -eq "error") {
      $hasBlocking = $true
    }
  }

  if ($hasBlocking) {
    $hints = @(
      "Desktop installer build is fail-closed on preflight blockers.",
      "Run automatic remediation: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
    )

    foreach ($command in $recommendedCommands) {
      if ([string]::IsNullOrWhiteSpace($command)) {
        continue
      }
      $hints += ("recommended: {0}" -f $command)
    }

    $statusHint = if ([string]::IsNullOrWhiteSpace($doctorStatus)) { "unknown" } else { $doctorStatus }
    throw (New-RemediationMessage -Headline ("desktop preflight reported blocking issues (status={0})." -f $statusHint) -Hints $hints)
  }

  return [pscustomobject]@{
    attempted = $true
    mode = $doctorMode
    status = if ([string]::IsNullOrWhiteSpace($doctorStatus)) { "ok" } else { $doctorStatus }
    summary_path = $doctorSummaryPath
    missing_package_ids = @($missingPackageIds)
    desktop_asset_issue_ids = @($desktopAssetIssueIds)
    recommended_commands = @($recommendedCommands)
  }
}

function Invoke-ReleaseBundleBuild {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseBundleScriptPath,
    [Parameter(Mandatory = $true)]
    [string]$ChannelValue,
    [bool]$InstallMissingRequested,
    [bool]$DryRunRequested,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseSummaryPath
  )

  if (-not (Test-Path -LiteralPath $ReleaseBundleScriptPath -PathType Leaf)) {
    throw "desktop release bundle script not found: $ReleaseBundleScriptPath"
  }
  Assert-PolicySafeNodeRunnerScript -ScriptPath $ReleaseBundleScriptPath -ScriptLabel "desktop release bundle"

  $buildArgs = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", $ReleaseBundleScriptPath,
    "-Channel", $ChannelValue,
    "-SummaryJson", $ReleaseSummaryPath,
    "-PrintSummaryJson", "0"
  )
  if ($InstallMissingRequested) {
    $buildArgs += "-InstallMissing"
  }

  Write-Step ("build command: powershell {0}" -f (Get-CommandDisplay -Path "powershell" -Arguments $buildArgs))

  if ($DryRunRequested) {
    Write-Step "dry-run enabled; release bundle build execution skipped"
    return [pscustomobject]@{
      attempted = $false
      summary_path = $ReleaseSummaryPath
      rc = 0
      status = "dry_run_skipped"
    }
  }

  & powershell @buildArgs
  $buildRc = $LASTEXITCODE
  if ($buildRc -ne 0) {
    throw (New-RemediationMessage -Headline ("desktop release bundle failed with exit code {0}." -f $buildRc) -Hints @(
      "Rerun directly for detailed output: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_release_bundle.ps1 -Channel $ChannelValue -InstallMissing",
      "If prerequisites are still missing, run: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
    ))
  }

  return [pscustomobject]@{
    attempted = $true
    summary_path = $ReleaseSummaryPath
    rc = $buildRc
    status = "ok"
  }
}

function Normalize-PathCandidate {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return ""
  }

  $candidate = $Value.Trim()
  if ($candidate.Length -ge 2 -and $candidate.StartsWith('"') -and $candidate.EndsWith('"')) {
    $candidate = $candidate.Substring(1, $candidate.Length - 2).Trim()
  }

  return $candidate
}

function Get-InstalledPackagedExecutableCandidates {
  $localAppData = [Environment]::GetEnvironmentVariable("LOCALAPPDATA", "Process")
  if ([string]::IsNullOrWhiteSpace($localAppData)) {
    $localAppData = [Environment]::GetFolderPath("LocalApplicationData")
  }

  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")

  $rootCandidates = @()
  if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
    $rootCandidates += $localAppData
    $rootCandidates += (Join-Path $localAppData "Programs")
  }
  if (-not [string]::IsNullOrWhiteSpace($programFiles)) {
    $rootCandidates += $programFiles
  }
  if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
    $rootCandidates += $programFilesX86
  }

  $roots = @()
  $rootSeen = @{}
  foreach ($rootCandidate in $rootCandidates) {
    if ([string]::IsNullOrWhiteSpace($rootCandidate)) {
      continue
    }

    $normalizedRoot = $rootCandidate.Trim().TrimEnd("\")
    if ([string]::IsNullOrWhiteSpace($normalizedRoot)) {
      continue
    }

    $rootKey = $normalizedRoot.ToLowerInvariant()
    if ($rootSeen.ContainsKey($rootKey)) {
      continue
    }
    $rootSeen[$rootKey] = $true
    $roots += $normalizedRoot
  }

  $relativePaths = @(
    "GPM Desktop\GPM Desktop.exe",
    "GPM Desktop\gpm-desktop.exe",
    "Global Private Mesh Desktop\Global Private Mesh Desktop.exe",
    "Global Private Mesh Desktop\global-private-mesh-desktop.exe",
    "TDPN Desktop\TDPN Desktop.exe",
    "TDPN Desktop\tdpn-desktop.exe"
  )

  $candidates = @()
  $candidateSeen = @{}
  foreach ($root in $roots) {
    foreach ($relativePath in $relativePaths) {
      $candidate = Join-Path $root $relativePath
      $candidateKey = $candidate.TrimEnd("\").ToLowerInvariant()
      if ($candidateSeen.ContainsKey($candidateKey)) {
        continue
      }
      $candidateSeen[$candidateKey] = $true
      $candidates += $candidate
    }
  }

  return $candidates
}

function Get-RepoPackagedExecutableCandidates {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath
  )

  if ([string]::IsNullOrWhiteSpace($RepoRootPath)) {
    return @()
  }

  $releaseRoot = Join-Path $RepoRootPath "apps\desktop\src-tauri\target\release"
  $relativePaths = @(
    "gpm-desktop.exe",
    "GPM Desktop.exe",
    "global-private-mesh-desktop.exe",
    "Global Private Mesh Desktop.exe",
    "tdpn-desktop.exe",
    "TDPN Desktop.exe"
  )

  $candidates = @()
  $seen = @{}
  foreach ($relativePath in $relativePaths) {
    $candidate = Join-Path $releaseRoot $relativePath
    $candidateKey = $candidate.TrimEnd("\").ToLowerInvariant()
    if ($seen.ContainsKey($candidateKey)) {
      continue
    }
    $seen[$candidateKey] = $true
    $candidates += $candidate
  }

  return $candidates
}

function Resolve-LaunchExecutableTarget {
  param(
    [AllowEmptyString()]
    [string]$OverridePath = "",
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath
  )

  $normalizedOverride = Normalize-PathCandidate -Value $OverridePath
  if (-not [string]::IsNullOrWhiteSpace($normalizedOverride)) {
    $fullPath = [System.IO.Path]::GetFullPath($normalizedOverride)
    return [pscustomobject]@{
      path   = $fullPath
      source = "override"
      exists = [bool](Test-Path -LiteralPath $fullPath -PathType Leaf)
    }
  }

  foreach ($candidate in (Get-InstalledPackagedExecutableCandidates)) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [pscustomobject]@{
        path   = (Resolve-Path -LiteralPath $candidate).Path
        source = "install"
        exists = $true
      }
    }
  }

  foreach ($candidate in (Get-RepoPackagedExecutableCandidates -RepoRootPath $RepoRootPath)) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [pscustomobject]@{
        path   = (Resolve-Path -LiteralPath $candidate).Path
        source = "repo"
        exists = $true
      }
    }
  }

  return [pscustomobject]@{
    path   = ""
    source = ""
    exists = $false
  }
}

function Write-SummaryJson {
  param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [hashtable]$Summary
  )

  $absolutePath = [System.IO.Path]::GetFullPath($OutputPath)
  $parentDir = Split-Path -Parent $absolutePath
  if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir -PathType Container)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
  }

  $payload = $Summary | ConvertTo-Json -Depth 10
  Set-Content -LiteralPath $absolutePath -Value $payload -Encoding utf8
  Write-Step "summary_json=$absolutePath"
  if ($PrintSummaryJson -eq 1) {
    Write-Step "summary_json_payload:"
    Write-Host $payload
  }
}

function Ensure-TauriIconScaffoldForBuild {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot
  )

  $iconPath = Join-Path $RepoRoot "apps\desktop\src-tauri\icons\icon.ico"
  if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
    Write-Step "icon_scaffold=exists path=$iconPath"
    return $false
  }

  $iconDir = Split-Path -Parent $iconPath
  if (-not (Test-Path -LiteralPath $iconDir -PathType Container)) {
    New-Item -ItemType Directory -Path $iconDir -Force | Out-Null
    Write-Step "icon_scaffold=created_parent path=$iconDir"
  }

  # Minimal valid 1x1 ICO payload (single 32-bit image + empty AND mask).
  [byte[]]$icoBytes = @(
    0x00,0x00,0x01,0x00,0x01,0x00,
    0x01,0x01,0x00,0x00,0x01,0x00,0x20,0x00,0x30,0x00,0x00,0x00,0x16,0x00,0x00,0x00,
    0x28,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,
    0x00,0x00,0x00,0x00
  )

  [System.IO.File]::WriteAllBytes($iconPath, $icoBytes)
  Write-Step "icon_scaffold=created path=$iconPath"
  return $true
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$bundleRoot = Join-Path $repoRoot "apps\desktop\src-tauri\target\release\bundle"
$releaseBundleScript = Join-Path $scriptDir "desktop_release_bundle.ps1"
Assert-WindowsNativeNonWsl -ScriptName "desktop_installer.ps1"
$wslDetected = [bool](Test-IsWslSession)

if ([string]::IsNullOrWhiteSpace($SummaryJson)) {
  $SummaryJson = Join-Path $repoRoot ".easy-node-logs\desktop_installer_windows_summary.json"
}

$summary = [ordered]@{
  version = 1
  generated_at_utc = ""
  status = "fail"
  rc = 1
  platform = "windows"
  execution_model = "windows-native-non-wsl"
  mode = if ($Mode -eq "build") { "desktop_installer_build_scaffold" } else { "desktop_installer_scaffold" }
  installer_mode = $Mode
  channel = $Channel
  wsl_required = $false
  wsl_detected = [bool]$wslDetected
  installer_path = ""
  installer_type = ""
  installer_source = ""
  silent = [bool]$Silent
  dry_run = [bool]$DryRun
  build_if_missing = [bool]$BuildIfMissing
  build_triggered = $false
  build_mode = [bool]($Mode -eq "build")
  preflight_attempted = $false
  preflight_mode = ""
  preflight_status = "not_run"
  preflight_summary_json = ""
  preflight_missing_package_ids = @()
  preflight_desktop_asset_issue_ids = @()
  preflight_recommended_commands = @()
  release_bundle_summary_json = ""
  launch_after_install = [bool]$LaunchAfterInstall
  launch_attempted = $false
  launch_status = if ([bool]$LaunchAfterInstall) { "not_attempted" } else { "disabled" }
  launched_executable_path = ""
  launch_failure_reason = ""
  icon_scaffold_created = $false
  icon_scaffold_error = ""
  recommended_commands = @()
  failure_stage = ""
}

$exitCode = 1

try {
  Write-Step "mode=scaffold-non-production"
  Write-Step "execution_model=windows-native-non-wsl"
  Write-Step "installer_mode=$Mode"
  Write-Step "wsl_required=false"
  Write-Step ("wsl_detected={0}" -f $(if ($wslDetected) { "true" } else { "false" }))
  Write-Step "repo_root=$repoRoot"
  Write-Step "bundle_root=$bundleRoot"
  Write-Step "installer_type=$InstallerType"
  Write-Step "channel=$Channel"
  Write-Step "build_if_missing=$([bool]$BuildIfMissing)"
  Write-Step "silent=$([bool]$Silent)"
  Write-Step "dry_run=$([bool]$DryRun)"
  Write-Step "launch_after_install=$([bool]$LaunchAfterInstall)"
  Write-Step ("installed_executable_path_override={0}" -f (Normalize-PathCandidate -Value $InstalledExecutablePath))

  $summary.recommended_commands = @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_installer.ps1 -Mode build -InstallMissing",
    "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass",
    "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_release_bundle.ps1 -Channel $Channel -InstallMissing"
  )

  $buildMode = $Mode -eq "build"
  if ($buildMode) {
    $summary.build_if_missing = $true
    Write-Step "build mode forces release-bundle build path"
  }
  $selectedInstallerPath = ""
  $selectedInstallerType = ""
  $selectedInstallerSource = ""

  if ($buildMode -and -not [string]::IsNullOrWhiteSpace($InstallerPath)) {
    throw "build mode does not accept -InstallerPath. Use -Mode build without explicit artifacts so the script can run preflight and build installers."
  }

  if (-not [string]::IsNullOrWhiteSpace($InstallerPath)) {
    $summary.failure_stage = "installer_validate"
    $resolvedExplicitPath = [System.IO.Path]::GetFullPath($InstallerPath)
    if (-not (Test-Path -LiteralPath $resolvedExplicitPath -PathType Leaf)) {
      throw "explicit installer path does not exist: $resolvedExplicitPath"
    }

    $pathType = Resolve-InstallerTypeFromPath -Path $resolvedExplicitPath
    if ([string]::IsNullOrWhiteSpace($pathType)) {
      throw "unable to infer installer type from explicit path (expected .exe or .msi): $resolvedExplicitPath"
    }

    if ($InstallerType -ne "auto" -and $InstallerType -ne $pathType) {
      throw "explicit installer path type '$pathType' does not match requested -InstallerType '$InstallerType'"
    }

    $selectedInstallerPath = $resolvedExplicitPath
    $selectedInstallerType = if ($InstallerType -eq "auto") { $pathType } else { $InstallerType }
    $selectedInstallerSource = "explicit"
    Write-Step "installer resolved from explicit path"
  } else {
    $summary.failure_stage = "installer_discovery"
    $found = Find-InstallerArtifact -BundleRoot $bundleRoot -RequestedType $InstallerType
    $releaseBundleSummaryPath = Join-Path $repoRoot ".easy-node-logs\desktop_installer_release_bundle_summary.json"

    if ($buildMode) {
      $summary.failure_stage = "preflight"
      $preflightResult = Invoke-DesktopBuildPreflight -RepoRootPath $repoRoot -InstallMissingRequested ([bool]$InstallMissing) -DryRunRequested ([bool]$DryRun)
      $summary.preflight_attempted = [bool]$preflightResult.attempted
      $summary.preflight_mode = [string]$preflightResult.mode
      $summary.preflight_status = [string]$preflightResult.status
      $summary.preflight_summary_json = [string]$preflightResult.summary_path
      $summary.preflight_missing_package_ids = @($preflightResult.missing_package_ids)
      $summary.preflight_desktop_asset_issue_ids = @($preflightResult.desktop_asset_issue_ids)
      $summary.preflight_recommended_commands = @($preflightResult.recommended_commands)
      if (@($summary.preflight_recommended_commands).Count -gt 0) {
        $summary.recommended_commands = @($summary.preflight_recommended_commands + $summary.recommended_commands)
      }

      try {
        $summary.icon_scaffold_created = [bool](Ensure-TauriIconScaffoldForBuild -RepoRoot $repoRoot)
      } catch {
        $summary.icon_scaffold_created = $false
        $summary.icon_scaffold_error = [string]$_.Exception.Message
        Write-Step "warning=icon_scaffold_failed error=$($summary.icon_scaffold_error)"
      }

      $summary.build_triggered = $true
      $summary.failure_stage = "build"
      $summary.release_bundle_summary_json = $releaseBundleSummaryPath
      [void](Invoke-ReleaseBundleBuild -ReleaseBundleScriptPath $releaseBundleScript -ChannelValue $Channel -InstallMissingRequested ([bool]$InstallMissing) -DryRunRequested ([bool]$DryRun) -ReleaseSummaryPath $releaseBundleSummaryPath)

      $summary.failure_stage = "installer_discovery"
      $found = Find-InstallerArtifact -BundleRoot $bundleRoot -RequestedType $InstallerType
    } elseif ($null -eq $found -and $BuildIfMissing) {
      $summary.failure_stage = "preflight"
      $preflightResult = Invoke-DesktopBuildPreflight -RepoRootPath $repoRoot -InstallMissingRequested ([bool]$InstallMissing) -DryRunRequested ([bool]$DryRun)
      $summary.preflight_attempted = [bool]$preflightResult.attempted
      $summary.preflight_mode = [string]$preflightResult.mode
      $summary.preflight_status = [string]$preflightResult.status
      $summary.preflight_summary_json = [string]$preflightResult.summary_path
      $summary.preflight_missing_package_ids = @($preflightResult.missing_package_ids)
      $summary.preflight_desktop_asset_issue_ids = @($preflightResult.desktop_asset_issue_ids)
      $summary.preflight_recommended_commands = @($preflightResult.recommended_commands)
      if (@($summary.preflight_recommended_commands).Count -gt 0) {
        $summary.recommended_commands = @($summary.preflight_recommended_commands + $summary.recommended_commands)
      }

      try {
        $summary.icon_scaffold_created = [bool](Ensure-TauriIconScaffoldForBuild -RepoRoot $repoRoot)
      } catch {
        $summary.icon_scaffold_created = $false
        $summary.icon_scaffold_error = [string]$_.Exception.Message
        Write-Step "warning=icon_scaffold_failed error=$($summary.icon_scaffold_error)"
      }

      $summary.build_triggered = $true
      $summary.failure_stage = "build"
      $summary.release_bundle_summary_json = $releaseBundleSummaryPath
      [void](Invoke-ReleaseBundleBuild -ReleaseBundleScriptPath $releaseBundleScript -ChannelValue $Channel -InstallMissingRequested ([bool]$InstallMissing) -DryRunRequested ([bool]$DryRun) -ReleaseSummaryPath $releaseBundleSummaryPath)

      $summary.failure_stage = "installer_discovery"
      $found = Find-InstallerArtifact -BundleRoot $bundleRoot -RequestedType $InstallerType
    }

    if ($null -eq $found) {
      if ($buildMode -and $DryRun) {
        $selectedInstallerPath = ""
        $selectedInstallerType = if ($InstallerType -eq "auto") { "" } else { $InstallerType }
        $selectedInstallerSource = "dry_run_unresolved"
        Write-Step "dry-run build mode: installer discovery skipped because build execution was not run"
      } else {
        throw (New-RemediationMessage -Headline "installer artifact not found under bundle root: $bundleRoot" -Hints @(
          "Run Windows-native build with remediation: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_installer.ps1 -Mode build -InstallMissing",
          "Or call release bundle directly: powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_release_bundle.ps1 -Channel $Channel -InstallMissing",
          "Then rerun this installer flow."
        ))
      }
    } else {
      $selectedInstallerPath = [string]$found.installer_path
      $selectedInstallerType = [string]$found.installer_type
      $selectedInstallerSource = if ($summary.build_triggered) { "discovered_after_build" } else { "discovered" }
      Write-Step "installer discovered from release bundle artifacts"
    }
  }

  $summary.installer_path = $selectedInstallerPath
  $summary.installer_type = $selectedInstallerType
  $summary.installer_source = $selectedInstallerSource

  if ($buildMode) {
    $summary.launch_after_install = $false
    $summary.launch_attempted = $false
    $summary.launch_status = "disabled_build_mode"
    $summary.launch_failure_reason = ""
    if ($DryRun) {
      $summary.status = "dry-run"
      Write-Step "dry-run enabled; build-only mode completed without executing release build"
    } else {
      $summary.status = "ok"
      if ([string]::IsNullOrWhiteSpace($selectedInstallerPath)) {
        Write-Step "build-only mode complete; installer artifact location unresolved"
      } else {
        Write-Step "build-only mode complete; installer artifact ready"
      }
    }
    $summary.failure_stage = ""
    $exitCode = 0
  } else {
    $summary.failure_stage = "install"
    $processPath = $selectedInstallerPath
    $processArgs = @()

    if ($selectedInstallerType -eq "msi") {
      $processPath = "msiexec.exe"
      $processArgs = @("/i", $selectedInstallerPath)
      if ($Silent) {
        $processArgs += "/quiet"
        $processArgs += "/norestart"
      }
    } elseif ($selectedInstallerType -eq "nsis") {
      if ($Silent) {
        $processArgs += "/S"
      }
    } else {
      throw "unsupported installer type: $selectedInstallerType"
    }

    $installCommand = Get-CommandDisplay -Path $processPath -Arguments $processArgs
    Write-Step "install command: $installCommand"

    if ($DryRun) {
      Write-Step "dry-run enabled; installer execution skipped"
      $exitCode = 0
    } else {
      $process = Start-Process -FilePath $processPath -ArgumentList $processArgs -Wait -PassThru
      $exitCode = [int]$process.ExitCode
      Write-Step "installer exited rc=$exitCode"
    }

    if ($exitCode -eq 0) {
      $summary.status = "ok"
      $summary.failure_stage = ""

      if ([bool]$LaunchAfterInstall) {
        $launchTarget = Resolve-LaunchExecutableTarget -OverridePath $InstalledExecutablePath -RepoRootPath $repoRoot
        $launchPath = [string]$launchTarget.path
        $summary.launched_executable_path = $launchPath

        if ([string]::IsNullOrWhiteSpace($launchPath)) {
          $summary.launch_status = "warning_missing_executable"
          $summary.launch_failure_reason = "unable to resolve installed executable path automatically"
          Write-Step "warning=launch_target_missing reason=$($summary.launch_failure_reason)"
        } else {
          $launchCommand = Get-CommandDisplay -Path $launchPath -Arguments @()
          Write-Step "launch command: $launchCommand"

          if ($DryRun) {
            $summary.launch_status = "dry_run_would_launch"
            $summary.launch_attempted = $false
            $summary.launch_failure_reason = ""
            Write-Step "dry-run enabled; launch execution skipped"
          } elseif (-not [bool]$launchTarget.exists) {
            $summary.launch_status = "warning_missing_executable"
            $summary.launch_failure_reason = "launch target does not exist: $launchPath"
            Write-Step "warning=launch_target_missing reason=$($summary.launch_failure_reason)"
          } else {
            try {
              $summary.launch_attempted = $true
              Start-Process -FilePath $launchPath | Out-Null
              $summary.launch_status = "launched"
              $summary.launch_failure_reason = ""
              Write-Step "launch started"
            } catch {
              $summary.launch_status = "warning_launch_failed"
              $summary.launch_failure_reason = [string]$_.Exception.Message
              Write-Step "warning=launch_failed error=$($summary.launch_failure_reason)"
            }
          }
        }
      } else {
        $summary.launch_status = "disabled"
        $summary.launch_attempted = $false
        $summary.launch_failure_reason = ""
      }
    } else {
      $summary.status = "fail"
    }
  }
} catch {
  $summary.status = "fail"
  if ([string]::IsNullOrWhiteSpace($summary.failure_stage)) {
    $summary.failure_stage = "runtime"
  }
  if ($summary.recommended_commands.Count -eq 0) {
    $summary.recommended_commands = @(
      "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_installer.ps1 -Mode build -InstallMissing",
      "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
    )
  }
  Write-Step "error=$($_.Exception.Message)"
  $exitCode = 1
} finally {
  $summary.generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $summary.rc = [int]$exitCode
  Write-SummaryJson -OutputPath $SummaryJson -Summary $summary
}

exit $exitCode
