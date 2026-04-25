param(
  [switch]$Compact,
  [switch]$Apply,
  [switch]$DryRun,
  [switch]$FailOnIssues,
  [switch]$PrintSummaryJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-first-run-remediation] $Message"
}

function Get-CommandPath {
  param([Parameter(Mandatory = $true)][string]$Name)

  $cmd = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $cmd) {
    return ""
  }

  if ($cmd -is [System.Management.Automation.AliasInfo]) {
    $resolvedPath = [string]$cmd.ResolvedCommand.Path
    if (-not [string]::IsNullOrWhiteSpace($resolvedPath)) {
      return $resolvedPath
    }
  }

  $cmdPath = [string]$cmd.Path
  if (-not [string]::IsNullOrWhiteSpace($cmdPath)) {
    return $cmdPath
  }

  $cmdSource = [string]$cmd.Source
  if (-not [string]::IsNullOrWhiteSpace($cmdSource)) {
    return $cmdSource
  }

  return ""
}

function Normalize-NodeCommandPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$CommandName,
    [AllowEmptyString()]
    [string]$PathValue
  )

  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return ""
  }

  $normalizedCommand = $CommandName.Trim().ToLowerInvariant()
  if ($normalizedCommand -notin @("npm", "npm.cmd", "npx", "npx.cmd")) {
    return $PathValue
  }

  $leaf = [System.IO.Path]::GetFileName($PathValue)
  $isNpmCommand = $normalizedCommand.StartsWith("npm")
  $isNpxCommand = $normalizedCommand.StartsWith("npx")

  $isPowerShellShim = $false
  if ($isNpmCommand -and $leaf.Equals("npm.ps1", [System.StringComparison]::OrdinalIgnoreCase)) {
    $isPowerShellShim = $true
  } elseif ($isNpxCommand -and $leaf.Equals("npx.ps1", [System.StringComparison]::OrdinalIgnoreCase)) {
    $isPowerShellShim = $true
  }

  if (-not $isPowerShellShim) {
    return $PathValue
  }

  $parent = Split-Path -Parent $PathValue
  if ([string]::IsNullOrWhiteSpace($parent)) {
    return ""
  }

  $siblingLeaf = if ($isNpmCommand) { "npm.cmd" } else { "npx.cmd" }
  $siblingCmd = Join-Path $parent $siblingLeaf
  if (Test-Path -LiteralPath $siblingCmd -PathType Leaf) {
    return $siblingCmd
  }

  return ""
}

function Refresh-SessionPath {
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $segments = @()

  if (-not [string]::IsNullOrWhiteSpace($machinePath)) {
    $segments += $machinePath.Split(";")
  }
  if (-not [string]::IsNullOrWhiteSpace($userPath)) {
    $segments += $userPath.Split(";")
  }

  $seen = @{}
  $normalized = @()
  foreach ($segment in $segments) {
    if ([string]::IsNullOrWhiteSpace($segment)) {
      continue
    }
    $trimmed = $segment.Trim()
    if ($trimmed.Length -eq 0) {
      continue
    }
    $key = $trimmed.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
      continue
    }
    $seen[$key] = $true
    $normalized += $trimmed
  }

  $env:Path = ($normalized -join ";")
}

function Get-CommonToolDirectories {
  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $userProfile = [Environment]::GetFolderPath("UserProfile")
  $systemDrive = [Environment]::GetEnvironmentVariable("SystemDrive", "Process")

  $candidates = @(
    (Join-Path $programFiles "Go\bin"),
    (Join-Path $programFilesX86 "Go\bin"),
    (Join-Path $systemDrive "Go\bin"),
    (Join-Path $programFiles "nodejs"),
    (Join-Path $programFilesX86 "nodejs"),
    (Join-Path $systemDrive "nodejs"),
    (Join-Path $userProfile ".cargo\bin"),
    (Join-Path $programFiles "Git"),
    (Join-Path $programFiles "Git\cmd"),
    (Join-Path $programFiles "Git\bin"),
    (Join-Path $programFiles "Git\usr\bin"),
    (Join-Path $programFilesX86 "Git"),
    (Join-Path $programFilesX86 "Git\cmd"),
    (Join-Path $programFilesX86 "Git\bin"),
    (Join-Path $programFilesX86 "Git\usr\bin")
  )

  $dirs = @()
  $seen = @{}
  foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
      continue
    }
    $normalized = $candidate.TrimEnd("\")
    $key = $normalized.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
      continue
    }
    $seen[$key] = $true
    $dirs += $normalized
  }

  return $dirs
}

function Add-SessionPathSegments {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Segments
  )

  if ($Segments.Count -eq 0) {
    return
  }

  $existing = @()
  if (-not [string]::IsNullOrWhiteSpace($env:Path)) {
    $existing = $env:Path.Split(";")
  }

  $seen = @{}
  $normalized = @()
  foreach ($segment in @($existing + $Segments)) {
    if ([string]::IsNullOrWhiteSpace($segment)) {
      continue
    }
    $trimmed = $segment.Trim().TrimEnd("\")
    if ($trimmed.Length -eq 0) {
      continue
    }
    $key = $trimmed.ToLowerInvariant()
    if ($seen.ContainsKey($key)) {
      continue
    }
    $seen[$key] = $true
    $normalized += $trimmed
  }

  $env:Path = ($normalized -join ";")
}

function Resolve-ToolPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [switch]$AllowWindowsAppsAlias
  )

  $nameLower = $Name.ToLowerInvariant()
  $path = Get-CommandPath $Name
  if ($nameLower -in @("npm", "npm.cmd", "npx", "npx.cmd")) {
    $path = Normalize-NodeCommandPath -CommandName $nameLower -PathValue $path
  }

  if (-not [string]::IsNullOrWhiteSpace($path)) {
    if ($AllowWindowsAppsAlias -or $path -notmatch '\\WindowsApps\\') {
      return $path
    }
  }

  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $localAppData = [Environment]::GetFolderPath("LocalApplicationData")
  $userProfile = [Environment]::GetFolderPath("UserProfile")
  $systemDrive = [Environment]::GetEnvironmentVariable("SystemDrive", "Process")

  $candidates = @()
  switch ($nameLower) {
    "winget" {
      $candidates = @(
        (Join-Path $localAppData "Microsoft\WindowsApps\winget.exe")
      )
    }
    "go" {
      $candidates = @(
        (Join-Path $programFiles "Go\bin\go.exe"),
        (Join-Path $programFilesX86 "Go\bin\go.exe"),
        (Join-Path $systemDrive "Go\bin\go.exe")
      )
    }
    "node" {
      $candidates = @(
        (Join-Path $programFiles "nodejs\node.exe"),
        (Join-Path $programFilesX86 "nodejs\node.exe"),
        (Join-Path $systemDrive "nodejs\node.exe")
      )
    }
    "npm" {
      $candidates = @(
        (Join-Path $programFiles "nodejs\npm.cmd"),
        (Join-Path $programFilesX86 "nodejs\npm.cmd"),
        (Join-Path $systemDrive "nodejs\npm.cmd")
      )
    }
    "npm.cmd" {
      $candidates = @(
        (Join-Path $programFiles "nodejs\npm.cmd"),
        (Join-Path $programFilesX86 "nodejs\npm.cmd"),
        (Join-Path $systemDrive "nodejs\npm.cmd")
      )
    }
    "npx" {
      $candidates = @(
        (Join-Path $programFiles "nodejs\npx.cmd"),
        (Join-Path $programFilesX86 "nodejs\npx.cmd"),
        (Join-Path $systemDrive "nodejs\npx.cmd")
      )
    }
    "npx.cmd" {
      $candidates = @(
        (Join-Path $programFiles "nodejs\npx.cmd"),
        (Join-Path $programFilesX86 "nodejs\npx.cmd"),
        (Join-Path $systemDrive "nodejs\npx.cmd")
      )
    }
    "rustc" {
      $candidates = @(
        (Join-Path $userProfile ".cargo\bin\rustc.exe")
      )
    }
    "cargo" {
      $candidates = @(
        (Join-Path $userProfile ".cargo\bin\cargo.exe")
      )
    }
    "bash.exe" {
      $candidates = @(
        (Join-Path $programFiles "Git\bin\bash.exe"),
        (Join-Path $programFiles "Git\usr\bin\bash.exe"),
        (Join-Path $programFilesX86 "Git\bin\bash.exe"),
        (Join-Path $programFilesX86 "Git\usr\bin\bash.exe")
      )
    }
  }

  foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return $candidate
    }
  }

  return ""
}

function Resolve-NpmCommandPath {
  $npmCmd = Resolve-ToolPath -Name "npm.cmd"
  if (-not [string]::IsNullOrWhiteSpace($npmCmd)) {
    return $npmCmd
  }

  return (Resolve-ToolPath -Name "npm")
}

function Resolve-ToolchainPaths {
  return [pscustomobject]@{
    go = (Resolve-ToolPath -Name "go")
    node = (Resolve-ToolPath -Name "node")
    npm = (Resolve-NpmCommandPath)
    npx = (Resolve-ToolPath -Name "npx")
    rustc = (Resolve-ToolPath -Name "rustc")
    cargo = (Resolve-ToolPath -Name "cargo")
  }
}

function Get-CommandPs1CmdSiblingStatus {
  param(
    [Parameter(Mandatory = $true)][string]$CommandName,
    [Parameter(Mandatory = $true)][string]$ResolvedPath
  )

  $available = -not [string]::IsNullOrWhiteSpace($ResolvedPath)
  $resolvesToPs1 = $false
  $cmdSiblingPath = ""
  $cmdSiblingAvailable = $false
  if ($available) {
    $leaf = [System.IO.Path]::GetFileName($ResolvedPath)
    $resolvesToPs1 = $leaf.Equals(("{0}.ps1" -f $CommandName), [System.StringComparison]::OrdinalIgnoreCase)
    if ($resolvesToPs1) {
      $candidateCmdSiblingPath = [System.IO.Path]::ChangeExtension($ResolvedPath, ".cmd")
      if (Test-Path -LiteralPath $candidateCmdSiblingPath -PathType Leaf) {
        $cmdSiblingPath = $candidateCmdSiblingPath
        $cmdSiblingAvailable = $true
      }
    }
  }

  return [pscustomobject]@{
    command_name = $CommandName
    available = [bool]$available
    resolved_path = $ResolvedPath
    resolves_to_ps1 = [bool]$resolvesToPs1
    cmd_sibling_available = [bool]$cmdSiblingAvailable
    cmd_sibling_path = $cmdSiblingPath
  }
}

function Invoke-SessionCmdAliasRemediation {
  param(
    [Parameter(Mandatory = $true)][string]$CommandName,
    [Parameter(Mandatory = $true)][bool]$ApplyRequested,
    [Parameter(Mandatory = $false)][bool]$DryRunMode = $false,
    [Parameter(Mandatory = $true)][bool]$ExecutionPolicyRisk,
    [Parameter(Mandatory = $true)][bool]$ResolvesToPs1,
    [Parameter(Mandatory = $false)][string]$CmdSiblingPath = ""
  )

  $result = [ordered]@{
    command = $CommandName
    eligible = [bool]($ExecutionPolicyRisk -and $ResolvesToPs1)
    attempted = $false
    applied = $false
    reason = ""
    alias_definition = ""
    error = ""
  }

  if (-not $result.eligible) {
    $result.reason = "not_needed"
    return [pscustomobject]$result
  }
  if (-not $ApplyRequested) {
    $result.reason = "apply_not_requested"
    return [pscustomobject]$result
  }
  if ($DryRunMode) {
    $result.attempted = $true
    $result.reason = "dry_run"
    return [pscustomobject]$result
  }
  if ([string]::IsNullOrWhiteSpace($CmdSiblingPath)) {
    $result.reason = "cmd_sibling_missing"
    return [pscustomobject]$result
  }

  $result.attempted = $true
  try {
    Set-Alias -Name $CommandName -Value $CmdSiblingPath -Scope Global -Force
    $aliasInfo = Get-Alias -Name $CommandName -ErrorAction SilentlyContinue
    if ($null -ne $aliasInfo) {
      $result.alias_definition = [string]$aliasInfo.Definition
    }
    $result.applied = $true
    $result.reason = "applied"
    return [pscustomobject]$result
  } catch {
    $result.reason = "set_alias_failed"
    $result.error = $_.Exception.Message
    return [pscustomobject]$result
  }
}

function Get-ExecutionPolicySnapshot {
  $scopes = @("Process", "CurrentUser", "LocalMachine")
  $snapshot = [ordered]@{}
  foreach ($scope in $scopes) {
    try {
      $snapshot[$scope] = [string](Get-ExecutionPolicy -Scope $scope)
    } catch {
      $snapshot[$scope] = "Unavailable"
    }
  }

  $effectivePolicy = "Unavailable"
  try {
    $effectivePolicy = [string](Get-ExecutionPolicy)
  } catch {
    $effectivePolicy = "Unavailable"
  }

  return [pscustomobject]@{
    effective = $effectivePolicy
    scopes = $snapshot
  }
}

function Add-UniqueHint {
  param(
    [Parameter(Mandatory = $true)]
    [ref]$Hints,
    [Parameter(Mandatory = $true)]
    [string]$Command
  )

  if ([string]::IsNullOrWhiteSpace($Command)) {
    return
  }
  if (-not $Hints.Value.Contains($Command)) {
    $Hints.Value.Add($Command) | Out-Null
  }
}

function Get-GitBashSnapshot {
  $checkedCandidates = New-Object System.Collections.Generic.List[string]
  $envCandidate = ""
  if (-not [string]::IsNullOrWhiteSpace($env:LOCAL_CONTROL_API_GIT_BASH_PATH)) {
    $envCandidate = [Environment]::ExpandEnvironmentVariables($env:LOCAL_CONTROL_API_GIT_BASH_PATH).Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($envCandidate)) {
    $checkedCandidates.Add($envCandidate) | Out-Null
  }

  $defaultCandidates = @(
    "C:\Program Files\Git\bin\bash.exe",
    "C:\Program Files\Git\usr\bin\bash.exe",
    "C:\Program Files (x86)\Git\bin\bash.exe",
    "C:\Program Files (x86)\Git\usr\bin\bash.exe"
  )
  foreach ($candidate in $defaultCandidates) {
    if (-not $checkedCandidates.Contains($candidate)) {
      $checkedCandidates.Add($candidate) | Out-Null
    }
  }

  foreach ($candidate in $checkedCandidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    $normalizedCandidate = $candidate.Trim('"').Trim()
    if (-not [System.IO.Path]::IsPathRooted($normalizedCandidate)) {
      continue
    }
    if (Test-Path -LiteralPath $normalizedCandidate -PathType Leaf) {
      $source = if ($normalizedCandidate -eq $envCandidate -and -not [string]::IsNullOrWhiteSpace($envCandidate)) { "env:LOCAL_CONTROL_API_GIT_BASH_PATH" } else { "trusted-default" }
      return [pscustomobject]@{
        available = $true
        path = $normalizedCandidate
        source = $source
        checked_candidates = @($checkedCandidates)
      }
    }
  }

  return [pscustomobject]@{
    available = $false
    path = ""
    source = "missing"
    checked_candidates = @($checkedCandidates)
  }
}

function Resolve-RepoRoot {
  $scriptDir = $PSScriptRoot
  if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $PSCommandPath
  }
  return (Resolve-Path (Join-Path $scriptDir "..\..")).Path
}

function Test-IcoBytesAreValid {
  param(
    [byte[]]$Bytes
  )

  if ($null -eq $Bytes -or $Bytes.Length -lt 22) {
    return $false
  }

  $reserved = [BitConverter]::ToUInt16($Bytes, 0)
  $imageType = [BitConverter]::ToUInt16($Bytes, 2)
  $imageCount = [BitConverter]::ToUInt16($Bytes, 4)
  if ($reserved -ne 0 -or $imageType -ne 1 -or $imageCount -le 0) {
    return $false
  }

  $imageSize = [BitConverter]::ToUInt32($Bytes, 14)
  $imageOffset = [BitConverter]::ToUInt32($Bytes, 18)
  if ($imageSize -le 0 -or $imageOffset -lt 22) {
    return $false
  }

  $imageEnd = [int64]$imageOffset + [int64]$imageSize
  return $imageEnd -le [int64]$Bytes.Length
}

function Test-IcoFileValid {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return [pscustomobject]@{
      valid = $false
      reason = "missing"
    }
  }

  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
  } catch {
    return [pscustomobject]@{
      valid = $false
      reason = ("unreadable: {0}" -f $_.Exception.Message)
    }
  }

  if (Test-IcoBytesAreValid -Bytes $bytes) {
    return [pscustomobject]@{
      valid = $true
      reason = "valid"
    }
  }

  return [pscustomobject]@{
    valid = $false
    reason = "invalid_ico"
  }
}

function Test-TauriBundleIconConfigured {
  param(
    [Parameter(Mandatory = $true)]
    [string]$TauriConfigPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedIconRelativePath
  )

  if (-not (Test-Path -LiteralPath $TauriConfigPath -PathType Leaf)) {
    return [pscustomobject]@{
      configured = $false
      reason = "missing_tauri_conf"
    }
  }

  $config = $null
  try {
    $config = Get-Content -Raw -LiteralPath $TauriConfigPath | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return [pscustomobject]@{
      configured = $false
      reason = "invalid_tauri_conf_json"
    }
  }

  $icons = @()
  if ($null -ne $config -and $null -ne $config.bundle -and $null -ne $config.bundle.icon) {
    foreach ($iconValue in @($config.bundle.icon)) {
      if ($null -eq $iconValue) {
        continue
      }
      $iconText = [string]$iconValue
      if ([string]::IsNullOrWhiteSpace($iconText)) {
        continue
      }
      $icons += $iconText.Trim()
    }
  }

  $expectedNormalized = $ExpectedIconRelativePath.Replace("\", "/").Trim().ToLowerInvariant()
  foreach ($icon in $icons) {
    $normalized = [string]$icon
    if ([string]::IsNullOrWhiteSpace($normalized)) {
      continue
    }
    $normalized = $normalized.Trim().Replace("\", "/").ToLowerInvariant()
    if ($normalized -eq $expectedNormalized) {
      return [pscustomobject]@{
        configured = $true
        reason = "configured"
      }
    }
  }

  return [pscustomobject]@{
    configured = $false
    reason = "missing_bundle_icon_entry"
  }
}

function Get-TauriBundleIconRepairCommand {
  return 'powershell -NoProfile -ExecutionPolicy Bypass -Command "$cfg=''apps/desktop/src-tauri/tauri.conf.json''; $json=Get-Content -Raw -LiteralPath $cfg | ConvertFrom-Json; if($null -eq $json.bundle){$json | Add-Member -NotePropertyName bundle -NotePropertyValue ([pscustomobject]@{})}; $icons=@(); if($null -ne $json.bundle.icon){$icons=@($json.bundle.icon)}; if($icons -notcontains ''icons/icon.ico''){$json.bundle.icon=@($icons + ''icons/icon.ico'')}; $json | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $cfg -Encoding UTF8"'
}

function Ensure-TauriBundleIconResource {
  param(
    [Parameter(Mandatory = $true)]
    [string]$TauriConfigPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedIconRelativePath
  )

  if (-not (Test-Path -LiteralPath $TauriConfigPath -PathType Leaf)) {
    throw "tauri config missing: $TauriConfigPath"
  }

  $config = Get-Content -Raw -LiteralPath $TauriConfigPath | ConvertFrom-Json -ErrorAction Stop
  $changed = $false

  if ($null -eq $config.bundle) {
    $config | Add-Member -NotePropertyName bundle -NotePropertyValue ([pscustomobject]@{}) -Force
    $changed = $true
  }

  $icons = @()
  if ($null -ne $config.bundle.icon) {
    foreach ($iconValue in @($config.bundle.icon)) {
      if ($null -eq $iconValue) {
        continue
      }
      $iconText = [string]$iconValue
      if ([string]::IsNullOrWhiteSpace($iconText)) {
        continue
      }
      $icons += $iconText.Trim()
    }
  }

  $expectedNormalized = $ExpectedIconRelativePath.Replace("\", "/").Trim().ToLowerInvariant()
  $hasExpected = $false
  foreach ($icon in $icons) {
    $normalized = [string]$icon
    if ([string]::IsNullOrWhiteSpace($normalized)) {
      continue
    }
    $normalized = $normalized.Trim().Replace("\", "/").ToLowerInvariant()
    if ($normalized -eq $expectedNormalized) {
      $hasExpected = $true
      break
    }
  }

  if (-not $hasExpected) {
    $icons += $ExpectedIconRelativePath
    $config.bundle | Add-Member -NotePropertyName icon -NotePropertyValue @($icons) -Force
    $changed = $true
  }

  if ($changed) {
    $jsonOut = $config | ConvertTo-Json -Depth 20
    Set-Content -LiteralPath $TauriConfigPath -Value $jsonOut -Encoding UTF8
  }

  return $changed
}

function Get-DesktopAssetSnapshot {
  $repoRoot = Resolve-RepoRoot
  $sourceIconRelativePath = "apps/desktop/src-tauri/icons/icon.svg"
  $generatedIconRelativePath = "apps/desktop/src-tauri/icons/icon.ico"
  $tauriConfigRelativePath = "apps/desktop/src-tauri/tauri.conf.json"

  $sourceIconPath = Join-Path $repoRoot "apps\desktop\src-tauri\icons\icon.svg"
  $generatedIconPath = Join-Path $repoRoot "apps\desktop\src-tauri\icons\icon.ico"
  $tauriConfigPath = Join-Path $repoRoot "apps\desktop\src-tauri\tauri.conf.json"

  $sourceIconAvailable = Test-Path -LiteralPath $sourceIconPath -PathType Leaf
  $generatedIconCheck = Test-IcoFileValid -Path $generatedIconPath
  $tauriBundleIconCheck = Test-TauriBundleIconConfigured -TauriConfigPath $tauriConfigPath -ExpectedIconRelativePath "icons/icon.ico"

  return [pscustomobject]@{
    source_icon = [pscustomobject]@{
      path = $sourceIconRelativePath
      available = [bool]$sourceIconAvailable
      status = $(if ($sourceIconAvailable) { "ok" } else { "missing" })
    }
    generated_icon = [pscustomobject]@{
      path = $generatedIconRelativePath
      available = [bool](Test-Path -LiteralPath $generatedIconPath -PathType Leaf)
      valid = [bool]$generatedIconCheck.valid
      status = [string]$generatedIconCheck.reason
    }
    tauri_bundle_icon = [pscustomobject]@{
      path = $tauriConfigRelativePath
      configured = [bool]$tauriBundleIconCheck.configured
      status = [string]$tauriBundleIconCheck.reason
    }
  }
}

$appliedActions = New-Object System.Collections.Generic.List[string]
$applyFailedActions = New-Object System.Collections.Generic.List[string]

$executionPolicyBefore = Get-ExecutionPolicySnapshot
$executionPolicyRiskBefore = $executionPolicyBefore.effective -notin @("Bypass", "Unrestricted", "RemoteSigned")

$applyRequested = [bool]$Apply
$effectiveApplyRequested = [bool]($applyRequested -and -not [bool]$DryRun)

if ($effectiveApplyRequested -and $executionPolicyRiskBefore) {
  try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    $appliedActions.Add("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force") | Out-Null
  } catch {
    $applyFailedActions.Add(("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force :: {0}" -f $_.Exception.Message)) | Out-Null
  }
}

$executionPolicySnapshot = Get-ExecutionPolicySnapshot
$executionPolicyRisk = $executionPolicySnapshot.effective -notin @("Bypass", "Unrestricted", "RemoteSigned")

$sessionPathRefreshAttempted = $false
$sessionPathRefreshSucceeded = $false
$sessionPathRefreshError = ""
$sessionPathBeforeRefresh = [string]$env:Path
$sessionPathAfterRefresh = [string]$env:Path
$sessionPathAugmentAttempted = $false
$sessionPathAugmentApplied = $false
$sessionPathAugmentError = ""
$sessionPathCandidates = @()
$sessionPathAppended = @()
$sessionPathBeforeAugment = [string]$env:Path
$sessionPathAfterAugment = [string]$env:Path
$toolResolutionPass = "initial"

$sessionPathRefreshAttempted = $true
try {
  Refresh-SessionPath
  $sessionPathRefreshSucceeded = $true
} catch {
  $sessionPathRefreshSucceeded = $false
  $sessionPathRefreshError = $_.Exception.Message
}
$sessionPathAfterRefresh = [string]$env:Path

$toolPaths = Resolve-ToolchainPaths
$goPath = [string]$toolPaths.go
$nodePath = [string]$toolPaths.node
$npmPath = [string]$toolPaths.npm
$npxPath = [string]$toolPaths.npx
$rustcPath = [string]$toolPaths.rustc
$cargoPath = [string]$toolPaths.cargo
$toolResolutionPass = "post_refresh"

$missingAfterRefresh = @()
if ([string]::IsNullOrWhiteSpace($goPath)) { $missingAfterRefresh += "go" }
if ([string]::IsNullOrWhiteSpace($nodePath)) { $missingAfterRefresh += "node" }
if ([string]::IsNullOrWhiteSpace($npmPath)) { $missingAfterRefresh += "npm" }
if ([string]::IsNullOrWhiteSpace($npxPath)) { $missingAfterRefresh += "npx" }
if ([string]::IsNullOrWhiteSpace($rustcPath)) { $missingAfterRefresh += "rustc" }
if ([string]::IsNullOrWhiteSpace($cargoPath)) { $missingAfterRefresh += "cargo" }

if ($missingAfterRefresh.Count -gt 0) {
  $sessionPathAugmentAttempted = $true
  $sessionPathBeforeAugment = [string]$env:Path
  try {
    $commonToolDirectories = @(Get-CommonToolDirectories)
    $sessionPathCandidates = @($commonToolDirectories)

    if ($commonToolDirectories.Count -gt 0) {
      $beforeKeys = @{}
      foreach ($segment in ($sessionPathBeforeAugment -split ";")) {
        if ([string]::IsNullOrWhiteSpace($segment)) { continue }
        $key = $segment.Trim().TrimEnd("\").ToLowerInvariant()
        if ($key.Length -eq 0) { continue }
        $beforeKeys[$key] = $true
      }

      Add-SessionPathSegments -Segments $commonToolDirectories
      $sessionPathAfterAugment = [string]$env:Path

      foreach ($candidate in $commonToolDirectories) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        $candidateKey = $candidate.Trim().TrimEnd("\").ToLowerInvariant()
        if ($candidateKey.Length -eq 0) { continue }
        if (-not $beforeKeys.ContainsKey($candidateKey)) {
          $sessionPathAppended += $candidate.Trim().TrimEnd("\")
        }
      }
      if ($sessionPathAppended.Count -gt 0) {
        $sessionPathAugmentApplied = $true
      }
    } else {
      $sessionPathAfterAugment = [string]$env:Path
    }
  } catch {
    $sessionPathAugmentError = $_.Exception.Message
    $sessionPathAfterAugment = [string]$env:Path
  }

  $toolPaths = Resolve-ToolchainPaths
  $goPath = [string]$toolPaths.go
  $nodePath = [string]$toolPaths.node
  $npmPath = [string]$toolPaths.npm
  $npxPath = [string]$toolPaths.npx
  $rustcPath = [string]$toolPaths.rustc
  $cargoPath = [string]$toolPaths.cargo
  $toolResolutionPass = "post_refresh_plus_common_dirs"
} else {
  $sessionPathBeforeAugment = $sessionPathAfterRefresh
  $sessionPathAfterAugment = [string]$env:Path
}

$gitBashSnapshot = Get-GitBashSnapshot

$goAvailable = -not [string]::IsNullOrWhiteSpace($goPath)
$nodeAvailable = -not [string]::IsNullOrWhiteSpace($nodePath)
$npmAvailable = -not [string]::IsNullOrWhiteSpace($npmPath)
$npxAvailable = -not [string]::IsNullOrWhiteSpace($npxPath)
$rustcAvailable = -not [string]::IsNullOrWhiteSpace($rustcPath)
$cargoAvailable = -not [string]::IsNullOrWhiteSpace($cargoPath)
$rustAvailable = $rustcAvailable -and $cargoAvailable
$gitBashAvailable = [bool]$gitBashSnapshot.available

$npmResolverStatus = Get-CommandPs1CmdSiblingStatus -CommandName "npm" -ResolvedPath $npmPath
$npxResolverStatus = Get-CommandPs1CmdSiblingStatus -CommandName "npx" -ResolvedPath $npxPath

$npmResolvesToPs1 = [bool]$npmResolverStatus.resolves_to_ps1
$npmCmdSiblingPath = [string]$npmResolverStatus.cmd_sibling_path
$npmCmdSiblingAvailable = [bool]$npmResolverStatus.cmd_sibling_available
$npxResolvesToPs1 = [bool]$npxResolverStatus.resolves_to_ps1
$npxCmdSiblingPath = [string]$npxResolverStatus.cmd_sibling_path
$npxCmdSiblingAvailable = [bool]$npxResolverStatus.cmd_sibling_available

$npmAliasRemediation = Invoke-SessionCmdAliasRemediation `
  -CommandName "npm" `
  -ApplyRequested ([bool]$applyRequested) `
  -DryRunMode ([bool]$DryRun) `
  -ExecutionPolicyRisk ([bool]$executionPolicyRisk) `
  -ResolvesToPs1 ([bool]$npmResolvesToPs1) `
  -CmdSiblingPath $npmCmdSiblingPath

$npxAliasRemediation = Invoke-SessionCmdAliasRemediation `
  -CommandName "npx" `
  -ApplyRequested ([bool]$applyRequested) `
  -DryRunMode ([bool]$DryRun) `
  -ExecutionPolicyRisk ([bool]$executionPolicyRisk) `
  -ResolvesToPs1 ([bool]$npxResolvesToPs1) `
  -CmdSiblingPath $npxCmdSiblingPath

if ([bool]$npmAliasRemediation.applied) {
  $appliedActions.Add(("Set-Alias -Name npm -Value `"{0}`" -Scope Global -Force" -f $npmCmdSiblingPath)) | Out-Null
}
if ([bool]$npxAliasRemediation.applied) {
  $appliedActions.Add(("Set-Alias -Name npx -Value `"{0}`" -Scope Global -Force" -f $npxCmdSiblingPath)) | Out-Null
}
if ([bool]$npmAliasRemediation.attempted -and -not [bool]$npmAliasRemediation.applied -and [string]$npmAliasRemediation.reason -eq "set_alias_failed") {
  $applyFailedActions.Add(("Set-Alias -Name npm failed :: {0}" -f $npmAliasRemediation.error)) | Out-Null
}
if ([bool]$npxAliasRemediation.attempted -and -not [bool]$npxAliasRemediation.applied -and [string]$npxAliasRemediation.reason -eq "set_alias_failed") {
  $applyFailedActions.Add(("Set-Alias -Name npx failed :: {0}" -f $npxAliasRemediation.error)) | Out-Null
}

$npmPs1PolicyIssue = $npmResolvesToPs1 -and $executionPolicyRisk -and -not [bool]$npmAliasRemediation.applied
$npmPs1ShimIssue = $npmResolvesToPs1 -and -not $npmCmdSiblingAvailable
$npxPs1PolicyIssue = $npxResolvesToPs1 -and $executionPolicyRisk -and -not [bool]$npxAliasRemediation.applied
$npxPs1ShimIssue = $npxResolvesToPs1 -and -not $npxCmdSiblingAvailable
$desktopAssets = Get-DesktopAssetSnapshot
$sourceIconAvailable = [bool]$desktopAssets.source_icon.available
$generatedIconValid = [bool]$desktopAssets.generated_icon.valid
$tauriBundleIconConfigured = [bool]$desktopAssets.tauri_bundle_icon.configured

$issues = New-Object System.Collections.Generic.List[string]
if ($executionPolicyRisk) { $issues.Add("execution_policy_risk") | Out-Null }
if (-not $sessionPathRefreshSucceeded) { $issues.Add("session_path_refresh_failed") | Out-Null }
if (-not [string]::IsNullOrWhiteSpace($sessionPathAugmentError)) { $issues.Add("session_path_augment_failed") | Out-Null }
if (-not $goAvailable) { $issues.Add("go_missing") | Out-Null }
if (-not $nodeAvailable) { $issues.Add("node_missing") | Out-Null }
if (-not $npmAvailable) { $issues.Add("npm_missing") | Out-Null }
if (-not $npxAvailable) { $issues.Add("npx_missing") | Out-Null }
if (-not $rustcAvailable) { $issues.Add("rustc_missing") | Out-Null }
if (-not $cargoAvailable) { $issues.Add("cargo_missing") | Out-Null }
if (-not $rustAvailable) { $issues.Add("rust_toolchain_missing") | Out-Null }
if (-not $gitBashAvailable) { $issues.Add("git_bash_missing") | Out-Null }
if ($npmPs1PolicyIssue) { $issues.Add("npm_ps1_policy_issue") | Out-Null }
if ($npmPs1ShimIssue) { $issues.Add("npm_ps1_without_npm_cmd") | Out-Null }
if ($npxPs1PolicyIssue) { $issues.Add("npx_ps1_policy_issue") | Out-Null }
if ($npxPs1ShimIssue) { $issues.Add("npx_ps1_without_npx_cmd") | Out-Null }
if (-not $sourceIconAvailable) { $issues.Add("desktop_icon_source_missing") | Out-Null }
if (-not $generatedIconValid) { $issues.Add("desktop_icon_missing_or_invalid") | Out-Null }
if (-not $tauriBundleIconConfigured) { $issues.Add("desktop_tauri_bundle_icon_resource_missing") | Out-Null }
if ([bool]$effectiveApplyRequested -and [bool]$npmAliasRemediation.eligible -and -not [bool]$npmAliasRemediation.applied) { $issues.Add("npm_session_alias_apply_failed") | Out-Null }
if ([bool]$effectiveApplyRequested -and [bool]$npxAliasRemediation.eligible -and -not [bool]$npxAliasRemediation.applied) { $issues.Add("npx_session_alias_apply_failed") | Out-Null }
if ($applyFailedActions.Count -gt 0) { $issues.Add("execution_policy_apply_failed") | Out-Null }

$safeHints = New-Object System.Collections.Generic.List[string]
if ($executionPolicyRisk) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
}
if (-not $goAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id GoLang.Go --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $nodeAvailable -or -not $npmAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $rustAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $gitBashAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id Git.Git --exact --accept-package-agreements --accept-source-agreements"
}
if ($npmPs1PolicyIssue) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command ".\scripts\windows\desktop_node.cmd npm -v"
}
if ($npxPs1PolicyIssue) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command ".\scripts\windows\desktop_node.cmd npx -v"
}
if ($npmPs1PolicyIssue -or $npxPs1PolicyIssue) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "powershell -NoProfile -ExecutionPolicy Bypass -Command `"if (Get-Command npm.cmd -ErrorAction SilentlyContinue) { Set-Alias -Name npm -Value npm.cmd -Scope Global -Force }; if (Get-Command npx.cmd -ErrorAction SilentlyContinue) { Set-Alias -Name npx -Value npx.cmd -Scope Global -Force }`""
}
if (-not $sourceIconAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "git checkout -- apps/desktop/src-tauri/icons/icon.svg"
}
if (-not $generatedIconValid) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command ".\scripts\windows\desktop_node.cmd npm run generate:windows-icon"
}
if (-not $tauriBundleIconConfigured) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command (Get-TauriBundleIconRepairCommand)
}
if ($issues.Count -gt 0) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass"
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun"
}

$checkResults = [ordered]@{
  execution_policy_unblocked = [bool](-not $executionPolicyRisk)
  session_path_refresh_safe = [bool]$sessionPathRefreshSucceeded
  session_path_augment_safe = [bool][string]::IsNullOrWhiteSpace($sessionPathAugmentError)
  go_available = [bool]$goAvailable
  node_available = [bool]$nodeAvailable
  npm_available = [bool]$npmAvailable
  npx_available = [bool]$npxAvailable
  rustc_available = [bool]$rustcAvailable
  cargo_available = [bool]$cargoAvailable
  git_bash_available = [bool]$gitBashAvailable
  npm_ps1_policy_safe = [bool](-not $npmPs1PolicyIssue)
  npm_ps1_cmd_shim_safe = [bool](-not $npmPs1ShimIssue)
  npx_ps1_policy_safe = [bool](-not $npxPs1PolicyIssue)
  npx_ps1_cmd_shim_safe = [bool](-not $npxPs1ShimIssue)
  npm_session_alias_remediation_safe = [bool](-not ([bool]$npmAliasRemediation.eligible -and -not [bool]$npmAliasRemediation.applied))
  npx_session_alias_remediation_safe = [bool](-not ([bool]$npxAliasRemediation.eligible -and -not [bool]$npxAliasRemediation.applied))
  desktop_icon_source_available = [bool]$sourceIconAvailable
  desktop_generated_icon_valid = [bool]$generatedIconValid
  desktop_tauri_bundle_icon_configured = [bool]$tauriBundleIconConfigured
}

$passCount = 0
$failCount = 0
foreach ($value in $checkResults.Values) {
  if ([bool]$value) {
    $passCount++
  } else {
    $failCount++
  }
}

$status = if ($issues.Count -eq 0) { "ok" } else { "needs_remediation" }
$statusLabel = if ($issues.Count -eq 0) { "PASS" } else { "FAIL" }

if ($Compact) {
  Write-Step ("summary: pass={0} fail={1} status={2}" -f $passCount, $failCount, $statusLabel)
  if ($applyRequested -or [bool]$DryRun) {
    Write-Step ("apply: requested={0} effective_apply={1} dry_run={2} applied={3} failed={4}" -f $applyRequested.ToString().ToLowerInvariant(), $effectiveApplyRequested.ToString().ToLowerInvariant(), ([bool]$DryRun).ToString().ToLowerInvariant(), $appliedActions.Count, $applyFailedActions.Count)
  }
  if ($issues.Count -gt 0) {
    Write-Step ("issues: {0}" -f ($issues -join ", "))
    Write-Step "remediation commands:"
    foreach ($hint in $safeHints) {
      Write-Host ("  {0}" -f $hint)
    }
  }
} else {
  Write-Step ("execution policy effective={0}; process={1}; current_user={2}; local_machine={3}" -f $executionPolicySnapshot.effective, $executionPolicySnapshot.scopes.Process, $executionPolicySnapshot.scopes.CurrentUser, $executionPolicySnapshot.scopes.LocalMachine)
  Write-Step ("go: {0}" -f $(if ($goAvailable) { $goPath } else { "missing" }))
  Write-Step ("node: {0}" -f $(if ($nodeAvailable) { $nodePath } else { "missing" }))
  Write-Step ("npm: {0}" -f $(if ($npmAvailable) { $npmPath } else { "missing" }))
  Write-Step ("npx: {0}" -f $(if ($npxAvailable) { $npxPath } else { "missing" }))
  Write-Step ("rustc: {0}" -f $(if ($rustcAvailable) { $rustcPath } else { "missing" }))
  Write-Step ("cargo: {0}" -f $(if ($cargoAvailable) { $cargoPath } else { "missing" }))
  Write-Step ("git-bash: {0}" -f $(if ($gitBashAvailable) { "$($gitBashSnapshot.path) [$($gitBashSnapshot.source)]" } else { "missing" }))
  Write-Step ("desktop source icon: {0} ({1})" -f $desktopAssets.source_icon.path, $(if ($sourceIconAvailable) { "ok" } else { "missing" }))
  Write-Step ("desktop generated icon: {0} ({1})" -f $desktopAssets.generated_icon.path, $desktopAssets.generated_icon.status)
  Write-Step ("desktop tauri bundle icon resource: {0} ({1})" -f $desktopAssets.tauri_bundle_icon.path, $(if ($tauriBundleIconConfigured) { "configured" } else { $desktopAssets.tauri_bundle_icon.status }))
  if ($npmResolvesToPs1) {
    Write-Step ("npm.ps1 resolver detected; sibling npm.cmd={0}" -f $(if ($npmCmdSiblingAvailable) { $npmCmdSiblingPath } else { "missing" }))
  }
  if ($npxResolvesToPs1) {
    Write-Step ("npx.ps1 resolver detected; sibling npx.cmd={0}" -f $(if ($npxCmdSiblingAvailable) { $npxCmdSiblingPath } else { "missing" }))
  }
  if ([bool]$npmAliasRemediation.applied) {
    Write-Step ("session alias remediation applied: npm -> {0}" -f $npmAliasRemediation.alias_definition)
  } elseif ([bool]$npmAliasRemediation.eligible -and -not [bool]$applyRequested) {
    Write-Step "session alias remediation available for npm; rerun with -Apply to force npm.cmd for this shell only"
  }
  if ([bool]$npxAliasRemediation.applied) {
    Write-Step ("session alias remediation applied: npx -> {0}" -f $npxAliasRemediation.alias_definition)
  } elseif ([bool]$npxAliasRemediation.eligible -and -not [bool]$applyRequested) {
    Write-Step "session alias remediation available for npx; rerun with -Apply to force npx.cmd for this shell only"
  }
  if ($applyRequested -or [bool]$DryRun) {
    Write-Step ("apply requested={0} effective_apply={1} dry_run={2} applied={3} failed={4}" -f $applyRequested.ToString().ToLowerInvariant(), $effectiveApplyRequested.ToString().ToLowerInvariant(), ([bool]$DryRun).ToString().ToLowerInvariant(), $appliedActions.Count, $applyFailedActions.Count)
    foreach ($failedAction in $applyFailedActions) {
      Write-Step ("apply failure: {0}" -f $failedAction)
    }
  }

  Write-Step ("summary: pass={0} fail={1} status={2}" -f $passCount, $failCount, $statusLabel)
  if ($issues.Count -gt 0) {
    Write-Step ("issues: {0}" -f ($issues -join ", "))
    Write-Step "remediation commands:"
    foreach ($hint in $safeHints) {
      Write-Host ("  {0}" -f $hint)
    }
  }
}

$summary = [ordered]@{
  version = 1
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  status = $status
  issues_detected = [int]$issues.Count
  issues = @($issues)
  apply = [ordered]@{
    requested = [bool]$applyRequested
    dry_run_requested = [bool]$DryRun
    effective_apply_requested = [bool]$effectiveApplyRequested
    execution_policy_risk_before = [bool]$executionPolicyRiskBefore
    execution_policy_effective_before = $executionPolicyBefore.effective
    execution_policy_effective_after = $executionPolicySnapshot.effective
    applied_actions = @($appliedActions)
    failed_actions = @($applyFailedActions)
  }
  checks = [ordered]@{
    pass_count = [int]$passCount
    fail_count = [int]$failCount
    execution_policy = [ordered]@{
      effective = $executionPolicySnapshot.effective
      process = $executionPolicySnapshot.scopes.Process
      current_user = $executionPolicySnapshot.scopes.CurrentUser
      local_machine = $executionPolicySnapshot.scopes.LocalMachine
      risk_detected = [bool]$executionPolicyRisk
    }
    session_path = [ordered]@{
      refresh_attempted = [bool]$sessionPathRefreshAttempted
      refresh_succeeded = [bool]$sessionPathRefreshSucceeded
      refresh_error = [string]$sessionPathRefreshError
      path_before_refresh = [string]$sessionPathBeforeRefresh
      path_after_refresh = [string]$sessionPathAfterRefresh
      augment_attempted = [bool]$sessionPathAugmentAttempted
      augment_applied = [bool]$sessionPathAugmentApplied
      augment_error = [string]$sessionPathAugmentError
      candidate_directories = @($sessionPathCandidates)
      appended_directories = @($sessionPathAppended)
      path_before_augment = [string]$sessionPathBeforeAugment
      path_after_augment = [string]$sessionPathAfterAugment
      tool_resolution_pass = [string]$toolResolutionPass
    }
    toolchain = [ordered]@{
      go_available = [bool]$goAvailable
      node_available = [bool]$nodeAvailable
      npm_available = [bool]$npmAvailable
      npx_available = [bool]$npxAvailable
      rustc_available = [bool]$rustcAvailable
      cargo_available = [bool]$cargoAvailable
      rust_available = [bool]$rustAvailable
      go_path = $goPath
      node_path = $nodePath
      npm_path = $npmPath
      npx_path = $npxPath
      rustc_path = $rustcPath
      cargo_path = $cargoPath
    }
    npm = [ordered]@{
      resolver_path = $npmPath
      npm_cmd_resolver_path = (Resolve-NpmCommandPath)
      resolves_to_npm_ps1 = [bool]$npmResolvesToPs1
      npm_cmd_sibling_available = [bool]$npmCmdSiblingAvailable
      npm_cmd_sibling_path = $npmCmdSiblingPath
      npm_ps1_policy_issue = [bool]$npmPs1PolicyIssue
      npm_ps1_without_npm_cmd = [bool]$npmPs1ShimIssue
      npx_resolver_path = $npxPath
      resolves_to_npx_ps1 = [bool]$npxResolvesToPs1
      npx_cmd_sibling_available = [bool]$npxCmdSiblingAvailable
      npx_cmd_sibling_path = $npxCmdSiblingPath
      npx_ps1_policy_issue = [bool]$npxPs1PolicyIssue
      npx_ps1_without_npx_cmd = [bool]$npxPs1ShimIssue
      session_alias_remediation = [ordered]@{
        npm = [ordered]@{
          eligible = [bool]$npmAliasRemediation.eligible
          attempted = [bool]$npmAliasRemediation.attempted
          applied = [bool]$npmAliasRemediation.applied
          reason = [string]$npmAliasRemediation.reason
          alias_definition = [string]$npmAliasRemediation.alias_definition
          error = [string]$npmAliasRemediation.error
        }
        npx = [ordered]@{
          eligible = [bool]$npxAliasRemediation.eligible
          attempted = [bool]$npxAliasRemediation.attempted
          applied = [bool]$npxAliasRemediation.applied
          reason = [string]$npxAliasRemediation.reason
          alias_definition = [string]$npxAliasRemediation.alias_definition
          error = [string]$npxAliasRemediation.error
        }
      }
    }
    git_bash = [ordered]@{
      available = [bool]$gitBashAvailable
      path = $gitBashSnapshot.path
      source = $gitBashSnapshot.source
      checked_candidates = @($gitBashSnapshot.checked_candidates)
    }
    desktop_assets = [ordered]@{
      source_icon = [ordered]@{
        path = [string]$desktopAssets.source_icon.path
        available = [bool]$sourceIconAvailable
        status = [string]$desktopAssets.source_icon.status
      }
      generated_icon = [ordered]@{
        path = [string]$desktopAssets.generated_icon.path
        available = [bool]$desktopAssets.generated_icon.available
        valid = [bool]$generatedIconValid
        status = [string]$desktopAssets.generated_icon.status
      }
      tauri_bundle_icon = [ordered]@{
        path = [string]$desktopAssets.tauri_bundle_icon.path
        configured = [bool]$tauriBundleIconConfigured
        status = [string]$desktopAssets.tauri_bundle_icon.status
      }
    }
  }
  remediation_hints = @($safeHints)
}

if ($PrintSummaryJson) {
  $summary | ConvertTo-Json -Depth 8
}

if ($FailOnIssues -and $issues.Count -gt 0) {
  exit 1
}

exit 0
