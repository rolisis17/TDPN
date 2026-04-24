param(
  [ValidateSet("check", "fix")]
  [string]$Mode = "check",
  [switch]$InstallMissing,
  [switch]$DryRun,
  [switch]$EnablePolicyBypass,
  [string]$SummaryJson = "",
  [ValidateSet(0, 1)]
  [int]$PrintSummaryJson = 0
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-doctor] $Message"
}

function Get-CommandPath {
  param([string]$Name)
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($null -eq $cmd) {
    return ""
  }
  return [string]$cmd.Source
}

function Normalize-NpmCommandPath {
  param(
    [AllowEmptyString()]
    [string]$PathValue
  )

  if ([string]::IsNullOrWhiteSpace($PathValue)) {
    return $PathValue
  }

  $leaf = [System.IO.Path]::GetFileName($PathValue)
  if (-not $leaf.Equals("npm.ps1", [System.StringComparison]::OrdinalIgnoreCase)) {
    return $PathValue
  }

  $parent = Split-Path -Parent $PathValue
  if ([string]::IsNullOrWhiteSpace($parent)) {
    return $PathValue
  }

  $siblingCmd = Join-Path $parent "npm.cmd"
  if (Test-Path -LiteralPath $siblingCmd -PathType Leaf) {
    return $siblingCmd
  }

  return $PathValue
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

function Resolve-ToolPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $nameLower = $Name.ToLowerInvariant()
  $path = Get-CommandPath $Name
  if ($nameLower -in @("npm", "npm.cmd")) {
    $path = Normalize-NpmCommandPath -PathValue $path
  }

  $allowWindowsAppsAlias = @("winget", "jq") -contains $nameLower
  if (-not [string]::IsNullOrWhiteSpace($path) -and ($allowWindowsAppsAlias -or $path -notmatch '\\WindowsApps\\')) {
    return $path
  }

  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $userProfile = [Environment]::GetFolderPath("UserProfile")
  $systemDrive = [Environment]::GetEnvironmentVariable("SystemDrive", "Process")

  $candidates = @()
  switch ($nameLower) {
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
    "git" {
      $candidates = @(
        (Join-Path $programFiles "Git\cmd\git.exe"),
        (Join-Path $programFiles "Git\bin\git.exe"),
        (Join-Path $programFiles "Git\mingw64\bin\git.exe"),
        (Join-Path $programFilesX86 "Git\cmd\git.exe"),
        (Join-Path $programFilesX86 "Git\bin\git.exe"),
        (Join-Path $programFilesX86 "Git\mingw64\bin\git.exe")
      )
    }
    "bash.exe" {
      $candidates = @(
        (Join-Path $programFiles "Git\bin\bash.exe"),
        (Join-Path $programFiles "Git\usr\bin\bash.exe"),
        (Join-Path $programFiles "Git\bash.exe"),
        (Join-Path $programFilesX86 "Git\bin\bash.exe"),
        (Join-Path $programFilesX86 "Git\usr\bin\bash.exe"),
        (Join-Path $programFilesX86 "Git\bash.exe")
      )
    }
    "git-bash.exe" {
      $candidates = @(
        (Join-Path $programFiles "Git\git-bash.exe"),
        (Join-Path $programFilesX86 "Git\git-bash.exe")
      )
    }
    "jq" {
      $candidates = @(
        (Join-Path $programFiles "jq\jq.exe"),
        (Join-Path $programFilesX86 "jq\jq.exe"),
        (Join-Path $userProfile "scoop\shims\jq.exe"),
        (Join-Path $userProfile "AppData\Local\Microsoft\WinGet\Links\jq.exe")
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

  return [pscustomobject]@{
    effective = [string](Get-ExecutionPolicy)
    scopes = $snapshot
  }
}

function Test-ExecutionPolicyRisk {
  param(
    [AllowEmptyString()]
    [string]$EffectivePolicy
  )

  $policy = [string]$EffectivePolicy
  if ([string]::IsNullOrWhiteSpace($policy)) {
    return $false
  }

  return $policy.Equals("Restricted", [System.StringComparison]::OrdinalIgnoreCase) -or
    $policy.Equals("AllSigned", [System.StringComparison]::OrdinalIgnoreCase)
}

function Show-ExecutionPolicyStatus {
  $snapshot = Get-ExecutionPolicySnapshot
  Write-Step ("execution policy: effective={0}; process={1}; current_user={2}; local_machine={3}" -f $snapshot.effective, $snapshot.scopes.Process, $snapshot.scopes.CurrentUser, $snapshot.scopes.LocalMachine)

  if (Test-ExecutionPolicyRisk -EffectivePolicy $snapshot.effective) {
    Write-Step "execution policy risk detected: effective_policy=$($snapshot.effective)"
    Write-Step "rerun in this shell with process-scope bypass:"
    Write-Host "  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
  }
}

function Ensure-PolicyBypassProcess {
  Show-ExecutionPolicyStatus

  if (-not $EnablePolicyBypass) {
    Write-Step "execution policy left unchanged for current process"
    return
  }

  if ($DryRun) {
    Write-Step "dry-run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
    return
  }

  try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Write-Step "execution policy set to Bypass for current process"
  } catch {
    Write-Warning "failed to set process execution policy bypass: $($_.Exception.Message)"
  }
}

function Resolve-GitBashPath {
  $envOverride = [Environment]::GetEnvironmentVariable("LOCAL_CONTROL_API_GIT_BASH_PATH", "Process")
  if (-not [string]::IsNullOrWhiteSpace($envOverride)) {
    return $envOverride.Trim()
  }

  $resolved = Resolve-ToolPath "bash.exe"
  if (-not [string]::IsNullOrWhiteSpace($resolved)) {
    return $resolved
  }

  $resolved = Resolve-ToolPath "git-bash.exe"
  if (-not [string]::IsNullOrWhiteSpace($resolved)) {
    return $resolved
  }

  return ""
}

function Resolve-RepoRoot {
  $scriptDir = $PSScriptRoot
  if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $PSCommandPath
  }
  return (Resolve-Path (Join-Path $scriptDir "..\..")).Path
}

function Get-VswherePath {
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $candidate = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    return $candidate
  }
  return ""
}

function Get-MsvcHostx64x64ClPath {
  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $installationRoots = @()
  $seen = @{}

  $vswherePath = Get-VswherePath
  if (-not [string]::IsNullOrWhiteSpace($vswherePath)) {
    try {
      $paths = & $vswherePath -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
      foreach ($path in @($paths)) {
        if ([string]::IsNullOrWhiteSpace($path)) {
          continue
        }
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
          continue
        }
        $key = $path.TrimEnd("\").ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
          continue
        }
        $seen[$key] = $true
        $installationRoots += $path
      }
    } catch {
      Write-Verbose "vswhere query failed: $($_.Exception.Message)"
    }
  }

  $vsYears = @("2022", "2019", "2017")
  $vsSkus = @("BuildTools", "Community", "Professional", "Enterprise")
  foreach ($year in $vsYears) {
    foreach ($sku in $vsSkus) {
      $candidateRoot = Join-Path $programFilesX86 ("Microsoft Visual Studio\{0}\{1}" -f $year, $sku)
      if (-not (Test-Path -LiteralPath $candidateRoot -PathType Container)) {
        continue
      }
      $key = $candidateRoot.TrimEnd("\").ToLowerInvariant()
      if ($seen.ContainsKey($key)) {
        continue
      }
      $seen[$key] = $true
      $installationRoots += $candidateRoot
    }
  }

  foreach ($installationRoot in $installationRoots) {
    $msvcRoot = Join-Path $installationRoot "VC\Tools\MSVC"
    if (-not (Test-Path -LiteralPath $msvcRoot -PathType Container)) {
      continue
    }

    $versionDirs = Get-ChildItem -LiteralPath $msvcRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($versionDir in $versionDirs) {
      $clPath = Join-Path $versionDir.FullName "bin\Hostx64\x64\cl.exe"
      if (Test-Path -LiteralPath $clPath -PathType Leaf) {
        return $clPath
      }
    }
  }

  $wildcardPatterns = @(
    (Join-Path $programFilesX86 "Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe"),
    (Join-Path $programFiles "Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe")
  )
  foreach ($pattern in $wildcardPatterns) {
    $matches = @(Get-Item -Path $pattern -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)
    if ($matches.Count -gt 0) {
      return $matches[0].FullName
    }
  }

  return ""
}

function Get-WindowsSdkEvidencePath {
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $candidateRoots = @()
  $seen = @{}

  try {
    $sdkReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0" -ErrorAction Stop
    $installationFolder = [string]$sdkReg.InstallationFolder
    if (-not [string]::IsNullOrWhiteSpace($installationFolder) -and (Test-Path -LiteralPath $installationFolder -PathType Container)) {
      $key = $installationFolder.TrimEnd("\").ToLowerInvariant()
      $seen[$key] = $true
      $candidateRoots += $installationFolder
    }
  } catch {
    Write-Verbose "windows sdk registry key not found: $($_.Exception.Message)"
  }

  $defaultRoot = Join-Path $programFilesX86 "Windows Kits\10"
  if (Test-Path -LiteralPath $defaultRoot -PathType Container) {
    $key = $defaultRoot.TrimEnd("\").ToLowerInvariant()
    if (-not $seen.ContainsKey($key)) {
      $seen[$key] = $true
      $candidateRoots += $defaultRoot
    }
  }

  foreach ($root in $candidateRoots) {
    $includeRoot = Join-Path $root "Include"
    if (-not (Test-Path -LiteralPath $includeRoot -PathType Container)) {
      continue
    }

    $versionDirs = Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($versionDir in $versionDirs) {
      $versionName = $versionDir.Name
      $windowsHeader = Join-Path $versionDir.FullName "um\windows.h"
      if (-not (Test-Path -LiteralPath $windowsHeader -PathType Leaf)) {
        continue
      }

      $rcPath = Join-Path $root ("bin\{0}\x64\rc.exe" -f $versionName)
      if (Test-Path -LiteralPath $rcPath -PathType Leaf) {
        return $rcPath
      }

      return $windowsHeader
    }
  }

  return ""
}

function Get-WebView2RuntimeEvidencePath {
  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $localAppData = [Environment]::GetFolderPath("LocalApplicationData")

  $runtimeRoots = @(
    (Join-Path $programFilesX86 "Microsoft\EdgeWebView\Application"),
    (Join-Path $programFiles "Microsoft\EdgeWebView\Application"),
    (Join-Path $localAppData "Microsoft\EdgeWebView\Application")
  )

  foreach ($runtimeRoot in $runtimeRoots) {
    if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
      continue
    }

    $versionDirs = Get-ChildItem -LiteralPath $runtimeRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending
    foreach ($versionDir in $versionDirs) {
      $exePath = Join-Path $versionDir.FullName "msedgewebview2.exe"
      if (Test-Path -LiteralPath $exePath -PathType Leaf) {
        return $exePath
      }
    }
  }

  $runtimeGuid = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
  $registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$runtimeGuid",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$runtimeGuid",
    "HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$runtimeGuid"
  )
  foreach ($registryPath in $registryPaths) {
    try {
      $runtimeReg = Get-ItemProperty -Path $registryPath -ErrorAction Stop
      $runtimeVersion = [string]$runtimeReg.pv
      if (-not [string]::IsNullOrWhiteSpace($runtimeVersion)) {
        return ("registry:{0}:pv={1}" -f $registryPath, $runtimeVersion)
      }
    } catch {
      continue
    }
  }

  return ""
}

function Get-DefaultDesktopPrerequisiteSummary {
  return [ordered]@{
    msvc_build_tools_x64 = [ordered]@{
      installed = $false
      package_id = "Microsoft.VisualStudio.2022.BuildTools"
      evidence = ""
      remediation_hint = "winget install --id Microsoft.VisualStudio.2022.BuildTools --exact (then ensure MSVC v143 x64/x64 and a Windows 10/11 SDK component are selected in Visual Studio Installer)"
    }
    windows_sdk = [ordered]@{
      installed = $false
      package_id = "Microsoft.WindowsSDK.10.0"
      evidence = ""
      remediation_hint = "install Windows 10/11 SDK from Visual Studio Installer (Individual components) or https://developer.microsoft.com/windows/downloads/windows-sdk/"
    }
    webview2_runtime = [ordered]@{
      installed = $false
      package_id = "Microsoft.EdgeWebView2Runtime"
      evidence = ""
      remediation_hint = "winget install --id Microsoft.EdgeWebView2Runtime --exact (or install from https://developer.microsoft.com/microsoft-edge/webview2/)"
    }
  }
}

function Get-DesktopPrerequisiteReport {
  $msvcEvidence = Get-MsvcHostx64x64ClPath
  $windowsSdkEvidence = Get-WindowsSdkEvidencePath
  $webView2Evidence = Get-WebView2RuntimeEvidencePath

  $entries = Get-DefaultDesktopPrerequisiteSummary
  $entries.msvc_build_tools_x64.installed = -not [string]::IsNullOrWhiteSpace($msvcEvidence)
  $entries.msvc_build_tools_x64.evidence = $msvcEvidence
  $entries.windows_sdk.installed = -not [string]::IsNullOrWhiteSpace($windowsSdkEvidence)
  $entries.windows_sdk.evidence = $windowsSdkEvidence
  $entries.webview2_runtime.installed = -not [string]::IsNullOrWhiteSpace($webView2Evidence)
  $entries.webview2_runtime.evidence = $webView2Evidence

  $missingPackageIds = @()
  foreach ($key in @("msvc_build_tools_x64", "windows_sdk", "webview2_runtime")) {
    $entry = $entries[$key]
    if (-not [bool]$entry.installed) {
      $missingPackageIds += [string]$entry.package_id
    }
  }

  return [PSCustomObject]@{
    entries = $entries
    missing_package_ids = $missingPackageIds
  }
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
      icon_entries = @()
    }
  }

  $config = $null
  try {
    $config = Get-Content -Raw -LiteralPath $TauriConfigPath | ConvertFrom-Json -ErrorAction Stop
  } catch {
    return [pscustomobject]@{
      configured = $false
      reason = "invalid_tauri_conf_json"
      icon_entries = @()
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
        icon_entries = @($icons)
      }
    }
  }

  return [pscustomobject]@{
    configured = $false
    reason = "missing_bundle_icon_entry"
    icon_entries = @($icons)
  }
}

function Get-DefaultDesktopAssetSummary {
  return [ordered]@{
    source_icon = [ordered]@{
      path = "apps/desktop/src-tauri/icons/icon.svg"
      exists = $false
      status = "missing"
      remediation_hint = "git checkout -- apps/desktop/src-tauri/icons/icon.svg"
    }
    generated_icon = [ordered]@{
      path = "apps/desktop/src-tauri/icons/icon.ico"
      exists = $false
      valid_ico = $false
      status = "missing"
      remediation_hint = "scripts\\windows\\desktop_node.cmd npm run generate:windows-icon"
    }
    tauri_bundle_icon = [ordered]@{
      path = "apps/desktop/src-tauri/tauri.conf.json"
      expected_entry = "icons/icon.ico"
      configured = $false
      status = "missing_bundle_icon_entry"
      remediation_hint = (Get-TauriBundleIconRepairCommand)
      icon_entries = @()
    }
  }
}

function Get-DesktopAssetReport {
  $repoRoot = Resolve-RepoRoot
  $desktopRoot = Join-Path $repoRoot "apps\desktop"

  $sourceRelativePath = "apps/desktop/src-tauri/icons/icon.svg"
  $iconRelativePath = "apps/desktop/src-tauri/icons/icon.ico"
  $tauriConfigRelativePath = "apps/desktop/src-tauri/tauri.conf.json"
  $sourcePath = Join-Path $repoRoot "apps\desktop\src-tauri\icons\icon.svg"
  $iconPath = Join-Path $repoRoot "apps\desktop\src-tauri\icons\icon.ico"
  $tauriConfigPath = Join-Path $repoRoot "apps\desktop\src-tauri\tauri.conf.json"

  $entries = Get-DefaultDesktopAssetSummary
  $entries.source_icon.path = $sourceRelativePath
  $entries.generated_icon.path = $iconRelativePath
  $entries.tauri_bundle_icon.path = $tauriConfigRelativePath

  $sourceExists = Test-Path -LiteralPath $sourcePath -PathType Leaf
  $entries.source_icon.exists = [bool]$sourceExists
  $entries.source_icon.status = $(if ($sourceExists) { "ok" } else { "missing" })

  $iconValidation = Test-IcoFileValid -Path $iconPath
  $iconExists = Test-Path -LiteralPath $iconPath -PathType Leaf
  $entries.generated_icon.exists = [bool]$iconExists
  $entries.generated_icon.valid_ico = [bool]$iconValidation.valid
  if (-not $iconExists) {
    $entries.generated_icon.status = "missing"
  } elseif ($iconValidation.valid) {
    $entries.generated_icon.status = "ok"
  } else {
    $entries.generated_icon.status = [string]$iconValidation.reason
  }

  $tauriConfigState = Test-TauriBundleIconConfigured -TauriConfigPath $tauriConfigPath -ExpectedIconRelativePath "icons/icon.ico"
  $entries.tauri_bundle_icon.configured = [bool]$tauriConfigState.configured
  $entries.tauri_bundle_icon.status = [string]$tauriConfigState.reason
  $entries.tauri_bundle_icon.icon_entries = @($tauriConfigState.icon_entries)

  $issueIds = @()
  if (-not $entries.source_icon.exists) {
    $issueIds += "desktop_icon_source_missing"
  }
  if (-not $entries.generated_icon.exists) {
    $issueIds += "desktop_icon_missing"
  } elseif (-not $entries.generated_icon.valid_ico) {
    $issueIds += "desktop_icon_invalid"
  }
  if (-not $entries.tauri_bundle_icon.configured) {
    switch ($entries.tauri_bundle_icon.status) {
      "missing_tauri_conf" { $issueIds += "desktop_tauri_conf_missing" }
      "invalid_tauri_conf_json" { $issueIds += "desktop_tauri_conf_invalid_json" }
      default { $issueIds += "desktop_tauri_bundle_icon_missing" }
    }
  }

  return [pscustomobject]@{
    repo_root = $repoRoot
    desktop_root = $desktopRoot
    entries = $entries
    issue_ids = @($issueIds)
  }
}

function Convert-DesktopAssetReport {
  param(
    [pscustomobject]$Report
  )

  if ($null -eq $Report -or $null -eq $Report.entries) {
    return (Get-DefaultDesktopAssetSummary)
  }

  return [ordered]@{
    source_icon = [ordered]@{
      path = [string]$Report.entries.source_icon.path
      exists = [bool]$Report.entries.source_icon.exists
      status = [string]$Report.entries.source_icon.status
      remediation_hint = [string]$Report.entries.source_icon.remediation_hint
    }
    generated_icon = [ordered]@{
      path = [string]$Report.entries.generated_icon.path
      exists = [bool]$Report.entries.generated_icon.exists
      valid_ico = [bool]$Report.entries.generated_icon.valid_ico
      status = [string]$Report.entries.generated_icon.status
      remediation_hint = [string]$Report.entries.generated_icon.remediation_hint
    }
    tauri_bundle_icon = [ordered]@{
      path = [string]$Report.entries.tauri_bundle_icon.path
      expected_entry = [string]$Report.entries.tauri_bundle_icon.expected_entry
      configured = [bool]$Report.entries.tauri_bundle_icon.configured
      status = [string]$Report.entries.tauri_bundle_icon.status
      remediation_hint = [string]$Report.entries.tauri_bundle_icon.remediation_hint
      icon_entries = @($Report.entries.tauri_bundle_icon.icon_entries)
    }
  }
}

function Show-DesktopAssetReport {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report
  )

  Write-Host "desktop asset report:"
  $sourceState = if ([bool]$Report.entries.source_icon.exists) { "ok" } else { "missing" }
  Write-Host ("  - source icon ({0}): {1}" -f $Report.entries.source_icon.path, $sourceState)
  if (-not [bool]$Report.entries.source_icon.exists) {
    Write-Host ("    remediation: {0}" -f $Report.entries.source_icon.remediation_hint)
  }

  $iconState = [string]$Report.entries.generated_icon.status
  Write-Host ("  - generated icon ({0}): {1}" -f $Report.entries.generated_icon.path, $iconState)
  if ($iconState -ne "ok") {
    Write-Host ("    remediation: {0}" -f $Report.entries.generated_icon.remediation_hint)
  }

  $resourceState = if ([bool]$Report.entries.tauri_bundle_icon.configured) { "ok" } else { [string]$Report.entries.tauri_bundle_icon.status }
  Write-Host ("  - tauri bundle icon resource ({0} -> {1}): {2}" -f $Report.entries.tauri_bundle_icon.path, $Report.entries.tauri_bundle_icon.expected_entry, $resourceState)
  if (-not [bool]$Report.entries.tauri_bundle_icon.configured) {
    Write-Host ("    remediation: {0}" -f $Report.entries.tauri_bundle_icon.remediation_hint)
  }
}

function Invoke-DesktopAssetRemediation {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$DesktopAssetReport,
    [Parameter(Mandatory = $true)]
    [pscustomobject]$ToolReport
  )

  $attempted = $false
  $completed = $false
  $updatedTauriConfig = $false
  $generatedIcon = $false
  $issueIds = @($DesktopAssetReport.issue_ids)
  if ($issueIds.Count -eq 0) {
    return [pscustomobject]@{
      attempted = $false
      completed = $true
      tauri_config_updated = $false
      icon_generated = $false
      report = $DesktopAssetReport
    }
  }

  $repoRoot = [string]$DesktopAssetReport.repo_root
  $desktopRoot = [string]$DesktopAssetReport.desktop_root
  $sourcePath = Join-Path $repoRoot "apps\desktop\src-tauri\icons\icon.svg"
  $iconPath = Join-Path $repoRoot "apps\desktop\src-tauri\icons\icon.ico"
  $tauriConfigPath = Join-Path $repoRoot "apps\desktop\src-tauri\tauri.conf.json"

  if ($issueIds -contains "desktop_tauri_bundle_icon_missing") {
    $attempted = $true
    if ($DryRun) {
      Write-Step "dry-run desktop asset remediation: would add icons/icon.ico to apps/desktop/src-tauri/tauri.conf.json bundle.icon"
    } else {
      try {
        $updatedTauriConfig = [bool](Ensure-TauriBundleIconResource -TauriConfigPath $tauriConfigPath -ExpectedIconRelativePath "icons/icon.ico")
        if ($updatedTauriConfig) {
          Write-Step "desktop asset remediation: updated apps/desktop/src-tauri/tauri.conf.json bundle.icon with icons/icon.ico"
        }
      } catch {
        Write-Step ("desktop asset remediation could not update tauri config: {0}" -f $_.Exception.Message)
      }
    }
  }

  if (($issueIds -contains "desktop_icon_missing" -or $issueIds -contains "desktop_icon_invalid") -and -not ($issueIds -contains "desktop_icon_source_missing")) {
    $attempted = $true
    if ([string]::IsNullOrWhiteSpace([string]$ToolReport.npm)) {
      Write-Step "desktop asset remediation skipped icon generation: npm is missing in this shell"
    } elseif (-not (Test-Path -LiteralPath (Join-Path $desktopRoot "package.json") -PathType Leaf)) {
      Write-Step ("desktop asset remediation skipped icon generation: missing package.json at {0}" -f $desktopRoot)
    } elseif (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
      Write-Step ("desktop asset remediation skipped icon generation: source icon missing at {0}" -f $sourcePath)
    } else {
      if ($DryRun) {
        Write-Step "dry-run desktop asset remediation: npm.cmd run generate:windows-icon"
      } else {
        Push-Location $desktopRoot
        try {
          Write-Step "desktop asset remediation: running npm.cmd run generate:windows-icon"
          & $ToolReport.npm run generate:windows-icon
          if ($LASTEXITCODE -eq 0) {
            $generatedIcon = $true
          } else {
            Write-Step ("desktop asset remediation icon generation failed with exit code {0}" -f $LASTEXITCODE)
          }
        } finally {
          Pop-Location
        }
      }
    }
  }

  if (($issueIds -contains "desktop_icon_missing" -or $issueIds -contains "desktop_icon_invalid") -and -not $generatedIcon) {
    if ($DryRun) {
      Write-Step "dry-run desktop asset scaffold fallback: would create placeholder apps/desktop/src-tauri/icons/icon.ico"
    } elseif (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
      $iconDir = Split-Path -Parent $iconPath
      if (-not (Test-Path -LiteralPath $iconDir -PathType Container)) {
        New-Item -ItemType Directory -Path $iconDir -Force | Out-Null
      }
      $icoBytes = [byte[]]@(
        0x00,0x00,0x01,0x00,0x01,0x00,
        0x01,0x01,0x00,0x00,0x01,0x00,0x20,0x00,0x30,0x00,0x00,0x00,0x16,0x00,0x00,0x00,
        0x28,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x20,0x00,
        0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xFF,0xFF,0xFF,0xFF,
        0x00,0x00,0x00,0x00
      )
      [System.IO.File]::WriteAllBytes($iconPath, $icoBytes)
      Write-Step "desktop asset remediation fallback: created placeholder apps/desktop/src-tauri/icons/icon.ico"
    }
  }

  $postReport = Get-DesktopAssetReport
  $completed = (@($postReport.issue_ids).Count -eq 0)
  return [pscustomobject]@{
    attempted = $attempted
    completed = $completed
    tauri_config_updated = [bool]$updatedTauriConfig
    icon_generated = [bool]$generatedIcon
    report = $postReport
  }
}

function Get-ToolReport {
  $goPath = Resolve-ToolPath "go"
  $nodePath = Resolve-ToolPath "node"
  $npmPath = Resolve-ToolPath "npm.cmd"
  if ([string]::IsNullOrWhiteSpace($npmPath)) {
    $npmPath = Resolve-ToolPath "npm"
  }
  $rustcPath = Resolve-ToolPath "rustc"
  $cargoPath = Resolve-ToolPath "cargo"
  $gitPath = Resolve-ToolPath "git"
  $gitBashPath = Resolve-GitBashPath
  $jqPath = Resolve-ToolPath "jq"
  $wingetPath = Resolve-ToolPath "winget"

  return [PSCustomObject]@{
    go = $goPath
    node = $nodePath
    npm = $npmPath
    rustc = $rustcPath
    cargo = $cargoPath
    git = $gitPath
    git_bash = $gitBashPath
    jq = $jqPath
    winget = $wingetPath
  }
}

function Convert-ToolReport {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report
  )

  return [ordered]@{
    go = $Report.go
    node = $Report.node
    npm = $Report.npm
    rustc = $Report.rustc
    cargo = $Report.cargo
    git = $Report.git
    git_bash = $Report.git_bash
    jq = $Report.jq
    winget = $Report.winget
  }
}

function Convert-DesktopPrerequisiteReport {
  param(
    [pscustomobject]$Report
  )

  if ($null -eq $Report -or $null -eq $Report.entries) {
    return (Get-DefaultDesktopPrerequisiteSummary)
  }

  return [ordered]@{
    msvc_build_tools_x64 = [ordered]@{
      installed = [bool]$Report.entries.msvc_build_tools_x64.installed
      package_id = [string]$Report.entries.msvc_build_tools_x64.package_id
      evidence = [string]$Report.entries.msvc_build_tools_x64.evidence
      remediation_hint = [string]$Report.entries.msvc_build_tools_x64.remediation_hint
    }
    windows_sdk = [ordered]@{
      installed = [bool]$Report.entries.windows_sdk.installed
      package_id = [string]$Report.entries.windows_sdk.package_id
      evidence = [string]$Report.entries.windows_sdk.evidence
      remediation_hint = [string]$Report.entries.windows_sdk.remediation_hint
    }
    webview2_runtime = [ordered]@{
      installed = [bool]$Report.entries.webview2_runtime.installed
      package_id = [string]$Report.entries.webview2_runtime.package_id
      evidence = [string]$Report.entries.webview2_runtime.evidence
      remediation_hint = [string]$Report.entries.webview2_runtime.remediation_hint
    }
  }
}

function Show-ToolReport {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report
  )

  Write-Host "tool report:"
  Write-Host ("  go: " + $(if ($Report.go) { $Report.go } else { "missing" }))
  Write-Host ("  node: " + $(if ($Report.node) { $Report.node } else { "missing" }))
  Write-Host ("  npm: " + $(if ($Report.npm) { $Report.npm } else { "missing" }))
  Write-Host ("  rustc: " + $(if ($Report.rustc) { $Report.rustc } else { "missing" }))
  Write-Host ("  cargo: " + $(if ($Report.cargo) { $Report.cargo } else { "missing" }))
  Write-Host ("  git: " + $(if ($Report.git) { $Report.git } else { "missing" }))
  Write-Host ("  git bash: " + $(if ($Report.git_bash) { $Report.git_bash } else { "missing" }))
  Write-Host ("  jq: " + $(if ($Report.jq) { $Report.jq } else { "missing" }))
  Write-Host ("  winget: " + $(if ($Report.winget) { $Report.winget } else { "missing" }))
}

function Show-DesktopPrerequisiteReport {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report
  )

  Write-Host "desktop prerequisite report:"
  foreach ($key in @("msvc_build_tools_x64", "windows_sdk", "webview2_runtime")) {
    $entry = $Report.entries[$key]
    $label = Get-DependencyLabel -PackageId ([string]$entry.package_id)
    $status = if ([bool]$entry.installed) { "ok" } else { "missing" }
    $evidence = [string]$entry.evidence
    if ([string]::IsNullOrWhiteSpace($evidence)) {
      Write-Host ("  - {0}: {1}" -f $label, $status)
    } else {
      Write-Host ("  - {0}: {1} ({2})" -f $label, $status, $evidence)
    }
    if (-not [bool]$entry.installed) {
      Write-Host ("    remediation: {0}" -f $entry.remediation_hint)
    }
  }
}

function Add-UniqueValue {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [System.Collections.ArrayList]$List,
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  if ($List -notcontains $Value) {
    [void]$List.Add($Value)
  }
}

function Get-MissingPackageIds {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report,
    [pscustomobject]$DesktopPrerequisiteReport = $null
  )

  $ids = New-Object System.Collections.ArrayList

  if (-not $Report.go) {
    Add-UniqueValue -List $ids -Value "GoLang.Go"
  }
  if (-not $Report.node -or -not $Report.npm) {
    Add-UniqueValue -List $ids -Value "OpenJS.NodeJS.LTS"
  }
  if (-not $Report.rustc -or -not $Report.cargo) {
    Add-UniqueValue -List $ids -Value "Rustlang.Rustup"
  }
  if (-not $Report.git -or -not $Report.git_bash) {
    Add-UniqueValue -List $ids -Value "Git.Git"
  }
  if (-not $Report.jq) {
    Add-UniqueValue -List $ids -Value "jqlang.jq"
  }
  if (-not $Report.winget) {
    Add-UniqueValue -List $ids -Value "Microsoft.AppInstaller"
  }
  if ($null -ne $DesktopPrerequisiteReport -and $null -ne $DesktopPrerequisiteReport.missing_package_ids) {
    foreach ($packageId in @($DesktopPrerequisiteReport.missing_package_ids)) {
      if ([string]::IsNullOrWhiteSpace($packageId)) {
        continue
      }
      Add-UniqueValue -List $ids -Value $packageId
    }
  }

  return @($ids.ToArray())
}

function Get-DependencyLabel {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  switch ($PackageId) {
    "GoLang.Go" { return "Go" }
    "OpenJS.NodeJS.LTS" { return "Node.js LTS / npm" }
    "Rustlang.Rustup" { return "Rust toolchain (rustc + cargo)" }
    "Git.Git" { return "Git + Git Bash" }
    "jqlang.jq" { return "jq" }
    "Microsoft.AppInstaller" { return "App Installer (winget)" }
    "Microsoft.VisualStudio.2022.BuildTools" { return "Microsoft Visual C++ Build Tools (Hostx64/x64)" }
    "Microsoft.WindowsSDK.10.0" { return "Windows 10/11 SDK" }
    "Microsoft.EdgeWebView2Runtime" { return "Microsoft Edge WebView2 Runtime" }
    default { return $PackageId }
  }
}

function Get-DependencyInstallHint {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  switch ($PackageId) {
    "GoLang.Go" { return "winget install --id GoLang.Go --exact" }
    "OpenJS.NodeJS.LTS" { return "winget install --id OpenJS.NodeJS.LTS --exact" }
    "Rustlang.Rustup" { return "winget install --id Rustlang.Rustup --exact" }
    "Git.Git" { return "winget install --id Git.Git --exact" }
    "jqlang.jq" { return "winget install --id jqlang.jq --exact" }
    "Microsoft.AppInstaller" { return "install App Installer from Microsoft Store" }
    "Microsoft.VisualStudio.2022.BuildTools" { return "winget install --id Microsoft.VisualStudio.2022.BuildTools --exact; then ensure MSVC v143 x64/x64 + Windows 10/11 SDK components are selected in Visual Studio Installer" }
    "Microsoft.WindowsSDK.10.0" { return "winget install --id Microsoft.WindowsSDK.10.0 --exact (or install Windows 10/11 SDK from Visual Studio Installer (Individual components) or https://developer.microsoft.com/windows/downloads/windows-sdk/)" }
    "Microsoft.EdgeWebView2Runtime" { return "winget install --id Microsoft.EdgeWebView2Runtime --exact (or install from https://developer.microsoft.com/microsoft-edge/webview2/)" }
    default { return "winget install --id $PackageId --exact" }
  }
}

function Get-DependencyWingetPackageId {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  switch ($PackageId) {
    "Microsoft.AppInstaller" { return "" }
    default { return $PackageId }
  }
}

function Get-WingetInstallCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  return ("winget install --id {0} --exact --accept-source-agreements --accept-package-agreements --silent" -f $PackageId)
}

function Get-DependencyManualRemediationCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  switch ($PackageId) {
    "Microsoft.AppInstaller" { return 'Start-Process "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"' }
    "Microsoft.WindowsSDK.10.0" { return 'Start-Process "https://developer.microsoft.com/windows/downloads/windows-sdk/"' }
    default { return "" }
  }
}

function Get-DependencyRecommendedCommands {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  $commands = New-Object System.Collections.ArrayList
  $wingetPackageId = Get-DependencyWingetPackageId -PackageId $PackageId
  if (-not [string]::IsNullOrWhiteSpace($wingetPackageId)) {
    Add-UniqueValue -List $commands -Value (Get-WingetInstallCommand -PackageId $wingetPackageId)
  }
  $manualCommand = Get-DependencyManualRemediationCommand -PackageId $PackageId
  if (-not [string]::IsNullOrWhiteSpace($manualCommand)) {
    Add-UniqueValue -List $commands -Value $manualCommand
  }

  return @($commands.ToArray())
}

function Get-DesktopAssetRecommendedCommands {
  param(
    [AllowEmptyCollection()]
    [string[]]$IssueIds = @()
  )

  $commands = New-Object System.Collections.ArrayList
  if ($IssueIds.Count -eq 0) {
    return @()
  }

  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_node.cmd npm run generate:windows-icon"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_node.cmd npm run tauri -- dev"
  Add-UniqueValue -List $commands -Value ("powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass")
  Add-UniqueValue -List $commands -Value ("powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode run-desktop -DesktopLaunchStrategy dev -InstallMissing -EnablePolicyBypass")

  if ($IssueIds -contains "desktop_icon_source_missing") {
    Add-UniqueValue -List $commands -Value "git checkout -- apps/desktop/src-tauri/icons/icon.svg"
  }
  if ($IssueIds -contains "desktop_tauri_conf_missing") {
    Add-UniqueValue -List $commands -Value "git checkout -- apps/desktop/src-tauri/tauri.conf.json"
  }
  if ($IssueIds -contains "desktop_tauri_conf_invalid_json" -or $IssueIds -contains "desktop_tauri_bundle_icon_missing") {
    Add-UniqueValue -List $commands -Value (Get-TauriBundleIconRepairCommand)
  }

  return @($commands.ToArray())
}

function Get-RecommendedCommands {
  param(
    [AllowEmptyCollection()]
    [string[]]$MissingPackageIds = @(),
    [AllowEmptyCollection()]
    [string[]]$DesktopAssetIssueIds = @()
  )

  $commands = New-Object System.Collections.ArrayList
  Add-UniqueValue -List $commands -Value "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"

  foreach ($packageId in $MissingPackageIds) {
    foreach ($dependencyCommand in @(Get-DependencyRecommendedCommands -PackageId $packageId)) {
      Add-UniqueValue -List $commands -Value $dependencyCommand
    }
  }

  Add-UniqueValue -List $commands -Value "powershell -NoProfile -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_node.cmd npm install"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_node.cmd npm run tauri -- dev"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_node.cmd npx --yes create-vite@latest"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_shell.cmd npm install"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_shell.cmd npm run tauri -- dev"
  Add-UniqueValue -List $commands -Value "npm.cmd install"
  Add-UniqueValue -List $commands -Value "npm.cmd run tauri -- dev"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_node.cmd npm run generate:windows-icon"
  Add-UniqueValue -List $commands -Value "powershell -NoProfile -File .\scripts\windows\desktop_one_click.ps1 -EnablePolicyBypass"

  foreach ($assetCommand in @(Get-DesktopAssetRecommendedCommands -IssueIds $DesktopAssetIssueIds)) {
    Add-UniqueValue -List $commands -Value $assetCommand
  }

  return @($commands.ToArray())
}

function Show-RecommendedCommands {
  param(
    [AllowEmptyCollection()]
    [string[]]$Commands = @()
  )

  if ($Commands.Count -eq 0) {
    return
  }

  Write-Step "recommended commands (copy/paste):"
  foreach ($command in $Commands) {
    Write-Host ("  - {0}" -f $command)
  }
}

function Show-MissingDependencies {
  param(
    [AllowEmptyCollection()]
    [string[]]$PackageIds = @()
  )

  if ($PackageIds.Count -eq 0) {
    Write-Step "all prerequisite tools detected"
    return
  }

  Write-Step ("missing prerequisite package ids: " + ($PackageIds -join ", "))
  foreach ($packageId in $PackageIds) {
    $label = Get-DependencyLabel -PackageId $packageId
    $hint = Get-DependencyInstallHint -PackageId $packageId
    Write-Host ("  - {0}: {1}" -f $label, $hint)
  }
}

function Show-DesktopAssetIssues {
  param(
    [AllowEmptyCollection()]
    [string[]]$IssueIds = @()
  )

  if ($IssueIds.Count -eq 0) {
    Write-Step "desktop icon/resource checks passed"
    return
  }

  Write-Step ("desktop icon/resource issue ids: " + ($IssueIds -join ", "))
  foreach ($issueId in $IssueIds) {
    switch ($issueId) {
      "desktop_icon_source_missing" {
        Write-Host "  - source icon missing: git checkout -- apps/desktop/src-tauri/icons/icon.svg"
      }
      "desktop_icon_missing" {
        Write-Host "  - generated icon missing: scripts\windows\desktop_node.cmd npm run generate:windows-icon"
      }
      "desktop_icon_invalid" {
        Write-Host "  - generated icon invalid: scripts\windows\desktop_node.cmd npm run generate:windows-icon"
      }
      "desktop_tauri_conf_missing" {
        Write-Host "  - tauri config missing: git checkout -- apps/desktop/src-tauri/tauri.conf.json"
      }
      "desktop_tauri_conf_invalid_json" {
        Write-Host ("  - tauri config invalid json: {0}" -f (Get-TauriBundleIconRepairCommand))
      }
      "desktop_tauri_bundle_icon_missing" {
        Write-Host ("  - tauri bundle icon resource missing: {0}" -f (Get-TauriBundleIconRepairCommand))
      }
      default {
        Write-Host ("  - {0}" -f $issueId)
      }
    }
  }
}

function Get-InstallablePackageIds {
  param(
    [AllowEmptyCollection()]
    [string[]]$PackageIds = @()
  )

  $installable = New-Object System.Collections.ArrayList
  foreach ($id in $PackageIds) {
    $wingetPackageId = Get-DependencyWingetPackageId -PackageId $id
    if ([string]::IsNullOrWhiteSpace($wingetPackageId)) {
      continue
    }
    Add-UniqueValue -List $installable -Value $wingetPackageId
  }
  return @($installable.ToArray())
}

function Invoke-WingetInstallWithSourceRetry {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WingetPath,
    [Parameter(Mandatory = $true)]
    [string]$PackageId,
    [Parameter(Mandatory = $true)]
    [string[]]$InstallArgs
  )

  & $WingetPath @InstallArgs
  if ($LASTEXITCODE -eq 0) {
    return
  }

  $initialExitCode = $LASTEXITCODE
  Write-Step ("winget install failed for {0} (exit code {1}); attempting retry path (winget source update + one retry)" -f $PackageId, $initialExitCode)

  & $WingetPath "source" "update"
  $sourceUpdateExitCode = $LASTEXITCODE
  if ($sourceUpdateExitCode -eq 0) {
    Write-Step ("winget source update completed; retrying install for {0}" -f $PackageId)
  } else {
    Write-Step ("winget source update failed with exit code {0}; retrying install for {1} anyway" -f $sourceUpdateExitCode, $PackageId)
  }

  & $WingetPath @InstallArgs
  if ($LASTEXITCODE -eq 0) {
    Write-Step ("winget install succeeded on retry for {0}" -f $PackageId)
    return
  }

  $retryExitCode = $LASTEXITCODE
  throw "winget install retry failed for $PackageId (initial exit code $initialExitCode, retry exit code $retryExitCode)"
}

function Install-WingetPackage {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WingetPath,
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  $wingetArgs = @(
    "install",
    "--id", $PackageId,
    "--exact",
    "--accept-source-agreements",
    "--accept-package-agreements",
    "--silent"
  )

  if ($DryRun) {
    Write-Step ("dry-run install: {0} {1}" -f $WingetPath, ($wingetArgs -join " "))
    return
  }

  Write-Step "installing missing dependency via winget: $PackageId"
  try {
    Invoke-WingetInstallWithSourceRetry -WingetPath $WingetPath -PackageId $PackageId -InstallArgs $wingetArgs
  } catch {
    $fallbackHint = Get-DependencyInstallHint -PackageId $PackageId
    throw "winget install failed for $PackageId. $($_.Exception.Message). manual remediation: $fallbackHint"
  }
}

function Configure-RustupDefaultToolchain {
  if ($DryRun) {
    Write-Step "dry-run: rustup default stable-x86_64-pc-windows-msvc"
    return
  }

  $rustupPath = Join-Path $env:USERPROFILE ".cargo\bin\rustup.exe"
  if (-not (Test-Path -LiteralPath $rustupPath -PathType Leaf)) {
    return
  }

  & $rustupPath default stable-x86_64-pc-windows-msvc
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "rustup default stable-x86_64-pc-windows-msvc failed with exit code $LASTEXITCODE"
  }
}

function Write-SummaryJsonFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Json
  )

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return
  }

  $resolvedPath = [System.IO.Path]::GetFullPath($Path)
  $parentDir = Split-Path -Parent $resolvedPath
  if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir -PathType Container)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
  }

  Set-Content -LiteralPath $resolvedPath -Value $Json -Encoding UTF8
  Write-Step "summary json written: $resolvedPath"
}

$summary = [ordered]@{
  status = "unknown"
  mode = $Mode
  tool_report = [ordered]@{}
  desktop_prerequisites = (Get-DefaultDesktopPrerequisiteSummary)
  desktop_assets = (Get-DefaultDesktopAssetSummary)
  missing_package_ids = @()
  desktop_asset_issue_ids = @()
  install_missing_enabled = [bool]$InstallMissing
  install_attempted = $false
  install_completed = $false
  install_attempted_package_ids = @()
  install_completed_package_ids = @()
  install_failed_package_ids = @()
  asset_remediation_attempted = $false
  asset_remediation_completed = $false
  install_skipped_reason = ""
  recommended_commands = @()
  generated_at_utc = ""
}

$exitCode = 0

try {
  Write-Step "mode=$Mode"

  Ensure-PolicyBypassProcess

  Refresh-SessionPath
  Write-Step "session PATH refreshed from machine+user PATH"

  $commonToolDirs = Get-CommonToolDirectories
  if ($commonToolDirs.Count -gt 0) {
    Add-SessionPathSegments -Segments $commonToolDirs
    Write-Step "session PATH augmented with common tool directories: $($commonToolDirs -join ';')"
  }

  $report = Get-ToolReport
  $summary.tool_report = Convert-ToolReport -Report $report
  Show-ToolReport -Report $report
  $desktopPrerequisiteReport = Get-DesktopPrerequisiteReport
  $summary.desktop_prerequisites = Convert-DesktopPrerequisiteReport -Report $desktopPrerequisiteReport
  Show-DesktopPrerequisiteReport -Report $desktopPrerequisiteReport
  $desktopAssetReport = Get-DesktopAssetReport
  $summary.desktop_assets = Convert-DesktopAssetReport -Report $desktopAssetReport
  $summary.desktop_asset_issue_ids = @($desktopAssetReport.issue_ids)
  Show-DesktopAssetReport -Report $desktopAssetReport

  $missingPackageIds = @(Get-MissingPackageIds -Report $report -DesktopPrerequisiteReport $desktopPrerequisiteReport)
  $summary.missing_package_ids = @($missingPackageIds)
  Show-MissingDependencies -PackageIds $missingPackageIds
  Show-DesktopAssetIssues -IssueIds @($summary.desktop_asset_issue_ids)

  if ($Mode -eq "fix") {
    if ($InstallMissing) {
      $installableIds = @(Get-InstallablePackageIds -PackageIds $missingPackageIds)
      if ($installableIds.Count -gt 0) {
        if ([string]::IsNullOrWhiteSpace($report.winget)) {
          $summary.install_skipped_reason = "winget is missing; remediation skipped"
          Write-Step "winget was not detected; cannot run automatic remediation"
        } else {
          $summary.install_attempted = $true
          $attemptedIds = New-Object System.Collections.ArrayList
          $completedIds = New-Object System.Collections.ArrayList
          $failedIds = New-Object System.Collections.ArrayList

          foreach ($packageId in $installableIds) {
            [void]$attemptedIds.Add($packageId)
            try {
              Install-WingetPackage -WingetPath $report.winget -PackageId $packageId
              [void]$completedIds.Add($packageId)
            } catch {
              [void]$failedIds.Add($packageId)
              throw
            }
          }

          $summary.install_attempted_package_ids = @($attemptedIds.ToArray())
          $summary.install_completed_package_ids = @($completedIds.ToArray())
          $summary.install_failed_package_ids = @($failedIds.ToArray())
          $summary.install_completed = ($failedIds.Count -eq 0)

          if ($summary.install_completed_package_ids -contains "Rustlang.Rustup") {
            Configure-RustupDefaultToolchain
          }

          Refresh-SessionPath
          if ($commonToolDirs.Count -gt 0) {
            Add-SessionPathSegments -Segments $commonToolDirs
          }
          Write-Step "session PATH refreshed after remediation"

          $report = Get-ToolReport
          $summary.tool_report = Convert-ToolReport -Report $report
          Show-ToolReport -Report $report
          $desktopPrerequisiteReport = Get-DesktopPrerequisiteReport
          $summary.desktop_prerequisites = Convert-DesktopPrerequisiteReport -Report $desktopPrerequisiteReport
          Show-DesktopPrerequisiteReport -Report $desktopPrerequisiteReport
          $missingPackageIds = @(Get-MissingPackageIds -Report $report -DesktopPrerequisiteReport $desktopPrerequisiteReport)
          $summary.missing_package_ids = @($missingPackageIds)
          Show-MissingDependencies -PackageIds $missingPackageIds
        }
      } else {
        $summary.install_skipped_reason = "nothing installable via winget"
        Write-Step "no installable package ids pending remediation"
      }

      $assetRemediationResult = Invoke-DesktopAssetRemediation -DesktopAssetReport $desktopAssetReport -ToolReport $report
      $summary.asset_remediation_attempted = [bool]$assetRemediationResult.attempted
      $summary.asset_remediation_completed = [bool]$assetRemediationResult.completed
      $desktopAssetReport = $assetRemediationResult.report
      $summary.desktop_assets = Convert-DesktopAssetReport -Report $desktopAssetReport
      $summary.desktop_asset_issue_ids = @($desktopAssetReport.issue_ids)
      Show-DesktopAssetReport -Report $desktopAssetReport
      Show-DesktopAssetIssues -IssueIds @($summary.desktop_asset_issue_ids)
    } else {
      $summary.install_skipped_reason = "InstallMissing switch not provided"
      Write-Step "fix mode selected without -InstallMissing; remediation skipped"
    }
  }

  $hasBlockingIssues = @($summary.missing_package_ids).Count -gt 0 -or @($summary.desktop_asset_issue_ids).Count -gt 0
  if (-not $hasBlockingIssues) {
    if ($Mode -eq "fix" -and $summary.install_attempted) {
      $summary.status = "fixed"
    } else {
      $summary.status = "ok"
    }
  } else {
    if ($Mode -eq "fix" -and $InstallMissing -and $DryRun -and ($summary.install_attempted -or $summary.asset_remediation_attempted)) {
      $summary.status = "dry-run"
    } else {
      $summary.status = "missing"
    }
  }

  $recommendedCommands = @(Get-RecommendedCommands -MissingPackageIds @($summary.missing_package_ids) -DesktopAssetIssueIds @($summary.desktop_asset_issue_ids))
  $summary.recommended_commands = @($recommendedCommands)

  Write-Step "status=$($summary.status)"
  Show-RecommendedCommands -Commands $recommendedCommands
  Write-Step "next step: run scripts/windows/desktop_native_bootstrap.ps1 -Mode run-full (or scripts/windows/desktop_one_click.ps1)"
} catch {
  $summary.status = "error"
  $summary.error = $_.Exception.Message
  $exitCode = 1
  Write-Error "[desktop-doctor] $($_.Exception.Message)"
}

$summary.generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
$summaryJsonText = $summary | ConvertTo-Json -Depth 8

if (-not [string]::IsNullOrWhiteSpace($SummaryJson)) {
  Write-SummaryJsonFile -Path $SummaryJson -Json $summaryJsonText
}

if ($PrintSummaryJson -eq 1) {
  Write-Output $summaryJsonText
}

exit $exitCode
