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

function Ensure-PolicyBypassProcess {
  if (-not $EnablePolicyBypass) {
    Write-Step "execution policy left unchanged (pass -EnablePolicyBypass to opt in)"
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

function Get-RecommendedCommands {
  param(
    [AllowEmptyCollection()]
    [string[]]$MissingPackageIds = @()
  )

  $commands = New-Object System.Collections.ArrayList
  Add-UniqueValue -List $commands -Value "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"

  foreach ($packageId in $MissingPackageIds) {
    foreach ($dependencyCommand in @(Get-DependencyRecommendedCommands -PackageId $packageId)) {
      Add-UniqueValue -List $commands -Value $dependencyCommand
    }
  }

  Add-UniqueValue -List $commands -Value "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_shell.cmd npm install"
  Add-UniqueValue -List $commands -Value "scripts\windows\desktop_shell.cmd npm run tauri -- dev"
  Add-UniqueValue -List $commands -Value "npm.cmd install"
  Add-UniqueValue -List $commands -Value "npm.cmd run tauri -- dev"
  Add-UniqueValue -List $commands -Value "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_one_click.ps1"

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
  missing_package_ids = @()
  install_missing_enabled = [bool]$InstallMissing
  install_attempted = $false
  install_completed = $false
  install_attempted_package_ids = @()
  install_completed_package_ids = @()
  install_failed_package_ids = @()
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

  $missingPackageIds = @(Get-MissingPackageIds -Report $report -DesktopPrerequisiteReport $desktopPrerequisiteReport)
  $summary.missing_package_ids = @($missingPackageIds)
  Show-MissingDependencies -PackageIds $missingPackageIds

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
    } else {
      $summary.install_skipped_reason = "InstallMissing switch not provided"
      Write-Step "fix mode selected without -InstallMissing; remediation skipped"
    }
  }

  if ($summary.missing_package_ids.Count -eq 0) {
    if ($Mode -eq "fix" -and $summary.install_attempted) {
      $summary.status = "fixed"
    } else {
      $summary.status = "ok"
    }
  } else {
    if ($Mode -eq "fix" -and $InstallMissing -and $DryRun -and $summary.install_attempted) {
      $summary.status = "dry-run"
    } else {
      $summary.status = "missing"
    }
  }

  $recommendedCommands = @(Get-RecommendedCommands -MissingPackageIds @($summary.missing_package_ids))
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
