param(
  [ValidateSet("check", "bootstrap", "run-api", "run-desktop", "run-full")]
  [string]$Mode = "bootstrap",
  [Alias("LaunchStrategy")]
  [ValidateSet("dev", "packaged", "auto")]
  [string]$DesktopLaunchStrategy = "auto",
  [string]$DesktopExecutableOverridePath = "",
  [switch]$InstallMissing,
  [switch]$SkipPathRefresh,
  [switch]$EnablePolicyBypass,
  [switch]$DryRun,
  [switch]$ForceNpmInstall,
  [string]$ApiAddr = "127.0.0.1:8095",
  [string]$CommandRunner = ""
)

$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-native-bootstrap] $Message"
}

function Resolve-RepoRoot {
  $scriptDir = $PSScriptRoot
  if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $PSCommandPath
  }
  return (Resolve-Path (Join-Path $scriptDir "..\..")).Path
}

function Get-CommandPath {
  param([string]$Name)
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($null -eq $cmd) {
    return ""
  }
  return [string]$cmd.Source
}

function Quote-PowerShellSingleQuotedString {
  param([Parameter(Mandatory = $true)][string]$Value)
  return "'" + ($Value -replace "'", "''") + "'"
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

  $path = Get-CommandPath $Name
  $allowWindowsAppsAlias = $Name.ToLowerInvariant() -eq "winget"
  if (-not [string]::IsNullOrWhiteSpace($path) -and ($allowWindowsAppsAlias -or $path -notmatch '\\WindowsApps\\')) {
    return $path
  }

  $programFiles = [Environment]::GetFolderPath("ProgramFiles")
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $userProfile = [Environment]::GetFolderPath("UserProfile")
  $systemDrive = [Environment]::GetEnvironmentVariable("SystemDrive", "Process")

  $candidates = @()
  switch ($Name.ToLowerInvariant()) {
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
    $scriptPath = Quote-PowerShellSingleQuotedString -Value $PSCommandPath
    $modeArg = " -Mode " + (Quote-PowerShellSingleQuotedString -Value $Mode)
    $desktopLaunchStrategyArg = " -DesktopLaunchStrategy " + (Quote-PowerShellSingleQuotedString -Value $DesktopLaunchStrategy)
    $desktopExecutableOverrideArg = if (-not [string]::IsNullOrWhiteSpace($DesktopExecutableOverridePath)) {
      " -DesktopExecutableOverridePath " + (Quote-PowerShellSingleQuotedString -Value $DesktopExecutableOverridePath)
    } else {
      ""
    }
    $installMissingArg = if ($InstallMissing) { " -InstallMissing" } else { "" }
    $skipPathRefreshArg = if ($SkipPathRefresh) { " -SkipPathRefresh" } else { "" }
    $dryRunArg = if ($DryRun) { " -DryRun" } else { "" }
    $forceNpmInstallArg = if ($ForceNpmInstall) { " -ForceNpmInstall" } else { "" }
    $apiAddrArg = " -ApiAddr " + (Quote-PowerShellSingleQuotedString -Value $ApiAddr)
    $commandRunnerArg = if (-not [string]::IsNullOrWhiteSpace($CommandRunner)) {
      " -CommandRunner " + (Quote-PowerShellSingleQuotedString -Value $CommandRunner)
    } else {
      ""
    }
    Write-Step ("rerun with process-scope bypass: powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File {0}{1}{2}{3}{4}{5}{6}{7}{8}{9}" -f $scriptPath, $modeArg, $desktopLaunchStrategyArg, $desktopExecutableOverrideArg, $installMissingArg, $skipPathRefreshArg, $dryRunArg, $forceNpmInstallArg, $apiAddrArg, $commandRunnerArg)
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

function New-DesktopLaunchError {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Headline,
    [string[]]$Hints = @()
  )

  $lines = @($Headline)
  foreach ($hint in $Hints) {
    $lines += "- $hint"
  }
  return ($lines -join [Environment]::NewLine)
}

function Get-DesktopPackagedExecutableCandidates {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath
  )

  $desktopDir = Join-Path $RepoRootPath "apps\desktop"
  $roots = @(
    (Join-Path $desktopDir "src-tauri\target\release"),
    (Join-Path $desktopDir "target\release")
  )

  $candidates = @()
  foreach ($root in $roots) {
    $candidates += (Join-Path $root "tdpn-desktop.exe")
    $candidates += (Join-Path $root "bundle\nsis\tdpn-desktop.exe")
    $candidates += (Join-Path $root "bundle\nsis\tdpn-desktop\tdpn-desktop.exe")
    $candidates += (Join-Path $root "bundle\msi\tdpn-desktop.exe")
    $candidates += (Join-Path $root "bundle\msi\tdpn-desktop\tdpn-desktop.exe")
  }

  return $candidates
}

function Resolve-DesktopExecutablePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [string]$DesktopExecutableOverridePath
  )

  if (-not [string]::IsNullOrWhiteSpace($DesktopExecutableOverridePath)) {
    $candidateOverride = $DesktopExecutableOverridePath.Trim()
    if (-not (Test-Path -LiteralPath $candidateOverride -PathType Leaf)) {
      throw (New-DesktopLaunchError -Headline "desktop executable override was not found: $candidateOverride" -Hints @(
        "Pass -DesktopExecutableOverridePath with the full path to a packaged TDPN Desktop executable.",
        "For a local build, try the packaged output under apps\desktop\src-tauri\target\release after building the desktop app."
      ))
    }
    return (Resolve-Path -LiteralPath $candidateOverride).Path
  }

  foreach ($candidate in (Get-DesktopPackagedExecutableCandidates -RepoRootPath $RepoRootPath)) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }

  return ""
}

function Resolve-DesktopLaunchPlan {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [ValidateSet("dev", "packaged", "auto")]
    [string]$DesktopLaunchStrategy = "auto",
    [string]$DesktopExecutableOverridePath = ""
  )

  $normalizedStrategy = $DesktopLaunchStrategy.Trim().ToLowerInvariant()
  if ($normalizedStrategy -eq "dev") {
    return [PSCustomObject]@{
      Strategy = "dev"
      DesktopExecutablePath = ""
      DesktopExecutableSource = "dev"
      RequiresDesktopBuildTools = $true
    }
  }

  $packagedExecutablePath = Resolve-DesktopExecutablePath -RepoRootPath $RepoRootPath -DesktopExecutableOverridePath $DesktopExecutableOverridePath
  if (-not [string]::IsNullOrWhiteSpace($packagedExecutablePath)) {
    return [PSCustomObject]@{
      Strategy = "packaged"
      DesktopExecutablePath = $packagedExecutablePath
      DesktopExecutableSource = if (-not [string]::IsNullOrWhiteSpace($DesktopExecutableOverridePath)) { "override" } else { "packaged-default" }
      RequiresDesktopBuildTools = $false
    }
  }

  if ($normalizedStrategy -eq "packaged") {
    throw (New-DesktopLaunchError -Headline "packaged desktop launch was requested, but no packaged executable was found." -Hints @(
      "Build the desktop app first, then rerun with -DesktopLaunchStrategy packaged.",
      "Or pass -DesktopExecutableOverridePath to point at the packaged executable directly.",
      "For one-click startup, use -DesktopLaunchStrategy auto and let the script fall back to dev mode when no packaged executable exists."
    ))
  }

  return [PSCustomObject]@{
    Strategy = "dev"
    DesktopExecutablePath = ""
    DesktopExecutableSource = "auto-fallback-dev"
    RequiresDesktopBuildTools = $true
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
  $wingetPath = Resolve-ToolPath "winget"
  $gitPath = Resolve-ToolPath "git"
  $gitBashPath = Resolve-GitBashPath

  return [PSCustomObject]@{
    go = $goPath
    node = $nodePath
    npm = $npmPath
    rustc = $rustcPath
    cargo = $cargoPath
    git = $gitPath
    git_bash = $gitBashPath
    winget = $wingetPath
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
  Write-Host ("  winget: " + $(if ($Report.winget) { $Report.winget } else { "missing" }))
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
    "Git.Git" { return "Git for Windows bash.exe" }
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
    default { return "winget install --id $PackageId --exact" }
  }
}

function Format-MissingDependencyMessage {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$PackageIds,
    [string]$SelectedMode = ""
  )

  $lines = @()
  if (-not [string]::IsNullOrWhiteSpace($SelectedMode)) {
    $lines += "required dependencies missing for mode '$SelectedMode':"
  } else {
    $lines += "missing prerequisites detected:"
  }

  foreach ($packageId in $PackageIds) {
    $label = Get-DependencyLabel -PackageId $packageId
    $hint = Get-DependencyInstallHint -PackageId $packageId
    $lines += ("- {0}: install with {1}" -f $label, $hint)
  }

  if ($PackageIds -contains "GoLang.Go" -or $PackageIds -contains "OpenJS.NodeJS.LTS" -or $PackageIds -contains "Rustlang.Rustup") {
    $lines += "- rerun with -InstallMissing to let winget install what it can after App Installer is available"
  }

  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    $lines += "- winget was not found; install App Installer first, then rerun with -InstallMissing"
  }

  return ($lines -join [Environment]::NewLine)
}

function Get-MissingIds {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report,
    [Parameter(Mandatory = $true)]
    [string]$SelectedMode,
    [Parameter(Mandatory = $true)]
    [pscustomobject]$DesktopLaunchPlan
  )

  $ids = @{}
  $needsDesktopBuildTools = $DesktopLaunchPlan.RequiresDesktopBuildTools

  switch ($SelectedMode) {
    "run-api" {
      if (-not $Report.go) {
        $ids["GoLang.Go"] = $true
      }
      if (-not $Report.git_bash) {
        $ids["Git.Git"] = $true
      }
    }
    "run-desktop" {
      if ($needsDesktopBuildTools) {
        if (-not $Report.node -or -not $Report.npm) {
          $ids["OpenJS.NodeJS.LTS"] = $true
        }
        if (-not $Report.rustc -or -not $Report.cargo) {
          $ids["Rustlang.Rustup"] = $true
        }
      }
    }
    "run-full" {
      if (-not $Report.go) {
        $ids["GoLang.Go"] = $true
      }
      if (-not $Report.git_bash) {
        $ids["Git.Git"] = $true
      }
      if ($needsDesktopBuildTools) {
        if (-not $Report.node -or -not $Report.npm) {
          $ids["OpenJS.NodeJS.LTS"] = $true
        }
        if (-not $Report.rustc -or -not $Report.cargo) {
          $ids["Rustlang.Rustup"] = $true
        }
      }
    }
    default {
      if (-not $Report.go) {
        $ids["GoLang.Go"] = $true
      }
      if (-not $Report.git_bash) {
        $ids["Git.Git"] = $true
      }
      if ($needsDesktopBuildTools) {
        if (-not $Report.node -or -not $Report.npm) {
          $ids["OpenJS.NodeJS.LTS"] = $true
        }
        if (-not $Report.rustc -or -not $Report.cargo) {
          $ids["Rustlang.Rustup"] = $true
        }
      }
    }
  }
  return @($ids.Keys)
}

function Install-WingetPackage {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  if ($DryRun) {
    Write-Step "dry-run install: winget install --id $PackageId --exact --accept-source-agreements --accept-package-agreements --silent"
    return
  }

  Write-Step "installing missing dependency via winget: $PackageId"
  & winget install --id $PackageId --exact --accept-source-agreements --accept-package-agreements --silent
  if ($LASTEXITCODE -ne 0) {
    throw "winget install failed for $PackageId (exit code $LASTEXITCODE)"
  }
}

function Install-MissingDependencies {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$PackageIds
  )

  if ($PackageIds.Count -eq 0) {
    return
  }
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "winget is not available. Install App Installer first, then rerun with -InstallMissing or install prerequisites manually."
  }

  foreach ($id in $PackageIds) {
    Install-WingetPackage -PackageId $id
  }

  $rustupPath = Join-Path $env:USERPROFILE ".cargo\bin\rustup.exe"
  if (Test-Path -LiteralPath $rustupPath -PathType Leaf) {
    if ($DryRun) {
      Write-Step "dry-run: $rustupPath default stable-x86_64-pc-windows-msvc"
    } else {
      & $rustupPath default stable-x86_64-pc-windows-msvc
      if ($LASTEXITCODE -ne 0) {
        Write-Warning "rustup default stable-x86_64-pc-windows-msvc failed with exit code $LASTEXITCODE"
      }
    }
  }
}

function Assert-ToolsForMode {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report,
    [Parameter(Mandatory = $true)]
    [string]$SelectedMode,
    [Parameter(Mandatory = $true)]
    [pscustomobject]$DesktopLaunchPlan
  )

  $missingPackageIds = Get-MissingIds -Report $Report -SelectedMode $SelectedMode -DesktopLaunchPlan $DesktopLaunchPlan
  if ($missingPackageIds.Count -gt 0) {
    $uniquePackageIds = @()
    $seen = @{}
    foreach ($packageId in $missingPackageIds) {
      if ($seen.ContainsKey($packageId)) {
        continue
      }
      $seen[$packageId] = $true
      $uniquePackageIds += $packageId
    }
    throw (Format-MissingDependencyMessage -PackageIds $uniquePackageIds -SelectedMode $SelectedMode)
  }
}

function Resolve-LocalApiAddr {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Addr
  )

  $Addr = $Addr.Trim()
  if ([string]::IsNullOrWhiteSpace($Addr)) {
    throw "ApiAddr is required"
  }

  $hostName = ""
  $port = 0
  if ($Addr.StartsWith("[")) {
    if ($Addr -notmatch "^\[(.+)\]:(\d+)$") {
      throw "ApiAddr must be [host]:port for IPv6 loopback"
    }
    $hostName = $matches[1]
    $port = [int]$matches[2]
  } else {
    if ($Addr -notmatch "^([^:]+):(\d+)$") {
      throw "ApiAddr must be host:port"
    }
    $hostName = $matches[1]
    $port = [int]$matches[2]
  }
  if ($port -lt 1 -or $port -gt 65535) {
    throw "ApiAddr port must be in 1..65535"
  }
  $normalizedHost = $hostName.Trim().ToLowerInvariant()
  if ($normalizedHost -ne "127.0.0.1" -and $normalizedHost -ne "localhost" -and $normalizedHost -ne "::1") {
    throw "ApiAddr must target loopback only (allowed hosts: 127.0.0.1, localhost, ::1)"
  }

  return "http://$Addr/v1/health"
}

function Wait-LocalApiReady {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Addr,
    [int]$TimeoutSec = 25
)

  $endpoint = Resolve-LocalApiAddr -Addr $Addr
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $result = Invoke-RestMethod -Uri $endpoint -Method Get -TimeoutSec 3
      if ($null -ne $result -and $result.ok -eq $true) {
        Write-Step "local api is healthy: $endpoint"
        return $true
      }
    } catch {
      Start-Sleep -Seconds 1
    }
  }
  Write-Warning "local api health check timed out: $endpoint"
  return $false
}

function Validate-LocalApiAddr {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Addr
  )

  [void](Resolve-LocalApiAddr -Addr $Addr)
}

function Invoke-LocalApiForeground {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [Parameter(Mandatory = $true)]
    [string]$Addr,
    [string]$RunnerPath
  )

  $scriptPath = Join-Path $RepoRootPath "scripts\windows\local_api_session.ps1"
  $args = @("-NoProfile")
  if ($EnablePolicyBypass) {
    $args += @("-ExecutionPolicy", "Bypass")
  }
  $args += @("-File", $scriptPath, "-ApiAddr", $Addr)
  if (-not [string]::IsNullOrWhiteSpace($RunnerPath)) {
    $args += @("-CommandRunner", $RunnerPath)
  }

  if ($DryRun) {
    Write-Step "dry-run local api foreground: powershell.exe $($args -join ' ')"
    return
  }

  & powershell.exe @args
  if ($LASTEXITCODE -ne 0) {
    throw "local api foreground session exited with code $LASTEXITCODE"
  }
}

function Start-LocalApiBackgroundWindow {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [Parameter(Mandatory = $true)]
    [string]$Addr,
    [string]$RunnerPath
  )

  $scriptPath = Join-Path $RepoRootPath "scripts\windows\local_api_session.ps1"
  $args = @("-NoExit", "-NoProfile")
  if ($EnablePolicyBypass) {
    $args += @("-ExecutionPolicy", "Bypass")
  }
  $args += @("-File", $scriptPath, "-ApiAddr", $Addr)
  if (-not [string]::IsNullOrWhiteSpace($RunnerPath)) {
    $args += @("-CommandRunner", $RunnerPath)
  }

  if ($DryRun) {
    Write-Step "dry-run local api background: powershell.exe $($args -join ' ')"
    return $null
  }

  $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $args -PassThru
  Write-Step "started local api window pid=$($proc.Id)"
  return $proc
}

function Invoke-DesktopDev {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath
  )

  $desktopDir = Join-Path $RepoRootPath "apps\desktop"
  if (-not (Test-Path -LiteralPath (Join-Path $desktopDir "package.json") -PathType Leaf)) {
    throw "desktop package.json not found: $desktopDir"
  }

  $iconPath = Join-Path $desktopDir "src-tauri\icons\icon.ico"
  Ensure-DesktopIconAsset -IconPath $iconPath

  $npmCmd = Resolve-ToolPath "npm.cmd"
  if ([string]::IsNullOrWhiteSpace($npmCmd)) {
    $npmCmd = Resolve-ToolPath "npm"
  }
  if ([string]::IsNullOrWhiteSpace($npmCmd)) {
    throw "npm not found. Install Node.js LTS first."
  }

  Push-Location $desktopDir
  try {
    $needsInstall = $ForceNpmInstall -or -not (Test-Path -LiteralPath (Join-Path $desktopDir "node_modules") -PathType Container)
    if ($needsInstall) {
      if ($DryRun) {
        Write-Step "dry-run desktop install: npm.cmd install"
      } else {
        Write-Step "running: npm.cmd install"
        & $npmCmd install
        if ($LASTEXITCODE -ne 0) {
          throw "npm install failed with exit code $LASTEXITCODE"
        }
      }
    } else {
      Write-Step "npm install skipped (node_modules exists)"
    }

    if ($DryRun) {
      Write-Step "dry-run desktop dev: npm.cmd run tauri -- dev"
      return
    }

    Write-Step "running: npm.cmd run tauri -- dev"
    & $npmCmd run tauri -- dev
    if ($LASTEXITCODE -ne 0) {
      throw "npm run tauri -- dev failed with exit code $LASTEXITCODE"
    }
  } finally {
    Pop-Location
  }
}

function Invoke-DesktopPackaged {
  param(
    [Parameter(Mandatory = $true)]
    [string]$DesktopExecutablePath
  )

  if ($DryRun) {
    Write-Step "dry-run packaged desktop: $DesktopExecutablePath"
    return
  }

  Write-Step "running packaged desktop: $DesktopExecutablePath"
  & $DesktopExecutablePath
  if ($LASTEXITCODE -ne 0) {
    throw "packaged desktop executable exited with code $LASTEXITCODE"
  }
}

function Ensure-DesktopIconAsset {
  param(
    [Parameter(Mandatory = $true)]
    [string]$IconPath
  )

  if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
    return
  }

  $iconDir = Split-Path -Parent $IconPath
  if (-not (Test-Path -LiteralPath $iconDir -PathType Container)) {
    if ($DryRun) {
      Write-Step "dry-run desktop asset scaffold: would create $IconPath"
      return
    }
    New-Item -ItemType Directory -Path $iconDir -Force | Out-Null
  }

  if ($DryRun) {
    Write-Step "dry-run desktop asset scaffold: would create $IconPath"
    return
  }

  Write-Step "desktop icon missing; creating placeholder scaffold: $IconPath"
  $icoBytes = [byte[]]@(
    0x00,0x00,0x01,0x00,0x01,0x00,
    0x01,0x01,0x00,0x00,0x01,0x00,0x20,0x00,0x30,0x00,0x00,0x00,0x16,0x00,0x00,0x00,
    0x28,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x01,0x00,0x20,0x00,
    0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,
    0x00,0x00,0x00,0x00
  )
  [System.IO.File]::WriteAllBytes($IconPath, $icoBytes)
}

$repoRoot = Resolve-RepoRoot

Write-Step "mode=$Mode"
Write-Step "desktop_launch_strategy=$DesktopLaunchStrategy"
if (-not [string]::IsNullOrWhiteSpace($DesktopExecutableOverridePath)) {
  Write-Step "desktop_executable_override=$DesktopExecutableOverridePath"
}
Write-Step "repo_root=$repoRoot"

Ensure-PolicyBypassProcess

if (-not $SkipPathRefresh) {
  Refresh-SessionPath
  Write-Step "session PATH refreshed from machine+user PATH"
} else {
  Write-Step "session PATH refresh skipped by flag"
}

$commonToolDirs = Get-CommonToolDirectories
if ($commonToolDirs.Count -gt 0) {
  Add-SessionPathSegments -Segments $commonToolDirs
  Write-Step "session PATH augmented with common tool directories: $($commonToolDirs -join ';')"
}

$report = Get-ToolReport
Show-ToolReport -Report $report

$desktopLaunchPlan = Resolve-DesktopLaunchPlan -RepoRootPath $repoRoot -DesktopLaunchStrategy $DesktopLaunchStrategy -DesktopExecutableOverridePath $DesktopExecutableOverridePath
Write-Step ("desktop launch resolved: strategy={0}, source={1}{2}" -f $desktopLaunchPlan.Strategy, $desktopLaunchPlan.DesktopExecutableSource, $(if (-not [string]::IsNullOrWhiteSpace($desktopLaunchPlan.DesktopExecutablePath)) { ", path=$($desktopLaunchPlan.DesktopExecutablePath)" } else { "" }))

$missingPackageIds = Get-MissingIds -Report $report -SelectedMode $Mode -DesktopLaunchPlan $desktopLaunchPlan
if ($missingPackageIds.Count -gt 0) {
  Write-Step ("missing dependency package ids: " + ($missingPackageIds -join ", "))
  if ($InstallMissing) {
    Install-MissingDependencies -PackageIds $missingPackageIds
    if (-not $SkipPathRefresh) {
      Refresh-SessionPath
      Write-Step "session PATH refreshed after installations"
    }
    $report = Get-ToolReport
    Show-ToolReport -Report $report
  } else {
    Write-Step "tip: rerun with -InstallMissing to auto-install prerequisites with winget"
  }
} else {
  Write-Step "all primary dependencies detected"
}

if ($Mode -eq "check") {
  Write-Step "check completed"
  exit 0
}

if ($Mode -eq "bootstrap") {
  if ((Get-MissingIds -Report $report).Count -gt 0) {
    throw "bootstrap completed with missing prerequisites; rerun with -InstallMissing or install manually"
  }
  Write-Step "bootstrap completed"
  exit 0
}

Assert-ToolsForMode -Report $report -SelectedMode $Mode -DesktopLaunchPlan $desktopLaunchPlan

if ($Mode -eq "run-api") {
  Invoke-LocalApiForeground -RepoRootPath $repoRoot -Addr $ApiAddr -RunnerPath $CommandRunner
  exit 0
}

if ($Mode -eq "run-desktop") {
  if ($desktopLaunchPlan.Strategy -eq "packaged") {
    Invoke-DesktopPackaged -DesktopExecutablePath $desktopLaunchPlan.DesktopExecutablePath
  } else {
    Invoke-DesktopDev -RepoRootPath $repoRoot
  }
  exit 0
}

if ($Mode -eq "run-full") {
  Validate-LocalApiAddr -Addr $ApiAddr
  if ($DryRun) {
    Write-Step "dry-run run-full: would start local api on $ApiAddr"
    if ($desktopLaunchPlan.Strategy -eq "packaged") {
      Write-Step "dry-run run-full: would launch packaged desktop: $($desktopLaunchPlan.DesktopExecutablePath)"
    } else {
      Write-Step "dry-run run-full: would launch desktop dev with npm.cmd run tauri -- dev"
    }
    exit 0
  }
  $apiProc = Start-LocalApiBackgroundWindow -RepoRootPath $repoRoot -Addr $ApiAddr -RunnerPath $CommandRunner
  $apiHealthy = $false
  try {
    $apiHealthy = [bool](Wait-LocalApiReady -Addr $ApiAddr -TimeoutSec 25)
    if (-not $apiHealthy) {
      throw "local api health check did not pass"
    }
    if ($desktopLaunchPlan.Strategy -eq "packaged") {
      Invoke-DesktopPackaged -DesktopExecutablePath $desktopLaunchPlan.DesktopExecutablePath
    } else {
      Invoke-DesktopDev -RepoRootPath $repoRoot
    }
  } finally {
    if (-not $apiHealthy -and $null -ne $apiProc) {
      try {
        if (-not $apiProc.HasExited) {
          Stop-Process -Id $apiProc.Id -Force -ErrorAction Stop
          Write-Step "stopped local api window pid=$($apiProc.Id) after failed startup"
        }
      } catch {
        Write-Warning "failed to stop local api process pid=$($apiProc.Id): $($_.Exception.Message)"
      }
    }
  }
  exit 0
}

throw "unsupported mode: $Mode"
