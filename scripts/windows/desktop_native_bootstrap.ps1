param(
  [ValidateSet("check", "bootstrap", "run-api", "run-desktop", "run-full")]
  [string]$Mode = "bootstrap",
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

  $candidates = @(
    "C:\Program Files\Git\bin\bash.exe",
    "C:\Program Files\Git\usr\bin\bash.exe",
    "C:\Program Files (x86)\Git\bin\bash.exe",
    "C:\Program Files (x86)\Git\usr\bin\bash.exe"
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return $candidate
    }
  }
  return ""
}

function Get-ToolReport {
  $goPath = Get-CommandPath "go"
  $nodePath = Get-CommandPath "node"
  $npmCmdPath = Get-CommandPath "npm.cmd"
  $npmPath = if (-not [string]::IsNullOrWhiteSpace($npmCmdPath)) { $npmCmdPath } else { Get-CommandPath "npm" }
  $rustcPath = Get-CommandPath "rustc"
  $cargoPath = Get-CommandPath "cargo"
  $wingetPath = Get-CommandPath "winget"
  $gitPath = Get-CommandPath "git"
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

function Get-MissingIds {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Report
  )

  $ids = @{}
  if (-not $Report.go) {
    $ids["GoLang.Go"] = $true
  }
  if (-not $Report.node -or -not $Report.npm) {
    $ids["OpenJS.NodeJS.LTS"] = $true
  }
  if (-not $Report.rustc -or -not $Report.cargo) {
    $ids["Rustlang.Rustup"] = $true
  }
  if (-not $Report.git_bash) {
    $ids["Git.Git"] = $true
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
    throw "winget is not available. Install App Installer or install dependencies manually."
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
    [string]$SelectedMode
  )

  $missing = @()
  switch ($SelectedMode) {
    "run-api" {
      if (-not $Report.go) { $missing += "go" }
      if (-not $Report.git_bash) { $missing += "git bash" }
    }
    "run-desktop" {
      if (-not $Report.node) { $missing += "node" }
      if (-not $Report.npm) { $missing += "npm" }
      if (-not $Report.rustc) { $missing += "rustc" }
      if (-not $Report.cargo) { $missing += "cargo" }
    }
    "run-full" {
      if (-not $Report.go) { $missing += "go" }
      if (-not $Report.node) { $missing += "node" }
      if (-not $Report.npm) { $missing += "npm" }
      if (-not $Report.rustc) { $missing += "rustc" }
      if (-not $Report.cargo) { $missing += "cargo" }
      if (-not $Report.git_bash) { $missing += "git bash" }
    }
  }

  if ($missing.Count -gt 0) {
    $joined = ($missing -join ", ")
    throw "required dependencies missing for mode '$SelectedMode': $joined"
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

  $host = ""
  $port = 0
  if ($Addr.StartsWith("[")) {
    if ($Addr -notmatch "^\[(.+)\]:(\d+)$") {
      throw "ApiAddr must be [host]:port for IPv6 loopback"
    }
    $host = $matches[1]
    $port = [int]$matches[2]
  } else {
    if ($Addr -notmatch "^([^:]+):(\d+)$") {
      throw "ApiAddr must be host:port"
    }
    $host = $matches[1]
    $port = [int]$matches[2]
  }
  if ($port -lt 1 -or $port -gt 65535) {
    throw "ApiAddr port must be in 1..65535"
  }
  $normalizedHost = $host.Trim().ToLowerInvariant()
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

  $npmCmd = Get-CommandPath "npm.cmd"
  if ([string]::IsNullOrWhiteSpace($npmCmd)) {
    throw "npm.cmd not found in PATH. Install Node.js LTS first."
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

$repoRoot = Resolve-RepoRoot

Write-Step "mode=$Mode"
Write-Step "repo_root=$repoRoot"

Ensure-PolicyBypassProcess

if (-not $SkipPathRefresh) {
  Refresh-SessionPath
  Write-Step "session PATH refreshed from machine+user PATH"
} else {
  Write-Step "session PATH refresh skipped by flag"
}

$report = Get-ToolReport
Show-ToolReport -Report $report

$missingPackageIds = Get-MissingIds -Report $report
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

Assert-ToolsForMode -Report $report -SelectedMode $Mode

if ($Mode -eq "run-api") {
  Invoke-LocalApiForeground -RepoRootPath $repoRoot -Addr $ApiAddr -RunnerPath $CommandRunner
  exit 0
}

if ($Mode -eq "run-desktop") {
  Invoke-DesktopDev -RepoRootPath $repoRoot
  exit 0
}

if ($Mode -eq "run-full") {
  Validate-LocalApiAddr -Addr $ApiAddr
  $apiProc = Start-LocalApiBackgroundWindow -RepoRootPath $repoRoot -Addr $ApiAddr -RunnerPath $CommandRunner
  $apiHealthy = $false
  try {
    $apiHealthy = [bool](Wait-LocalApiReady -Addr $ApiAddr -TimeoutSec 25)
    if (-not $apiHealthy) {
      throw "local api health check did not pass"
    }
    Invoke-DesktopDev -RepoRootPath $repoRoot
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
