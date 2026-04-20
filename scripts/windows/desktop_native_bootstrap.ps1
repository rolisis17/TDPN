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
  [string]$CommandRunner = "",
  [string]$SummaryJson = "",
  [ValidateSet(0, 1)]
  [int]$PrintSummaryJson = 0
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

  $relativePaths = @(
    "gpm-desktop.exe",
    "GPM Desktop.exe",
    "global-private-mesh-desktop.exe",
    "Global Private Mesh Desktop.exe",
    "tdpn-desktop.exe",
    "TDPN Desktop.exe",
    "bundle\nsis\gpm-desktop.exe",
    "bundle\nsis\gpm-desktop\gpm-desktop.exe",
    "bundle\nsis\GPM Desktop.exe",
    "bundle\nsis\GPM Desktop\GPM Desktop.exe",
    "bundle\nsis\global-private-mesh-desktop.exe",
    "bundle\nsis\global-private-mesh-desktop\global-private-mesh-desktop.exe",
    "bundle\nsis\Global Private Mesh Desktop.exe",
    "bundle\nsis\Global Private Mesh Desktop\Global Private Mesh Desktop.exe",
    "bundle\nsis\tdpn-desktop.exe",
    "bundle\nsis\tdpn-desktop\tdpn-desktop.exe",
    "bundle\nsis\TDPN Desktop.exe",
    "bundle\nsis\TDPN Desktop\TDPN Desktop.exe",
    "bundle\msi\gpm-desktop.exe",
    "bundle\msi\gpm-desktop\gpm-desktop.exe",
    "bundle\msi\GPM Desktop.exe",
    "bundle\msi\GPM Desktop\GPM Desktop.exe",
    "bundle\msi\global-private-mesh-desktop.exe",
    "bundle\msi\global-private-mesh-desktop\global-private-mesh-desktop.exe",
    "bundle\msi\Global Private Mesh Desktop.exe",
    "bundle\msi\Global Private Mesh Desktop\Global Private Mesh Desktop.exe",
    "bundle\msi\tdpn-desktop.exe",
    "bundle\msi\tdpn-desktop\tdpn-desktop.exe",
    "bundle\msi\TDPN Desktop.exe",
    "bundle\msi\TDPN Desktop\TDPN Desktop.exe"
  )

  $candidates = @()
  $seen = @{}
  foreach ($root in $roots) {
    foreach ($relativePath in $relativePaths) {
      $candidate = Join-Path $root $relativePath
      $candidateKey = $candidate.TrimEnd("\").ToLowerInvariant()
      if ($seen.ContainsKey($candidateKey)) {
        continue
      }
      $seen[$candidateKey] = $true
      $candidates += $candidate
    }
  }

  return $candidates
}

function Get-DesktopPackagedExecutableEnvOverrides {
  $envVarNames = @(
    "GPM_DESKTOP_PACKAGED_EXE",
    "GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE",
    "TDPN_DESKTOP_PACKAGED_EXE"
  )

  $overrides = @()
  foreach ($envVarName in $envVarNames) {
    $overrides += [PSCustomObject]@{
      Name = $envVarName
      Value = [Environment]::GetEnvironmentVariable($envVarName, "Process")
    }
  }

  return $overrides
}

function Resolve-DesktopExecutableResolution {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [string]$DesktopExecutableOverridePath
  )

  if (-not [string]::IsNullOrWhiteSpace($DesktopExecutableOverridePath)) {
    $candidateOverride = $DesktopExecutableOverridePath.Trim()
    if (-not (Test-Path -LiteralPath $candidateOverride -PathType Leaf)) {
      throw (New-DesktopLaunchError -Headline "desktop executable override was not found: $candidateOverride" -Hints @(
        "Pass -DesktopExecutableOverridePath with the full path to a packaged desktop executable.",
        "For a local build, try the packaged output under apps\desktop\src-tauri\target\release after building the desktop app."
      ))
    }
    return [PSCustomObject]@{
      Path = (Resolve-Path -LiteralPath $candidateOverride).Path
      Source = "override"
    }
  }

  foreach ($envOverride in (Get-DesktopPackagedExecutableEnvOverrides)) {
    $envValue = $envOverride.Value
    if ([string]::IsNullOrWhiteSpace($envValue)) {
      continue
    }

    $candidateOverride = $envValue.Trim()
    if (-not (Test-Path -LiteralPath $candidateOverride -PathType Leaf)) {
      throw (New-DesktopLaunchError -Headline ("desktop executable env override was not found ({0}): {1}" -f $envOverride.Name, $candidateOverride) -Hints @(
        "Set GPM_DESKTOP_PACKAGED_EXE with the full path to a packaged desktop executable (TDPN_DESKTOP_PACKAGED_EXE remains available as a legacy alias; GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE is also supported).",
        ("Unset {0} to allow packaged auto-discovery under apps\desktop\src-tauri\target\release." -f $envOverride.Name),
        "You can also pass -DesktopExecutableOverridePath to force a one-off packaged executable path."
      ))
    }

    return [PSCustomObject]@{
      Path = (Resolve-Path -LiteralPath $candidateOverride).Path
      Source = ("env:{0}" -f $envOverride.Name)
    }
  }

  foreach ($candidate in (Get-DesktopPackagedExecutableCandidates -RepoRootPath $RepoRootPath)) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [PSCustomObject]@{
        Path = (Resolve-Path -LiteralPath $candidate).Path
        Source = "packaged-default"
      }
    }
  }

  return [PSCustomObject]@{
    Path = ""
    Source = ""
  }
}

function Resolve-DesktopExecutablePath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRootPath,
    [string]$DesktopExecutableOverridePath
  )

  $resolution = Resolve-DesktopExecutableResolution -RepoRootPath $RepoRootPath -DesktopExecutableOverridePath $DesktopExecutableOverridePath
  return $resolution.Path
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

  $packagedExecutableResolution = Resolve-DesktopExecutableResolution -RepoRootPath $RepoRootPath -DesktopExecutableOverridePath $DesktopExecutableOverridePath
  $packagedExecutablePath = $packagedExecutableResolution.Path
  if (-not [string]::IsNullOrWhiteSpace($packagedExecutablePath)) {
    return [PSCustomObject]@{
      Strategy = "packaged"
      DesktopExecutablePath = $packagedExecutablePath
      DesktopExecutableSource = $packagedExecutableResolution.Source
      RequiresDesktopBuildTools = $false
    }
  }

  if ($normalizedStrategy -eq "packaged") {
    throw (New-DesktopLaunchError -Headline "packaged desktop launch was requested, but no packaged executable was found." -Hints @(
      "Build the desktop app first, then rerun with -DesktopLaunchStrategy packaged.",
      "Or pass -DesktopExecutableOverridePath to point at the packaged executable directly.",
      "Or set GPM_DESKTOP_PACKAGED_EXE to the packaged executable path (TDPN_DESKTOP_PACKAGED_EXE remains available as a legacy alias; GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE is also supported).",
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

function Get-SummaryToolReport {
  param(
    [pscustomobject]$Report
  )

  return [ordered]@{
    go = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.go)) { $Report.go } else { "" })
    node = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.node)) { $Report.node } else { "" })
    npm = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.npm)) { $Report.npm } else { "" })
    rustc = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.rustc)) { $Report.rustc } else { "" })
    cargo = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.cargo)) { $Report.cargo } else { "" })
    git = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.git)) { $Report.git } else { "" })
    bash = $(if ($null -ne $Report -and -not [string]::IsNullOrWhiteSpace($Report.git_bash)) { $Report.git_bash } else { "" })
  }
}

function Write-SummaryJsonFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$JsonText
  )

  $parent = Split-Path -Parent $Path
  if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  Set-Content -LiteralPath $Path -Value $JsonText -Encoding UTF8
}

function Resolve-SummaryStatus {
  param(
    [Parameter(Mandatory = $true)]
    [int]$ExitCode,
    [Parameter(Mandatory = $true)]
    [bool]$DryRunEnabled,
    [AllowEmptyCollection()]
    [string[]]$MissingPackageIds = @(),
    [Parameter(Mandatory = $true)]
    [bool]$HasError
  )

  if ($HasError) {
    if ($MissingPackageIds.Count -gt 0) {
      return "missing"
    }
    return "error"
  }
  if ($DryRunEnabled) {
    return "dry-run"
  }
  if ($MissingPackageIds.Count -gt 0) {
    return "missing"
  }
  if ($ExitCode -eq 0) {
    return "ok"
  }
  return "error"
}

function Emit-Summary {
  param(
    [Parameter(Mandatory = $true)]
    [hashtable]$Summary
  )

  $json = $Summary | ConvertTo-Json -Depth 8
  if (-not [string]::IsNullOrWhiteSpace($SummaryJson)) {
    try {
      Write-SummaryJsonFile -Path $SummaryJson -JsonText $json
    } catch {
      Write-Warning "failed to write summary json at '$SummaryJson': $($_.Exception.Message)"
    }
  }
  if ($PrintSummaryJson -eq 1) {
    Write-Output $json
  }
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

function Add-UniqueValue {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [System.Collections.ArrayList]$List,
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return
  }
  if ($List -notcontains $Value) {
    [void]$List.Add($Value)
  }
}

function Get-WingetInstallCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PackageId
  )

  return ("winget install --id {0} --exact --accept-source-agreements --accept-package-agreements --silent" -f $PackageId)
}

function Get-RecommendedCommands {
  param(
    [AllowEmptyCollection()]
    [string[]]$MissingPackageIds = @(),
    [string]$SelectedMode = "bootstrap"
  )

  $commands = New-Object System.Collections.ArrayList
  $normalizedMode = $SelectedMode
  if ([string]::IsNullOrWhiteSpace($normalizedMode)) {
    $normalizedMode = "bootstrap"
  }

  Add-UniqueValue -List $commands -Value "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
  Add-UniqueValue -List $commands -Value ("powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode {0}" -f $normalizedMode)
  foreach ($packageId in $MissingPackageIds) {
    Add-UniqueValue -List $commands -Value (Get-WingetInstallCommand -PackageId $packageId)
  }
  Add-UniqueValue -List $commands -Value ("powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode {0} -InstallMissing -EnablePolicyBypass" -f $normalizedMode)
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

function Invoke-BootstrapMain {
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
  $script:BootstrapSummary.tool_report = Get-SummaryToolReport -Report $report

  $desktopLaunchPlan = Resolve-DesktopLaunchPlan -RepoRootPath $repoRoot -DesktopLaunchStrategy $DesktopLaunchStrategy -DesktopExecutableOverridePath $DesktopExecutableOverridePath
  $script:BootstrapSummary.desktop_launch_strategy = $desktopLaunchPlan.Strategy
  $script:BootstrapSummary.desktop_launch_source = $desktopLaunchPlan.DesktopExecutableSource
  $script:BootstrapSummary.desktop_executable_path = $(if (-not [string]::IsNullOrWhiteSpace($desktopLaunchPlan.DesktopExecutablePath)) { $desktopLaunchPlan.DesktopExecutablePath } else { "" })
  Write-Step ("desktop launch resolved: strategy={0}, source={1}{2}" -f $desktopLaunchPlan.Strategy, $desktopLaunchPlan.DesktopExecutableSource, $(if (-not [string]::IsNullOrWhiteSpace($desktopLaunchPlan.DesktopExecutablePath)) { ", path=$($desktopLaunchPlan.DesktopExecutablePath)" } else { "" }))

  $missingPackageIds = Get-MissingIds -Report $report -SelectedMode $Mode -DesktopLaunchPlan $desktopLaunchPlan
  $script:BootstrapSummary.missing_package_ids = @($missingPackageIds)
  if ($missingPackageIds.Count -gt 0) {
    Write-Step ("missing dependency package ids: " + ($missingPackageIds -join ", "))
    if ($InstallMissing) {
      $script:BootstrapSummary.install_attempted = $true
      Install-MissingDependencies -PackageIds $missingPackageIds
      if (-not $SkipPathRefresh) {
        Refresh-SessionPath
        Write-Step "session PATH refreshed after installations"
      }
      $report = Get-ToolReport
      Show-ToolReport -Report $report
      $script:BootstrapSummary.tool_report = Get-SummaryToolReport -Report $report
      $script:BootstrapSummary.missing_package_ids = @(Get-MissingIds -Report $report -SelectedMode $Mode -DesktopLaunchPlan $desktopLaunchPlan)
    } else {
      Write-Step "tip: rerun with -InstallMissing to auto-install prerequisites with winget"
    }
  } else {
    Write-Step "all primary dependencies detected"
  }

  if ($Mode -eq "check") {
    Write-Step "check completed"
    return 0
  }

  if ($Mode -eq "bootstrap") {
    if ((Get-MissingIds -Report $report -SelectedMode $Mode -DesktopLaunchPlan $desktopLaunchPlan).Count -gt 0) {
      throw "bootstrap completed with missing prerequisites; rerun with -InstallMissing or install manually"
    }
    Write-Step "bootstrap completed"
    return 0
  }

  Assert-ToolsForMode -Report $report -SelectedMode $Mode -DesktopLaunchPlan $desktopLaunchPlan

  if ($Mode -eq "run-api") {
    Invoke-LocalApiForeground -RepoRootPath $repoRoot -Addr $ApiAddr -RunnerPath $CommandRunner
    return 0
  }

  if ($Mode -eq "run-desktop") {
    if ($desktopLaunchPlan.Strategy -eq "packaged") {
      Invoke-DesktopPackaged -DesktopExecutablePath $desktopLaunchPlan.DesktopExecutablePath
    } else {
      Invoke-DesktopDev -RepoRootPath $repoRoot
    }
    return 0
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
      return 0
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
    return 0
  }

  throw "unsupported mode: $Mode"
}

$script:BootstrapSummary = [ordered]@{
  generated_at_utc = ""
  status = ""
  mode = $Mode
  dry_run = [bool]$DryRun
  desktop_launch_strategy = $DesktopLaunchStrategy
  desktop_launch_source = ""
  desktop_executable_path = ""
  api_addr = $ApiAddr
  tool_report = (Get-SummaryToolReport -Report $null)
  missing_package_ids = @()
  recommended_commands = @()
  install_missing = [bool]$InstallMissing
  install_attempted = $false
  error = ""
}
$script:BootstrapExitCode = 1
$script:BootstrapErrorMessage = ""

try {
  $script:BootstrapExitCode = Invoke-BootstrapMain
} catch {
  $script:BootstrapErrorMessage = $_.Exception.Message
  throw
} finally {
  if (-not [string]::IsNullOrWhiteSpace($script:BootstrapErrorMessage)) {
    $script:BootstrapSummary.error = $script:BootstrapErrorMessage
  }
  $recommendedCommands = @(Get-RecommendedCommands -MissingPackageIds @($script:BootstrapSummary.missing_package_ids) -SelectedMode $Mode)
  $script:BootstrapSummary.recommended_commands = @($recommendedCommands)
  $script:BootstrapSummary.generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
  $script:BootstrapSummary.status = Resolve-SummaryStatus -ExitCode $script:BootstrapExitCode -DryRunEnabled ([bool]$DryRun) -MissingPackageIds @($script:BootstrapSummary.missing_package_ids) -HasError (-not [string]::IsNullOrWhiteSpace($script:BootstrapSummary.error))
  Show-RecommendedCommands -Commands $recommendedCommands
  Emit-Summary -Summary $script:BootstrapSummary
}

exit $script:BootstrapExitCode
