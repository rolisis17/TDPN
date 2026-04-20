param(
  [ValidateSet("desktop", "local-api", "both")]
  [string]$Workflow = "both",
  [switch]$InstallMissing,
  [switch]$NonInteractive,
  [switch]$EnablePolicyBypass,
  [switch]$SkipPathRefresh,
  [switch]$DryRun
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Write-Step {
  param([string]$Message)
  Write-Host "[setup-windows-native] $Message"
}

function Quote-PowerShellSingleQuotedString {
  param([Parameter(Mandatory = $true)][string]$Value)
  return "'" + ($Value -replace "'", "''") + "'"
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
    return ""
  }

  $leaf = [System.IO.Path]::GetFileName($PathValue)
  if (-not $leaf.Equals("npm.ps1", [System.StringComparison]::OrdinalIgnoreCase)) {
    return $PathValue
  }

  $parent = Split-Path -Parent $PathValue
  if ([string]::IsNullOrWhiteSpace($parent)) {
    return ""
  }

  $siblingCmd = Join-Path $parent "npm.cmd"
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

  if ($nameLower -in @("npm", "npm.cmd")) {
    $path = Normalize-NpmCommandPath -PathValue $path
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

function Add-UniqueCommand {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [System.Collections.ArrayList]$Commands,
    [Parameter(Mandatory = $true)]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return
  }
  if ($Commands -contains $Value) {
    return
  }
  [void]$Commands.Add($Value)
}

function Get-WingetInstallCommand {
  param([Parameter(Mandatory = $true)][string]$PackageId)
  return ("winget install --id {0} --exact --source winget --accept-source-agreements --accept-package-agreements --silent --disable-interactivity" -f $PackageId)
}

function Get-DependencySpecs {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SelectedWorkflow
  )

  $desktopSelected = $SelectedWorkflow -in @("desktop", "both")
  $localApiSelected = $SelectedWorkflow -in @("local-api", "both")

  return @(
    [pscustomobject]@{
      id = "GoLang.Go"
      label = "Go toolchain"
      check_commands = @("go")
      version_commands = @("go version")
      winget_id = "GoLang.Go"
      fallback_commands = @('Start-Process "https://go.dev/dl/"')
      required = [bool]$localApiSelected
      optional = [bool](-not $localApiSelected)
      rationale = "Needed by scripts/windows/local_api_session.ps1"
    },
    [pscustomobject]@{
      id = "OpenJS.NodeJS.LTS"
      label = "Node.js + npm"
      check_commands = @("node", "npm.cmd")
      version_commands = @("node -v", "npm.cmd -v")
      winget_id = "OpenJS.NodeJS.LTS"
      fallback_commands = @('Start-Process "https://nodejs.org/en/download"')
      required = [bool]$desktopSelected
      optional = [bool](-not $desktopSelected)
      rationale = "Needed by scripts/windows/desktop_dev.ps1"
    },
    [pscustomobject]@{
      id = "Rustlang.Rustup"
      label = "Rust toolchain (rustc + cargo)"
      check_commands = @("rustc", "cargo")
      version_commands = @("rustc -V", "cargo -V")
      winget_id = "Rustlang.Rustup"
      fallback_commands = @('Start-Process "https://rustup.rs/"')
      required = [bool]$desktopSelected
      optional = [bool](-not $desktopSelected)
      rationale = "Needed for desktop native dev/build path"
    },
    [pscustomobject]@{
      id = "Git.Git"
      label = "Git Bash (bash.exe from Git for Windows)"
      check_commands = @("bash.exe")
      version_commands = @("bash --version")
      winget_id = "Git.Git"
      fallback_commands = @('Start-Process "https://git-scm.com/download/win"')
      required = [bool]$localApiSelected
      optional = [bool](-not $localApiSelected)
      rationale = "Needed when local API bridge executes scripts/easy_node.sh"
    }
  )
}

function Test-DependencyState {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Dependency
  )

  $resolved = @()
  $missing = @()

  foreach ($commandName in $Dependency.check_commands) {
    $allowWindowsAppsAlias = $commandName.ToLowerInvariant() -eq "winget"
    $path = Resolve-ToolPath -Name $commandName -AllowWindowsAppsAlias:$allowWindowsAppsAlias
    if ([string]::IsNullOrWhiteSpace($path)) {
      $missing += $commandName
      continue
    }
    $resolved += [pscustomobject]@{
      command = $commandName
      path = $path
    }
  }

  return [pscustomobject]@{
    dependency = $Dependency
    installed = [bool]($missing.Count -eq 0)
    missing_commands = @($missing)
    resolved_paths = @($resolved)
  }
}

function Show-DependencyReport {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject[]]$Reports
  )

  Write-Step "dependency check:"
  foreach ($report in $Reports) {
    $dependency = $report.dependency
    $state = "ok"
    if (-not $report.installed) {
      if ([bool]$dependency.required) {
        $state = "missing(required)"
      } else {
        $state = "missing(optional)"
      }
    }
    Write-Host ("  - {0}: {1}" -f $dependency.label, $state)
    if (-not $report.installed -and $report.missing_commands.Count -gt 0) {
      Write-Host ("    missing commands: {0}" -f ($report.missing_commands -join ", "))
    }
    if ($report.resolved_paths.Count -gt 0) {
      foreach ($resolved in $report.resolved_paths) {
        Write-Host ("    {0}: {1}" -f $resolved.command, $resolved.path)
      }
    }
  }
}

function Get-DependencyRemediationHints {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Dependency,
    [Parameter(Mandatory = $true)]
    [bool]$WingetAvailable
  )

  $hints = New-Object System.Collections.ArrayList
  if ($WingetAvailable -and -not [string]::IsNullOrWhiteSpace($Dependency.winget_id)) {
    Add-UniqueCommand -Commands $hints -Value (Get-WingetInstallCommand -PackageId $Dependency.winget_id)
  }
  foreach ($fallbackCommand in @($Dependency.fallback_commands)) {
    Add-UniqueCommand -Commands $hints -Value $fallbackCommand
  }
  return @($hints.ToArray())
}

function Show-RemediationHints {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject[]]$MissingReports,
    [Parameter(Mandatory = $true)]
    [bool]$WingetAvailable
  )

  if ($MissingReports.Count -eq 0) {
    return
  }

  Write-Step "remediation hints:"
  foreach ($report in $MissingReports) {
    $dependency = $report.dependency
    Write-Host ("  - {0}" -f $dependency.label)
    foreach ($hint in @(Get-DependencyRemediationHints -Dependency $dependency -WingetAvailable $WingetAvailable)) {
      Write-Host ("    {0}" -f $hint)
    }
  }
}

function Get-InstallablePackageIds {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject[]]$MissingReports
  )

  $ids = New-Object System.Collections.ArrayList
  foreach ($report in $MissingReports) {
    $dependency = $report.dependency
    if (-not [bool]$dependency.required) {
      continue
    }
    if ([string]::IsNullOrWhiteSpace($dependency.winget_id)) {
      continue
    }
    Add-UniqueCommand -Commands $ids -Value $dependency.winget_id
  }
  return @($ids.ToArray())
}

function Test-InteractivePromptAvailable {
  if ($NonInteractive) {
    return $false
  }
  if (-not [Environment]::UserInteractive) {
    return $false
  }
  try {
    $null = $Host.UI.RawUI
    return $true
  } catch {
    return $false
  }
}

function Get-ProcessBypassRerunCommand {
  $scriptPath = Quote-PowerShellSingleQuotedString -Value $PSCommandPath
  $workflowArg = " -Workflow " + (Quote-PowerShellSingleQuotedString -Value $Workflow)
  $installArg = if ($InstallMissing) { " -InstallMissing" } else { "" }
  $nonInteractiveArg = if ($NonInteractive) { " -NonInteractive" } else { "" }
  $dryRunArg = if ($DryRun) { " -DryRun" } else { "" }
  $skipPathRefreshArg = if ($SkipPathRefresh) { " -SkipPathRefresh" } else { "" }
  return ("powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File {0}{1}{2}{3}{4}{5}" -f $scriptPath, $workflowArg, $installArg, $nonInteractiveArg, $dryRunArg, $skipPathRefreshArg)
}

function Ensure-ProcessExecutionPolicy {
  if ($EnablePolicyBypass) {
    if ($DryRun) {
      Write-Step "dry-run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
      return
    }
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Write-Step "execution policy set to Bypass for current process"
    return
  }

  $effectivePolicy = Get-ExecutionPolicy
  if ($effectivePolicy -notin @("Bypass", "Unrestricted")) {
    Write-Step ("execution policy unchanged (effective_policy={0})" -f $effectivePolicy)
    Write-Step "if script execution is blocked in this shell, use one of the following:"
    Write-Host "  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
    Write-Host ("  {0}" -f (Get-ProcessBypassRerunCommand))
  }
}

function Install-MissingDependencies {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WingetPath,
    [Parameter(Mandatory = $true)]
    [string[]]$PackageIds
  )

  if ($PackageIds.Count -eq 0) {
    return
  }

  $confirmInstall = $true
  if (-not $NonInteractive -and -not $DryRun) {
    if (Test-InteractivePromptAvailable) {
      $answer = Read-Host ("Install missing prerequisites via winget now ({0})? [y/N]" -f ($PackageIds -join ", "))
      if ($answer -notmatch "^(?i)y(es)?$") {
        $confirmInstall = $false
        Write-Step "user declined auto-remediation install; continuing with hints only"
      }
    } else {
      $confirmInstall = $false
      Write-Step "non-interactive shell detected; skipping installs for safety (pass -NonInteractive to permit unattended installs)"
    }
  }

  if (-not $confirmInstall) {
    return
  }

  foreach ($packageId in $PackageIds) {
    $commandText = Get-WingetInstallCommand -PackageId $packageId
    if ($DryRun) {
      Write-Step ("dry-run install: {0}" -f $commandText)
      continue
    }

    Write-Step ("installing via winget: {0}" -f $packageId)
    $args = @(
      "install",
      "--id", $packageId,
      "--exact",
      "--source", "winget",
      "--accept-source-agreements",
      "--accept-package-agreements",
      "--silent",
      "--disable-interactivity"
    )
    & $WingetPath @args
    if ($LASTEXITCODE -ne 0) {
      throw "winget install failed for $packageId (exit code $LASTEXITCODE)"
    }
  }
}

function Get-RecommendedCommands {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SelectedWorkflow,
    [Parameter(Mandatory = $true)]
    [pscustomobject[]]$Dependencies
  )

  $commands = New-Object System.Collections.ArrayList
  Add-UniqueCommand -Commands $commands -Value "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
  Add-UniqueCommand -Commands $commands -Value ("powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\setup_windows_native.ps1 -Workflow {0} -InstallMissing -EnablePolicyBypass -NonInteractive" -f $SelectedWorkflow)

  foreach ($dependency in $Dependencies) {
    foreach ($versionCommand in @($dependency.version_commands)) {
      Add-UniqueCommand -Commands $commands -Value $versionCommand
    }
  }

  if ($SelectedWorkflow -in @("local-api", "both")) {
    Add-UniqueCommand -Commands $commands -Value "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun"
  }
  if ($SelectedWorkflow -in @("desktop", "both")) {
    Add-UniqueCommand -Commands $commands -Value "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_dev.ps1 -DryRun"
  }

  return @($commands.ToArray())
}

function Resolve-NextCommand {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SelectedWorkflow,
    [Parameter(Mandatory = $true)]
    [int]$MissingRequiredCount,
    [Parameter(Mandatory = $true)]
    [string[]]$RecommendedCommands
  )

  if ($MissingRequiredCount -gt 0) {
    $preferred = $RecommendedCommands | Where-Object { $_ -like "*setup_windows_native.ps1*" -and $_ -like "*-InstallMissing*" } | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace([string]$preferred)) {
      return [string]$preferred
    }
  }

  if ($SelectedWorkflow -in @("local-api", "both")) {
    $localApi = $RecommendedCommands | Where-Object { $_ -like "*local_api_session.ps1*" } | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace([string]$localApi)) {
      return [string]$localApi
    }
  }

  if ($SelectedWorkflow -in @("desktop", "both")) {
    $desktop = $RecommendedCommands | Where-Object { $_ -like "*desktop_dev.ps1*" } | Select-Object -First 1
    if (-not [string]::IsNullOrWhiteSpace([string]$desktop)) {
      return [string]$desktop
    }
  }

  if ($RecommendedCommands.Count -eq 0) {
    return ""
  }
  return [string]$RecommendedCommands[0]
}


Write-Step ("workflow={0}" -f $Workflow)
Write-Step ("install_missing={0}" -f ($(if ($InstallMissing) { "true" } else { "false" })))
Write-Step ("non_interactive={0}" -f ($(if ($NonInteractive) { "true" } else { "false" })))
Write-Step ("dry_run={0}" -f ($(if ($DryRun) { "true" } else { "false" })))

Ensure-ProcessExecutionPolicy

if (-not $SkipPathRefresh) {
  Refresh-SessionPath
  Add-SessionPathSegments -Segments (Get-CommonToolDirectories)
  Write-Step "session PATH refreshed from machine/user PATH and common tool directories"
} else {
  Write-Step "session PATH refresh skipped by flag"
}

$dependencies = Get-DependencySpecs -SelectedWorkflow $Workflow
$wingetPath = Resolve-ToolPath -Name "winget" -AllowWindowsAppsAlias
Write-Step ("winget={0}" -f $(if ([string]::IsNullOrWhiteSpace($wingetPath)) { "missing" } else { $wingetPath }))

$initialReports = @($dependencies | ForEach-Object { Test-DependencyState -Dependency $_ })
Show-DependencyReport -Reports $initialReports

$missingReports = @($initialReports | Where-Object { -not $_.installed })
$missingRequiredReports = @($missingReports | Where-Object { [bool]$_.dependency.required })
$missingOptionalReports = @($missingReports | Where-Object { -not [bool]$_.dependency.required })

if ($InstallMissing -and $missingRequiredReports.Count -gt 0) {
  if ([string]::IsNullOrWhiteSpace($wingetPath)) {
    Write-Step "winget not found; auto-remediation install is unavailable in this shell"
  } else {
    $installIds = Get-InstallablePackageIds -MissingReports $missingRequiredReports
    Install-MissingDependencies -WingetPath $wingetPath -PackageIds $installIds
    if (-not $SkipPathRefresh) {
      Refresh-SessionPath
      Add-SessionPathSegments -Segments (Get-CommonToolDirectories)
      Write-Step "session PATH refreshed after install attempts"
    }
  }
}

$finalReports = @($dependencies | ForEach-Object { Test-DependencyState -Dependency $_ })
$finalMissingReports = @($finalReports | Where-Object { -not $_.installed })
$finalMissingRequiredReports = @($finalMissingReports | Where-Object { [bool]$_.dependency.required })
$finalMissingOptionalReports = @($finalMissingReports | Where-Object { -not [bool]$_.dependency.required })

if ($finalMissingReports.Count -gt 0) {
  Show-RemediationHints -MissingReports $finalMissingReports -WingetAvailable (-not [string]::IsNullOrWhiteSpace($wingetPath))
}

$recommendedCommands = Get-RecommendedCommands -SelectedWorkflow $Workflow -Dependencies $dependencies
$nextCommand = Resolve-NextCommand -SelectedWorkflow $Workflow -MissingRequiredCount $finalMissingRequiredReports.Count -RecommendedCommands $recommendedCommands

Write-Step "recommended commands (copy/paste):"
foreach ($command in $recommendedCommands) {
  Write-Host ("  - {0}" -f $command)
}
if (-not [string]::IsNullOrWhiteSpace($nextCommand)) {
  Write-Step ("next command: {0}" -f $nextCommand)
}

$status = "ok"
if ($finalMissingRequiredReports.Count -gt 0) {
  $status = "missing"
} elseif ($DryRun) {
  $status = "dry-run"
}
Write-Step ("status={0} required_missing={1} optional_missing={2}" -f $status, $finalMissingRequiredReports.Count, $finalMissingOptionalReports.Count)

if ($finalMissingRequiredReports.Count -gt 0) {
  throw "missing required prerequisites remain for workflow '$Workflow'"
}
