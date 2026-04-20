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
  $wingetPath = Resolve-ToolPath "winget"

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
    winget = $Report.winget
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
    [pscustomobject]$Report
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
  if (-not $Report.winget) {
    Add-UniqueValue -List $ids -Value "Microsoft.AppInstaller"
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
    "Microsoft.AppInstaller" { return "App Installer (winget)" }
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
    "Microsoft.AppInstaller" { return "install App Installer from Microsoft Store" }
    default { return "winget install --id $PackageId --exact" }
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
    [string[]]$MissingPackageIds = @()
  )

  $commands = New-Object System.Collections.ArrayList
  Add-UniqueValue -List $commands -Value "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"

  foreach ($packageId in $MissingPackageIds) {
    Add-UniqueValue -List $commands -Value (Get-WingetInstallCommand -PackageId $packageId)
  }

  Add-UniqueValue -List $commands -Value "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass"
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
    if ($id -eq "Microsoft.AppInstaller") {
      continue
    }
    Add-UniqueValue -List $installable -Value $id
  }
  return @($installable.ToArray())
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
  & $WingetPath @wingetArgs
  if ($LASTEXITCODE -ne 0) {
    throw "winget install failed for $PackageId (exit code $LASTEXITCODE)"
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

  $missingPackageIds = @(Get-MissingPackageIds -Report $report)
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
          $missingPackageIds = @(Get-MissingPackageIds -Report $report)
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
