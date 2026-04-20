param(
  [switch]$DryRun,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$CommandTokens
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
  Write-Host "Windows-safe desktop shell wrapper"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "  ./scripts/windows/desktop_shell.ps1 [-DryRun] <command> [args...]"
  Write-Host ""
  Write-Host "Examples:"
  Write-Host "  ./scripts/windows/desktop_shell.ps1 npm install"
  Write-Host "  ./scripts/windows/desktop_shell.ps1 npx --yes create-vite@latest"
  Write-Host "  ./scripts/windows/desktop_shell.ps1 -DryRun go test ./..."
  Write-Host ""
  Write-Host "Notes:"
  Write-Host "  - Refreshes PATH from machine+user scope before resolving the command."
  Write-Host "  - Adds common Go, Node.js, Cargo, and Git tool directories when present."
  Write-Host "  - Resolves npm/npx to npm.cmd/npx.cmd so npm.ps1 is never selected."
}

function Quote-ForDisplay {
  param(
    [AllowNull()]
    [string]$Value
  )

  if ($null -eq $Value) {
    return "''"
  }

  return "'" + ($Value -replace "'", "''") + "'"
}

function Get-CommandDisplayText {
  param(
    [Parameter(Mandatory = $true)]
    $CommandInfo
  )

  foreach ($propertyName in @("Source", "Path", "Definition", "Name")) {
    try {
      $value = [string]$CommandInfo.$propertyName
      if (-not [string]::IsNullOrWhiteSpace($value)) {
        return $value
      }
    } catch {
      continue
    }
  }

  return [string]$CommandInfo
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

function Normalize-NodeToolName {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  if ($Name -match '^(?i)npm(?:\.(?:cmd|ps1))?$') {
    return "npm.cmd"
  }

  if ($Name -match '^(?i)npx(?:\.(?:cmd|ps1))?$') {
    return "npx.cmd"
  }

  return $Name
}

function Resolve-CommandInvocation {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  $normalizedName = Normalize-NodeToolName -Name $Name
  $command = Get-Command -Name $normalizedName -ErrorAction SilentlyContinue
  if ($null -eq $command) {
    throw "command not found: $Name"
  }

  return [PSCustomObject]@{
    Invocation = $command
    Display = Get-CommandDisplayText -CommandInfo $command
    IsExternal = ($command.CommandType -in @("Application", "ExternalScript"))
  }
}

function Format-ResolvedCommand {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$ResolvedInvocation,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $parts = @("&", (Quote-ForDisplay -Value $ResolvedInvocation.Display))
  foreach ($argument in $Arguments) {
    $parts += (Quote-ForDisplay -Value $argument)
  }

  return ($parts -join " ")
}

if ($null -eq $CommandTokens) {
  $CommandTokens = @()
}

if ($CommandTokens.Count -eq 0) {
  Show-Usage
  exit 0
}

switch ($CommandTokens[0]) {
  "-h" { Show-Usage; exit 0 }
  "--help" { Show-Usage; exit 0 }
  "help" { Show-Usage; exit 0 }
  "/?" { Show-Usage; exit 0 }
}

Refresh-SessionPath
$commonToolDirs = @(Get-CommonToolDirectories)
if ($commonToolDirs.Count -gt 0) {
  Add-SessionPathSegments -Segments $commonToolDirs
}

$commandName = [string]$CommandTokens[0]
$commandArgs = @()
if ($CommandTokens.Count -gt 1) {
  $commandArgs = @($CommandTokens[1..($CommandTokens.Count - 1)])
}

$resolvedInvocation = Resolve-CommandInvocation -Name $commandName

if ($DryRun) {
  Write-Host ("[desktop-shell] dry-run: {0}" -f (Format-ResolvedCommand -ResolvedInvocation $resolvedInvocation -Arguments $commandArgs))
  exit 0
}

& $resolvedInvocation.Invocation @commandArgs
if ($resolvedInvocation.IsExternal) {
  exit $LASTEXITCODE
}

if ($?) {
  exit 0
}

exit 1
