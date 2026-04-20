param(
  [string]$DesktopExecutablePath = "",
  [switch]$InstallMissing,
  [switch]$EnablePolicyBypass,
  [switch]$DryRun,
  [string]$ApiAddr = "127.0.0.1:8095",
  [string]$CommandRunner = "",
  [string]$DoctorSummaryJson = "",
  [Nullable[int]]$PrintDoctorSummaryJson = $null
)

$ErrorActionPreference = "Stop"

if ($null -ne $PrintDoctorSummaryJson -and $PrintDoctorSummaryJson -notin @(0, 1)) {
  throw "-PrintDoctorSummaryJson must be 0 or 1 when provided."
}

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
  $scriptDir = Split-Path -Parent $PSCommandPath
}

function Write-PackagedRunStep {
  param([string]$Message)
  Write-Host "[desktop-packaged-run] $Message"
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
    "GPM\GPM Desktop\GPM Desktop.exe",
    "GPM\GPM Desktop\gpm-desktop.exe",
    "Global Private Mesh Desktop\Global Private Mesh Desktop.exe",
    "Global Private Mesh Desktop\global-private-mesh-desktop.exe",
    "Global Private Mesh\Global Private Mesh Desktop\Global Private Mesh Desktop.exe",
    "Global Private Mesh\Global Private Mesh Desktop\global-private-mesh-desktop.exe",
    "TDPN Desktop\TDPN Desktop.exe",
    "TDPN Desktop\tdpn-desktop.exe",
    "TDPN\TDPN Desktop\TDPN Desktop.exe",
    "TDPN\TDPN Desktop\tdpn-desktop.exe"
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

function Resolve-DesktopPackagedExecutableAuto {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptDirectory
  )

  $envOverrides = @(
    @{ Name = "GPM_DESKTOP_PACKAGED_EXE"; Value = [Environment]::GetEnvironmentVariable("GPM_DESKTOP_PACKAGED_EXE", "Process") },
    @{ Name = "GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE"; Value = [Environment]::GetEnvironmentVariable("GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE", "Process") },
    @{ Name = "TDPN_DESKTOP_PACKAGED_EXE"; Value = [Environment]::GetEnvironmentVariable("TDPN_DESKTOP_PACKAGED_EXE", "Process") }
  )

  foreach ($envOverride in $envOverrides) {
    $candidate = Normalize-PathCandidate -Value ([string]$envOverride.Value)
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [PSCustomObject]@{
        Path = (Resolve-Path -LiteralPath $candidate).Path
        Source = "env"
      }
    }
    Write-Warning ("[desktop-packaged-run] env override {0} points to a missing file: {1}" -f $envOverride.Name, $candidate)
  }

  foreach ($candidate in (Get-InstalledPackagedExecutableCandidates)) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [PSCustomObject]@{
        Path = (Resolve-Path -LiteralPath $candidate).Path
        Source = "install"
      }
    }
  }

  $repoRoot = ""
  try {
    $repoRoot = (Resolve-Path -LiteralPath (Join-Path $ScriptDirectory "..\..")).Path
  } catch {
    $repoRoot = ""
  }

  foreach ($candidate in (Get-RepoPackagedExecutableCandidates -RepoRootPath $repoRoot)) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return [PSCustomObject]@{
        Path = (Resolve-Path -LiteralPath $candidate).Path
        Source = "repo"
      }
    }
  }

  return $null
}

$doctorScript = Join-Path $scriptDir "desktop_doctor.ps1"
if (-not (Test-Path -LiteralPath $doctorScript -PathType Leaf)) {
  throw "missing doctor script: $doctorScript"
}

$bootstrapScript = Join-Path $scriptDir "desktop_native_bootstrap.ps1"
if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
  throw "missing bootstrap script: $bootstrapScript"
}

$shouldEnablePolicyBypass = $true
if ($PSBoundParameters.ContainsKey("EnablePolicyBypass")) {
  $shouldEnablePolicyBypass = [bool]$EnablePolicyBypass
}

$doctorInvokeArgs = @()
if ($InstallMissing) {
  $doctorInvokeArgs += @("-Mode", "fix", "-InstallMissing")
} else {
  $doctorInvokeArgs += @("-Mode", "check")
}
if ($DryRun) {
  $doctorInvokeArgs += "-DryRun"
}
if ($shouldEnablePolicyBypass) {
  $doctorInvokeArgs += "-EnablePolicyBypass"
}
if (-not [string]::IsNullOrWhiteSpace($DoctorSummaryJson)) {
  $doctorInvokeArgs += @("-SummaryJson", $DoctorSummaryJson)
}
if ($null -ne $PrintDoctorSummaryJson) {
  $doctorInvokeArgs += @("-PrintSummaryJson", ([string]$PrintDoctorSummaryJson))
}

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $doctorScript @doctorInvokeArgs
$doctorExitCode = $LASTEXITCODE
if ($doctorExitCode -ne 0) {
  exit $doctorExitCode
}

$resolvedDesktopExecutablePath = $DesktopExecutablePath
if ([string]::IsNullOrWhiteSpace($resolvedDesktopExecutablePath)) {
  $autoDiscoveredDesktopExecutable = Resolve-DesktopPackagedExecutableAuto -ScriptDirectory $scriptDir
  if ($null -ne $autoDiscoveredDesktopExecutable -and -not [string]::IsNullOrWhiteSpace($autoDiscoveredDesktopExecutable.Path)) {
    $resolvedDesktopExecutablePath = $autoDiscoveredDesktopExecutable.Path
    Write-PackagedRunStep ("packaged executable auto-discovered ({0}): {1}" -f $autoDiscoveredDesktopExecutable.Source, $resolvedDesktopExecutablePath)
  }
}

$bootstrapInvokeArgs = @(
  "-Mode", "run-full",
  "-DesktopLaunchStrategy", "packaged",
  "-ApiAddr", $ApiAddr
)

if (-not [string]::IsNullOrWhiteSpace($resolvedDesktopExecutablePath)) {
  $bootstrapInvokeArgs += @("-DesktopExecutableOverridePath", $resolvedDesktopExecutablePath)
}
if ($InstallMissing) {
  $bootstrapInvokeArgs += "-InstallMissing"
}
if ($DryRun) {
  $bootstrapInvokeArgs += "-DryRun"
}
if ($shouldEnablePolicyBypass) {
  $bootstrapInvokeArgs += "-EnablePolicyBypass"
}
if (-not [string]::IsNullOrWhiteSpace($CommandRunner)) {
  $bootstrapInvokeArgs += @("-CommandRunner", $CommandRunner)
}

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript @bootstrapInvokeArgs
exit $LASTEXITCODE
