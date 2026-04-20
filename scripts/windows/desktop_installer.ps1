param(
  [string]$InstallerPath = "",
  [ValidateSet("auto", "nsis", "msi")]
  [string]$InstallerType = "auto",
  [switch]$BuildIfMissing,
  [switch]$InstallMissing,
  [ValidateSet("stable", "beta", "canary")]
  [string]$Channel = "stable",
  [switch]$Silent,
  [switch]$DryRun,
  [string]$SummaryJson = "",
  [ValidateSet(0, 1)]
  [int]$PrintSummaryJson = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-installer] $Message"
}

function Resolve-InstallerTypeFromPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )

  $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()
  switch ($extension) {
    ".exe" { return "nsis" }
    ".msi" { return "msi" }
    default { return "" }
  }
}

function Get-PreferredInstallerFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$SearchRoot,
    [Parameter(Mandatory = $true)]
    [string]$Filter
  )

  if (-not (Test-Path -LiteralPath $SearchRoot -PathType Container)) {
    return $null
  }

  $candidates = @(
    Get-ChildItem -LiteralPath $SearchRoot -File -Recurse -Filter $Filter |
      Sort-Object -Property LastWriteTimeUtc, FullName -Descending
  )
  if ($candidates.Count -eq 0) {
    return $null
  }

  return $candidates[0]
}

function Find-InstallerArtifact {
  param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,
    [Parameter(Mandatory = $true)]
    [string]$RequestedType
  )

  $nsisRoot = Join-Path $BundleRoot "nsis"
  $msiRoot = Join-Path $BundleRoot "msi"

  if ($RequestedType -eq "nsis") {
    $nsisFile = Get-PreferredInstallerFile -SearchRoot $nsisRoot -Filter "*.exe"
    if ($null -eq $nsisFile) {
      return $null
    }
    return [pscustomobject]@{
      installer_path = $nsisFile.FullName
      installer_type = "nsis"
    }
  }

  if ($RequestedType -eq "msi") {
    $msiFile = Get-PreferredInstallerFile -SearchRoot $msiRoot -Filter "*.msi"
    if ($null -eq $msiFile) {
      return $null
    }
    return [pscustomobject]@{
      installer_path = $msiFile.FullName
      installer_type = "msi"
    }
  }

  $nsisPreferred = Find-InstallerArtifact -BundleRoot $BundleRoot -RequestedType "nsis"
  if ($null -ne $nsisPreferred) {
    return $nsisPreferred
  }

  return Find-InstallerArtifact -BundleRoot $BundleRoot -RequestedType "msi"
}

function Get-CommandDisplay {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [AllowEmptyCollection()]
    [string[]]$Arguments
  )

  $parts = @("'" + ($Path -replace "'", "''") + "'")
  foreach ($arg in $Arguments) {
    $parts += ("'" + ($arg -replace "'", "''") + "'")
  }
  return ($parts -join " ")
}

function Write-SummaryJson {
  param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [Parameter(Mandatory = $true)]
    [hashtable]$Summary
  )

  $absolutePath = [System.IO.Path]::GetFullPath($OutputPath)
  $parentDir = Split-Path -Parent $absolutePath
  if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir -PathType Container)) {
    New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
  }

  $payload = $Summary | ConvertTo-Json -Depth 10
  Set-Content -LiteralPath $absolutePath -Value $payload -Encoding utf8
  Write-Step "summary_json=$absolutePath"
  if ($PrintSummaryJson -eq 1) {
    Write-Step "summary_json_payload:"
    Write-Host $payload
  }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $scriptDir "..\..")).Path
$bundleRoot = Join-Path $repoRoot "apps\desktop\src-tauri\target\release\bundle"
$releaseBundleScript = Join-Path $scriptDir "desktop_release_bundle.ps1"

if ([string]::IsNullOrWhiteSpace($SummaryJson)) {
  $SummaryJson = Join-Path $repoRoot ".easy-node-logs\desktop_installer_windows_summary.json"
}

$summary = [ordered]@{
  version = 1
  generated_at_utc = ""
  status = "fail"
  rc = 1
  platform = "windows"
  mode = "desktop_installer_scaffold"
  channel = $Channel
  installer_path = ""
  installer_type = ""
  installer_source = ""
  silent = [bool]$Silent
  dry_run = [bool]$DryRun
  build_if_missing = [bool]$BuildIfMissing
  build_triggered = $false
  failure_stage = ""
}

$exitCode = 1

try {
  Write-Step "mode=scaffold-non-production"
  Write-Step "repo_root=$repoRoot"
  Write-Step "bundle_root=$bundleRoot"
  Write-Step "installer_type=$InstallerType"
  Write-Step "channel=$Channel"
  Write-Step "build_if_missing=$([bool]$BuildIfMissing)"
  Write-Step "silent=$([bool]$Silent)"
  Write-Step "dry_run=$([bool]$DryRun)"

  $selectedInstallerPath = ""
  $selectedInstallerType = ""
  $selectedInstallerSource = ""

  if (-not [string]::IsNullOrWhiteSpace($InstallerPath)) {
    $summary.failure_stage = "installer_validate"
    $resolvedExplicitPath = [System.IO.Path]::GetFullPath($InstallerPath)
    if (-not (Test-Path -LiteralPath $resolvedExplicitPath -PathType Leaf)) {
      throw "explicit installer path does not exist: $resolvedExplicitPath"
    }

    $pathType = Resolve-InstallerTypeFromPath -Path $resolvedExplicitPath
    if ([string]::IsNullOrWhiteSpace($pathType)) {
      throw "unable to infer installer type from explicit path (expected .exe or .msi): $resolvedExplicitPath"
    }

    if ($InstallerType -ne "auto" -and $InstallerType -ne $pathType) {
      throw "explicit installer path type '$pathType' does not match requested -InstallerType '$InstallerType'"
    }

    $selectedInstallerPath = $resolvedExplicitPath
    $selectedInstallerType = if ($InstallerType -eq "auto") { $pathType } else { $InstallerType }
    $selectedInstallerSource = "explicit"
    Write-Step "installer resolved from explicit path"
  } else {
    $summary.failure_stage = "installer_discovery"
    $found = Find-InstallerArtifact -BundleRoot $bundleRoot -RequestedType $InstallerType
    if ($null -eq $found -and $BuildIfMissing) {
      if (-not (Test-Path -LiteralPath $releaseBundleScript -PathType Leaf)) {
        throw "desktop release bundle script not found: $releaseBundleScript"
      }

      $summary.build_triggered = $true
      $summary.failure_stage = "build"
      $buildArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $releaseBundleScript,
        "-Channel", $Channel
      )
      if ($InstallMissing) {
        $buildArgs += "-InstallMissing"
      }

      Write-Step ("installer not found; triggering build: powershell {0}" -f (Get-CommandDisplay -Path "powershell" -Arguments $buildArgs))
      & powershell @buildArgs
      $buildRc = $LASTEXITCODE
      if ($buildRc -ne 0) {
        throw "desktop release bundle failed with exit code $buildRc"
      }

      $summary.failure_stage = "installer_discovery"
      $found = Find-InstallerArtifact -BundleRoot $bundleRoot -RequestedType $InstallerType
    }

    if ($null -eq $found) {
      throw "installer artifact not found under bundle root: $bundleRoot"
    }

    $selectedInstallerPath = [string]$found.installer_path
    $selectedInstallerType = [string]$found.installer_type
    $selectedInstallerSource = if ($summary.build_triggered) { "discovered_after_build" } else { "discovered" }
    Write-Step "installer discovered from release bundle artifacts"
  }

  $summary.installer_path = $selectedInstallerPath
  $summary.installer_type = $selectedInstallerType
  $summary.installer_source = $selectedInstallerSource

  $summary.failure_stage = "install"
  $processPath = $selectedInstallerPath
  $processArgs = @()

  if ($selectedInstallerType -eq "msi") {
    $processPath = "msiexec.exe"
    $processArgs = @("/i", $selectedInstallerPath)
    if ($Silent) {
      $processArgs += "/quiet"
      $processArgs += "/norestart"
    }
  } elseif ($selectedInstallerType -eq "nsis") {
    if ($Silent) {
      $processArgs += "/S"
    }
  } else {
    throw "unsupported installer type: $selectedInstallerType"
  }

  $installCommand = Get-CommandDisplay -Path $processPath -Arguments $processArgs
  Write-Step "install command: $installCommand"

  if ($DryRun) {
    Write-Step "dry-run enabled; installer execution skipped"
    $exitCode = 0
  } else {
    $process = Start-Process -FilePath $processPath -ArgumentList $processArgs -Wait -PassThru
    $exitCode = [int]$process.ExitCode
    Write-Step "installer exited rc=$exitCode"
  }

  if ($exitCode -eq 0) {
    $summary.status = "ok"
    $summary.failure_stage = ""
  } else {
    $summary.status = "fail"
  }
} catch {
  if ([string]::IsNullOrWhiteSpace($summary.failure_stage)) {
    $summary.failure_stage = "runtime"
  }
  Write-Step "error=$($_.Exception.Message)"
  $exitCode = 1
} finally {
  $summary.generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $summary.rc = [int]$exitCode
  Write-SummaryJson -OutputPath $SummaryJson -Summary $summary
}

exit $exitCode
