param(
  [switch]$InstallMissing,
  [switch]$NoInstallMissing,
  [switch]$EnablePolicyBypass,
  [switch]$DryRun,
  [switch]$ForceNpmInstall
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-dev] $Message"
}

function Assert-PolicySafeNodeRunnerScript {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string]$ScriptLabel
  )

  if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
    throw "missing $ScriptLabel script: $ScriptPath"
  }

  $contents = ""
  try {
    $contents = [string](Get-Content -Raw -LiteralPath $ScriptPath -ErrorAction Stop)
  } catch {
    throw "failed to inspect $ScriptLabel script for npm/npx policy guardrails: $ScriptPath"
  }

  if (-not $contents.Contains("npm.cmd")) {
    throw @"
$ScriptLabel script is missing policy-safe npm runner marker 'npm.cmd': $ScriptPath
To avoid npm.ps1/npx.ps1 execution-policy failures, update that script to use npm.cmd/npx.cmd (or desktop_node.cmd / desktop_shell.cmd).
"@
  }

  $npxPolicySafe = $contents.Contains("npx.cmd") -or
    $contents.Contains("desktop_node.cmd npx") -or
    $contents.Contains("desktop_shell.cmd npx")
  if ($contents -match '(?i)\bnpx\b' -and -not $npxPolicySafe) {
    throw @"
$ScriptLabel script references npx but is missing a policy-safe npx runner marker: $ScriptPath
Use npx.cmd directly or route npx through desktop_node.cmd / desktop_shell.cmd to avoid npm.ps1/npx.ps1 execution-policy failures.
"@
  }
}

function Test-IsWslSession {
  $wslDistro = [Environment]::GetEnvironmentVariable("WSL_DISTRO_NAME", "Process")
  if (-not [string]::IsNullOrWhiteSpace($wslDistro)) {
    return $true
  }

  $wslInterop = [Environment]::GetEnvironmentVariable("WSL_INTEROP", "Process")
  if (-not [string]::IsNullOrWhiteSpace($wslInterop)) {
    return $true
  }

  foreach ($probePath in @("/proc/sys/kernel/osrelease", "/proc/version")) {
    if (-not (Test-Path -LiteralPath $probePath -PathType Leaf)) {
      continue
    }

    $contents = ""
    try {
      $contents = [string](Get-Content -Raw -LiteralPath $probePath -ErrorAction Stop)
    } catch {
      $contents = ""
    }

    if (-not [string]::IsNullOrWhiteSpace($contents) -and $contents.ToLowerInvariant().Contains("microsoft")) {
      return $true
    }
  }

  return $false
}

function Get-WslDistroLabel {
  $wslDistro = [Environment]::GetEnvironmentVariable("WSL_DISTRO_NAME", "Process")
  if ([string]::IsNullOrWhiteSpace($wslDistro)) {
    return "(unknown)"
  }
  return $wslDistro.Trim()
}

function Assert-WindowsNativeNonWsl {
  if (-not (Test-IsWslSession)) {
    return
  }

  $wslDistro = Get-WslDistroLabel
  throw @"
desktop_dev.ps1 is Windows-native and must run outside WSL.
Detected WSL environment: distro=$wslDistro
Run this script from Windows PowerShell or Windows Terminal (non-WSL).
Windows-native command:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_dev.ps1 -InstallMissing
If you intended the WSL path instead, use:
  scripts\windows\wsl2_easy.cmd bootstrap
"@
}

function ConvertTo-NullableBoolean {
  param(
    [AllowNull()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $null
  }

  $normalized = $Value.Trim()
  if ($normalized.StartsWith("$")) {
    $normalized = $normalized.Substring(1)
  }
  $normalized = $normalized.ToLowerInvariant()

  if ($normalized -in @("1", "true", "yes", "on")) {
    return $true
  }

  if ($normalized -in @("0", "false", "no", "off")) {
    return $false
  }

  return $null
}

function Get-AutoInstallMissingEnvOverride {
  $envVarNames = @(
    "GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING",
    "TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING"
  )

  foreach ($envVarName in $envVarNames) {
    $rawValue = [Environment]::GetEnvironmentVariable($envVarName)
    $parsedValue = ConvertTo-NullableBoolean -Value $rawValue
    if ($null -ne $parsedValue) {
      return [bool]$parsedValue
    }
  }

  return $null
}

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
  $scriptDir = Split-Path -Parent $PSCommandPath
}

Assert-WindowsNativeNonWsl
Write-Step "execution_model=windows-native-non-wsl"
Write-Step "wsl_required=false"

$bootstrapScript = Join-Path $scriptDir "desktop_native_bootstrap.ps1"
if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
  throw "missing bootstrap script: $bootstrapScript"
}
Assert-PolicySafeNodeRunnerScript -ScriptPath $bootstrapScript -ScriptLabel "desktop bootstrap"

$shouldEnablePolicyBypass = $false
if ($PSBoundParameters.ContainsKey("EnablePolicyBypass")) {
  $shouldEnablePolicyBypass = [bool]$EnablePolicyBypass
}

$installMissingWasSpecified = $PSBoundParameters.ContainsKey("InstallMissing")
$noInstallMissingWasSpecified = $PSBoundParameters.ContainsKey("NoInstallMissing")
if ($installMissingWasSpecified -and $noInstallMissingWasSpecified) {
  throw "conflicting install intent: specify only one of -InstallMissing or -NoInstallMissing"
}

$installMissingIntent = $true
if ($installMissingWasSpecified) {
  $installMissingIntent = [bool]$InstallMissing
} elseif ($noInstallMissingWasSpecified) {
  $installMissingIntent = -not [bool]$NoInstallMissing
} else {
  $envAutoInstallMissing = Get-AutoInstallMissingEnvOverride
  if ($null -ne $envAutoInstallMissing) {
    $installMissingIntent = [bool]$envAutoInstallMissing
  }
}

$invokeArgs = @(
  "-Mode", "run-desktop",
  "-DesktopLaunchStrategy", "dev"
)

if ($installMissingIntent) {
  $invokeArgs += "-InstallMissing"
}
if ($DryRun) {
  $invokeArgs += "-DryRun"
}
if ($ForceNpmInstall) {
  $invokeArgs += "-ForceNpmInstall"
}
if ($shouldEnablePolicyBypass) {
  $invokeArgs += "-EnablePolicyBypass"
}

$bootstrapLaunchArgs = @("-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass")
$bootstrapLaunchArgs += @("-File", $bootstrapScript)
$bootstrapLaunchArgs += $invokeArgs

& powershell.exe @bootstrapLaunchArgs
exit $LASTEXITCODE
