param(
  [switch]$InstallMissing,
  [switch]$NoInstallMissing,
  [switch]$EnablePolicyBypass,
  [switch]$DryRun,
  [switch]$ForceNpmInstall
)

$ErrorActionPreference = "Stop"

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

$bootstrapScript = Join-Path $scriptDir "desktop_native_bootstrap.ps1"
if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
  throw "missing bootstrap script: $bootstrapScript"
}

$shouldEnablePolicyBypass = $true
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

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript @invokeArgs
exit $LASTEXITCODE
