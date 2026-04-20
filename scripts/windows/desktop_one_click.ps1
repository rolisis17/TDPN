param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$BootstrapArgs
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Test-ArgNamePresent {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Args,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  foreach ($arg in $Args) {
    if ($arg -eq $Name) {
      return $true
    }
  }

  return $false
}

function Test-SwitchEnabled {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Args,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  foreach ($arg in $Args) {
    if ($arg -eq $Name) {
      return $true
    }

    if ($arg -like "${Name}:*") {
      $rawValue = $arg.Substring($Name.Length + 1).Trim()
      if ([string]::IsNullOrWhiteSpace($rawValue)) {
        return $true
      }

      $normalized = $rawValue.Trim()
      if ($normalized.StartsWith("$")) {
        $normalized = $normalized.Substring(1)
      }
      $normalized = $normalized.ToLowerInvariant()
      if ($normalized -eq "1" -or $normalized -eq "true") {
        return $true
      }
    }
  }

  return $false
}

function Test-ArgSpecified {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Args,
    [Parameter(Mandatory = $true)]
    [string]$Name
  )

  foreach ($arg in $Args) {
    if ($arg -eq $Name -or $arg -like "${Name}:*") {
      return $true
    }
  }

  return $false
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

$doctorScript = Join-Path $scriptDir "desktop_doctor.ps1"
if (-not (Test-Path -LiteralPath $doctorScript -PathType Leaf)) {
  throw "missing doctor script: $doctorScript"
}

$bootstrapScript = Join-Path $scriptDir "desktop_native_bootstrap.ps1"
if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
  throw "missing bootstrap script: $bootstrapScript"
}

$doctorInvokeArgs = @("-Mode", "check")
$installMissingSpecified = Test-ArgSpecified -Args $BootstrapArgs -Name "-InstallMissing"
$installMissingEnabled = Test-SwitchEnabled -Args $BootstrapArgs -Name "-InstallMissing"
$noInstallMissingSpecified = Test-ArgSpecified -Args $BootstrapArgs -Name "-NoInstallMissing"
$noInstallMissingEnabled = Test-SwitchEnabled -Args $BootstrapArgs -Name "-NoInstallMissing"
$forwardBootstrapArgs = @()
foreach ($arg in $BootstrapArgs) {
  if ($arg -eq "-NoInstallMissing" -or $arg -like "-NoInstallMissing:*") {
    continue
  }
  $forwardBootstrapArgs += $arg
}

if ($installMissingSpecified -and $noInstallMissingSpecified) {
  throw "conflicting install intent: specify only one of -InstallMissing or -NoInstallMissing"
}

$envAutoInstallMissing = Get-AutoInstallMissingEnvOverride
$installIntent = $true
if ($null -ne $envAutoInstallMissing) {
  $installIntent = [bool]$envAutoInstallMissing
}
if ($installMissingSpecified) {
  $installIntent = $installMissingEnabled
} elseif ($noInstallMissingSpecified) {
  $installIntent = -not $noInstallMissingEnabled
}
if ($installIntent) {
  $doctorInvokeArgs = @("-Mode", "fix", "-InstallMissing")
}
if (Test-SwitchEnabled -Args $BootstrapArgs -Name "-DryRun") {
  $doctorInvokeArgs += "-DryRun"
}
if (-not (Test-ArgNamePresent -Args $BootstrapArgs -Name "-EnablePolicyBypass") -or (Test-SwitchEnabled -Args $BootstrapArgs -Name "-EnablePolicyBypass")) {
  $doctorInvokeArgs += "-EnablePolicyBypass"
}

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $doctorScript @doctorInvokeArgs
$doctorExitCode = $LASTEXITCODE
if ($doctorExitCode -ne 0) {
  exit $doctorExitCode
}

$invokeArgs = @()
if (-not (Test-ArgNamePresent -Args $BootstrapArgs -Name "-EnablePolicyBypass")) {
  $invokeArgs += "-EnablePolicyBypass"
}
if (-not (Test-ArgNamePresent -Args $BootstrapArgs -Name "-Mode")) {
  $invokeArgs += @("-Mode", "run-full")
}
if (-not (Test-ArgNamePresent -Args $BootstrapArgs -Name "-DesktopLaunchStrategy")) {
  $invokeArgs += @("-DesktopLaunchStrategy", "auto")
}
if ($installIntent -and -not $installMissingSpecified -and -not $noInstallMissingSpecified) {
  $invokeArgs += "-InstallMissing"
}

$invokeArgs += $forwardBootstrapArgs

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript @invokeArgs
exit $LASTEXITCODE
