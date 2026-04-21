param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$BootstrapArgs
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-one-click] $Message"
}

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

function Get-ExecutionPolicySnapshot {
  $scopes = @("Process", "CurrentUser", "LocalMachine")
  $snapshot = [ordered]@{}

  foreach ($scope in $scopes) {
    try {
      $snapshot[$scope] = [string](Get-ExecutionPolicy -Scope $scope)
    } catch {
      $snapshot[$scope] = "Unavailable"
    }
  }

  return [pscustomobject]@{
    effective = [string](Get-ExecutionPolicy)
    scopes = $snapshot
  }
}

function Show-ExecutionPolicyStatus {
  $snapshot = Get-ExecutionPolicySnapshot
  Write-Step ("execution policy: effective={0}; process={1}; current_user={2}; local_machine={3}" -f $snapshot.effective, $snapshot.scopes.Process, $snapshot.scopes.CurrentUser, $snapshot.scopes.LocalMachine)

  if ($snapshot.effective -notin @("Bypass", "Unrestricted")) {
    Write-Step "execution policy risk detected: effective_policy=$($snapshot.effective)"
    Write-Step "rerun in this shell with process-scope bypass:"
    Write-Host "  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
  }
}

function Get-PowerShellBinary {
  foreach ($candidate in @("powershell.exe", "powershell", "pwsh")) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
      return [string]$cmd.Source
    }
  }

  return ""
}

function Invoke-BypassScript {
  param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments
  )

  $powershellBinary = Get-PowerShellBinary
  if ([string]::IsNullOrWhiteSpace($powershellBinary)) {
    throw "missing PowerShell binary"
  }

  $previousErrorActionPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $childOutput = & $powershellBinary -NoLogo -NoProfile -ExecutionPolicy Bypass -File $ScriptPath $Arguments 2>&1
    foreach ($line in @($childOutput)) {
      if ([string]::IsNullOrWhiteSpace([string]$line)) {
        continue
      }
      Write-Host $line
    }
    return $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
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

Show-ExecutionPolicyStatus

$doctorInvokeArgs = @("-Mode", "check")
$installMissingSpecified = Test-ArgSpecified -Args $BootstrapArgs -Name "-InstallMissing"
$installMissingEnabled = Test-SwitchEnabled -Args $BootstrapArgs -Name "-InstallMissing"
$noInstallMissingSpecified = Test-ArgSpecified -Args $BootstrapArgs -Name "-NoInstallMissing"
$noInstallMissingEnabled = Test-SwitchEnabled -Args $BootstrapArgs -Name "-NoInstallMissing"
$dryRunEnabled = Test-SwitchEnabled -Args $BootstrapArgs -Name "-DryRun"
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
if ($dryRunEnabled) {
  $doctorInvokeArgs += "-DryRun"
}
if (-not (Test-ArgNamePresent -Args $BootstrapArgs -Name "-EnablePolicyBypass") -or (Test-SwitchEnabled -Args $BootstrapArgs -Name "-EnablePolicyBypass")) {
  $doctorInvokeArgs += "-EnablePolicyBypass"
}

$doctorLaunchCommand = ("{0} -NoLogo -NoProfile -ExecutionPolicy Bypass -File {1} {2}" -f (Get-PowerShellBinary), $doctorScript, ($doctorInvokeArgs -join " "))
Write-Step ("launching doctor: {0}" -f $doctorLaunchCommand)
$doctorExitCode = Invoke-BypassScript -ScriptPath $doctorScript -Arguments $doctorInvokeArgs
Write-Step ("doctor exit code: {0}" -f $doctorExitCode)
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

$bootstrapLaunchCommand = ("{0} -NoLogo -NoProfile -ExecutionPolicy Bypass -File {1} {2}" -f (Get-PowerShellBinary), $bootstrapScript, ($invokeArgs -join " "))
Write-Step ("launching bootstrap: {0}" -f $bootstrapLaunchCommand)
$bootstrapExitCode = Invoke-BypassScript -ScriptPath $bootstrapScript -Arguments $invokeArgs
Write-Step ("bootstrap exit code: {0}" -f $bootstrapExitCode)
if ($dryRunEnabled) {
  exit 0
}
exit $bootstrapExitCode
