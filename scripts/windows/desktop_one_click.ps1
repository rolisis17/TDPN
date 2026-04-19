param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$BootstrapArgs
)

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
$installIntent = Test-SwitchEnabled -Args $BootstrapArgs -Name "-InstallMissing"
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

$invokeArgs += $BootstrapArgs

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $bootstrapScript @invokeArgs
exit $LASTEXITCODE
