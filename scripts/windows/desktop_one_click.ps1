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

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
  $scriptDir = Split-Path -Parent $PSCommandPath
}

$bootstrapScript = Join-Path $scriptDir "desktop_native_bootstrap.ps1"
if (-not (Test-Path -LiteralPath $bootstrapScript -PathType Leaf)) {
  throw "missing bootstrap script: $bootstrapScript"
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
