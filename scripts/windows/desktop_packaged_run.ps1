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

$bootstrapInvokeArgs = @(
  "-Mode", "run-full",
  "-DesktopLaunchStrategy", "packaged",
  "-ApiAddr", $ApiAddr
)

if (-not [string]::IsNullOrWhiteSpace($DesktopExecutablePath)) {
  $bootstrapInvokeArgs += @("-DesktopExecutableOverridePath", $DesktopExecutablePath)
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
