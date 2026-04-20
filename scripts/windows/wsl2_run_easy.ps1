param(
  [string]$Distro = ""
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "wsl.exe not found."
}

function ConvertTo-BashSingleQuotedLiteral {
  param(
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Value
  )

  return "'" + $Value.Replace("'", "'\''") + "'"
}

function Resolve-RequestedDistro {
  param(
    [string]$RequestedDistro
  )

  $trimmed = ""
  if ($null -ne $RequestedDistro) {
    $trimmed = $RequestedDistro.Trim()
  }
  if ([string]::IsNullOrWhiteSpace($trimmed)) {
    return ""
  }

  $distroListRaw = & wsl.exe --list --quiet 2>$null
  if ($LASTEXITCODE -ne 0) {
    return $trimmed
  }

  $available = @()
  foreach ($entry in $distroListRaw) {
    $name = [string]$entry
    if (-not [string]::IsNullOrWhiteSpace($name)) {
      $available += $name.Trim()
    }
  }
  if ($available.Count -eq 0) {
    return $trimmed
  }

  foreach ($name in $available) {
    if ($name.Equals($trimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $name
    }
  }

  $availableList = $available -join ", "
  throw "WSL distro '$trimmed' was not found. Available distros: $availableList. Use 'wsl -l -v' to inspect installed distros."
}

function Resolve-EffectiveDistro {
  param(
    [string]$RequestedDistro
  )

  $resolvedRequested = Resolve-RequestedDistro -RequestedDistro $RequestedDistro
  if ($resolvedRequested -ne "") {
    return @{
      Distro = $resolvedRequested
      Source = "parameter"
    }
  }

  $envOverrideRaw = $env:TDPN_WSL_DISTRO
  if ($null -eq $envOverrideRaw) {
    return @{
      Distro = ""
      Source = "default"
    }
  }

  $envOverride = $envOverrideRaw.Trim()
  if ([string]::IsNullOrWhiteSpace($envOverride)) {
    return @{
      Distro = ""
      Source = "default"
    }
  }

  return @{
    Distro = (Resolve-RequestedDistro -RequestedDistro $envOverride)
    Source = "environment"
  }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$repoRootWindows = $repoRoot.Path
$distroResolution = Resolve-EffectiveDistro -RequestedDistro $Distro
$Distro = $distroResolution.Distro
if ($distroResolution.Source -eq "environment") {
  Write-Host "Using WSL distro '$Distro' from TDPN_WSL_DISTRO." -ForegroundColor DarkGray
}

$wslArgs = @()
if ($Distro -ne "") {
  $wslArgs += @("-d", $Distro)
}
$wslArgs += @("--", "wslpath", "-a", $repoRootWindows)

$repoRootWslRaw = & wsl.exe @wslArgs 2>&1
$wslPathExit = $LASTEXITCODE
if ($wslPathExit -ne 0) {
  $details = ($repoRootWslRaw | Out-String).Trim()
  if ([string]::IsNullOrWhiteSpace($details)) {
    $details = "no output"
  }
  if ($Distro -eq "") {
    throw "failed to convert repo path to WSL path. Ensure a default WSL distro exists or pass -Distro. Details: $details"
  }
  throw "failed to convert repo path to WSL path for distro '$Distro'. Details: $details"
}

$repoRootWslText = ($repoRootWslRaw | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($repoRootWslText)) {
  if ($Distro -eq "") {
    throw "failed to convert repo path to WSL path (empty output). Ensure a default WSL distro exists or pass -Distro."
  }
  throw "failed to convert repo path to WSL path for distro '$Distro' (empty output)."
}
$repoRootWsl = $repoRootWslText
$repoRootWslQuoted = ConvertTo-BashSingleQuotedLiteral -Value $repoRootWsl

$args = @()
if ($Distro -ne "") {
  $args += @("-d", $Distro)
}
$args += @("--", "bash", "-lc", "cd $repoRootWslQuoted; ./bin/privacynode-easy")
& wsl.exe @args
if ($LASTEXITCODE -ne 0) {
  throw "failed to run launcher in WSL"
}
