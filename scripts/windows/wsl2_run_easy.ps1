param(
  [string]$Distro = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "wsl.exe not found."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$repoRootWindows = $repoRoot.Path

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

$args = @()
if ($Distro -ne "") {
  $args += @("-d", $Distro)
}
$args += @("--", "bash", "-lc", "cd '$repoRootWsl'; ./bin/privacynode-easy")
& wsl.exe @args
if ($LASTEXITCODE -ne 0) {
  throw "failed to run launcher in WSL"
}
