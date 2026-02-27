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
$repoRootWsl = (& wsl.exe @wslArgs).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRootWsl)) {
  throw "failed to convert repo path to WSL path"
}

$args = @()
if ($Distro -ne "") {
  $args += @("-d", $Distro)
}
$args += @("--", "bash", "-lc", "cd '$repoRootWsl' && ./bin/privacynode-easy")
& wsl.exe @args
if ($LASTEXITCODE -ne 0) {
  throw "failed to run launcher in WSL"
}
