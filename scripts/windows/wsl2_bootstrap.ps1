param(
  [string]$Distro = "",
  [switch]$NoAutoInstall
)

$ErrorActionPreference = "Stop"

function Invoke-WSL {
  param(
    [string]$Command
  )

  $args = @()
  if ($Distro -ne "") {
    $args += @("-d", $Distro)
  }
  $args += @("--", "bash", "-lc", $Command)

  & wsl.exe @args
  if ($LASTEXITCODE -ne 0) {
    throw "WSL command failed: $Command"
  }
}

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  throw "wsl.exe not found. Install/enable WSL2 first."
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

$installFlag = "--auto-install"
if ($NoAutoInstall) {
  $installFlag = ""
}

$cmd = @"
cd '$repoRootWsl'
chmod +x ./scripts/install_wsl2_mode.sh ./scripts/install_easy_mode.sh ./scripts/easy_node.sh
./scripts/install_wsl2_mode.sh $installFlag
"@

Invoke-WSL -Command $cmd

Write-Host ""
Write-Host "WSL2 bootstrap complete." -ForegroundColor Green
Write-Host "To run launcher:" -ForegroundColor Yellow
if ($Distro -ne "") {
  Write-Host "wsl -d $Distro -- bash -lc \"cd '$repoRootWsl' && ./bin/privacynode-easy\""
} else {
  Write-Host "wsl -- bash -lc \"cd '$repoRootWsl' && ./bin/privacynode-easy\""
}
