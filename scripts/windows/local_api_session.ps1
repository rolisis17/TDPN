param(
  [string]$ApiAddr = "127.0.0.1:8095",
  [string]$ScriptPath = "",
  [string]$CommandRunner = "",
  [switch]$AllowRemoteBind,
  [switch]$AllowExternalScript,
  [switch]$AllowUntrustedRunner,
  [switch]$AllowRunnerEnvOverride,
  [ValidateSet("0", "1")]
  [string]$AllowUpdate = "0",
  [int]$CommandTimeoutSec = 120,
  [string]$Config = "",
  [string]$ConnectPathProfileDefault = "",
  [string]$ConnectInterfaceDefault = "",
  [string]$ConnectRunPreflightDefault = "",
  [string]$ConnectProdProfileDefault = "",
  [switch]$InstallMissing,
  [switch]$DryRun
)


Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Set-Or-ClearEnv {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [AllowEmptyString()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    Remove-Item -Path ("Env:{0}" -f $Name) -ErrorAction SilentlyContinue
    return
  }
  Set-Item -Path ("Env:{0}" -f $Name) -Value $Value
}

function Convert-ToGitBashPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$PathValue
  )

  $trimmed = $PathValue.Trim()
  if ($trimmed -match "^[A-Za-z]:\\") {
    $drive = $trimmed.Substring(0, 1).ToLowerInvariant()
    $rest = $trimmed.Substring(2).Replace("\", "/").TrimStart("/")
    return "/$drive/$rest"
  }
  return $trimmed
}

function Resolve-CommandRunner {
  param(
    [string]$ExplicitRunner,
    [switch]$AllowEnvOverride,
    [switch]$AllowUntrusted
  )

  $runner = ""
  if (-not [string]::IsNullOrWhiteSpace($ExplicitRunner)) {
    $runner = $ExplicitRunner.Trim()
  } elseif ($AllowEnvOverride -and -not [string]::IsNullOrWhiteSpace($env:LOCAL_CONTROL_API_GIT_BASH_PATH)) {
    $runner = $env:LOCAL_CONTROL_API_GIT_BASH_PATH.Trim()
  } else {
    $candidates = @(
      "C:\Program Files\Git\bin\bash.exe",
      "C:\Program Files\Git\usr\bin\bash.exe",
      "C:\Program Files (x86)\Git\bin\bash.exe",
      "C:\Program Files (x86)\Git\usr\bin\bash.exe"
    )
    foreach ($candidate in $candidates) {
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $runner = $candidate
        break
      }
    }
  }

  if ([string]::IsNullOrWhiteSpace($runner)) {
    throw "No Windows-native bash runner was found. Install Git for Windows or pass -CommandRunner `<path-to-bash.exe`>."
  }

  if (-not [System.IO.Path]::IsPathRooted($runner)) {
    throw "Command runner must be an absolute executable path: $runner"
  }

  if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Command runner path not found: $runner"
  }

  if ($runner -match "(?i)\\WindowsApps\\bash\.exe$") {
    throw "Command runner resolves to WSL shim ($runner). Pass Git for Windows bash.exe via -CommandRunner to stay WSL-free."
  }

  $runner = [System.IO.Path]::GetFullPath($runner)
  if (-not $AllowUntrusted) {
    $leaf = [System.IO.Path]::GetFileName($runner).ToLowerInvariant()
    if ($leaf -ne "bash.exe") {
      throw "Command runner must be bash.exe from a trusted Git for Windows install (pass -AllowUntrustedRunner to override)."
    }
    $trustedRoots = @(
      "C:\Program Files\Git\",
      "C:\Program Files (x86)\Git\"
    )
    $trusted = $false
    foreach ($root in $trustedRoots) {
      if ($runner.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $trusted = $true
        break
      }
    }
    if (-not $trusted) {
      throw "Command runner path is outside trusted Git for Windows locations (pass -AllowUntrustedRunner to override): $runner"
    }
  }

  return $runner
}

function Parse-ApiAddr {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Addr
  )

  $value = $Addr.Trim()
  if ([string]::IsNullOrWhiteSpace($value)) {
    throw "-ApiAddr is required"
  }

  if ($value.StartsWith("[")) {
    if ($value -notmatch "^\[(.+)\]:(\d+)$") {
      throw "-ApiAddr must be host:port (or [host]:port for IPv6)"
    }
    return @{
      Host = $matches[1]
      Port = [int]$matches[2]
      Addr = $value
    }
  }

  if ($value -notmatch "^([^:]+):(\d+)$") {
    throw "-ApiAddr must be host:port"
  }
  return @{
    Host = $matches[1]
    Port = [int]$matches[2]
    Addr = $value
  }
}

function Test-LoopbackHost {
  param(
    [Parameter(Mandatory = $true)]
    [string]$HostValue
  )

  $normalized = $HostValue.Trim().Trim("[").Trim("]").ToLowerInvariant()
  return $normalized -eq "127.0.0.1" -or $normalized -eq "localhost" -or $normalized -eq "::1"
}

function Validate-ApiAddrPolicy {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Addr,
    [switch]$AllowRemote
  )

  $parsed = Parse-ApiAddr -Addr $Addr
  if ($parsed.Port -lt 1 -or $parsed.Port -gt 65535) {
    throw "-ApiAddr port must be in 1..65535"
  }
  if (-not (Test-LoopbackHost -HostValue $parsed.Host)) {
    if (-not $AllowRemote) {
      throw "-ApiAddr must target loopback by default (127.0.0.1, localhost, ::1). Pass -AllowRemoteBind to override."
    }
    $authToken = [string]::Empty
    if (-not [string]::IsNullOrWhiteSpace($env:LOCAL_CONTROL_API_AUTH_TOKEN)) {
      $authToken = $env:LOCAL_CONTROL_API_AUTH_TOKEN.Trim()
    }
    if ([string]::IsNullOrWhiteSpace($authToken)) {
      throw "Remote bind requires LOCAL_CONTROL_API_AUTH_TOKEN to be set."
    }
  }
}

function Validate-ConnectDefaults {
  param(
    [string]$PathProfile,
    [string]$RunPreflight,
    [string]$ProdDefault
  )

  if (-not [string]::IsNullOrWhiteSpace($PathProfile)) {
    $normalized = $PathProfile.Trim().ToLowerInvariant()
    if ($normalized -notin @("1hop", "2hop", "3hop")) {
      throw "-ConnectPathProfileDefault must be one of: 1hop, 2hop, 3hop"
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($RunPreflight)) {
    $normalized = $RunPreflight.Trim()
    if ($normalized -notin @("0", "1")) {
      throw "-ConnectRunPreflightDefault must be 0 or 1"
    }
  }

  if (-not [string]::IsNullOrWhiteSpace($ProdDefault)) {
    $normalized = $ProdDefault.Trim().ToLowerInvariant()
    if ($normalized -notin @("auto", "0", "1")) {
      throw "-ConnectProdProfileDefault must be one of: auto, 0, 1"
    }
  }
}

function Resolve-GoExecutable {
  $cmd = Get-Command go -ErrorAction SilentlyContinue
  if ($cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source) -and (Test-Path -LiteralPath $cmd.Source -PathType Leaf)) {
    return $cmd.Source
  }

  $candidates = @()
  if (-not [string]::IsNullOrWhiteSpace($env:GOROOT)) {
    $candidates += (Join-Path $env:GOROOT "bin\go.exe")
  }
  if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
    $candidates += (Join-Path $env:ProgramFiles "Go\bin\go.exe")
  }
  if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
    $candidates += (Join-Path ${env:ProgramFiles(x86)} "Go\bin\go.exe")
  }
  if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
    $candidates += (Join-Path $env:SystemDrive "Go\bin\go.exe")
  }

  foreach ($candidate in $candidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return $candidate
    }
  }

  throw @"
go was not found in PATH (or common install paths).
Install Go with:
  winget install --id GoLang.Go --exact
Or rerun with auto-remediation:
  .\scripts\windows\local_api_session.ps1 -InstallMissing
Then open a new terminal and rerun:
  .\scripts\windows\local_api_session.ps1
"@
}

function Refresh-ProcessPath {
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $segments = @()
  if (-not [string]::IsNullOrWhiteSpace($machinePath)) {
    $segments += $machinePath.Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($userPath)) {
    $segments += $userPath.Trim()
  }
  if ($segments.Count -gt 0) {
    $env:Path = ($segments -join ";")
  }
}

function Invoke-WingetInstallGo {
  $winget = Get-Command winget -ErrorAction SilentlyContinue
  if (-not $winget -or [string]::IsNullOrWhiteSpace($winget.Source) -or -not (Test-Path -LiteralPath $winget.Source -PathType Leaf)) {
    throw @"
Go auto-remediation requested but winget was not found.
Install Go manually with:
  winget install --id GoLang.Go --exact --source winget --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
"@
  }

  $installArgs = @(
    "install",
    "--id", "GoLang.Go",
    "--exact",
    "--source", "winget",
    "--accept-package-agreements",
    "--accept-source-agreements",
    "--silent",
    "--disable-interactivity"
  )
  & $winget.Source @installArgs
  if ($LASTEXITCODE -ne 0) {
    throw "winget install for GoLang.Go failed with exit code $LASTEXITCODE"
  }
}

if ($CommandTimeoutSec -lt 5) {
  throw "-CommandTimeoutSec must be >= 5"
}

Validate-ConnectDefaults -PathProfile $ConnectPathProfileDefault -RunPreflight $ConnectRunPreflightDefault -ProdDefault $ConnectProdProfileDefault

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")

Validate-ApiAddrPolicy -Addr $ApiAddr -AllowRemote:$AllowRemoteBind

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
  $ScriptPath = Join-Path $repoRoot.Path "scripts\easy_node.sh"
} elseif (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
  $ScriptPath = Join-Path $repoRoot.Path $ScriptPath
}
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path

if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
  throw "Script path was not found: $ScriptPath"
}

$scriptPathExt = [System.IO.Path]::GetExtension($ScriptPath).ToLowerInvariant()
if ($scriptPathExt -ne ".sh") {
  throw "Script path must reference a .sh script file."
}
if (-not $AllowExternalScript) {
  $repoScriptsRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot.Path "scripts"))
  $resolvedScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
  $scriptsPrefix = $repoScriptsRoot + [System.IO.Path]::DirectorySeparatorChar
  if (-not ($resolvedScriptPath.Equals($repoScriptsRoot, [System.StringComparison]::OrdinalIgnoreCase) -or $resolvedScriptPath.StartsWith($scriptsPrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
    throw "Script path must stay under $repoScriptsRoot by default (pass -AllowExternalScript to override)."
  }
}

$resolvedRunner = Resolve-CommandRunner -ExplicitRunner $CommandRunner -AllowEnvOverride:$AllowRunnerEnvOverride -AllowUntrusted:$AllowUntrustedRunner
$scriptPathForRunner = $ScriptPath
if ($resolvedRunner -match "(?i)bash(\.exe)?$") {
  $scriptPathForRunner = Convert-ToGitBashPath -PathValue $ScriptPath
}

if (-not [string]::IsNullOrWhiteSpace($Config)) {
  if (-not [System.IO.Path]::IsPathRooted($Config)) {
    $Config = Join-Path $repoRoot.Path $Config
  }
  $Config = (Resolve-Path -LiteralPath $Config).Path
}

Set-Item -Path "Env:LOCAL_CONTROL_API_ADDR" -Value $ApiAddr
Set-Item -Path "Env:LOCAL_CONTROL_API_SCRIPT" -Value $scriptPathForRunner
Set-Item -Path "Env:LOCAL_CONTROL_API_RUNNER" -Value $resolvedRunner
Set-Item -Path "Env:LOCAL_CONTROL_API_ALLOW_UPDATE" -Value $AllowUpdate
Set-Item -Path "Env:LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC" -Value ([string]$CommandTimeoutSec)

Set-Or-ClearEnv -Name "LOCAL_CONTROL_API_CONNECT_PATH_PROFILE" -Value $ConnectPathProfileDefault
Set-Or-ClearEnv -Name "LOCAL_CONTROL_API_CONNECT_INTERFACE" -Value $ConnectInterfaceDefault
Set-Or-ClearEnv -Name "LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT" -Value $ConnectRunPreflightDefault
Set-Or-ClearEnv -Name "LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT" -Value $ConnectProdProfileDefault

$goArgs = @("run", "./cmd/node")
if (-not [string]::IsNullOrWhiteSpace($Config)) {
  $goArgs += @("--config", $Config)
}
$goArgs += @("--local-api")

Write-Host "local-api-session (windows-native):"
Write-Host "  api_addr: $ApiAddr"
Write-Host "  script_path: $ScriptPath"
Write-Host "  script_path_runner: $scriptPathForRunner"
Write-Host "  command_runner: $resolvedRunner"
Write-Host "  allow_update: $AllowUpdate"
Write-Host "  command_timeout_sec: $CommandTimeoutSec"
$installMissingEnabled = if ($InstallMissing) { "true" } else { "false" }
Write-Host "  install_missing: $installMissingEnabled"
if (-not [string]::IsNullOrWhiteSpace($Config)) {
  Write-Host "  node_config: $Config"
} else {
  Write-Host "  node_config: (default)"
}
Write-Host "  command: go $($goArgs -join ' ')"

if ($DryRun) {
  Write-Host "local-api-session dry-run: command not executed"
  exit 0
}

$goExe = ""
try {
  $goExe = Resolve-GoExecutable
} catch {
  if (-not $InstallMissing) {
    throw
  }
  Write-Host "local-api-session: go not found; attempting install with winget (GoLang.Go)..."
  Invoke-WingetInstallGo
  Refresh-ProcessPath
  try {
    $goExe = Resolve-GoExecutable
  } catch {
    throw @"
Go installation was attempted but go is still unavailable in PATH/common locations.
Try opening a new terminal and verify:
  go version
If still missing, reinstall manually:
  winget install --id GoLang.Go --exact --source winget --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
"@
  }
}

Push-Location $repoRoot.Path
try {
  & $goExe @goArgs
  if ($LASTEXITCODE -ne 0) {
    throw "local-api session exited with code $LASTEXITCODE"
  }
} finally {
  Pop-Location
}
