[CmdletBinding(PositionalBinding = $false)]
param(
  [string]$ScriptPath = "",
  [string]$CommandRunner = "",
  [switch]$AllowExternalScript,
  [switch]$AllowRunnerEnvOverride,
  [switch]$AllowUntrustedRunner,
  [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
  [string[]]$EasyNodeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Parse-BoolLike {
  param(
    [AllowEmptyString()]
    [string]$Raw
  )

  if ([string]::IsNullOrWhiteSpace($Raw)) {
    return $false
  }
  switch ($Raw.Trim().ToLowerInvariant()) {
    "1" { return $true }
    "true" { return $true }
    "yes" { return $true }
    "on" { return $true }
    default { return $false }
  }
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
    throw @"
No Git Bash runner was found.
Install Git for Windows and rerun:
  winget install --id Git.Git --exact
Or provide one explicitly:
  .\scripts\windows\easy_node_bridge.ps1 -CommandRunner "C:\Program Files\Git\bin\bash.exe" -- <easy-node-args>
"@
  }

  if (-not [System.IO.Path]::IsPathRooted($runner)) {
    throw "Command runner must be an absolute executable path: $runner"
  }

  if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Command runner path not found: $runner"
  }

  if ($runner -match "(?i)\\WindowsApps\\bash\.exe$") {
    throw "Command runner resolves to WSL shim ($runner). Pass Git for Windows bash.exe to stay WSL-free."
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

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")

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
  throw "Script path must reference a .sh file."
}

if (-not $AllowExternalScript) {
  $repoScriptsRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot.Path "scripts"))
  $resolvedScriptPath = [System.IO.Path]::GetFullPath($ScriptPath)
  $scriptsPrefix = $repoScriptsRoot + [System.IO.Path]::DirectorySeparatorChar
  if (-not ($resolvedScriptPath.Equals($repoScriptsRoot, [System.StringComparison]::OrdinalIgnoreCase) -or $resolvedScriptPath.StartsWith($scriptsPrefix, [System.StringComparison]::OrdinalIgnoreCase))) {
    throw "Script path must stay under $repoScriptsRoot by default (pass -AllowExternalScript to override)."
  }
}

$explicitRunner = $CommandRunner
if ([string]::IsNullOrWhiteSpace($explicitRunner) -and -not [string]::IsNullOrWhiteSpace($env:LOCAL_CONTROL_API_BRIDGE_COMMAND_RUNNER)) {
  $explicitRunner = $env:LOCAL_CONTROL_API_BRIDGE_COMMAND_RUNNER.Trim()
}

$allowRunnerEnvOverrideEffective = $AllowRunnerEnvOverride -or (Parse-BoolLike -Raw $env:LOCAL_CONTROL_API_BRIDGE_ALLOW_RUNNER_ENV_OVERRIDE)
$allowUntrustedRunnerEffective = $AllowUntrustedRunner -or (Parse-BoolLike -Raw $env:LOCAL_CONTROL_API_BRIDGE_ALLOW_UNTRUSTED_RUNNER)

$resolvedRunner = Resolve-CommandRunner -ExplicitRunner $explicitRunner -AllowEnvOverride:$allowRunnerEnvOverrideEffective -AllowUntrusted:$allowUntrustedRunnerEffective
$scriptPathForRunner = Convert-ToGitBashPath -PathValue $ScriptPath

$runnerArgs = @($scriptPathForRunner)
if ($EasyNodeArgs) {
  $runnerArgs += $EasyNodeArgs
}

& $resolvedRunner @runnerArgs
$exitCode = [int]$LASTEXITCODE
if ($exitCode -ne 0) {
  exit $exitCode
}
