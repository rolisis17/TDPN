param(
  [switch]$DryRun,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$CommandTokens
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
  Write-Host "Policy-safe Node tool wrapper for Windows desktop workflows"
  Write-Host ""
  Write-Host "Usage:"
  Write-Host "  scripts\windows\desktop_node.ps1 [-DryRun] <npm|npx> <args...>"
  Write-Host "  scripts\windows\desktop_node.ps1 [-DryRun] <npm args...>"
  Write-Host ""
  Write-Host "Examples:"
  Write-Host "  scripts\windows\desktop_node.ps1 npm install"
  Write-Host "  scripts\windows\desktop_node.ps1 npm run tauri -- dev"
  Write-Host "  scripts\windows\desktop_node.ps1 npx --yes create-vite@latest"
  Write-Host "  scripts\windows\desktop_node.ps1 install   # npm implied"
  Write-Host ""
  Write-Host "Notes:"
  Write-Host "  - Uses desktop_shell.ps1 internally with ExecutionPolicy Bypass."
  Write-Host "  - Normalizes npm/npx resolution to npm.cmd/npx.cmd."
}

function Normalize-NodeToolName {
  param(
    [AllowNull()]
    [string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Name)) {
    return ""
  }

  $trimmed = $Name.Trim().ToLowerInvariant()
  switch -Regex ($trimmed) {
    '^npm(?:\.cmd|\.ps1)?$' { return "npm" }
    '^npx(?:\.cmd|\.ps1)?$' { return "npx" }
    default { return "" }
  }
}

if ($null -eq $CommandTokens) {
  $CommandTokens = @()
}

if ($CommandTokens.Count -eq 0) {
  Show-Usage
  exit 0
}

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
  $scriptDir = Split-Path -Parent $PSCommandPath
}

$desktopShellScript = Join-Path $scriptDir "desktop_shell.ps1"
if (-not (Test-Path -LiteralPath $desktopShellScript -PathType Leaf)) {
  throw "missing desktop shell script: $desktopShellScript"
}

$firstToken = [string]$CommandTokens[0]
$explicitTool = Normalize-NodeToolName -Name $firstToken

$toolName = "npm"
$toolArgs = @($CommandTokens)
if (-not [string]::IsNullOrWhiteSpace($explicitTool)) {
  $toolName = $explicitTool
  if ($CommandTokens.Count -gt 1) {
    $toolArgs = @($CommandTokens[1..($CommandTokens.Count - 1)])
  } else {
    $toolArgs = @()
  }
}

$invokeArgs = @()
if ($DryRun) {
  $invokeArgs += "-DryRun"
}
$invokeArgs += $toolName
$invokeArgs += $toolArgs

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $desktopShellScript @invokeArgs
exit $LASTEXITCODE
