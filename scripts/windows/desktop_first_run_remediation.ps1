param(
  [switch]$Compact,
  [switch]$FailOnIssues,
  [switch]$PrintSummaryJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host "[desktop-first-run-remediation] $Message"
}

function Get-CommandPath {
  param([Parameter(Mandatory = $true)][string]$Name)

  $cmd = Get-Command $Name -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($null -eq $cmd) {
    return ""
  }

  if ($cmd -is [System.Management.Automation.AliasInfo]) {
    $resolvedPath = [string]$cmd.ResolvedCommand.Path
    if (-not [string]::IsNullOrWhiteSpace($resolvedPath)) {
      return $resolvedPath
    }
  }

  $cmdPath = [string]$cmd.Path
  if (-not [string]::IsNullOrWhiteSpace($cmdPath)) {
    return $cmdPath
  }

  $cmdSource = [string]$cmd.Source
  if (-not [string]::IsNullOrWhiteSpace($cmdSource)) {
    return $cmdSource
  }

  return ""
}

function Get-ExecutionPolicySnapshot {
  $scopes = @("Process", "CurrentUser", "LocalMachine")
  $snapshot = [ordered]@{}
  foreach ($scope in $scopes) {
    try {
      $snapshot[$scope] = [string](Get-ExecutionPolicy -Scope $scope)
    } catch {
      $snapshot[$scope] = "Unavailable"
    }
  }

  $effectivePolicy = "Unavailable"
  try {
    $effectivePolicy = [string](Get-ExecutionPolicy)
  } catch {
    $effectivePolicy = "Unavailable"
  }

  return [pscustomobject]@{
    effective = $effectivePolicy
    scopes = $snapshot
  }
}

function Add-UniqueHint {
  param(
    [Parameter(Mandatory = $true)]
    [ref]$Hints,
    [Parameter(Mandatory = $true)]
    [string]$Command
  )

  if ([string]::IsNullOrWhiteSpace($Command)) {
    return
  }
  if (-not $Hints.Value.Contains($Command)) {
    $Hints.Value.Add($Command) | Out-Null
  }
}

$executionPolicySnapshot = Get-ExecutionPolicySnapshot
$executionPolicyRisk = $executionPolicySnapshot.effective -notin @("Bypass", "Unrestricted", "RemoteSigned")

$goPath = Get-CommandPath "go"
$nodePath = Get-CommandPath "node"
$rustcPath = Get-CommandPath "rustc"
$cargoPath = Get-CommandPath "cargo"
$npmPath = Get-CommandPath "npm"

$goAvailable = -not [string]::IsNullOrWhiteSpace($goPath)
$nodeAvailable = -not [string]::IsNullOrWhiteSpace($nodePath)
$rustcAvailable = -not [string]::IsNullOrWhiteSpace($rustcPath)
$cargoAvailable = -not [string]::IsNullOrWhiteSpace($cargoPath)
$rustAvailable = $rustcAvailable -and $cargoAvailable

$npmResolvesToPs1 = $false
$npmCmdSiblingPath = ""
$npmCmdSiblingAvailable = $false
if (-not [string]::IsNullOrWhiteSpace($npmPath)) {
  $npmLeaf = [System.IO.Path]::GetFileName($npmPath)
  $npmResolvesToPs1 = $npmLeaf.Equals("npm.ps1", [System.StringComparison]::OrdinalIgnoreCase)
  if ($npmResolvesToPs1) {
    $candidateCmdSiblingPath = [System.IO.Path]::ChangeExtension($npmPath, ".cmd")
    if (Test-Path -LiteralPath $candidateCmdSiblingPath -PathType Leaf) {
      $npmCmdSiblingPath = $candidateCmdSiblingPath
      $npmCmdSiblingAvailable = $true
    }
  }
}

$npmPs1PolicyIssue = $npmResolvesToPs1 -and $executionPolicyRisk
$npmPs1ShimIssue = $npmResolvesToPs1 -and -not $npmCmdSiblingAvailable

$issues = New-Object System.Collections.Generic.List[string]
if ($executionPolicyRisk) { $issues.Add("execution_policy_risk") | Out-Null }
if (-not $goAvailable) { $issues.Add("go_missing") | Out-Null }
if (-not $nodeAvailable) { $issues.Add("node_missing") | Out-Null }
if (-not $rustAvailable) { $issues.Add("rust_toolchain_missing") | Out-Null }
if ($npmPs1PolicyIssue) { $issues.Add("npm_ps1_policy_issue") | Out-Null }
if ($npmPs1ShimIssue) { $issues.Add("npm_ps1_without_npm_cmd") | Out-Null }

$safeHints = New-Object System.Collections.Generic.List[string]
if ($executionPolicyRisk) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
}
if (-not $goAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id GoLang.Go --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $nodeAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $rustAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements"
}
if ($npmPs1PolicyIssue) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command ".\scripts\windows\desktop_node.cmd npm -v"
}
if ($npmPs1ShimIssue) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements"
}
if ($issues.Count -gt 0) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass"
}

if ($Compact) {
  if ($issues.Count -eq 0) {
    Write-Step "first-run blocker scan: no blockers detected (policy/toolchain/npm shim checks all passed)"
  } else {
    Write-Step ("first-run blockers detected: {0}" -f ($issues -join ", "))
    Write-Step "safe one-command remediation hints:"
    foreach ($hint in $safeHints) {
      Write-Host ("  {0}" -f $hint)
    }
  }
} else {
  Write-Step ("execution policy effective={0}; process={1}; current_user={2}; local_machine={3}" -f $executionPolicySnapshot.effective, $executionPolicySnapshot.scopes.Process, $executionPolicySnapshot.scopes.CurrentUser, $executionPolicySnapshot.scopes.LocalMachine)
  Write-Step ("go: {0}" -f $(if ($goAvailable) { $goPath } else { "missing" }))
  Write-Step ("node: {0}" -f $(if ($nodeAvailable) { $nodePath } else { "missing" }))
  Write-Step ("rustc: {0}" -f $(if ($rustcAvailable) { $rustcPath } else { "missing" }))
  Write-Step ("cargo: {0}" -f $(if ($cargoAvailable) { $cargoPath } else { "missing" }))
  Write-Step ("npm resolver: {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($npmPath)) { $npmPath } else { "missing" }))
  if ($npmResolvesToPs1) {
    Write-Step ("npm.ps1 resolver detected; sibling npm.cmd={0}" -f $(if ($npmCmdSiblingAvailable) { $npmCmdSiblingPath } else { "missing" }))
  }

  if ($issues.Count -eq 0) {
    Write-Step "diagnosis: pass (no first-run blockers detected)"
  } else {
    Write-Step ("diagnosis: fail ({0} blocker(s))" -f $issues.Count)
    Write-Step "safe one-command remediation hints:"
    foreach ($hint in $safeHints) {
      Write-Host ("  {0}" -f $hint)
    }
  }
}

$summary = [ordered]@{
  version = 1
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  status = $(if ($issues.Count -eq 0) { "ok" } else { "needs_remediation" })
  issues_detected = [int]$issues.Count
  issues = @($issues)
  checks = [ordered]@{
    execution_policy = [ordered]@{
      effective = $executionPolicySnapshot.effective
      process = $executionPolicySnapshot.scopes.Process
      current_user = $executionPolicySnapshot.scopes.CurrentUser
      local_machine = $executionPolicySnapshot.scopes.LocalMachine
      risk_detected = [bool]$executionPolicyRisk
    }
    toolchain = [ordered]@{
      go_available = [bool]$goAvailable
      node_available = [bool]$nodeAvailable
      rustc_available = [bool]$rustcAvailable
      cargo_available = [bool]$cargoAvailable
      rust_available = [bool]$rustAvailable
      go_path = $goPath
      node_path = $nodePath
      rustc_path = $rustcPath
      cargo_path = $cargoPath
    }
    npm = [ordered]@{
      resolver_path = $npmPath
      resolves_to_npm_ps1 = [bool]$npmResolvesToPs1
      npm_cmd_sibling_available = [bool]$npmCmdSiblingAvailable
      npm_cmd_sibling_path = $npmCmdSiblingPath
      npm_ps1_policy_issue = [bool]$npmPs1PolicyIssue
      npm_ps1_without_npm_cmd = [bool]$npmPs1ShimIssue
    }
  }
  remediation_hints = @($safeHints)
}

if ($PrintSummaryJson) {
  $summary | ConvertTo-Json -Depth 8
}

if ($FailOnIssues -and $issues.Count -gt 0) {
  exit 1
}

exit 0
