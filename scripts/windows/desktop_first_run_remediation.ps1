param(
  [switch]$Compact,
  [switch]$Apply,
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

function Get-GitBashSnapshot {
  $checkedCandidates = New-Object System.Collections.Generic.List[string]
  $envCandidate = ""
  if (-not [string]::IsNullOrWhiteSpace($env:LOCAL_CONTROL_API_GIT_BASH_PATH)) {
    $envCandidate = [Environment]::ExpandEnvironmentVariables($env:LOCAL_CONTROL_API_GIT_BASH_PATH).Trim()
  }
  if (-not [string]::IsNullOrWhiteSpace($envCandidate)) {
    $checkedCandidates.Add($envCandidate) | Out-Null
  }

  $defaultCandidates = @(
    "C:\Program Files\Git\bin\bash.exe",
    "C:\Program Files\Git\usr\bin\bash.exe",
    "C:\Program Files (x86)\Git\bin\bash.exe",
    "C:\Program Files (x86)\Git\usr\bin\bash.exe"
  )
  foreach ($candidate in $defaultCandidates) {
    if (-not $checkedCandidates.Contains($candidate)) {
      $checkedCandidates.Add($candidate) | Out-Null
    }
  }

  foreach ($candidate in $checkedCandidates) {
    if ([string]::IsNullOrWhiteSpace($candidate)) {
      continue
    }
    $normalizedCandidate = $candidate.Trim('"').Trim()
    if (-not [System.IO.Path]::IsPathRooted($normalizedCandidate)) {
      continue
    }
    if (Test-Path -LiteralPath $normalizedCandidate -PathType Leaf) {
      $source = if ($normalizedCandidate -eq $envCandidate -and -not [string]::IsNullOrWhiteSpace($envCandidate)) { "env:LOCAL_CONTROL_API_GIT_BASH_PATH" } else { "trusted-default" }
      return [pscustomobject]@{
        available = $true
        path = $normalizedCandidate
        source = $source
        checked_candidates = @($checkedCandidates)
      }
    }
  }

  return [pscustomobject]@{
    available = $false
    path = ""
    source = "missing"
    checked_candidates = @($checkedCandidates)
  }
}

$appliedActions = New-Object System.Collections.Generic.List[string]
$applyFailedActions = New-Object System.Collections.Generic.List[string]

$executionPolicyBefore = Get-ExecutionPolicySnapshot
$executionPolicyRiskBefore = $executionPolicyBefore.effective -notin @("Bypass", "Unrestricted", "RemoteSigned")

if ($Apply -and $executionPolicyRiskBefore) {
  try {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    $appliedActions.Add("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force") | Out-Null
  } catch {
    $applyFailedActions.Add(("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force :: {0}" -f $_.Exception.Message)) | Out-Null
  }
}

$executionPolicySnapshot = Get-ExecutionPolicySnapshot
$executionPolicyRisk = $executionPolicySnapshot.effective -notin @("Bypass", "Unrestricted", "RemoteSigned")

$goPath = Get-CommandPath "go"
$nodePath = Get-CommandPath "node"
$npmPath = Get-CommandPath "npm"
$rustcPath = Get-CommandPath "rustc"
$cargoPath = Get-CommandPath "cargo"
$gitBashSnapshot = Get-GitBashSnapshot

$goAvailable = -not [string]::IsNullOrWhiteSpace($goPath)
$nodeAvailable = -not [string]::IsNullOrWhiteSpace($nodePath)
$npmAvailable = -not [string]::IsNullOrWhiteSpace($npmPath)
$rustcAvailable = -not [string]::IsNullOrWhiteSpace($rustcPath)
$cargoAvailable = -not [string]::IsNullOrWhiteSpace($cargoPath)
$rustAvailable = $rustcAvailable -and $cargoAvailable
$gitBashAvailable = [bool]$gitBashSnapshot.available

$npmResolvesToPs1 = $false
$npmCmdSiblingPath = ""
$npmCmdSiblingAvailable = $false
if ($npmAvailable) {
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
if (-not $npmAvailable) { $issues.Add("npm_missing") | Out-Null }
if (-not $rustcAvailable) { $issues.Add("rustc_missing") | Out-Null }
if (-not $cargoAvailable) { $issues.Add("cargo_missing") | Out-Null }
if (-not $rustAvailable) { $issues.Add("rust_toolchain_missing") | Out-Null }
if (-not $gitBashAvailable) { $issues.Add("git_bash_missing") | Out-Null }
if ($npmPs1PolicyIssue) { $issues.Add("npm_ps1_policy_issue") | Out-Null }
if ($npmPs1ShimIssue) { $issues.Add("npm_ps1_without_npm_cmd") | Out-Null }
if ($applyFailedActions.Count -gt 0) { $issues.Add("execution_policy_apply_failed") | Out-Null }

$safeHints = New-Object System.Collections.Generic.List[string]
if ($executionPolicyRisk) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
}
if (-not $goAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id GoLang.Go --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $nodeAvailable -or -not $npmAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id OpenJS.NodeJS.LTS --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $rustAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id Rustlang.Rustup --exact --accept-package-agreements --accept-source-agreements"
}
if (-not $gitBashAvailable) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "winget install --id Git.Git --exact --accept-package-agreements --accept-source-agreements"
}
if ($npmPs1PolicyIssue) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command ".\scripts\windows\desktop_node.cmd npm -v"
}
if ($issues.Count -gt 0) {
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\desktop_native_bootstrap.ps1 -Mode bootstrap -InstallMissing -EnablePolicyBypass"
  Add-UniqueHint -Hints ([ref]$safeHints) -Command "powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows\local_api_session.ps1 -DryRun"
}

$checkResults = [ordered]@{
  execution_policy_unblocked = [bool](-not $executionPolicyRisk)
  go_available = [bool]$goAvailable
  node_available = [bool]$nodeAvailable
  npm_available = [bool]$npmAvailable
  rustc_available = [bool]$rustcAvailable
  cargo_available = [bool]$cargoAvailable
  git_bash_available = [bool]$gitBashAvailable
  npm_ps1_policy_safe = [bool](-not $npmPs1PolicyIssue)
  npm_ps1_cmd_shim_safe = [bool](-not $npmPs1ShimIssue)
}

$passCount = 0
$failCount = 0
foreach ($value in $checkResults.Values) {
  if ([bool]$value) {
    $passCount++
  } else {
    $failCount++
  }
}

$status = if ($issues.Count -eq 0) { "ok" } else { "needs_remediation" }
$statusLabel = if ($issues.Count -eq 0) { "PASS" } else { "FAIL" }

if ($Compact) {
  Write-Step ("summary: pass={0} fail={1} status={2}" -f $passCount, $failCount, $statusLabel)
  if ($Apply) {
    Write-Step ("apply: requested=true applied={0} failed={1}" -f $appliedActions.Count, $applyFailedActions.Count)
  }
  if ($issues.Count -gt 0) {
    Write-Step ("issues: {0}" -f ($issues -join ", "))
    Write-Step "remediation commands:"
    foreach ($hint in $safeHints) {
      Write-Host ("  {0}" -f $hint)
    }
  }
} else {
  Write-Step ("execution policy effective={0}; process={1}; current_user={2}; local_machine={3}" -f $executionPolicySnapshot.effective, $executionPolicySnapshot.scopes.Process, $executionPolicySnapshot.scopes.CurrentUser, $executionPolicySnapshot.scopes.LocalMachine)
  Write-Step ("go: {0}" -f $(if ($goAvailable) { $goPath } else { "missing" }))
  Write-Step ("node: {0}" -f $(if ($nodeAvailable) { $nodePath } else { "missing" }))
  Write-Step ("npm: {0}" -f $(if ($npmAvailable) { $npmPath } else { "missing" }))
  Write-Step ("rustc: {0}" -f $(if ($rustcAvailable) { $rustcPath } else { "missing" }))
  Write-Step ("cargo: {0}" -f $(if ($cargoAvailable) { $cargoPath } else { "missing" }))
  Write-Step ("git-bash: {0}" -f $(if ($gitBashAvailable) { "$($gitBashSnapshot.path) [$($gitBashSnapshot.source)]" } else { "missing" }))
  if ($npmResolvesToPs1) {
    Write-Step ("npm.ps1 resolver detected; sibling npm.cmd={0}" -f $(if ($npmCmdSiblingAvailable) { $npmCmdSiblingPath } else { "missing" }))
  }
  if ($Apply) {
    Write-Step ("apply requested=true applied={0} failed={1}" -f $appliedActions.Count, $applyFailedActions.Count)
    foreach ($failedAction in $applyFailedActions) {
      Write-Step ("apply failure: {0}" -f $failedAction)
    }
  }

  Write-Step ("summary: pass={0} fail={1} status={2}" -f $passCount, $failCount, $statusLabel)
  if ($issues.Count -gt 0) {
    Write-Step ("issues: {0}" -f ($issues -join ", "))
    Write-Step "remediation commands:"
    foreach ($hint in $safeHints) {
      Write-Host ("  {0}" -f $hint)
    }
  }
}

$summary = [ordered]@{
  version = 1
  generated_at_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  status = $status
  issues_detected = [int]$issues.Count
  issues = @($issues)
  apply = [ordered]@{
    requested = [bool]$Apply
    execution_policy_risk_before = [bool]$executionPolicyRiskBefore
    execution_policy_effective_before = $executionPolicyBefore.effective
    execution_policy_effective_after = $executionPolicySnapshot.effective
    applied_actions = @($appliedActions)
    failed_actions = @($applyFailedActions)
  }
  checks = [ordered]@{
    pass_count = [int]$passCount
    fail_count = [int]$failCount
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
      npm_available = [bool]$npmAvailable
      rustc_available = [bool]$rustcAvailable
      cargo_available = [bool]$cargoAvailable
      rust_available = [bool]$rustAvailable
      go_path = $goPath
      node_path = $nodePath
      npm_path = $npmPath
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
    git_bash = [ordered]@{
      available = [bool]$gitBashAvailable
      path = $gitBashSnapshot.path
      source = $gitBashSnapshot.source
      checked_candidates = @($gitBashSnapshot.checked_candidates)
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
