# GitHub Security Baseline

This runbook enforces repository-level security settings with one script.

## Prerequisites
1. Install GitHub CLI (`gh`) and authenticate:
   ```bash
   gh auth login
   ```
2. Ensure your account has admin rights on the target repository.
3. Install `jq`.

## Baseline Status Check
```bash
./scripts/github_repo_security_baseline.sh status --repo <owner/repo> --branch main
```

Checks performed:
- Branch protection on `main`
- Required PR approvals (`>=1`)
- Dismiss stale approvals enabled
- Strict required status checks enabled
- Required checks include: `test`, `codeql-go`, `govulncheck`, `dependency-review`
- `secret_scanning` enabled
- `secret_scanning_push_protection` enabled
- Vulnerability alerts enabled
- Automated security fixes enabled
- Optional: `advanced_security` enabled (default on)

## Apply Baseline
```bash
./scripts/github_repo_security_baseline.sh apply --repo <owner/repo> --branch main
```

What `apply` configures:
- Branch protection policy for `main`
- Repository `security_and_analysis` baseline
- Vulnerability alerts
- Automated security fixes
- Immediate post-apply validation (`status`)

## Variants
Disable advanced-security requirement when the repository plan does not include it:
```bash
./scripts/github_repo_security_baseline.sh status --repo <owner/repo> --enable-advanced-security 0
./scripts/github_repo_security_baseline.sh apply  --repo <owner/repo> --enable-advanced-security 0
```

Allow status output without non-zero exit (diagnostic mode):
```bash
./scripts/github_repo_security_baseline.sh status --repo <owner/repo> --no-fail
```
