# Open-Source Release Checklist

Use this before making the repository public.

## 1) Legal and licensing
1. Choose a license and add a `LICENSE` file.
2. Confirm third-party dependency licenses are compatible.
3. Add attribution notices if required.

## 2) Security baseline
1. Ensure `SECURITY.md` exists and points to private reporting.
2. Enable GitHub security features:
   - Dependabot alerts
   - Dependabot security updates
   - Secret scanning (including push protection)
   - Code scanning (if available)
   - Baseline repo config check:
     ```bash
     ./scripts/integration_security_baseline.sh
     ```
3. Set branch protection on `main`:
   - Require PR reviews
   - Require status checks
   - Dismiss stale approvals when new commits are pushed

## 3) Secret hygiene
1. Verify no secrets in tracked files:
   ```bash
   ./scripts/integration_secret_hygiene.sh
   ```
   - keys, tokens, cert private keys, `.env` credentials
2. Rotate any credentials used during development.
3. If anything leaked previously, rewrite git history and rotate credentials.

## 4) Repository hygiene
1. Ensure these files exist:
   - `README.md`
   - `CONTRIBUTING.md`
   - `CODE_OF_CONDUCT.md`
   - `GOVERNANCE.md`
   - `SUPPORT.md`
   - `SECURITY.md`
2. Add issue templates and PR template.
3. Mark project status clearly as `beta` in README/docs.

## 5) Technical readiness
1. Run:
   ```bash
   go test ./...
   ./scripts/ci_local.sh
   ./scripts/beta_preflight.sh
   ```
2. Verify launcher + key scripts work from a clean clone.
3. Confirm docs match real commands.

## 6) Publication steps (GitHub)
1. Repository -> `Settings` -> `General` -> `Change repository visibility` -> `Public`.
2. Immediately enable the security settings above.
3. Create first public release tag with notes:
   - Known limitations
   - Security model
   - Supported environments

## 7) Post-publication
1. Triage issues weekly.
2. Patch critical security issues quickly.
3. Keep roadmap transparent (what is experimental vs stable).
