# Release Process

This process creates reproducible release artifacts with checksums.

## 1) Prepare clean state
1. Ensure `main` is up to date.
2. Ensure local checks are green:
   ```bash
   ./scripts/ci_local.sh
   ./scripts/beta_preflight.sh
   ```
3. Keep working tree clean (default release script policy).

## 2) Build release artifacts locally
```bash
./scripts/release_prepare.sh --version v0.1.0
```

Outputs:
- `dist/v0.1.0/bin/node_<os>_<arch>[.exe]`
- `dist/v0.1.0/source_v0.1.0.tar`
- `dist/v0.1.0/manifest.json`
- `dist/v0.1.0/sbom_go_modules_v0.1.0.json`
- `dist/v0.1.0/sha256sums.txt`

Quick verification:
```bash
./scripts/integration_release_integrity.sh
./scripts/integration_release_sbom.sh
./scripts/integration_release_tag_verify.sh
./scripts/integration_release_policy_gate.sh
```

## 3) Tag and push
```bash
git tag -a v0.1.0 -m "v0.1.0 release"
# recommended when maintainer signing keys are configured:
# git tag -s v0.1.0 -m "v0.1.0 release"
git push origin v0.1.0
```

When the tag is pushed, `.github/workflows/release.yml` will:
1. Verify tag metadata (`release_verify_tag.sh`):
   - annotated tag required
   - points at workflow `HEAD`
   - optional signed-tag enforcement via repository variable `RELEASE_REQUIRE_SIGNED_TAG=1`
2. Rebuild release artifacts with `--require-tag-match 1`
3. Enforce release policy gate (`release_policy_gate.sh`):
   - required release files and binaries exist
   - `sha256sums.txt` validates cleanly
   - optional tag-note heading enforcement via `RELEASE_REQUIRE_TAG_NOTES=1` (enabled by default in workflow)
4. Upload workflow artifacts
5. Publish files to the GitHub Release
6. Emit provenance attestations for:
   - `sha256sums.txt`
   - `sbom_go_modules_<version>.json`

## 4) Optional tuning
- Override targets:
  ```bash
  ./scripts/release_prepare.sh --version v0.1.0 --targets linux/amd64,linux/arm64
  ```
- Allow dirty build for local dry-run:
  ```bash
  ./scripts/release_prepare.sh --version v0.1.0-rc1 --allow-dirty 1
  ```
- Explicit tag verification:
  ```bash
  ./scripts/release_verify_tag.sh --version v0.1.0 --require-head-match 1 --require-signature 1
  ```
- Explicit release policy gate:
  ```bash
  ./scripts/release_policy_gate.sh --version v0.1.0 --release-dir dist/v0.1.0 --require-tag-exists 1 --require-tag-notes 1
  ```
- Generate SBOM only (for diagnostics):
  ```bash
  ./scripts/release_generate_sbom.sh --version v0.1.0
  ```
