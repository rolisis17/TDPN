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
- `dist/v0.1.0/sha256sums.txt`

Quick verification:
```bash
./scripts/integration_release_integrity.sh
```

## 3) Tag and push
```bash
git tag v0.1.0
git push origin v0.1.0
```

When the tag is pushed, `.github/workflows/release.yml` will:
1. Rebuild release artifacts with `--require-tag-match 1`
2. Upload workflow artifacts
3. Publish files to the GitHub Release

## 4) Optional tuning
- Override targets:
  ```bash
  ./scripts/release_prepare.sh --version v0.1.0 --targets linux/amd64,linux/arm64
  ```
- Allow dirty build for local dry-run:
  ```bash
  ./scripts/release_prepare.sh --version v0.1.0-rc1 --allow-dirty 1
  ```
