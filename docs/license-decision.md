# License Decision Guide

You must add a `LICENSE` file before claiming the repo is open source.

Current repository choice: `Apache-2.0`.

## Common choices

## 1) AGPL-3.0
Use if you want hosted/network deployments of modified versions to publish source changes.

Good for:
- Preventing closed-source hosted forks of the core
- Strong copyleft in networked software

Tradeoff:
- Some companies avoid AGPL dependencies.

## 2) Apache-2.0
Use if you want broad adoption, including commercial use, with patent grant.

Good for:
- Ecosystem growth and integration
- Fewer legal adoption barriers

Tradeoff:
- Competitors can build closed hosted services on top.

## 3) GPL-3.0
Strong copyleft for distribution, but weaker than AGPL for pure hosted use.

## Practical recommendation for this project
- If your priority is keeping network-service improvements open: choose `AGPL-3.0`.
- If your priority is fastest adoption: choose `Apache-2.0`.

## How to apply
1. Decide license.
2. Add `LICENSE` file text at repo root.
3. Add license badge to `README.md`.
4. Ensure both repositories (VPN + blockchain) have explicit compatible licenses.
