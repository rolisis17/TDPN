#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/blockchain_cosmos_only_guardrail.sh [--root PATH]

Description:
  Fail-closed Cosmos-only guardrail for blockchain-focused paths.
  Scope is intentionally limited to avoid docs false positives:
    - blockchain/
    - pkg/settlement/
    - scripts/

  Violations detected:
    1) top-level entries under blockchain/ other than "tdpn-chain"
    2) suspicious non-Cosmos path-name tokens:
       solana, ethereum, evm, hardhat, foundry, substrate, polkadot, near, aptos, sui

Output:
  Deterministic JSON to stdout.
  Exit code is 0 when clean, 1 when violations exist.

Options:
  --root PATH  Root directory to scan (default: repository root).
  --help       Show this help message.
EOF
}

for cmd in jq find sort tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

scan_root="$ROOT_DIR"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      if [[ $# -lt 2 ]]; then
        echo "--root requires a path"
        exit 2
      fi
      scan_root="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ ! -d "$scan_root" ]]; then
  echo "scan root does not exist: $scan_root"
  exit 2
fi

scan_root="$(cd "$scan_root" && pwd)"

normalize_path() {
  local raw_path="$1"
  local path="$raw_path"

  path="${path%$'\r'}"
  path="${path//\\//}"
  path="${path#./}"
  while [[ "$path" == /* ]]; do
    path="${path#/}"
  done

  printf '%s\n' "$path"
}

to_sorted_json_array() {
  local -n source_array="$1"
  if [[ "${#source_array[@]}" -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "${source_array[@]}" \
    | LC_ALL=C sort -u \
    | jq -R -s 'split("\n") | map(select(length > 0))'
}

to_sorted_suspicious_json_array() {
  local -n source_array="$1"
  if [[ "${#source_array[@]}" -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "${source_array[@]}" \
    | LC_ALL=C sort -u \
    | jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({ path: .[0], token: .[1] })
      '
}

contains_token() {
  local lower_path="$1"
  local token="$2"

  if [[ "$lower_path" =~ (^|[^a-z0-9])${token}([^a-z0-9]|$) ]]; then
    return 0
  fi
  return 1
}

declare -a non_tdpn_chain_top_level_entries=()
declare -a suspicious_non_cosmos_path_pairs=()

if [[ -d "$scan_root/blockchain" ]]; then
  while IFS= read -r child; do
    child="$(normalize_path "$child")"
    if [[ -z "$child" ]]; then
      continue
    fi
    if [[ "$child" != "tdpn-chain" ]]; then
      non_tdpn_chain_top_level_entries+=("blockchain/$child")
    fi
  done < <(find "$scan_root/blockchain" -mindepth 1 -maxdepth 1 -printf '%P\n')
fi

scan_paths=("blockchain" "pkg/settlement" "scripts")
tokens=("solana" "ethereum" "evm" "hardhat" "foundry" "substrate" "polkadot" "near" "aptos" "sui")

for rel_root in "${scan_paths[@]}"; do
  abs_root="$scan_root/$rel_root"
  if [[ ! -e "$abs_root" ]]; then
    continue
  fi

  while IFS= read -r abs_path; do
    rel_path="${abs_path#"$scan_root"/}"
    rel_path="$(normalize_path "$rel_path")"
    if [[ -z "$rel_path" ]]; then
      continue
    fi

    lower_path="$(printf '%s' "$rel_path" | tr '[:upper:]' '[:lower:]')"
    for token in "${tokens[@]}"; do
      if contains_token "$lower_path" "$token"; then
        suspicious_non_cosmos_path_pairs+=("$rel_path"$'\t'"$token")
        break
      fi
    done
  done < <(find "$abs_root" -mindepth 1 -print)
done

non_tdpn_chain_top_level_entries_json="$(to_sorted_json_array non_tdpn_chain_top_level_entries)"
suspicious_non_cosmos_paths_json="$(to_sorted_suspicious_json_array suspicious_non_cosmos_path_pairs)"

summary_json="$(
  jq -cn \
    --argjson non_tdpn "$non_tdpn_chain_top_level_entries_json" \
    --argjson suspicious "$suspicious_non_cosmos_paths_json" \
    '{
      non_tdpn_chain_top_level_blockchain_entries: ($non_tdpn | length),
      suspicious_non_cosmos_paths: ($suspicious | length),
      violation_total: (($non_tdpn | length) + ($suspicious | length)),
      status: (if (($non_tdpn | length) + ($suspicious | length)) == 0 then "pass" else "fail" end)
    }'
)"

result_json="$(
  jq -cn \
    --arg root "$scan_root" \
    --argjson non_tdpn "$non_tdpn_chain_top_level_entries_json" \
    --argjson suspicious "$suspicious_non_cosmos_paths_json" \
    --argjson summary "$summary_json" \
    '{
      schema: { id: "blockchain_cosmos_only_guardrail", major: 1, minor: 0 },
      root: $root,
      scanned_roots: ["blockchain", "pkg/settlement", "scripts"],
      findings: {
        non_tdpn_chain_top_level_blockchain_entries: $non_tdpn,
        suspicious_non_cosmos_paths: $suspicious
      },
      summary: $summary
    }'
)"

printf '%s\n' "$result_json"

if [[ "$(jq -r '.summary.status' <<<"$result_json")" != "pass" ]]; then
  exit 1
fi

