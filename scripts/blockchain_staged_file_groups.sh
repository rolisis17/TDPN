#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/blockchain_staged_file_groups.sh [--staged-files-file PATH]

Description:
  Emit deterministic blockchain-only staged file groups for commit slicing:
    - core_chain_settlement
    - ci_contracts
    - docs

  Non-blockchain spillover paths are explicitly filtered into
  excluded_non_blockchain_spillover.

Options:
  --staged-files-file PATH  Read candidate staged paths from PATH instead of
                            using "git diff --cached --name-only".
  --help                    Show this help message.
EOF
}

for cmd in jq sort; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

staged_files_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --staged-files-file)
      if [[ $# -lt 2 ]]; then
        echo "--staged-files-file requires a path"
        exit 2
      fi
      staged_files_file="$2"
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

if [[ -n "$staged_files_file" && ! -f "$staged_files_file" ]]; then
  echo "staged files fixture does not exist: $staged_files_file"
  exit 2
fi

read_candidate_paths() {
  if [[ -n "$staged_files_file" ]]; then
    cat "$staged_files_file"
    return
  fi

  if ! command -v git >/dev/null 2>&1; then
    echo "git is required when --staged-files-file is not provided"
    exit 2
  fi

  git diff --cached --name-only --diff-filter=ACMR
}

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

is_non_blockchain_spillover() {
  local path="$1"
  case "$path" in
    apps/*|bin/*|cmd/*|data/*|deploy/*|internal/*|runtime/*|tools/*|User/*)
      return 0
      ;;
    services/directory/*|services/entry/*|services/exit/*)
      return 0
      ;;
    pkg/adminauth/*|pkg/crypto/*|pkg/securehttp/*)
      return 0
      ;;
    scripts/ci_phase0.sh|scripts/ci_phase1_*|scripts/ci_phase2_*|scripts/ci_phase3_*|scripts/ci_phase4_*|scripts/ci_local.sh)
      return 0
      ;;
    scripts/integration_ci_phase0.sh|scripts/integration_ci_phase1_*|scripts/integration_ci_phase2_*|scripts/integration_ci_phase3_*|scripts/integration_ci_phase4_*)
      return 0
      ;;
    scripts/client_*|scripts/integration_client_*|scripts/vpn_*|scripts/integration_vpn_*|scripts/profile_*|scripts/integration_profile_*)
      return 0
      ;;
    scripts/pre_real_host_readiness.sh|scripts/integration_pre_real_host_readiness.sh|scripts/runtime_*|scripts/integration_runtime_*)
      return 0
      ;;
    scripts/three_machine_*|scripts/integration_three_machine_*|scripts/prod_*|scripts/integration_prod_*|scripts/wg_only_*|scripts/integration_wg_only_*)
      return 0
      ;;
    docs/client-*|docs/exit-node-*|docs/global-privacy-mesh-track.md|docs/mvp-status.md)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_docs_path() {
  local path="$1"
  case "$path" in
    docs/blockchain-*.md|docs/cosmos-*.md|docs/full-execution-plan-2026-2027.md|docs/product-roadmap.md|docs/testing-guide.md|docs/protocol.md)
      return 0
      ;;
    blockchain/tdpn-chain/docs/*|blockchain/tdpn-chain/README.md)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_core_chain_settlement_path() {
  local path="$1"
  case "$path" in
    blockchain/tdpn-chain/*|pkg/settlement/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_ci_contracts_path() {
  local path="$1"
  case "$path" in
    scripts/blockchain_fastlane.sh|scripts/blockchain_gate_bundle.sh|scripts/blockchain_mainnet_activation_*)
      return 0
      ;;
    scripts/ci_blockchain_parallel_sweep.sh|scripts/integration_ci_blockchain_parallel_sweep.sh)
      return 0
      ;;
    scripts/ci_phase5_settlement_layer.sh|scripts/integration_ci_phase5_settlement_layer.sh|scripts/phase5_settlement_layer_*|scripts/integration_phase5_settlement_layer_*)
      return 0
      ;;
    scripts/ci_phase6_cosmos_l1_build_testnet.sh|scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh|scripts/ci_phase6_cosmos_l1_contracts.sh|scripts/integration_ci_phase6_cosmos_l1_contracts.sh|scripts/phase6_cosmos_l1_*|scripts/integration_phase6_cosmos_l1_*)
      return 0
      ;;
    scripts/ci_phase7_mainnet_cutover.sh|scripts/integration_ci_phase7_mainnet_cutover.sh|scripts/phase7_mainnet_cutover_*|scripts/integration_phase7_mainnet_cutover_*)
      return 0
      ;;
    scripts/integration_blockchain_*|scripts/integration_cosmos_*|scripts/integration_issuer_admin_blockchain_handlers_coverage_floor.sh|scripts/integration_slash_violation_type_contract_consistency.sh|scripts/integration_cosmos_record_normalization_contract_consistency.sh)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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

declare -a core_chain_settlement_paths=()
declare -a ci_contracts_paths=()
declare -a docs_paths=()
declare -a excluded_non_blockchain_spillover=()
declare -a unmatched_paths=()

while IFS= read -r raw_path; do
  path="$(normalize_path "$raw_path")"
  if [[ -z "$path" || "$path" == \#* ]]; then
    continue
  fi

  if is_non_blockchain_spillover "$path"; then
    excluded_non_blockchain_spillover+=("$path")
    continue
  fi
  if is_docs_path "$path"; then
    docs_paths+=("$path")
    continue
  fi
  if is_core_chain_settlement_path "$path"; then
    core_chain_settlement_paths+=("$path")
    continue
  fi
  if is_ci_contracts_path "$path"; then
    ci_contracts_paths+=("$path")
    continue
  fi

  unmatched_paths+=("$path")
done < <(read_candidate_paths)

core_chain_settlement_json="$(to_sorted_json_array core_chain_settlement_paths)"
ci_contracts_json="$(to_sorted_json_array ci_contracts_paths)"
docs_json="$(to_sorted_json_array docs_paths)"
excluded_non_blockchain_spillover_json="$(to_sorted_json_array excluded_non_blockchain_spillover)"
unmatched_paths_json="$(to_sorted_json_array unmatched_paths)"
selected_json="$(
  jq -cn \
    --argjson core "$core_chain_settlement_json" \
    --argjson ci "$ci_contracts_json" \
    --argjson docs "$docs_json" \
    '$core + $ci + $docs | unique'
)"

source_label="git_diff_cached"
if [[ -n "$staged_files_file" ]]; then
  source_label="$staged_files_file"
fi

jq -n \
  --arg source "$source_label" \
  --argjson core "$core_chain_settlement_json" \
  --argjson ci "$ci_contracts_json" \
  --argjson docs "$docs_json" \
  --argjson selected "$selected_json" \
  --argjson excluded "$excluded_non_blockchain_spillover_json" \
  --argjson unmatched "$unmatched_paths_json" \
  '{
    schema: { id: "blockchain_staged_file_groups", major: 1, minor: 0 },
    source: $source,
    groups: {
      core_chain_settlement: $core,
      ci_contracts: $ci,
      docs: $docs
    },
    selected: $selected,
    excluded_non_blockchain_spillover: $excluded,
    unmatched: $unmatched,
    summary: {
      core_chain_settlement: ($core | length),
      ci_contracts: ($ci | length),
      docs: ($docs | length),
      selected_total: ($selected | length),
      excluded_spillover_total: ($excluded | length),
      unmatched_total: ($unmatched | length)
    }
  }'
