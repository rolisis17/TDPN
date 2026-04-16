#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_progress_report.sh \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--manual-refresh-timeout-sec N] \
    [--single-machine-refresh-timeout-sec N] \
    [--manual-validation-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--profile-compare-signoff-summary-json PATH] \
    [--single-machine-summary-json PATH] \
    [--phase0-summary-json PATH] \
    [--phase1-resilience-handoff-summary-json PATH] \
    [--vpn-rc-resilience-summary-json PATH] \
    [--phase2-linux-prod-candidate-summary-json PATH] \
    [--phase3-windows-client-beta-summary-json PATH] \
    [--phase4-windows-full-parity-summary-json PATH] \
    [--phase5-settlement-layer-summary-json PATH] \
    [--phase6-cosmos-l1-summary-json PATH] \
    [--phase7-mainnet-cutover-summary-json PATH] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Generate one concise roadmap progress handoff (JSON + markdown) from current
  manual-validation readiness state, with optional one-host readiness refresh.

Notes:
  - This does not replace real machine-C and true 3-machine production signoff.
  - Blockchain/payment track is reported as a Cosmos-first parallel track with VPN dataplane independence.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

resolve_path_with_base() {
  local candidate
  local base_file
  local base_dir=""
  candidate="$(trim "${1:-}")"
  base_file="$(trim "${2:-}")"
  if [[ -z "$candidate" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$candidate" == /* ]]; then
    printf '%s' "$candidate"
    return
  fi
  if [[ -n "$base_file" ]]; then
    base_dir="$(cd "$(dirname "$base_file")" && pwd)"
    if [[ -f "$base_dir/$candidate" ]]; then
      printf '%s' "$base_dir/$candidate"
      return
    fi
  fi
  printf '%s' "$ROOT_DIR/$candidate"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

json_file_valid_01() {
  local path="$1"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

manual_validation_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    (.summary | type == "object")
    and (.report | type == "object")
    and ((.report.readiness_status // "") | type == "string")
    and (
      .schema == null
      or (
        (.schema | type == "object")
        and ((.schema.id // "") == "manual_validation_readiness_summary")
        and ((.schema.major // 0) | type == "number")
        and ((.schema.major // 0) >= 1)
        and ((.schema.major // 0) <= 1)
        and (((.schema.major // 0) | floor) == (.schema.major // 0))
      )
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

single_machine_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    ((.status // "") | type == "string")
    and (.summary | type == "object")
    and (
      .schema == null
      or (
        (.schema | type == "object")
        and ((.schema.id // "") == "single_machine_prod_readiness_summary")
        and ((.schema.major // 0) | type == "number")
        and ((.schema.major // 0) >= 1)
        and ((.schema.major // 0) <= 1)
        and (((.schema.major // 0) | floor) == (.schema.major // 0))
      )
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

phase0_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    ((.status // "") | type == "string")
    and (.steps | type == "object")
    and (
      .schema == null
      or (
        (.schema | type == "object")
        and ((.schema.id // "") == "ci_phase0_summary")
        and ((.schema.major // 0) | type == "number")
        and ((.schema.major // 0) >= 1)
        and ((.schema.major // 0) <= 1)
        and (((.schema.major // 0) | floor) == (.schema.major // 0))
      )
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

phase0_step_ok_json_or_null() {
  local path="$1"
  local step_id="$2"
  local value=""
  if [[ ! -f "$path" ]]; then
    printf '%s' "null"
    return
  fi
  value="$(jq -r --arg step_id "$step_id" '
    if (.steps[$step_id].ok | type) == "boolean" then .steps[$step_id].ok
    else
      ((.steps[$step_id].status // "") | ascii_downcase) as $s
      | if $s == "pass" then true
        elif $s == "fail" then false
        else empty end
    end
  ' "$path" 2>/dev/null || true)"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' "null"
      ;;
  esac
}

json_bool_value_or_empty() {
  local path="$1"
  local jq_expr="$2"
  local value=""
  if [[ ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi
  value="$(jq -r "$jq_expr" "$path" 2>/dev/null || true)"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

resilience_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

roadmap_resilience_logs_root() {
  local logs_root="${ROADMAP_PROGRESS_LOGS_ROOT:-$ROOT_DIR/.easy-node-logs}"
  logs_root="$(abs_path "$logs_root")"
  printf '%s' "$logs_root"
}

file_mtime_epoch() {
  local path="$1"
  local mtime=""
  if mtime="$(stat -c %Y "$path" 2>/dev/null)" && [[ "$mtime" =~ ^[0-9]+$ ]]; then
    printf '%s' "$mtime"
    return
  fi
  if mtime="$(stat -f %m "$path" 2>/dev/null)" && [[ "$mtime" =~ ^[0-9]+$ ]]; then
    printf '%s' "$mtime"
    return
  fi
  if mtime="$(date -r "$path" +%s 2>/dev/null)" && [[ "$mtime" =~ ^[0-9]+$ ]]; then
    printf '%s' "$mtime"
    return
  fi
  printf '%s' "0"
}

summary_dry_run_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    ([.. | objects | .dry_run?] | any(. == true))
    or
    ([.. | objects | .dryRun?] | any(. == true))
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

summary_effective_dry_run_01() {
  local path="$1"
  local dir=""
  local file=""
  local candidate=""
  local linked_ci_summary_json=""
  local candidates=()
  if [[ "$(summary_dry_run_01 "$path")" == "1" ]]; then
    printf '1'
    return
  fi
  dir="$(dirname "$path")"
  file="$(basename "$path")"
  case "$file" in
    phase1_resilience_handoff_check_summary.json)
      candidates+=("$dir/phase1_resilience_handoff_run_summary.json")
      candidates+=("$dir/ci_phase1_resilience_summary.json")
      linked_ci_summary_json="$(jq -r '.inputs.ci_phase1_summary_json // ""' "$path" 2>/dev/null || true)"
      linked_ci_summary_json="$(resolve_path_with_base "$linked_ci_summary_json" "$path")"
      if [[ -n "$linked_ci_summary_json" ]]; then
        candidates+=("$linked_ci_summary_json")
      fi
      ;;
    phase2_linux_prod_candidate_check_summary.json)
      candidates+=("$dir/phase2_linux_prod_candidate_run_summary.json")
      ;;
    phase3_windows_client_beta_check_summary.json)
      candidates+=("$dir/phase3_windows_client_beta_run_summary.json")
      candidates+=("$dir/phase3_windows_client_beta_handoff_run_summary.json")
      ;;
    phase3_windows_client_beta_handoff_check_summary.json)
      candidates+=("$dir/phase3_windows_client_beta_handoff_run_summary.json")
      candidates+=("$dir/phase3_windows_client_beta_run_summary.json")
      ;;
    phase4_windows_full_parity_check_summary.json)
      candidates+=("$dir/phase4_windows_full_parity_run_summary.json")
      candidates+=("$dir/phase4_windows_full_parity_handoff_run_summary.json")
      ;;
    phase4_windows_full_parity_handoff_check_summary.json)
      candidates+=("$dir/phase4_windows_full_parity_handoff_run_summary.json")
      candidates+=("$dir/phase4_windows_full_parity_run_summary.json")
      ;;
    phase5_settlement_layer_check_summary.json)
      candidates+=("$dir/phase5_settlement_layer_run_summary.json")
      candidates+=("$dir/phase5_settlement_layer_handoff_run_summary.json")
      ;;
    phase5_settlement_layer_handoff_check_summary.json)
      candidates+=("$dir/phase5_settlement_layer_handoff_run_summary.json")
      candidates+=("$dir/phase5_settlement_layer_run_summary.json")
      ;;
    phase6_cosmos_l1_build_testnet_check_summary.json)
      candidates+=("$dir/phase6_cosmos_l1_build_testnet_run_summary.json")
      candidates+=("$dir/phase6_cosmos_l1_build_testnet_handoff_run_summary.json")
      ;;
    phase6_cosmos_l1_build_testnet_handoff_check_summary.json)
      candidates+=("$dir/phase6_cosmos_l1_build_testnet_handoff_run_summary.json")
      candidates+=("$dir/phase6_cosmos_l1_build_testnet_run_summary.json")
      ;;
  esac
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]] && [[ "$(summary_dry_run_01 "$candidate")" == "1" ]]; then
      printf '1'
      return
    fi
  done
  printf '0'
}

find_latest_resilience_summary_json() {
  local logs_root
  local candidate=""
  local candidate_mtime=0
  local best_path=""
  local best_mtime=-1
  logs_root="$(roadmap_resilience_logs_root)"
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(resilience_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_mtime > best_mtime )); then
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
      # Deterministic tie-break when mtimes are equal.
      best_path="$candidate"
    fi
  done < <(find "$logs_root" -type f -name 'vpn_rc_resilience_path_summary.json' -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_resilience_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

phase1_resilience_handoff_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      (
        (.schema == null)
        or (
          (.schema | type) == "object"
          and (
            (.schema.id // "") == "phase1_resilience_handoff_check_summary"
            or (.schema.id // "") == "phase1_resilience_handoff_run_summary"
            or (.schema.id // "") == "ci_phase1_resilience_summary"
          )
          and ((.schema.major // 0) | type == "number")
          and ((.schema.major // 0) >= 1)
          and ((.schema.major // 0) <= 1)
          and (((.schema.major // 0) | floor) == (.schema.major // 0))
        )
      )
      or ((.handoff | type) == "object")
      or ((.steps | type) == "object")
      or ((.vpn_track.resilience_handoff | type) == "object")
      or ((.summary | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

find_latest_phase1_resilience_handoff_summary_json() {
  local logs_root="$ROOT_DIR/.easy-node-logs"
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(phase1_resilience_handoff_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase1_resilience_handoff_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'phase1_resilience_handoff_run_summary.json' \
       -o -name 'phase1_resilience_handoff_check_summary.json' \
       -o -name 'ci_phase1_resilience_summary.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_phase1_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

phase1_linked_handoff_summary_json_from_run() {
  local run_path="$1"
  local candidate=""
  if [[ "$(json_file_valid_01 "$run_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  candidate="$(jq -r '.artifacts.handoff_summary_json // .steps.phase1_resilience_handoff_check.artifacts.summary_json // ""' "$run_path" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$run_path")"
  if [[ -n "$candidate" ]] && [[ "$(phase1_resilience_handoff_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
  else
    printf '%s' ""
  fi
}

phase1_linked_ci_summary_json_from_run() {
  local run_path="$1"
  local candidate=""
  if [[ "$(json_file_valid_01 "$run_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  candidate="$(jq -r '.artifacts.ci_summary_json // .steps.ci_phase1_resilience.artifacts.summary_json // ""' "$run_path" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$run_path")"
  if [[ -n "$candidate" ]] && [[ "$(phase1_resilience_handoff_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
  else
    printf '%s' ""
  fi
}

phase1_linked_resilience_summary_json_from_run() {
  local run_path="$1"
  local handoff_summary_json="$2"
  local ci_summary_json="$3"
  local candidate=""
  if [[ "$(json_file_valid_01 "$run_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  candidate="$(jq -r '.artifacts.vpn_rc_resilience_summary_json // ""' "$run_path" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$run_path")"
  if [[ -z "$candidate" && -n "$handoff_summary_json" ]]; then
    candidate="$(jq -r '.inputs.vpn_rc_resilience_summary_json // ""' "$handoff_summary_json" 2>/dev/null || true)"
    candidate="$(resolve_path_with_base "$candidate" "$handoff_summary_json")"
  fi
  if [[ -z "$candidate" && -n "$ci_summary_json" ]]; then
    candidate="$(jq -r '.steps.vpn_rc_resilience_path.artifacts.summary_json // .steps.vpn_rc_matrix_path.artifacts.summary_json // .artifacts.vpn_rc_resilience_summary_json // ""' "$ci_summary_json" 2>/dev/null || true)"
    candidate="$(resolve_path_with_base "$candidate" "$ci_summary_json")"
  fi
  if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
  else
    printf '%s' ""
  fi
}

phase1_linked_ci_summary_json_from_handoff() {
  local handoff_path="$1"
  local candidate=""
  if [[ "$(json_file_valid_01 "$handoff_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  candidate="$(jq -r '.inputs.ci_phase1_summary_json // .steps.ci_phase1_resilience.artifacts.summary_json // ""' "$handoff_path" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$handoff_path")"
  if [[ -n "$candidate" ]] && [[ "$(phase1_resilience_handoff_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
  else
    printf '%s' ""
  fi
}

phase1_linked_resilience_summary_json_from_ci() {
  local ci_summary_json="$1"
  local candidate=""
  if [[ "$(json_file_valid_01 "$ci_summary_json")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  candidate="$(jq -r '.steps.vpn_rc_resilience_path.artifacts.summary_json // .steps.vpn_rc_matrix_path.artifacts.summary_json // .artifacts.vpn_rc_resilience_summary_json // ""' "$ci_summary_json" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$ci_summary_json")"
  if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
  else
    printf '%s' ""
  fi
}

phase1_linked_resilience_summary_json_from_handoff() {
  local handoff_summary_json="$1"
  local ci_summary_json=""
  local candidate=""
  if [[ "$(json_file_valid_01 "$handoff_summary_json")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  candidate="$(jq -r '.inputs.vpn_rc_resilience_summary_json // .artifacts.vpn_rc_resilience_summary_json // ""' "$handoff_summary_json" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$handoff_summary_json")"
  if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
    return
  fi
  ci_summary_json="$(phase1_linked_ci_summary_json_from_handoff "$handoff_summary_json")"
  if [[ -n "$ci_summary_json" ]]; then
    candidate="$(phase1_linked_resilience_summary_json_from_ci "$ci_summary_json")"
    if [[ -n "$candidate" ]]; then
      printf '%s' "$candidate"
      return
    fi
  fi
  printf '%s' ""
}

phase1_linked_resilience_summary_json_from_source() {
  local source_summary_json="$1"
  local source_summary_kind="$2"
  local handoff_summary_json=""
  local ci_summary_json=""
  local candidate=""
  if [[ "$(json_file_valid_01 "$source_summary_json")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  case "$source_summary_kind" in
    run)
      handoff_summary_json="$(phase1_linked_handoff_summary_json_from_run "$source_summary_json")"
      ci_summary_json="$(phase1_linked_ci_summary_json_from_run "$source_summary_json")"
      candidate="$(phase1_linked_resilience_summary_json_from_run "$source_summary_json" "$handoff_summary_json" "$ci_summary_json")"
      ;;
    check)
      candidate="$(phase1_linked_resilience_summary_json_from_handoff "$source_summary_json")"
      ;;
    ci)
      candidate="$(phase1_linked_resilience_summary_json_from_ci "$source_summary_json")"
      ;;
  esac
  if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
    return
  fi
  candidate="$(jq -r '.artifacts.vpn_rc_resilience_summary_json // .inputs.vpn_rc_resilience_summary_json // .steps.vpn_rc_resilience_path.artifacts.summary_json // .steps.vpn_rc_matrix_path.artifacts.summary_json // ""' "$source_summary_json" 2>/dev/null || true)"
  candidate="$(resolve_path_with_base "$candidate" "$source_summary_json")"
  if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
    printf '%s' "$candidate"
    return
  fi
  handoff_summary_json="$(jq -r '.artifacts.handoff_summary_json // .steps.phase1_resilience_handoff_check.artifacts.summary_json // ""' "$source_summary_json" 2>/dev/null || true)"
  handoff_summary_json="$(resolve_path_with_base "$handoff_summary_json" "$source_summary_json")"
  if [[ -n "$handoff_summary_json" ]] && [[ "$(phase1_resilience_handoff_summary_usable_01 "$handoff_summary_json")" == "1" ]]; then
    candidate="$(phase1_linked_resilience_summary_json_from_handoff "$handoff_summary_json")"
    if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
      printf '%s' "$candidate"
      return
    fi
  fi
  ci_summary_json="$(jq -r '.artifacts.ci_summary_json // .steps.ci_phase1_resilience.artifacts.summary_json // .inputs.ci_phase1_summary_json // ""' "$source_summary_json" 2>/dev/null || true)"
  ci_summary_json="$(resolve_path_with_base "$ci_summary_json" "$source_summary_json")"
  if [[ -n "$ci_summary_json" ]] && [[ "$(phase1_resilience_handoff_summary_usable_01 "$ci_summary_json")" == "1" ]]; then
    candidate="$(phase1_linked_resilience_summary_json_from_ci "$ci_summary_json")"
    if [[ -n "$candidate" ]] && [[ "$(resilience_summary_usable_01 "$candidate")" == "1" ]]; then
      printf '%s' "$candidate"
      return
    fi
  fi
  printf '%s' ""
}

phase1_run_linked_summary_candidates() {
  local run_path="$1"
  local handoff_summary_json=""
  local ci_summary_json=""
  local resilience_summary_json=""
  local emitted=""
  local candidate=""
  if [[ "$(json_file_valid_01 "$run_path")" != "1" ]]; then
    return
  fi
  handoff_summary_json="$(phase1_linked_handoff_summary_json_from_run "$run_path")"
  ci_summary_json="$(phase1_linked_ci_summary_json_from_run "$run_path")"
  resilience_summary_json="$(phase1_linked_resilience_summary_json_from_run "$run_path" "$handoff_summary_json" "$ci_summary_json")"
  for candidate in "$resilience_summary_json" "$handoff_summary_json" "$ci_summary_json"; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    if [[ "|$emitted|" == *"|$candidate|"* ]]; then
      continue
    fi
    emitted="${emitted:+$emitted|}$candidate"
    printf '%s\n' "$candidate"
  done
}

resolve_phase1_bool_with_source_chain() {
  local source_path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  local candidate=""
  value="$(resolve_phase1_bool_with_fallback "$source_path" "$explicit_expr" "$fallback_expr")"
  if [[ "$value" != "null" ]]; then
    printf '%s' "$value"
    return
  fi
  while IFS= read -r candidate; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    value="$(resolve_phase1_bool_with_fallback "$candidate" "$explicit_expr" "$fallback_expr")"
    if [[ "$value" != "null" ]]; then
      printf '%s' "$value"
      return
    fi
  done < <(phase1_run_linked_summary_candidates "$source_path")
  printf '%s' "null"
}

resolve_phase1_string_with_fallback() {
  local source_path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  if [[ "$(json_file_valid_01 "$source_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  value="$(jq -r "$explicit_expr" "$source_path" 2>/dev/null || true)"
  if [[ -n "$value" && "$value" != "null" ]]; then
    printf '%s' "$value"
    return
  fi
  if [[ -n "$fallback_expr" ]]; then
    value="$(jq -r "$fallback_expr" "$source_path" 2>/dev/null || true)"
    if [[ -n "$value" && "$value" != "null" ]]; then
      printf '%s' "$value"
      return
    fi
  fi
  printf '%s' ""
}

resolve_phase1_string_with_source_chain() {
  local source_path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  local candidate=""
  value="$(resolve_phase1_string_with_fallback "$source_path" "$explicit_expr" "$fallback_expr")"
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
    return
  fi
  while IFS= read -r candidate; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    value="$(resolve_phase1_string_with_fallback "$candidate" "$explicit_expr" "$fallback_expr")"
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
      return
    fi
  done < <(phase1_run_linked_summary_candidates "$source_path")
  printf '%s' ""
}

candidate_bool_signal_present_01() {
  local path="$1"
  local signal="$2"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' "0"
    return
  fi
  if jq -e --arg signal "$signal" '
    (
      if (.[$signal] | type) == "boolean" then .[$signal]
      elif (.summary[$signal] | type) == "boolean" then .summary[$signal]
      elif (.handoff[$signal] | type) == "boolean" then .handoff[$signal]
      elif (.signals[$signal] | type) == "boolean" then .signals[$signal]
      elif (.automation[$signal] | type) == "boolean" then .automation[$signal]
      elif (.phase1_resilience_handoff[$signal] | type) == "boolean" then .phase1_resilience_handoff[$signal]
      elif (.phase2_linux_prod_candidate_handoff[$signal] | type) == "boolean" then .phase2_linux_prod_candidate_handoff[$signal]
      elif (.phase3_windows_client_beta_handoff[$signal] | type) == "boolean" then .phase3_windows_client_beta_handoff[$signal]
      elif (.phase4_windows_full_parity_handoff[$signal] | type) == "boolean" then .phase4_windows_full_parity_handoff[$signal]
      elif (.phase5_settlement_layer_handoff[$signal] | type) == "boolean" then .phase5_settlement_layer_handoff[$signal]
      elif (.phase6_cosmos_l1_handoff[$signal] | type) == "boolean" then .phase6_cosmos_l1_handoff[$signal]
      elif (.vpn_track.phase1_resilience_handoff[$signal] | type) == "boolean" then .vpn_track.phase1_resilience_handoff[$signal]
      elif (.vpn_track.phase2_linux_prod_candidate_handoff[$signal] | type) == "boolean" then .vpn_track.phase2_linux_prod_candidate_handoff[$signal]
      elif (.vpn_track.phase3_windows_client_beta_handoff[$signal] | type) == "boolean" then .vpn_track.phase3_windows_client_beta_handoff[$signal]
      elif (.vpn_track.phase4_windows_full_parity_handoff[$signal] | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff[$signal]
      elif (.vpn_track.phase5_settlement_layer_handoff[$signal] | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff[$signal]
      elif (.vpn_track.phase6_cosmos_l1_handoff[$signal] | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff[$signal]
      elif (.blockchain_track.phase6_cosmos_l1_handoff[$signal] | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff[$signal]
      else empty
      end
    ) | type == "boolean"
  ' "$path" >/dev/null 2>&1; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

phase1_signal_present_in_source_chain_01() {
  local path="$1"
  local signal="$2"
  local candidate=""
  if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
    printf '%s' "1"
    return
  fi
  while IFS= read -r candidate; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    if [[ "$(candidate_bool_signal_present_01 "$candidate" "$signal")" == "1" ]]; then
      printf '%s' "1"
      return
    fi
  done < <(phase1_run_linked_summary_candidates "$path")
  printf '%s' "0"
}

phase1_string_present_in_source_chain_01() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(resolve_phase1_string_with_source_chain "$path" "$explicit_expr" "$fallback_expr")"
  if [[ -n "$value" ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

phase1_resilience_handoff_summary_completeness_score() {
  local path="$1"
  local score=0
  local signal=""
  for signal in profile_matrix_stable peer_loss_recovery_ok session_churn_guard_ok automatable_without_sudo_or_github; do
    if [[ "$(phase1_signal_present_in_source_chain_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  if [[ "$(phase1_string_present_in_source_chain_01 \
    "$path" \
    'if (.failure.kind | type) == "string" then .failure.kind
      elif (.handoff.failure.kind | type) == "string" then .handoff.failure.kind
      elif (.summary.failure.kind | type) == "string" then .summary.failure.kind
      elif (.resilience_handoff.failure.kind | type) == "string" then .resilience_handoff.failure.kind
      elif (.phase1_resilience_handoff.failure.kind | type) == "string" then .phase1_resilience_handoff.failure.kind
      elif (.vpn_track.phase1_resilience_handoff.failure.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure.kind
      else empty end' \
    '')" == "1" ]]; then
    score=$((score + 1))
  fi
  if [[ "$(phase1_string_present_in_source_chain_01 \
    "$path" \
    'if (.policy_outcome.decision | type) == "string" then .policy_outcome.decision
      elif (.handoff.policy_outcome.decision | type) == "string" then .handoff.policy_outcome.decision
      elif (.summary.policy_outcome.decision | type) == "string" then .summary.policy_outcome.decision
      elif (.phase1_resilience_handoff.policy_outcome.decision | type) == "string" then .phase1_resilience_handoff.policy_outcome.decision
      elif (.vpn_track.phase1_resilience_handoff.policy_outcome.decision | type) == "string" then .vpn_track.phase1_resilience_handoff.policy_outcome.decision
      elif (.policy_outcome.signoff_decision | type) == "string" then .policy_outcome.signoff_decision
      else empty end' \
    '')" == "1" ]]; then
    score=$((score + 1))
  fi
  if [[ "$(phase1_string_present_in_source_chain_01 \
    "$path" \
    'if (.handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .handoff.failure_semantics.profile_matrix_stable.kind
      elif (.failure_semantics.profile_matrix_stable.kind | type) == "string" then .failure_semantics.profile_matrix_stable.kind
      elif (.summary.failure_semantics.profile_matrix_stable.kind | type) == "string" then .summary.failure_semantics.profile_matrix_stable.kind
      elif (.signals.profile_matrix_stable.failure_kind | type) == "string" then .signals.profile_matrix_stable.failure_kind
      elif (.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind
      elif (.vpn_track.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind
      elif (.phase1_resilience_handoff.profile_matrix_stable_failure_kind | type) == "string" then .phase1_resilience_handoff.profile_matrix_stable_failure_kind
      elif (.vpn_track.phase1_resilience_handoff.profile_matrix_stable_failure_kind | type) == "string" then .vpn_track.phase1_resilience_handoff.profile_matrix_stable_failure_kind
      else empty end' \
    '')" == "1" ]]; then
    score=$((score + 1))
  fi
  if [[ "$(phase1_string_present_in_source_chain_01 \
    "$path" \
    'if (.handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .handoff.failure_semantics.peer_loss_recovery_ok.kind
      elif (.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .failure_semantics.peer_loss_recovery_ok.kind
      elif (.summary.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .summary.failure_semantics.peer_loss_recovery_ok.kind
      elif (.signals.peer_loss_recovery_ok.failure_kind | type) == "string" then .signals.peer_loss_recovery_ok.failure_kind
      elif (.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind
      elif (.vpn_track.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind
      elif (.phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind | type) == "string" then .phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind
      elif (.vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind | type) == "string" then .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind
      else empty end' \
    '')" == "1" ]]; then
    score=$((score + 1))
  fi
  if [[ "$(phase1_string_present_in_source_chain_01 \
    "$path" \
    'if (.handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .handoff.failure_semantics.session_churn_guard_ok.kind
      elif (.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .failure_semantics.session_churn_guard_ok.kind
      elif (.summary.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .summary.failure_semantics.session_churn_guard_ok.kind
      elif (.signals.session_churn_guard_ok.failure_kind | type) == "string" then .signals.session_churn_guard_ok.failure_kind
      elif (.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind
      elif (.vpn_track.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind
      elif (.phase1_resilience_handoff.session_churn_guard_ok_failure_kind | type) == "string" then .phase1_resilience_handoff.session_churn_guard_ok_failure_kind
      elif (.vpn_track.phase1_resilience_handoff.session_churn_guard_ok_failure_kind | type) == "string" then .vpn_track.phase1_resilience_handoff.session_churn_guard_ok_failure_kind
      else empty end' \
    '')" == "1" ]]; then
    score=$((score + 1))
  fi
  printf '%s' "$score"
}

phase2_linux_prod_candidate_summary_completeness_score() {
  local path="$1"
  local score=0
  local signal=""
  for signal in release_integrity_ok release_policy_ok operator_lifecycle_ok pilot_signoff_ok; do
    if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  printf '%s' "$score"
}

phase3_windows_client_beta_summary_completeness_score() {
  local path="$1"
  local score=0
  local signal=""
  for signal in windows_parity_ok desktop_contract_ok installer_update_ok telemetry_stability_ok; do
    if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  printf '%s' "$score"
}

phase4_windows_full_parity_summary_completeness_score() {
  local path="$1"
  local score=0
  local signal=""
  for signal in windows_server_packaging_ok windows_role_runbooks_ok cross_platform_interop_ok role_combination_validation_ok; do
    if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  printf '%s' "$score"
}

phase5_settlement_layer_summary_completeness_score() {
  local path="$1"
  local score=0
  local signal=""
  for signal in settlement_failsoft_ok settlement_acceptance_ok settlement_bridge_smoke_ok settlement_state_persistence_ok settlement_adapter_roundtrip_ok issuer_sponsor_api_live_smoke_ok; do
    if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  printf '%s' "$score"
}

phase2_linux_prod_candidate_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      (
        (.schema == null)
        or (
          (.schema | type) == "object"
          and (
            (.schema.id // "") == "phase2_linux_prod_candidate_check_summary"
            or (.schema.id // "") == "phase2_linux_prod_candidate_run_summary"
          )
          and ((.schema.major // 0) | type == "number")
          and ((.schema.major // 0) >= 1)
          and ((.schema.major // 0) <= 1)
          and (((.schema.major // 0) | floor) == (.schema.major // 0))
        )
      )
      or ((.signals | type) == "object")
      or ((.stages | type) == "object")
      or ((.steps | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

find_latest_phase2_linux_prod_candidate_summary_json() {
  local logs_root="$ROOT_DIR/.easy-node-logs"
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(phase2_linux_prod_candidate_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase2_linux_prod_candidate_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'phase2_linux_prod_candidate_run_summary.json' -o -name 'phase2_linux_prod_candidate_check_summary.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_phase2_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

phase3_windows_client_beta_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      (
        (.schema == null)
        or (
          (.schema | type) == "object"
          and (
            (.schema.id // "") == "phase3_windows_client_beta_check_summary"
            or (.schema.id // "") == "phase3_windows_client_beta_run_summary"
            or (.schema.id // "") == "phase3_windows_client_beta_handoff_summary"
            or (.schema.id // "") == "phase3_windows_client_beta_handoff_check_summary"
            or (.schema.id // "") == "phase3_windows_client_beta_handoff_run_summary"
          )
          and ((.schema.major // 0) | type == "number")
          and ((.schema.major // 0) >= 1)
          and ((.schema.major // 0) <= 1)
          and (((.schema.major // 0) | floor) == (.schema.major // 0))
        )
      )
      or ((.signals | type) == "object")
      or ((.stages | type) == "object")
      or ((.steps | type) == "object")
      or ((.phase3_windows_client_beta_handoff | type) == "object")
      or ((.vpn_track.phase3_windows_client_beta_handoff | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

find_latest_phase3_windows_client_beta_summary_json() {
  local logs_root="$ROOT_DIR/.easy-node-logs"
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(phase3_windows_client_beta_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase3_windows_client_beta_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'phase3_windows_client_beta_handoff_check_summary.json' \
       -o -name 'phase3_windows_client_beta_handoff_summary.json' \
       -o -name 'phase3_windows_client_beta_handoff_run_summary.json' \
       -o -name 'phase3_windows_client_beta_check_summary.json' \
       -o -name 'phase3_windows_client_beta_run_summary.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_phase3_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

phase4_windows_full_parity_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      (
        (.schema == null)
        or (
          (.schema | type) == "object"
          and (
            (.schema.id // "") == "phase4_windows_full_parity_check_summary"
            or (.schema.id // "") == "phase4_windows_full_parity_run_summary"
            or (.schema.id // "") == "phase4_windows_full_parity_handoff_summary"
            or (.schema.id // "") == "phase4_windows_full_parity_handoff_check_summary"
            or (.schema.id // "") == "phase4_windows_full_parity_handoff_run_summary"
          )
          and ((.schema.major // 0) | type == "number")
          and ((.schema.major // 0) >= 1)
          and ((.schema.major // 0) <= 1)
          and (((.schema.major // 0) | floor) == (.schema.major // 0))
        )
      )
      or ((.signals | type) == "object")
      or ((.stages | type) == "object")
      or ((.steps | type) == "object")
      or ((.phase4_windows_full_parity_handoff | type) == "object")
      or ((.vpn_track.phase4_windows_full_parity_handoff | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

find_latest_phase4_windows_full_parity_summary_json() {
  local logs_root="$ROOT_DIR/.easy-node-logs"
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(phase4_windows_full_parity_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase4_windows_full_parity_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'phase4_windows_full_parity_handoff_check_summary.json' \
       -o -name 'phase4_windows_full_parity_handoff_summary.json' \
       -o -name 'phase4_windows_full_parity_handoff_run_summary.json' \
       -o -name 'phase4_windows_full_parity_check_summary.json' \
       -o -name 'phase4_windows_full_parity_run_summary.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_phase4_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

phase5_settlement_layer_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      (
        (.schema == null)
        or (
          (.schema | type) == "object"
          and (
            (.schema.id // "") == "phase5_settlement_layer_check_summary"
            or (.schema.id // "") == "phase5_settlement_layer_run_summary"
            or (.schema.id // "") == "phase5_settlement_layer_handoff_summary"
            or (.schema.id // "") == "phase5_settlement_layer_handoff_check_summary"
            or (.schema.id // "") == "phase5_settlement_layer_handoff_run_summary"
          )
          and ((.schema.major // 0) | type == "number")
          and ((.schema.major // 0) >= 1)
          and ((.schema.major // 0) <= 1)
          and (((.schema.major // 0) | floor) == (.schema.major // 0))
        )
      )
      or ((.signals | type) == "object")
      or ((.stages | type) == "object")
      or ((.steps | type) == "object")
      or ((.phase5_settlement_layer_handoff | type) == "object")
      or ((.vpn_track.phase5_settlement_layer_handoff | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

find_latest_phase5_settlement_layer_summary_json() {
  local logs_root="$ROOT_DIR/.easy-node-logs"
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(phase5_settlement_layer_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase5_settlement_layer_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'phase5_settlement_layer_handoff_check_summary.json' \
       -o -name 'phase5_settlement_layer_handoff_summary.json' \
       -o -name 'phase5_settlement_layer_handoff_run_summary.json' \
       -o -name 'phase5_settlement_layer_check_summary.json' \
       -o -name 'phase5_settlement_layer_run_summary.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_phase5_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

phase6_cosmos_l1_summary_kind_from_source() {
  local path="$1"
  local schema_id=""
  local file_name=""
  if [[ -f "$path" ]]; then
    schema_id="$(jq -r '.schema.id // ""' "$path" 2>/dev/null || true)"
  fi
  case "$schema_id" in
    phase6_cosmos_l1_build_testnet_handoff_check_summary) printf '%s' "handoff-check"; return ;;
    phase6_cosmos_l1_build_testnet_handoff_run_summary) printf '%s' "handoff-run"; return ;;
    phase6_cosmos_l1_build_testnet_check_summary) printf '%s' "check"; return ;;
    phase6_cosmos_l1_build_testnet_run_summary) printf '%s' "run"; return ;;
    phase6_cosmos_l1_build_testnet_suite_summary) printf '%s' "suite"; return ;;
    ci_phase6_cosmos_l1_build_testnet_summary) printf '%s' "ci"; return ;;
    ci_phase6_cosmos_l1_contracts_summary) printf '%s' "contracts"; return ;;
    phase6_cosmos_l1_summary_report) printf '%s' "summary-report"; return ;;
  esac
  file_name="$(basename "$path")"
  case "$file_name" in
    phase6_cosmos_l1_build_testnet_handoff_check_summary.json) printf '%s' "handoff-check" ;;
    phase6_cosmos_l1_build_testnet_handoff_run_summary.json) printf '%s' "handoff-run" ;;
    phase6_cosmos_l1_build_testnet_check_summary.json) printf '%s' "check" ;;
    phase6_cosmos_l1_build_testnet_run_summary.json) printf '%s' "run" ;;
    phase6_cosmos_l1_build_testnet_suite_summary.json) printf '%s' "suite" ;;
    phase6_cosmos_l1_build_testnet_ci_summary.json|ci_phase6_cosmos_l1_build_testnet_summary.json) printf '%s' "ci" ;;
    phase6_cosmos_l1_contracts_summary.json|ci_phase6_cosmos_l1_contracts_summary.json) printf '%s' "contracts" ;;
    phase6_cosmos_l1_summary_report.json) printf '%s' "summary-report" ;;
    *) printf '%s' "unknown" ;;
  esac
}

phase6_cosmos_l1_summary_completeness_score() {
  local path="$1"
  local score=0
  local signal=""
  for signal in run_pipeline_ok module_tx_surface_ok tdpnd_grpc_runtime_smoke_ok tdpnd_grpc_live_smoke_ok tdpnd_grpc_auth_live_smoke_ok; do
    if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  printf '%s' "$score"
}

phase6_cosmos_l1_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      (
        (.schema == null)
        or (
          (.schema | type) == "object"
          and (
            (.schema.id // "") == "phase6_cosmos_l1_build_testnet_handoff_check_summary"
            or (.schema.id // "") == "phase6_cosmos_l1_build_testnet_handoff_run_summary"
            or (.schema.id // "") == "phase6_cosmos_l1_build_testnet_check_summary"
            or (.schema.id // "") == "phase6_cosmos_l1_build_testnet_run_summary"
            or (.schema.id // "") == "phase6_cosmos_l1_build_testnet_suite_summary"
            or (.schema.id // "") == "ci_phase6_cosmos_l1_build_testnet_summary"
            or (.schema.id // "") == "ci_phase6_cosmos_l1_contracts_summary"
            or (.schema.id // "") == "phase6_cosmos_l1_summary_report"
          )
          and ((.schema.major // 0) | type == "number")
          and ((.schema.major // 0) >= 1)
          and ((.schema.major // 0) <= 1)
          and (((.schema.major // 0) | floor) == (.schema.major // 0))
        )
      )
      or ((.handoff | type) == "object")
      or ((.signals | type) == "object")
      or ((.steps | type) == "object")
      or ((.stages | type) == "object")
      or ((.summaries | type) == "object")
      or ((.phase6_cosmos_l1_handoff | type) == "object")
      or ((.vpn_track.phase6_cosmos_l1_handoff | type) == "object")
      or ((.blockchain_track.phase6_cosmos_l1_handoff | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

phase7_mainnet_cutover_summary_kind_from_source() {
  local path="$1"
  local schema_id=""
  local file_name=""
  if [[ -f "$path" ]]; then
    schema_id="$(jq -r '.schema.id // ""' "$path" 2>/dev/null || true)"
  fi
  case "$schema_id" in
    phase7_mainnet_cutover_summary_report) printf '%s' "summary-report"; return ;;
    phase7_mainnet_cutover_check_summary) printf '%s' "check"; return ;;
    phase7_mainnet_cutover_run_summary) printf '%s' "run"; return ;;
    phase7_mainnet_cutover_handoff_check_summary) printf '%s' "handoff-check"; return ;;
    phase7_mainnet_cutover_handoff_run_summary) printf '%s' "handoff-run"; return ;;
  esac
  file_name="$(basename "$path")"
  case "$file_name" in
    phase7_mainnet_cutover_summary_report.json) printf '%s' "summary-report" ;;
    phase7_mainnet_cutover_check_summary.json) printf '%s' "check" ;;
    phase7_mainnet_cutover_run_summary.json) printf '%s' "run" ;;
    phase7_mainnet_cutover_handoff_check_summary.json) printf '%s' "handoff-check" ;;
    phase7_mainnet_cutover_handoff_run_summary.json) printf '%s' "handoff-run" ;;
    *) printf '%s' "unknown" ;;
  esac
}

phase7_mainnet_cutover_summary_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      .schema == null
      or (
        (.schema | type) == "object"
        and (
          (.schema.id // "") == "phase7_mainnet_cutover_summary_report"
          or (.schema.id // "") == "phase7_mainnet_cutover_check_summary"
          or (.schema.id // "") == "phase7_mainnet_cutover_run_summary"
          or (.schema.id // "") == "phase7_mainnet_cutover_handoff_check_summary"
          or (.schema.id // "") == "phase7_mainnet_cutover_handoff_run_summary"
        )
        and ((.schema.major // 0) | type == "number")
        and ((.schema.major // 0) >= 1)
        and ((.schema.major // 0) <= 1)
        and (((.schema.major // 0) | floor) == (.schema.major // 0))
      )
    )
    and (
      ((.summaries | type) == "object")
      or ((.signals | type) == "object")
      or ((.stages | type) == "object")
      or ((.steps | type) == "object")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

phase7_mainnet_cutover_bool_value_or_null() {
  local path="$1"
  local jq_expr="$2"
  local value=""
  if [[ ! -f "$path" ]]; then
    printf '%s' "null"
    return
  fi
  value="$(jq -r "$jq_expr" "$path" 2>/dev/null || true)"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' "null"
      ;;
  esac
}

phase6_cosmos_l1_linked_summary_candidates() {
  local source_path="$1"
  local emitted=""
  local queued=""
  local current_path=""
  local candidate_rel=""
  local candidate_abs=""
  local queue=()
  local idx=0
  if [[ "$(phase6_cosmos_l1_summary_usable_01 "$source_path")" != "1" ]]; then
    return
  fi
  queue+=("$source_path")
  queued="|$source_path|"
  while (( idx < ${#queue[@]} )); do
    current_path="${queue[$idx]}"
    idx=$((idx + 1))
    if [[ -z "$current_path" ]]; then
      continue
    fi
    if [[ "$(phase6_cosmos_l1_summary_usable_01 "$current_path")" != "1" ]]; then
      continue
    fi
    if [[ "|$emitted|" != *"|$current_path|"* ]]; then
      emitted="${emitted:+$emitted|}$current_path"
      printf '%s\n' "$current_path"
    fi
    while IFS= read -r candidate_rel; do
      if [[ -z "$candidate_rel" ]]; then
        continue
      fi
      candidate_abs="$(resolve_path_with_base "$candidate_rel" "$current_path")"
      if [[ -z "$candidate_abs" ]]; then
        continue
      fi
      if [[ "$(phase6_cosmos_l1_summary_usable_01 "$candidate_abs")" != "1" ]]; then
        continue
      fi
      if [[ "|$queued|" == *"|$candidate_abs|"* ]]; then
        continue
      fi
      queued="${queued}${candidate_abs}|"
      queue+=("$candidate_abs")
    done < <(jq -r '
      .artifacts.handoff_summary_json // empty,
      .artifacts.handoff_check_summary_json // empty,
      .artifacts.check_summary_json // empty,
      .artifacts.run_summary_json // empty,
      .artifacts.handoff_run_summary_json // empty,
      .artifacts.ci_summary_json // empty,
      .artifacts.contracts_summary_json // empty,
      .inputs.phase6_run_summary_json // empty,
      .inputs.phase6_check_summary_json // empty,
      .inputs.ci_phase6_summary_json // empty,
      .inputs.ci_summary_json // empty,
      .inputs.run_summary_json // empty,
      .inputs.check_summary_json // empty,
      .steps.phase6_cosmos_l1_build_testnet_handoff_check.artifacts.summary_json // empty,
      .steps.phase6_cosmos_l1_build_testnet_check.artifacts.summary_json // empty,
      .steps.phase6_cosmos_l1_build_testnet_handoff_run.artifacts.summary_json // empty,
      .steps.phase6_cosmos_l1_build_testnet_run.artifacts.summary_json // empty,
      .steps.ci_phase6_cosmos_l1_build_testnet.artifacts.summary_json // empty,
      .steps.phase6_cosmos_l1_build_testnet_suite.artifacts.summary_json // empty,
      .summaries.build_testnet_ci.path // empty,
      .summaries.contracts_ci.path // empty,
      .summaries.build_testnet_suite.path // empty
    ' "$current_path" 2>/dev/null || true)
  done
}

phase6_cosmos_l1_pick_best_source_summary_json() {
  local source_path="$1"
  local candidate=""
  local candidate_score=0
  local candidate_non_dry=1
  local candidate_mtime=0
  local best_path=""
  local best_score=-1
  local best_non_dry=-1
  local best_mtime=-1
  if [[ -z "$source_path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$(phase6_cosmos_l1_summary_usable_01 "$source_path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r candidate; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    if [[ "$(phase6_cosmos_l1_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase6_cosmos_l1_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(phase6_cosmos_l1_linked_summary_candidates "$source_path")
  printf '%s' "$best_path"
}

find_latest_phase6_cosmos_l1_summary_json() {
  local logs_root="$ROOT_DIR/.easy-node-logs"
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(phase6_cosmos_l1_summary_usable_01 "$candidate")" != "1" ]]; then
      continue
    fi
    candidate_score="$(phase6_cosmos_l1_summary_completeness_score "$candidate")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_score > best_score )); then
      best_score="$candidate_score"
      best_non_dry="$candidate_non_dry"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_score == best_score )); then
      if (( candidate_non_dry > best_non_dry )); then
        best_non_dry="$candidate_non_dry"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_dry == best_non_dry )); then
        if (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          # Deterministic tie-break when score/dryness/mtime are equal.
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'phase6_cosmos_l1_build_testnet_handoff_check_summary.json' \
       -o -name 'phase6_cosmos_l1_build_testnet_handoff_run_summary.json' \
       -o -name 'phase6_cosmos_l1_build_testnet_check_summary.json' \
       -o -name 'phase6_cosmos_l1_build_testnet_run_summary.json' \
       -o -name 'phase6_cosmos_l1_build_testnet_suite_summary.json' \
       -o -name 'phase6_cosmos_l1_build_testnet_ci_summary.json' \
       -o -name 'phase6_cosmos_l1_contracts_summary.json' \
       -o -name 'phase6_cosmos_l1_summary_report.json' \
       -o -name 'ci_phase6_cosmos_l1_build_testnet_summary.json' \
       -o -name 'ci_phase6_cosmos_l1_contracts_summary.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

resolve_phase6_bool_with_fallback() {
  local path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  value="$(json_bool_value_or_empty "$path" "$explicit_expr")"
  if [[ -z "$value" && -n "$fallback_expr" ]]; then
    value="$(json_bool_value_or_empty "$path" "$fallback_expr")"
  fi
  if [[ -n "$value" ]]; then
    printf '%s' "$value"
  else
    printf '%s' "null"
  fi
}

resolve_phase6_bool_with_source_chain() {
  local source_path="$1"
  local explicit_expr="$2"
  local fallback_expr="$3"
  local value=""
  local candidate=""
  value="$(resolve_phase6_bool_with_fallback "$source_path" "$explicit_expr" "$fallback_expr")"
  if [[ "$value" != "null" ]]; then
    printf '%s' "$value"
    return
  fi
  while IFS= read -r candidate; do
    if [[ -z "$candidate" ]]; then
      continue
    fi
    value="$(resolve_phase6_bool_with_fallback "$candidate" "$explicit_expr" "$fallback_expr")"
    if [[ "$value" != "null" ]]; then
      printf '%s' "$value"
      return
    fi
  done < <(phase6_cosmos_l1_linked_summary_candidates "$source_path")
  printf '%s' "null"
}

single_machine_refresh_transient_non_blocking_01() {
  local refresh_log="$1"
  local summary_path="$2"

  if [[ ! -f "$refresh_log" ]]; then
    printf '0'
    return
  fi
  if ! rg -qi \
    'server misbehaving|temporary failure in name resolution|tls handshake timeout|i/o timeout|context deadline exceeded|connection reset by peer|failed to do request|request canceled while waiting for connection' \
    "$refresh_log"; then
    printf '0'
    return
  fi
  if [[ "$(single_machine_summary_usable_01 "$summary_path")" != "1" ]]; then
    printf '0'
    return
  fi

  if jq -e '
    def arr_or_empty(v): if (v | type) == "array" then v else [] end;
    (
      (arr_or_empty(.summary.critical_failed_steps) | length) > 0
      and (
        (arr_or_empty(.summary.critical_failed_steps)
          | map((.step_id // "") | tostring)
          | unique
        ) == ["three_machine_docker_readiness"]
      )
      and ((arr_or_empty(.summary.pending_local_checks) | length) == 0)
    )
    or
    (
      ((.status // "") | tostring) == "fail"
      and (((.summary.three_machine_docker_readiness.status // "") | tostring) == "fail")
      and ((arr_or_empty(.summary.pending_local_checks) | length) == 0)
    )
  ' "$summary_path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

restore_json_snapshot() {
  local snapshot_path="$1"
  local target_path="$2"
  local restore_tmp=""
  if [[ ! -f "$snapshot_path" ]]; then
    return 1
  fi
  if ! jq -e . "$snapshot_path" >/dev/null 2>&1; then
    return 1
  fi
  mkdir -p "$(dirname "$target_path")"
  restore_tmp="$(mktemp "${target_path}.restore.tmp.XXXXXX")"
  cp "$snapshot_path" "$restore_tmp"
  if ! jq -e . "$restore_tmp" >/dev/null 2>&1; then
    rm -f "$restore_tmp"
    return 1
  fi
  mv -f "$restore_tmp" "$target_path"
}

refresh_manual_validation="1"
refresh_single_machine_readiness="0"
manual_refresh_timeout_sec="${ROADMAP_PROGRESS_MANUAL_REFRESH_TIMEOUT_SEC:-900}"
# Full single-machine refresh can include ci_local + beta_preflight + deep_test_suite.
# Keep default high enough to avoid false fail-close timeouts on healthy hosts.
single_machine_refresh_timeout_sec="${ROADMAP_PROGRESS_SINGLE_MACHINE_REFRESH_TIMEOUT_SEC:-7200}"
print_report="1"
print_summary_json="1"

summary_json="$ROOT_DIR/.easy-node-logs/roadmap_progress_summary.json"
report_md="$ROOT_DIR/.easy-node-logs/roadmap_progress_report.md"
manual_validation_summary_json="$ROOT_DIR/.easy-node-logs/manual_validation_readiness_summary.json"
manual_validation_report_md="$ROOT_DIR/.easy-node-logs/manual_validation_readiness_report.md"
profile_compare_signoff_summary_json="$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json"
single_machine_summary_json="$ROOT_DIR/.easy-node-logs/single_machine_prod_readiness_latest.json"
phase0_summary_json="${ROADMAP_PROGRESS_PHASE0_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/ci_phase0_summary.json}"
phase1_resilience_handoff_summary_json="${ROADMAP_PROGRESS_PHASE1_RESILIENCE_HANDOFF_SUMMARY_JSON:-}"
vpn_rc_resilience_summary_json="${ROADMAP_PROGRESS_VPN_RC_RESILIENCE_SUMMARY_JSON:-}"
vpn_rc_resilience_summary_explicit_01="0"
if [[ -n "$vpn_rc_resilience_summary_json" ]]; then
  vpn_rc_resilience_summary_explicit_01="1"
fi
phase2_linux_prod_candidate_summary_json="${ROADMAP_PROGRESS_PHASE2_LINUX_PROD_CANDIDATE_SUMMARY_JSON:-}"
phase3_windows_client_beta_summary_json="${ROADMAP_PROGRESS_PHASE3_WINDOWS_CLIENT_BETA_SUMMARY_JSON:-}"
phase4_windows_full_parity_summary_json="${ROADMAP_PROGRESS_PHASE4_WINDOWS_FULL_PARITY_SUMMARY_JSON:-}"
phase5_settlement_layer_summary_json="${ROADMAP_PROGRESS_PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON:-}"
phase6_cosmos_l1_summary_json="${ROADMAP_PROGRESS_PHASE6_COSMOS_L1_SUMMARY_JSON:-}"
phase7_mainnet_cutover_summary_json="${ROADMAP_PROGRESS_PHASE7_MAINNET_CUTOVER_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_summary_report.json}"
phase7_mainnet_cutover_summary_json="$(abs_path "$phase7_mainnet_cutover_summary_json")"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --refresh-manual-validation)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_manual_validation="${2:-}"
        shift 2
      else
        refresh_manual_validation="1"
        shift
      fi
      ;;
    --refresh-single-machine-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_single_machine_readiness="${2:-}"
        shift 2
      else
        refresh_single_machine_readiness="1"
        shift
      fi
      ;;
    --manual-validation-summary-json)
      manual_validation_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --manual-refresh-timeout-sec)
      manual_refresh_timeout_sec="${2:-}"
      shift 2
      ;;
    --single-machine-refresh-timeout-sec)
      single_machine_refresh_timeout_sec="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="$(abs_path "${2:-}")"
      shift 2
      ;;
    --profile-compare-signoff-summary-json)
      profile_compare_signoff_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --single-machine-summary-json)
      single_machine_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase0-summary-json)
      phase0_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase1-resilience-handoff-summary-json)
      phase1_resilience_handoff_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --vpn-rc-resilience-summary-json)
      vpn_rc_resilience_summary_json="$(abs_path "${2:-}")"
      vpn_rc_resilience_summary_explicit_01="1"
      shift 2
      ;;
    --phase2-linux-prod-candidate-summary-json)
      phase2_linux_prod_candidate_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase3-windows-client-beta-summary-json)
      phase3_windows_client_beta_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase4-windows-full-parity-summary-json)
      phase4_windows_full_parity_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase5-settlement-layer-summary-json)
      phase5_settlement_layer_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase6-cosmos-l1-summary-json)
      phase6_cosmos_l1_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase7-mainnet-cutover-summary-json)
      phase7_mainnet_cutover_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --summary-json)
      summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --report-md)
      report_md="$(abs_path "${2:-}")"
      shift 2
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    -h|--help|help)
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

for cmd in jq date mktemp rg; do
  need_cmd "$cmd"
done

bool_arg_or_die "--refresh-manual-validation" "$refresh_manual_validation"
bool_arg_or_die "--refresh-single-machine-readiness" "$refresh_single_machine_readiness"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
if ! [[ "$manual_refresh_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--manual-refresh-timeout-sec must be an integer >= 0"
  exit 2
fi
if ! [[ "$single_machine_refresh_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--single-machine-refresh-timeout-sec must be an integer >= 0"
  exit 2
fi
phase0_summary_json="$(abs_path "$phase0_summary_json")"

run_with_optional_timeout() {
  local timeout_sec="$1"
  shift
  if [[ "$timeout_sec" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_sec}s" "$@"
  else
    "$@"
  fi
}

manual_validation_report_script="${ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT:-$ROOT_DIR/scripts/manual_validation_report.sh}"
single_machine_script="${ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT:-$ROOT_DIR/scripts/single_machine_prod_readiness.sh}"
product_roadmap_doc="${ROADMAP_PROGRESS_PRODUCT_ROADMAP_DOC:-$ROOT_DIR/docs/product-roadmap.md}"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$report_md")"
mkdir -p "$(dirname "$manual_validation_summary_json")"
mkdir -p "$(dirname "$manual_validation_report_md")"
mkdir -p "$(dirname "$single_machine_summary_json")"

log_dir="$ROOT_DIR/.easy-node-logs"
mkdir -p "$log_dir"
ts="$(date +%Y%m%d_%H%M%S)"
manual_refresh_log="$log_dir/roadmap_progress_manual_validation_${ts}.log"
single_machine_refresh_log="$log_dir/roadmap_progress_single_machine_${ts}.log"

manual_refresh_status="skip"
manual_refresh_rc=0
manual_refresh_timed_out="false"
manual_refresh_duration_sec=0
single_machine_refresh_status="skip"
single_machine_refresh_rc=0
single_machine_refresh_timed_out="false"
single_machine_refresh_duration_sec=0
single_machine_refresh_non_blocking_transient="false"
single_machine_refresh_non_blocking_reason=""

manual_summary_snapshot=""
manual_summary_snapshot_valid="false"
manual_summary_restored="false"
manual_summary_valid_after_run="false"
single_machine_summary_snapshot=""
single_machine_summary_snapshot_valid="false"
single_machine_summary_restored="false"
single_machine_summary_valid_after_run="false"

if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" == "1" ]]; then
  manual_summary_snapshot="$(mktemp "$log_dir/roadmap_progress_manual_validation_snapshot_${ts}_XXXXXX.json")"
  cp "$manual_validation_summary_json" "$manual_summary_snapshot"
  manual_summary_snapshot_valid="true"
fi
if [[ "$(single_machine_summary_usable_01 "$single_machine_summary_json")" == "1" ]]; then
  single_machine_summary_snapshot="$(mktemp "$log_dir/roadmap_progress_single_machine_snapshot_${ts}_XXXXXX.json")"
  cp "$single_machine_summary_json" "$single_machine_summary_snapshot"
  single_machine_summary_snapshot_valid="true"
fi

if [[ "$refresh_single_machine_readiness" == "1" ]]; then
  single_machine_refresh_status="fail"
  single_machine_refresh_timed_out="false"
  single_machine_started_at="$(date +%s)"
  if [[ "$single_machine_refresh_timeout_sec" -gt 0 ]] && ! command -v timeout >/dev/null 2>&1; then
    echo "[roadmap-progress-report] warn=timeout command not found; running single-machine refresh without timeout guard"
  fi
  echo "[roadmap-progress-report] refresh_step=single_machine_prod_readiness status=running timeout_sec=$single_machine_refresh_timeout_sec log=$single_machine_refresh_log"
  set +e
  run_with_optional_timeout "$single_machine_refresh_timeout_sec" "$single_machine_script" \
    --summary-json "$single_machine_summary_json" \
    --manual-validation-report-summary-json "$manual_validation_summary_json" \
    --manual-validation-report-md "$manual_validation_report_md" \
    --print-summary-json 0 >"$single_machine_refresh_log" 2>&1
  single_machine_refresh_rc=$?
  set -e
  single_machine_refresh_duration_sec="$(( $(date +%s) - single_machine_started_at ))"
  if [[ "$single_machine_refresh_rc" -eq 124 ]]; then
    single_machine_refresh_timed_out="true"
  fi
  if [[ "$single_machine_refresh_rc" -eq 0 ]]; then
    single_machine_refresh_status="pass"
  fi
  single_machine_summary_valid_after_run="false"
  if [[ "$(single_machine_summary_usable_01 "$single_machine_summary_json")" == "1" ]]; then
    single_machine_summary_valid_after_run="true"
  fi
  if [[ "$single_machine_refresh_status" == "pass" && "$single_machine_summary_valid_after_run" != "true" ]]; then
    single_machine_refresh_status="fail"
    if [[ "$single_machine_refresh_rc" -eq 0 ]]; then
      single_machine_refresh_rc=3
    fi
  fi
  if [[ "$single_machine_summary_valid_after_run" != "true" && "$single_machine_summary_snapshot_valid" == "true" ]]; then
    if restore_json_snapshot "$single_machine_summary_snapshot" "$single_machine_summary_json"; then
      single_machine_summary_restored="true"
      single_machine_summary_valid_after_run="true"
    fi
  fi
  if [[ "$single_machine_refresh_status" == "fail" && "$single_machine_refresh_timed_out" != "true" ]]; then
    if [[ "$(single_machine_refresh_transient_non_blocking_01 "$single_machine_refresh_log" "$single_machine_summary_json")" == "1" ]]; then
      single_machine_refresh_status="warn"
      single_machine_refresh_non_blocking_transient="true"
      single_machine_refresh_non_blocking_reason="Transient docker registry/network failure during single-machine docker rehearsal; latest usable summary retained."
    fi
  fi
  echo "[roadmap-progress-report] refresh_step=single_machine_prod_readiness status=$single_machine_refresh_status rc=$single_machine_refresh_rc timed_out=$single_machine_refresh_timed_out duration_sec=$single_machine_refresh_duration_sec log=$single_machine_refresh_log"
fi
if [[ "$refresh_single_machine_readiness" != "1" ]]; then
  if [[ "$(single_machine_summary_usable_01 "$single_machine_summary_json")" == "1" ]]; then
    single_machine_summary_valid_after_run="true"
  fi
fi

if [[ "$refresh_manual_validation" == "1" ]]; then
  manual_refresh_status="fail"
  manual_refresh_timed_out="false"
  manual_started_at="$(date +%s)"
  if [[ "$manual_refresh_timeout_sec" -gt 0 ]] && ! command -v timeout >/dev/null 2>&1; then
    echo "[roadmap-progress-report] warn=timeout command not found; running manual-validation refresh without timeout guard"
  fi
  echo "[roadmap-progress-report] refresh_step=manual_validation_report status=running timeout_sec=$manual_refresh_timeout_sec log=$manual_refresh_log"
  set +e
  run_with_optional_timeout "$manual_refresh_timeout_sec" "$manual_validation_report_script" \
    --profile-compare-signoff-summary-json "$profile_compare_signoff_summary_json" \
    --summary-json "$manual_validation_summary_json" \
    --report-md "$manual_validation_report_md" \
    --print-report 0 \
    --print-summary-json 0 >"$manual_refresh_log" 2>&1
  manual_refresh_rc=$?
  set -e
  manual_refresh_duration_sec="$(( $(date +%s) - manual_started_at ))"
  if [[ "$manual_refresh_rc" -eq 124 ]]; then
    manual_refresh_timed_out="true"
  fi
  if [[ "$manual_refresh_rc" -eq 0 ]]; then
    manual_refresh_status="pass"
  fi
  manual_summary_valid_after_run="false"
  if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" == "1" ]]; then
    manual_summary_valid_after_run="true"
  fi
  if [[ "$manual_refresh_status" == "pass" && "$manual_summary_valid_after_run" != "true" ]]; then
    manual_refresh_status="fail"
    if [[ "$manual_refresh_rc" -eq 0 ]]; then
      manual_refresh_rc=3
    fi
  fi
  if [[ "$manual_summary_valid_after_run" != "true" && "$manual_summary_snapshot_valid" == "true" ]]; then
    if restore_json_snapshot "$manual_summary_snapshot" "$manual_validation_summary_json"; then
      manual_summary_restored="true"
      manual_summary_valid_after_run="true"
    fi
  fi
  echo "[roadmap-progress-report] refresh_step=manual_validation_report status=$manual_refresh_status rc=$manual_refresh_rc timed_out=$manual_refresh_timed_out duration_sec=$manual_refresh_duration_sec log=$manual_refresh_log"
fi
if [[ "$refresh_manual_validation" != "1" ]]; then
  if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" == "1" ]]; then
    manual_summary_valid_after_run="true"
  fi
fi

if [[ ! -f "$manual_validation_summary_json" ]]; then
  echo "manual-validation summary JSON not found: $manual_validation_summary_json"
  exit 1
fi
if [[ "$(manual_validation_summary_usable_01 "$manual_validation_summary_json")" != "1" ]]; then
  echo "manual-validation summary JSON is missing required fields or uses an incompatible schema: $manual_validation_summary_json"
  exit 1
fi

phase0_product_surface_available_json="false"
phase0_product_surface_input_summary_json="$phase0_summary_json"
phase0_product_surface_source_summary_json=""
phase0_product_surface_status_json="missing"
phase0_product_surface_rc_json="null"
phase0_product_surface_dry_run_json="null"
phase0_product_surface_contract_ok_json="null"
phase0_product_surface_all_required_steps_ok_json="null"
phase0_product_surface_launcher_wiring_ok_json="null"
phase0_product_surface_launcher_runtime_ok_json="null"
phase0_product_surface_prompt_budget_ok_json="null"
phase0_product_surface_config_v1_ok_json="null"
phase0_product_surface_local_control_api_ok_json="null"
if [[ -f "$phase0_summary_json" ]]; then
  if [[ "$(phase0_summary_usable_01 "$phase0_summary_json")" == "1" ]]; then
    phase0_product_surface_available_json="true"
    phase0_product_surface_source_summary_json="$phase0_summary_json"
    phase0_product_surface_status_json="$(jq -r '.status // "unknown"' "$phase0_summary_json" 2>/dev/null || echo "unknown")"
    phase0_product_surface_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase0_summary_json" 2>/dev/null || true)"
    if [[ -z "$phase0_product_surface_rc_json" ]]; then
      phase0_product_surface_rc_json="null"
    fi
    phase0_product_surface_dry_run_json="$(json_bool_value_or_empty "$phase0_summary_json" '.dry_run')"
    if [[ -z "$phase0_product_surface_dry_run_json" ]]; then
      phase0_product_surface_dry_run_json="null"
    fi
    phase0_product_surface_contract_ok_json="$(json_bool_value_or_empty "$phase0_summary_json" '.summary.contract_ok // .contract_ok')"
    if [[ -z "$phase0_product_surface_contract_ok_json" ]]; then
      case "${phase0_product_surface_status_json,,}" in
        pass)
          phase0_product_surface_contract_ok_json="true"
          ;;
        fail|dry-run)
          phase0_product_surface_contract_ok_json="false"
          ;;
        *)
          phase0_product_surface_contract_ok_json="null"
          ;;
      esac
    fi
    phase0_product_surface_all_required_steps_ok_json="$(json_bool_value_or_empty "$phase0_summary_json" '.summary.all_required_steps_ok')"
    if [[ -z "$phase0_product_surface_all_required_steps_ok_json" ]]; then
      phase0_product_surface_all_required_steps_ok_json="null"
    fi
    phase0_product_surface_launcher_wiring_ok_json="$(phase0_step_ok_json_or_null "$phase0_summary_json" "launcher_wiring")"
    phase0_product_surface_launcher_runtime_ok_json="$(phase0_step_ok_json_or_null "$phase0_summary_json" "launcher_runtime")"
    phase0_product_surface_prompt_budget_ok_json="$(phase0_step_ok_json_or_null "$phase0_summary_json" "prompt_budget")"
    phase0_product_surface_config_v1_ok_json="$(phase0_step_ok_json_or_null "$phase0_summary_json" "config_v1")"
    phase0_product_surface_local_control_api_ok_json="$(phase0_step_ok_json_or_null "$phase0_summary_json" "local_control_api")"
  else
    phase0_product_surface_status_json="invalid"
  fi
fi

if [[ -z "$phase1_resilience_handoff_summary_json" ]]; then
  phase1_resilience_handoff_summary_json="$(find_latest_phase1_resilience_handoff_summary_json)"
else
  phase1_resilience_handoff_summary_json="$(abs_path "$phase1_resilience_handoff_summary_json")"
fi

phase1_resilience_handoff_available_json="false"
phase1_resilience_handoff_input_summary_json=""
phase1_resilience_handoff_source_summary_json=""
phase1_resilience_handoff_source_summary_kind=""
phase1_resilience_handoff_status_json="missing"
phase1_resilience_handoff_rc_json="null"
phase1_resilience_handoff_profile_matrix_stable_json="null"
phase1_resilience_handoff_peer_loss_recovery_ok_json="null"
phase1_resilience_handoff_session_churn_guard_ok_json="null"
phase1_resilience_handoff_automatable_without_sudo_or_github_json="null"
phase1_resilience_handoff_failure_kind_json=""
phase1_resilience_handoff_policy_outcome_decision_json=""
phase1_resilience_handoff_policy_outcome_fail_closed_no_go_json="null"
phase1_resilience_handoff_profile_matrix_stable_failure_kind_json=""
phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind_json=""
phase1_resilience_handoff_session_churn_guard_ok_failure_kind_json=""
if [[ -n "$phase1_resilience_handoff_summary_json" ]]; then
  phase1_resilience_handoff_input_summary_json="$phase1_resilience_handoff_summary_json"
  if [[ "$(phase1_resilience_handoff_summary_usable_01 "$phase1_resilience_handoff_summary_json")" == "1" ]]; then
    phase1_schema_id="$(jq -r '.schema.id // ""' "$phase1_resilience_handoff_summary_json" 2>/dev/null || true)"
    phase1_default_source_kind="check"
    case "$phase1_schema_id" in
      *handoff_run*)
        phase1_default_source_kind="run"
        ;;
      *handoff_check*)
        phase1_default_source_kind="check"
        ;;
      *ci_phase1*)
        phase1_default_source_kind="ci"
        ;;
    esac
    phase1_resilience_handoff_source_summary_json="$phase1_resilience_handoff_summary_json"
    if [[ -n "$phase1_resilience_handoff_source_summary_json" ]]; then
      phase1_source_schema_id="$(jq -r '.schema.id // ""' "$phase1_resilience_handoff_source_summary_json" 2>/dev/null || true)"
      phase1_resilience_handoff_source_summary_kind="$phase1_default_source_kind"
      case "$phase1_source_schema_id" in
        *handoff_run*)
          phase1_resilience_handoff_source_summary_kind="run"
          ;;
        *handoff_check*)
          phase1_resilience_handoff_source_summary_kind="check"
          ;;
        *ci_phase1*)
          phase1_resilience_handoff_source_summary_kind="ci"
          ;;
      esac
      phase1_resilience_handoff_status_json="$(jq -r '.status // "unknown"' "$phase1_resilience_handoff_source_summary_json" 2>/dev/null || echo "unknown")"
      phase1_resilience_handoff_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase1_resilience_handoff_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase1_resilience_handoff_rc_json" ]]; then
        phase1_resilience_handoff_rc_json="null"
      fi
      phase1_resilience_handoff_available_json="true"
      phase1_resilience_handoff_profile_matrix_stable_json="$(resolve_phase1_bool_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.handoff.profile_matrix_stable | type) == "boolean" then .handoff.profile_matrix_stable
          elif (.profile_matrix_stable | type) == "boolean" then .profile_matrix_stable
          elif (.summary.profile_matrix_stable | type) == "boolean" then .summary.profile_matrix_stable
          elif (.resilience_handoff.profile_matrix_stable | type) == "boolean" then .resilience_handoff.profile_matrix_stable
          elif (.vpn_track.resilience_handoff.profile_matrix_stable | type) == "boolean" then .vpn_track.resilience_handoff.profile_matrix_stable
          else empty end' \
        '((.steps.three_machine_docker_profile_matrix.status // "") | ascii_downcase) as $s
          | if $s == "pass" then true
            elif $s == "fail" then false
            else empty end')"
      phase1_resilience_handoff_peer_loss_recovery_ok_json="$(resolve_phase1_bool_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.handoff.peer_loss_recovery_ok | type) == "boolean" then .handoff.peer_loss_recovery_ok
          elif (.peer_loss_recovery_ok | type) == "boolean" then .peer_loss_recovery_ok
          elif (.summary.peer_loss_recovery_ok | type) == "boolean" then .summary.peer_loss_recovery_ok
          elif (.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .resilience_handoff.peer_loss_recovery_ok
          elif (.vpn_track.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .vpn_track.resilience_handoff.peer_loss_recovery_ok
          else empty end' \
        '((.steps.vpn_rc_resilience_path.status // .steps.vpn_rc_matrix_path.status // "") | ascii_downcase) as $s
          | if $s == "pass" then true
            elif $s == "fail" then false
            else empty end')"
      phase1_resilience_handoff_session_churn_guard_ok_json="$(resolve_phase1_bool_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.handoff.session_churn_guard_ok | type) == "boolean" then .handoff.session_churn_guard_ok
          elif (.session_churn_guard_ok | type) == "boolean" then .session_churn_guard_ok
          elif (.summary.session_churn_guard_ok | type) == "boolean" then .summary.session_churn_guard_ok
          elif (.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .resilience_handoff.session_churn_guard_ok
          elif (.vpn_track.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .vpn_track.resilience_handoff.session_churn_guard_ok
          else empty end' \
        '((.steps.session_churn_guard.status // "") | ascii_downcase) as $s
          | if $s == "pass" then true
            elif $s == "fail" then false
            else empty end')"
      phase1_resilience_handoff_automatable_without_sudo_or_github_json="$(resolve_phase1_bool_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.automation.automatable_without_sudo_or_github | type) == "boolean" then .automation.automatable_without_sudo_or_github
          elif ((.automation.requires_sudo | type) == "boolean" or (.automation.requires_github | type) == "boolean") then ((.automation.requires_sudo // false | not) and (.automation.requires_github // false | not))
          else empty end' \
        'if (.schema.id // "") == "phase1_resilience_handoff_check_summary" or (.schema.id // "") == "phase1_resilience_handoff_run_summary" or (.schema.id // "") == "ci_phase1_resilience_summary" then true else empty end')"
      phase1_resilience_handoff_failure_kind_json="$(resolve_phase1_string_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.failure.kind | type) == "string" then .failure.kind
          elif (.handoff.failure.kind | type) == "string" then .handoff.failure.kind
          elif (.summary.failure.kind | type) == "string" then .summary.failure.kind
          elif (.resilience_handoff.failure.kind | type) == "string" then .resilience_handoff.failure.kind
          elif (.phase1_resilience_handoff.failure.kind | type) == "string" then .phase1_resilience_handoff.failure.kind
          elif (.vpn_track.phase1_resilience_handoff.failure.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure.kind
          else empty end' \
        '')"
      phase1_resilience_handoff_policy_outcome_decision_json="$(resolve_phase1_string_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.policy_outcome.decision | type) == "string" then .policy_outcome.decision
          elif (.handoff.policy_outcome.decision | type) == "string" then .handoff.policy_outcome.decision
          elif (.summary.policy_outcome.decision | type) == "string" then .summary.policy_outcome.decision
          elif (.phase1_resilience_handoff.policy_outcome.decision | type) == "string" then .phase1_resilience_handoff.policy_outcome.decision
          elif (.vpn_track.phase1_resilience_handoff.policy_outcome.decision | type) == "string" then .vpn_track.phase1_resilience_handoff.policy_outcome.decision
          elif (.policy_outcome.signoff_decision | type) == "string" then .policy_outcome.signoff_decision
          else empty end' \
        '')"
      phase1_resilience_handoff_policy_outcome_fail_closed_no_go_json="$(resolve_phase1_bool_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.policy_outcome.fail_closed_no_go | type) == "boolean" then .policy_outcome.fail_closed_no_go
          elif (.handoff.policy_outcome.fail_closed_no_go | type) == "boolean" then .handoff.policy_outcome.fail_closed_no_go
          elif (.summary.policy_outcome.fail_closed_no_go | type) == "boolean" then .summary.policy_outcome.fail_closed_no_go
          elif (.phase1_resilience_handoff.policy_outcome.fail_closed_no_go | type) == "boolean" then .phase1_resilience_handoff.policy_outcome.fail_closed_no_go
          elif (.vpn_track.phase1_resilience_handoff.policy_outcome.fail_closed_no_go | type) == "boolean" then .vpn_track.phase1_resilience_handoff.policy_outcome.fail_closed_no_go
          else empty end' \
        '')"
      phase1_resilience_handoff_profile_matrix_stable_failure_kind_json="$(resolve_phase1_string_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .handoff.failure_semantics.profile_matrix_stable.kind
          elif (.failure_semantics.profile_matrix_stable.kind | type) == "string" then .failure_semantics.profile_matrix_stable.kind
          elif (.summary.failure_semantics.profile_matrix_stable.kind | type) == "string" then .summary.failure_semantics.profile_matrix_stable.kind
          elif (.signals.profile_matrix_stable.failure_kind | type) == "string" then .signals.profile_matrix_stable.failure_kind
          elif (.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind
          elif (.vpn_track.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind
          elif (.phase1_resilience_handoff.profile_matrix_stable_failure_kind | type) == "string" then .phase1_resilience_handoff.profile_matrix_stable_failure_kind
          elif (.vpn_track.phase1_resilience_handoff.profile_matrix_stable_failure_kind | type) == "string" then .vpn_track.phase1_resilience_handoff.profile_matrix_stable_failure_kind
          else empty end' \
        '')"
      phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind_json="$(resolve_phase1_string_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .handoff.failure_semantics.peer_loss_recovery_ok.kind
          elif (.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .failure_semantics.peer_loss_recovery_ok.kind
          elif (.summary.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .summary.failure_semantics.peer_loss_recovery_ok.kind
          elif (.signals.peer_loss_recovery_ok.failure_kind | type) == "string" then .signals.peer_loss_recovery_ok.failure_kind
          elif (.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind
          elif (.vpn_track.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind
          elif (.phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind | type) == "string" then .phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind
          elif (.vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind | type) == "string" then .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok_failure_kind
          else empty end' \
        '')"
      phase1_resilience_handoff_session_churn_guard_ok_failure_kind_json="$(resolve_phase1_string_with_source_chain \
        "$phase1_resilience_handoff_source_summary_json" \
        'if (.handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .handoff.failure_semantics.session_churn_guard_ok.kind
          elif (.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .failure_semantics.session_churn_guard_ok.kind
          elif (.summary.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .summary.failure_semantics.session_churn_guard_ok.kind
          elif (.signals.session_churn_guard_ok.failure_kind | type) == "string" then .signals.session_churn_guard_ok.failure_kind
          elif (.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind
          elif (.vpn_track.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .vpn_track.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind
          elif (.phase1_resilience_handoff.session_churn_guard_ok_failure_kind | type) == "string" then .phase1_resilience_handoff.session_churn_guard_ok_failure_kind
          elif (.vpn_track.phase1_resilience_handoff.session_churn_guard_ok_failure_kind | type) == "string" then .vpn_track.phase1_resilience_handoff.session_churn_guard_ok_failure_kind
          else empty end' \
        '')"
    fi
  else
    phase1_resilience_handoff_status_json="invalid"
  fi
fi

vpn_rc_resilience_summary_from_phase1_linked_json="false"
if [[ "$vpn_rc_resilience_summary_explicit_01" == "1" ]]; then
  vpn_rc_resilience_summary_json="$(abs_path "$vpn_rc_resilience_summary_json")"
else
  vpn_rc_resilience_summary_json=""
  if [[ -n "$phase1_resilience_handoff_source_summary_json" ]]; then
    vpn_rc_resilience_summary_json="$(phase1_linked_resilience_summary_json_from_source \
      "$phase1_resilience_handoff_source_summary_json" \
      "$phase1_resilience_handoff_source_summary_kind")"
    if [[ -n "$vpn_rc_resilience_summary_json" ]]; then
      vpn_rc_resilience_summary_from_phase1_linked_json="true"
    fi
  fi
  if [[ -z "$vpn_rc_resilience_summary_json" ]]; then
    vpn_rc_resilience_summary_json="$(find_latest_resilience_summary_json)"
    vpn_rc_resilience_summary_from_phase1_linked_json="false"
  fi
fi

resilience_handoff_available_json="false"
resilience_handoff_source_summary_json=""
resilience_profile_matrix_stable_json="null"
resilience_peer_loss_recovery_ok_json="null"
resilience_session_churn_guard_ok_json="null"
if [[ -n "$vpn_rc_resilience_summary_json" ]] && [[ "$(resilience_summary_usable_01 "$vpn_rc_resilience_summary_json")" == "1" ]]; then
  resilience_handoff_available_json="true"
  resilience_handoff_source_summary_json="$vpn_rc_resilience_summary_json"
  resilience_profile_matrix_stable_json="$(resolve_resilience_bool_with_fallback \
    "$vpn_rc_resilience_summary_json" \
    'if (.profile_matrix_stable | type) == "boolean" then .profile_matrix_stable
      elif (.summary.profile_matrix_stable | type) == "boolean" then .summary.profile_matrix_stable
      elif (.handoff.profile_matrix_stable | type) == "boolean" then .handoff.profile_matrix_stable
      elif (.signals.profile_matrix_stable | type) == "boolean" then .signals.profile_matrix_stable
      elif (.resilience_handoff.profile_matrix_stable | type) == "boolean" then .resilience_handoff.profile_matrix_stable
      elif (.vpn_track.resilience_handoff.profile_matrix_stable | type) == "boolean" then .vpn_track.resilience_handoff.profile_matrix_stable
      else empty end' \
    '((.steps.three_machine_docker_profile_matrix.status // "") | ascii_downcase) as $s
      | if $s == "pass" then true
        elif $s == "fail" then false
        else (
          (.steps.three_machine_docker_profile_matrix.summary.profiles_fail // null) as $profiles_fail
          | (.steps.three_machine_docker_profile_matrix.summary.profiles_total // null) as $profiles_total
          | if (($profiles_fail | type) == "number") and (($profiles_total | type) == "number") and ($profiles_total > 0) then ($profiles_fail == 0) else empty end
        ) end')"
  resilience_peer_loss_recovery_ok_json="$(resolve_resilience_bool_with_fallback \
    "$vpn_rc_resilience_summary_json" \
    'if (.peer_loss_recovery_ok | type) == "boolean" then .peer_loss_recovery_ok
      elif (.summary.peer_loss_recovery_ok | type) == "boolean" then .summary.peer_loss_recovery_ok
      elif (.handoff.peer_loss_recovery_ok | type) == "boolean" then .handoff.peer_loss_recovery_ok
      elif (.signals.peer_loss_recovery_ok | type) == "boolean" then .signals.peer_loss_recovery_ok
      elif (.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .resilience_handoff.peer_loss_recovery_ok
      elif (.vpn_track.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .vpn_track.resilience_handoff.peer_loss_recovery_ok
      else empty end' \
    '((.steps.vpn_rc_matrix_path.status // "") | ascii_downcase) as $s
      | if $s == "pass" then true
        elif $s == "fail" then false
        else empty end')"
  resilience_session_churn_guard_ok_json="$(resolve_resilience_bool_with_fallback \
    "$vpn_rc_resilience_summary_json" \
    'if (.session_churn_guard_ok | type) == "boolean" then .session_churn_guard_ok
      elif (.summary.session_churn_guard_ok | type) == "boolean" then .summary.session_churn_guard_ok
      elif (.handoff.session_churn_guard_ok | type) == "boolean" then .handoff.session_churn_guard_ok
      elif (.signals.session_churn_guard_ok | type) == "boolean" then .signals.session_churn_guard_ok
      elif (.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .resilience_handoff.session_churn_guard_ok
      elif (.vpn_track.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .vpn_track.resilience_handoff.session_churn_guard_ok
      else empty end' \
    '((.steps.vpn_rc_matrix_path.status // "") | ascii_downcase) as $s
      | if $s == "pass" then true
        elif $s == "fail" then false
        else empty end')"
fi

# Keep resilience handoff internally consistent with the selected Phase-1 source
# when its linked resilience artifact is stale/conflicting and no explicit
# resilience summary was requested by the caller.
if [[ "$vpn_rc_resilience_summary_explicit_01" != "1" \
   && "$phase1_resilience_handoff_available_json" == "true" \
   && -n "$phase1_resilience_handoff_source_summary_json" ]]; then
  phase1_resilience_source_mtime=""
  resolved_resilience_source_mtime=""
  override_due_to_stale_resilience_source="false"
  if [[ -n "$resilience_handoff_source_summary_json" ]]; then
    phase1_resilience_source_mtime="$(file_mtime_epoch "$phase1_resilience_handoff_source_summary_json")"
    resolved_resilience_source_mtime="$(file_mtime_epoch "$resilience_handoff_source_summary_json")"
    if [[ "$phase1_resilience_source_mtime" =~ ^[0-9]+$ \
       && "$resolved_resilience_source_mtime" =~ ^[0-9]+$ \
       && "$resolved_resilience_source_mtime" -lt "$phase1_resilience_source_mtime" ]]; then
      override_due_to_stale_resilience_source="true"
    fi
  fi
  if [[ "$phase1_resilience_handoff_profile_matrix_stable_json" != "null" \
     && "$phase1_resilience_handoff_peer_loss_recovery_ok_json" != "null" \
     && "$phase1_resilience_handoff_session_churn_guard_ok_json" != "null" ]]; then
    if [[ "$resilience_profile_matrix_stable_json" == "null" \
       || "$resilience_peer_loss_recovery_ok_json" == "null" \
       || "$resilience_session_churn_guard_ok_json" == "null" \
       || "$resilience_profile_matrix_stable_json" != "$phase1_resilience_handoff_profile_matrix_stable_json" \
       || "$resilience_peer_loss_recovery_ok_json" != "$phase1_resilience_handoff_peer_loss_recovery_ok_json" \
       || "$resilience_session_churn_guard_ok_json" != "$phase1_resilience_handoff_session_churn_guard_ok_json" ]]; then
      if [[ "$vpn_rc_resilience_summary_from_phase1_linked_json" == "true" \
         || "$override_due_to_stale_resilience_source" == "true" ]]; then
      resilience_handoff_available_json="true"
      resilience_handoff_source_summary_json="$phase1_resilience_handoff_source_summary_json"
      resilience_profile_matrix_stable_json="$phase1_resilience_handoff_profile_matrix_stable_json"
      resilience_peer_loss_recovery_ok_json="$phase1_resilience_handoff_peer_loss_recovery_ok_json"
      resilience_session_churn_guard_ok_json="$phase1_resilience_handoff_session_churn_guard_ok_json"
      fi
    fi
  fi
fi

if [[ -z "$phase2_linux_prod_candidate_summary_json" ]]; then
  phase2_linux_prod_candidate_summary_json="$(find_latest_phase2_linux_prod_candidate_summary_json)"
else
  phase2_linux_prod_candidate_summary_json="$(abs_path "$phase2_linux_prod_candidate_summary_json")"
fi

phase2_linux_prod_candidate_handoff_available_json="false"
phase2_linux_prod_candidate_handoff_input_summary_json=""
phase2_linux_prod_candidate_handoff_source_summary_json=""
phase2_linux_prod_candidate_handoff_source_summary_kind=""
phase2_linux_prod_candidate_handoff_status_json="missing"
phase2_linux_prod_candidate_handoff_rc_json="null"
phase2_linux_prod_candidate_handoff_release_integrity_ok_json="null"
phase2_linux_prod_candidate_handoff_release_policy_ok_json="null"
phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json="null"
phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json="null"
if [[ -n "$phase2_linux_prod_candidate_summary_json" ]]; then
  phase2_linux_prod_candidate_handoff_input_summary_json="$phase2_linux_prod_candidate_summary_json"
  if [[ "$(phase2_linux_prod_candidate_summary_usable_01 "$phase2_linux_prod_candidate_summary_json")" == "1" ]]; then
    phase2_schema_id="$(jq -r '.schema.id // ""' "$phase2_linux_prod_candidate_summary_json" 2>/dev/null || true)"
    if [[ "$phase2_schema_id" == "phase2_linux_prod_candidate_run_summary" ]]; then
      phase2_nested_check_summary_json="$(jq -r '.artifacts.check_summary_json // .steps.phase2_linux_prod_candidate_check.artifacts.summary_json // ""' "$phase2_linux_prod_candidate_summary_json" 2>/dev/null || true)"
      phase2_nested_check_summary_json="$(abs_path "$phase2_nested_check_summary_json")"
      if [[ -n "$phase2_nested_check_summary_json" ]] && [[ "$(phase2_linux_prod_candidate_summary_usable_01 "$phase2_nested_check_summary_json")" == "1" ]]; then
        phase2_linux_prod_candidate_handoff_source_summary_json="$phase2_nested_check_summary_json"
        phase2_linux_prod_candidate_handoff_source_summary_kind="check"
      fi
    else
      phase2_linux_prod_candidate_handoff_source_summary_json="$phase2_linux_prod_candidate_summary_json"
      phase2_linux_prod_candidate_handoff_source_summary_kind="check"
    fi
    if [[ -n "$phase2_linux_prod_candidate_handoff_source_summary_json" ]]; then
      phase2_linux_prod_candidate_handoff_status_json="$(jq -r '.status // "unknown"' "$phase2_linux_prod_candidate_handoff_source_summary_json" 2>/dev/null || echo "unknown")"
      phase2_linux_prod_candidate_handoff_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase2_linux_prod_candidate_handoff_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase2_linux_prod_candidate_handoff_rc_json" ]]; then
        phase2_linux_prod_candidate_handoff_rc_json="null"
      fi
      phase2_linux_prod_candidate_handoff_available_json="true"
      phase2_linux_prod_candidate_handoff_release_integrity_ok_json="$(resolve_phase2_bool_with_fallback \
        "$phase2_linux_prod_candidate_handoff_source_summary_json" \
        'if (.release_integrity_ok | type) == "boolean" then .release_integrity_ok
          elif (.summary.release_integrity_ok | type) == "boolean" then .summary.release_integrity_ok
          elif (.handoff.release_integrity_ok | type) == "boolean" then .handoff.release_integrity_ok
          elif (.signals.release_integrity_ok | type) == "boolean" then .signals.release_integrity_ok
          elif (.phase2_linux_prod_candidate_handoff.release_integrity_ok | type) == "boolean" then .phase2_linux_prod_candidate_handoff.release_integrity_ok
          elif (.vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok | type) == "boolean" then .vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok
          else empty end' \
        '((.signals.release_integrity_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.release_integrity.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.release_integrity.ok
                else ((.stages.release_integrity.status // .steps.release_integrity.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase2_linux_prod_candidate_handoff_release_policy_ok_json="$(resolve_phase2_bool_with_fallback \
        "$phase2_linux_prod_candidate_handoff_source_summary_json" \
        'if (.release_policy_ok | type) == "boolean" then .release_policy_ok
          elif (.summary.release_policy_ok | type) == "boolean" then .summary.release_policy_ok
          elif (.handoff.release_policy_ok | type) == "boolean" then .handoff.release_policy_ok
          elif (.signals.release_policy_ok | type) == "boolean" then .signals.release_policy_ok
          elif (.phase2_linux_prod_candidate_handoff.release_policy_ok | type) == "boolean" then .phase2_linux_prod_candidate_handoff.release_policy_ok
          elif (.vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok | type) == "boolean" then .vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok
          else empty end' \
        '((.signals.release_policy_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.release_policy.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.release_policy.ok
                else ((.stages.release_policy.status // .steps.release_policy.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json="$(resolve_phase2_bool_with_fallback \
        "$phase2_linux_prod_candidate_handoff_source_summary_json" \
        'if (.operator_lifecycle_ok | type) == "boolean" then .operator_lifecycle_ok
          elif (.summary.operator_lifecycle_ok | type) == "boolean" then .summary.operator_lifecycle_ok
          elif (.handoff.operator_lifecycle_ok | type) == "boolean" then .handoff.operator_lifecycle_ok
          elif (.signals.operator_lifecycle_ok | type) == "boolean" then .signals.operator_lifecycle_ok
          elif (.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok | type) == "boolean" then .phase2_linux_prod_candidate_handoff.operator_lifecycle_ok
          elif (.vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok | type) == "boolean" then .vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok
          else empty end' \
        '((.signals.operator_lifecycle_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.operator_lifecycle.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.operator_lifecycle.ok
                else ((.stages.operator_lifecycle.status // .steps.operator_lifecycle.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json="$(resolve_phase2_bool_with_fallback \
        "$phase2_linux_prod_candidate_handoff_source_summary_json" \
        'if (.pilot_signoff_ok | type) == "boolean" then .pilot_signoff_ok
          elif (.summary.pilot_signoff_ok | type) == "boolean" then .summary.pilot_signoff_ok
          elif (.handoff.pilot_signoff_ok | type) == "boolean" then .handoff.pilot_signoff_ok
          elif (.signals.pilot_signoff_ok | type) == "boolean" then .signals.pilot_signoff_ok
          elif (.phase2_linux_prod_candidate_handoff.pilot_signoff_ok | type) == "boolean" then .phase2_linux_prod_candidate_handoff.pilot_signoff_ok
          elif (.vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok | type) == "boolean" then .vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok
          else empty end' \
        '((.signals.pilot_signoff_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.pilot_signoff.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.pilot_signoff.ok
                else ((.stages.pilot_signoff.status // .steps.pilot_signoff.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
    fi
  else
    phase2_linux_prod_candidate_handoff_status_json="invalid"
  fi
fi

if [[ -z "$phase3_windows_client_beta_summary_json" ]]; then
  phase3_windows_client_beta_summary_json="$(find_latest_phase3_windows_client_beta_summary_json)"
else
  phase3_windows_client_beta_summary_json="$(abs_path "$phase3_windows_client_beta_summary_json")"
fi

phase3_windows_client_beta_handoff_available_json="false"
phase3_windows_client_beta_handoff_input_summary_json=""
phase3_windows_client_beta_handoff_source_summary_json=""
phase3_windows_client_beta_handoff_source_summary_kind=""
phase3_windows_client_beta_handoff_status_json="missing"
phase3_windows_client_beta_handoff_rc_json="null"
phase3_windows_client_beta_handoff_windows_parity_ok_json="null"
phase3_windows_client_beta_handoff_desktop_contract_ok_json="null"
phase3_windows_client_beta_handoff_installer_update_ok_json="null"
phase3_windows_client_beta_handoff_telemetry_stability_ok_json="null"
if [[ -n "$phase3_windows_client_beta_summary_json" ]]; then
  phase3_windows_client_beta_handoff_input_summary_json="$phase3_windows_client_beta_summary_json"
  if [[ "$(phase3_windows_client_beta_summary_usable_01 "$phase3_windows_client_beta_summary_json")" == "1" ]]; then
    phase3_schema_id="$(jq -r '.schema.id // ""' "$phase3_windows_client_beta_summary_json" 2>/dev/null || true)"
    phase3_default_source_kind="check"
    case "$phase3_schema_id" in
      *handoff*)
        phase3_default_source_kind="handoff"
        ;;
      *run*)
        phase3_default_source_kind="run"
        ;;
      *check*)
        phase3_default_source_kind="check"
        ;;
    esac
    if [[ "$phase3_schema_id" == "phase3_windows_client_beta_run_summary" || "$phase3_schema_id" == "phase3_windows_client_beta_handoff_run_summary" ]]; then
      phase3_nested_source_summary_json="$(jq -r '.artifacts.handoff_summary_json // .artifacts.handoff_check_summary_json // .artifacts.check_summary_json // .steps.phase3_windows_client_beta_handoff_check.artifacts.summary_json // .steps.phase3_windows_client_beta_check.artifacts.summary_json // ""' "$phase3_windows_client_beta_summary_json" 2>/dev/null || true)"
      phase3_nested_source_summary_json="$(abs_path "$phase3_nested_source_summary_json")"
      if [[ -n "$phase3_nested_source_summary_json" ]] && [[ "$(phase3_windows_client_beta_summary_usable_01 "$phase3_nested_source_summary_json")" == "1" ]]; then
        phase3_windows_client_beta_handoff_source_summary_json="$phase3_nested_source_summary_json"
      fi
    fi
    if [[ -z "$phase3_windows_client_beta_handoff_source_summary_json" ]]; then
      phase3_windows_client_beta_handoff_source_summary_json="$phase3_windows_client_beta_summary_json"
    fi
    if [[ -n "$phase3_windows_client_beta_handoff_source_summary_json" ]]; then
      phase3_source_schema_id="$(jq -r '.schema.id // ""' "$phase3_windows_client_beta_handoff_source_summary_json" 2>/dev/null || true)"
      phase3_windows_client_beta_handoff_source_summary_kind="$phase3_default_source_kind"
      case "$phase3_source_schema_id" in
        *handoff*)
          phase3_windows_client_beta_handoff_source_summary_kind="handoff"
          ;;
        *run*)
          phase3_windows_client_beta_handoff_source_summary_kind="run"
          ;;
        *check*)
          phase3_windows_client_beta_handoff_source_summary_kind="check"
          ;;
      esac
      phase3_windows_client_beta_handoff_status_json="$(jq -r '.status // "unknown"' "$phase3_windows_client_beta_handoff_source_summary_json" 2>/dev/null || echo "unknown")"
      phase3_windows_client_beta_handoff_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase3_windows_client_beta_handoff_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase3_windows_client_beta_handoff_rc_json" ]]; then
        phase3_windows_client_beta_handoff_rc_json="null"
      fi
      phase3_windows_client_beta_handoff_available_json="true"
      phase3_windows_client_beta_handoff_windows_parity_ok_json="$(resolve_phase3_bool_with_fallback \
        "$phase3_windows_client_beta_handoff_source_summary_json" \
        'if (.windows_parity_ok | type) == "boolean" then .windows_parity_ok
          elif (.summary.windows_parity_ok | type) == "boolean" then .summary.windows_parity_ok
          elif (.handoff.windows_parity_ok | type) == "boolean" then .handoff.windows_parity_ok
          elif ((.handoff.desktop_scaffold_ok | type) == "boolean"
            and (.handoff.local_control_api_ok | type) == "boolean"
            and (.handoff.launcher_wiring_ok | type) == "boolean"
            and (.handoff.launcher_runtime_ok | type) == "boolean") then
            (.handoff.desktop_scaffold_ok
              and .handoff.local_control_api_ok
              and .handoff.launcher_wiring_ok
              and .handoff.launcher_runtime_ok)
          elif (.signals.windows_parity_ok | type) == "boolean" then .signals.windows_parity_ok
          elif (.phase3_windows_client_beta_handoff.windows_parity_ok | type) == "boolean" then .phase3_windows_client_beta_handoff.windows_parity_ok
          elif (.vpn_track.phase3_windows_client_beta_handoff.windows_parity_ok | type) == "boolean" then .vpn_track.phase3_windows_client_beta_handoff.windows_parity_ok
          else empty end' \
        '((.signals.windows_parity_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.windows_parity.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.windows_parity.ok
                else ((.stages.windows_parity.status // .stages.windows_client_parity.status // .steps.windows_parity.status // .steps.windows_client_parity.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase3_windows_client_beta_handoff_desktop_contract_ok_json="$(resolve_phase3_bool_with_fallback \
        "$phase3_windows_client_beta_handoff_source_summary_json" \
        'if (.desktop_contract_ok | type) == "boolean" then .desktop_contract_ok
          elif (.summary.desktop_contract_ok | type) == "boolean" then .summary.desktop_contract_ok
          elif (.handoff.desktop_contract_ok | type) == "boolean" then .handoff.desktop_contract_ok
          elif ((.handoff.desktop_scaffold_ok | type) == "boolean"
            and (.handoff.local_control_api_ok | type) == "boolean") then
            (.handoff.desktop_scaffold_ok and .handoff.local_control_api_ok)
          elif (.signals.desktop_contract_ok | type) == "boolean" then .signals.desktop_contract_ok
          elif (.phase3_windows_client_beta_handoff.desktop_contract_ok | type) == "boolean" then .phase3_windows_client_beta_handoff.desktop_contract_ok
          elif (.vpn_track.phase3_windows_client_beta_handoff.desktop_contract_ok | type) == "boolean" then .vpn_track.phase3_windows_client_beta_handoff.desktop_contract_ok
          else empty end' \
        '((.signals.desktop_contract_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.desktop_contract.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.desktop_contract.ok
                else ((.stages.desktop_contract.status // .stages.desktop_api_contract.status // .steps.desktop_contract.status // .steps.desktop_api_contract.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase3_windows_client_beta_handoff_installer_update_ok_json="$(resolve_phase3_bool_with_fallback \
        "$phase3_windows_client_beta_handoff_source_summary_json" \
        'if (.installer_update_ok | type) == "boolean" then .installer_update_ok
          elif (.summary.installer_update_ok | type) == "boolean" then .summary.installer_update_ok
          elif (.handoff.installer_update_ok | type) == "boolean" then .handoff.installer_update_ok
          elif ((.handoff.easy_node_config_v1_ok | type) == "boolean"
            and (.handoff.launcher_wiring_ok | type) == "boolean") then
            (.handoff.easy_node_config_v1_ok and .handoff.launcher_wiring_ok)
          elif (.signals.installer_update_ok | type) == "boolean" then .signals.installer_update_ok
          elif (.phase3_windows_client_beta_handoff.installer_update_ok | type) == "boolean" then .phase3_windows_client_beta_handoff.installer_update_ok
          elif (.vpn_track.phase3_windows_client_beta_handoff.installer_update_ok | type) == "boolean" then .vpn_track.phase3_windows_client_beta_handoff.installer_update_ok
          else empty end' \
        '((.signals.installer_update_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.installer_update.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.installer_update.ok
                else ((.stages.installer_update.status // .stages.installer_and_update.status // .steps.installer_update.status // .steps.installer_and_update.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase3_windows_client_beta_handoff_telemetry_stability_ok_json="$(resolve_phase3_bool_with_fallback \
        "$phase3_windows_client_beta_handoff_source_summary_json" \
        'if (.telemetry_stability_ok | type) == "boolean" then .telemetry_stability_ok
          elif (.summary.telemetry_stability_ok | type) == "boolean" then .summary.telemetry_stability_ok
          elif (.handoff.telemetry_stability_ok | type) == "boolean" then .handoff.telemetry_stability_ok
          elif ((.handoff.local_api_config_defaults_ok | type) == "boolean"
            and (.handoff.launcher_runtime_ok | type) == "boolean") then
            (.handoff.local_api_config_defaults_ok and .handoff.launcher_runtime_ok)
          elif (.signals.telemetry_stability_ok | type) == "boolean" then .signals.telemetry_stability_ok
          elif (.phase3_windows_client_beta_handoff.telemetry_stability_ok | type) == "boolean" then .phase3_windows_client_beta_handoff.telemetry_stability_ok
          elif (.vpn_track.phase3_windows_client_beta_handoff.telemetry_stability_ok | type) == "boolean" then .vpn_track.phase3_windows_client_beta_handoff.telemetry_stability_ok
          else empty end' \
        '((.signals.telemetry_stability_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.telemetry_stability.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.telemetry_stability.ok
                else ((.stages.telemetry_stability.status // .stages.beta_telemetry.status // .steps.telemetry_stability.status // .steps.beta_telemetry.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
    fi
  else
    phase3_windows_client_beta_handoff_status_json="invalid"
  fi
fi

if [[ -z "$phase4_windows_full_parity_summary_json" ]]; then
  phase4_windows_full_parity_summary_json="$(find_latest_phase4_windows_full_parity_summary_json)"
else
  phase4_windows_full_parity_summary_json="$(abs_path "$phase4_windows_full_parity_summary_json")"
fi

phase4_windows_full_parity_handoff_available_json="false"
phase4_windows_full_parity_handoff_input_summary_json=""
phase4_windows_full_parity_handoff_source_summary_json=""
phase4_windows_full_parity_handoff_source_summary_kind=""
phase4_windows_full_parity_handoff_status_json="missing"
phase4_windows_full_parity_handoff_rc_json="null"
phase4_windows_full_parity_handoff_windows_server_packaging_ok_json="null"
phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json="null"
phase4_windows_full_parity_handoff_cross_platform_interop_ok_json="null"
phase4_windows_full_parity_handoff_role_combination_validation_ok_json="null"
if [[ -n "$phase4_windows_full_parity_summary_json" ]]; then
  phase4_windows_full_parity_handoff_input_summary_json="$phase4_windows_full_parity_summary_json"
  if [[ "$(phase4_windows_full_parity_summary_usable_01 "$phase4_windows_full_parity_summary_json")" == "1" ]]; then
    phase4_schema_id="$(jq -r '.schema.id // ""' "$phase4_windows_full_parity_summary_json" 2>/dev/null || true)"
    phase4_default_source_kind="check"
    case "$phase4_schema_id" in
      *handoff*)
        phase4_default_source_kind="handoff"
        ;;
      *run*)
        phase4_default_source_kind="run"
        ;;
      *check*)
        phase4_default_source_kind="check"
        ;;
    esac
    if [[ "$phase4_schema_id" == "phase4_windows_full_parity_run_summary" || "$phase4_schema_id" == "phase4_windows_full_parity_handoff_run_summary" ]]; then
      phase4_nested_source_summary_json="$(jq -r '.artifacts.handoff_summary_json // .artifacts.handoff_check_summary_json // .artifacts.check_summary_json // .steps.phase4_windows_full_parity_handoff_check.artifacts.summary_json // .steps.phase4_windows_full_parity_check.artifacts.summary_json // ""' "$phase4_windows_full_parity_summary_json" 2>/dev/null || true)"
      phase4_nested_source_summary_json="$(abs_path "$phase4_nested_source_summary_json")"
      if [[ -n "$phase4_nested_source_summary_json" ]] && [[ "$(phase4_windows_full_parity_summary_usable_01 "$phase4_nested_source_summary_json")" == "1" ]]; then
        phase4_windows_full_parity_handoff_source_summary_json="$phase4_nested_source_summary_json"
      fi
    fi
    if [[ -z "$phase4_windows_full_parity_handoff_source_summary_json" ]]; then
      phase4_windows_full_parity_handoff_source_summary_json="$phase4_windows_full_parity_summary_json"
    fi
    if [[ -n "$phase4_windows_full_parity_handoff_source_summary_json" ]]; then
      phase4_source_schema_id="$(jq -r '.schema.id // ""' "$phase4_windows_full_parity_handoff_source_summary_json" 2>/dev/null || true)"
      phase4_windows_full_parity_handoff_source_summary_kind="$phase4_default_source_kind"
      case "$phase4_source_schema_id" in
        *handoff*)
          phase4_windows_full_parity_handoff_source_summary_kind="handoff"
          ;;
        *run*)
          phase4_windows_full_parity_handoff_source_summary_kind="run"
          ;;
        *check*)
          phase4_windows_full_parity_handoff_source_summary_kind="check"
          ;;
      esac
      phase4_windows_full_parity_handoff_status_json="$(jq -r '.status // "unknown"' "$phase4_windows_full_parity_handoff_source_summary_json" 2>/dev/null || echo "unknown")"
      phase4_windows_full_parity_handoff_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase4_windows_full_parity_handoff_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase4_windows_full_parity_handoff_rc_json" ]]; then
        phase4_windows_full_parity_handoff_rc_json="null"
      fi
      phase4_windows_full_parity_handoff_available_json="true"
      phase4_windows_full_parity_handoff_windows_server_packaging_ok_json="$(resolve_phase4_bool_with_fallback \
        "$phase4_windows_full_parity_handoff_source_summary_json" \
        'if (.windows_server_packaging_ok | type) == "boolean" then .windows_server_packaging_ok
          elif (.summary.windows_server_packaging_ok | type) == "boolean" then .summary.windows_server_packaging_ok
          elif (.handoff.windows_server_packaging_ok | type) == "boolean" then .handoff.windows_server_packaging_ok
          elif (.signals.windows_server_packaging_ok | type) == "boolean" then .signals.windows_server_packaging_ok
          elif (.phase4_windows_full_parity_handoff.windows_server_packaging_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_server_packaging_ok
          elif (.vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok
          else empty end' \
        '((.signals.windows_server_packaging_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.windows_server_packaging.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.windows_server_packaging.ok
                else ((.stages.windows_server_packaging.status // .stages.windows_provider_packaging.status // .stages.windows_server_roles_packaging.status // .steps.windows_server_packaging.status // .steps.windows_provider_packaging.status // .steps.windows_server_roles_packaging.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json="$(resolve_phase4_bool_with_fallback \
        "$phase4_windows_full_parity_handoff_source_summary_json" \
        'if (.windows_role_runbooks_ok | type) == "boolean" then .windows_role_runbooks_ok
          elif (.summary.windows_role_runbooks_ok | type) == "boolean" then .summary.windows_role_runbooks_ok
          elif (.handoff.windows_role_runbooks_ok | type) == "boolean" then .handoff.windows_role_runbooks_ok
          elif (.signals.windows_role_runbooks_ok | type) == "boolean" then .signals.windows_role_runbooks_ok
          elif (.phase4_windows_full_parity_handoff.windows_role_runbooks_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_role_runbooks_ok
          elif (.vpn_track.phase4_windows_full_parity_handoff.windows_role_runbooks_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_role_runbooks_ok
          else empty end' \
        '((.signals.windows_role_runbooks_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.windows_role_runbooks.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.windows_role_runbooks.ok
                else ((.stages.windows_role_runbooks.status // .stages.role_runbooks.status // .steps.windows_role_runbooks.status // .steps.role_runbooks.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase4_windows_full_parity_handoff_cross_platform_interop_ok_json="$(resolve_phase4_bool_with_fallback \
        "$phase4_windows_full_parity_handoff_source_summary_json" \
        'if (.cross_platform_interop_ok | type) == "boolean" then .cross_platform_interop_ok
          elif (.summary.cross_platform_interop_ok | type) == "boolean" then .summary.cross_platform_interop_ok
          elif (.handoff.cross_platform_interop_ok | type) == "boolean" then .handoff.cross_platform_interop_ok
          elif (.signals.cross_platform_interop_ok | type) == "boolean" then .signals.cross_platform_interop_ok
          elif (.phase4_windows_full_parity_handoff.cross_platform_interop_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.cross_platform_interop_ok
          elif (.vpn_track.phase4_windows_full_parity_handoff.cross_platform_interop_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.cross_platform_interop_ok
          else empty end' \
        '((.signals.cross_platform_interop_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.cross_platform_interop.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.cross_platform_interop.ok
                else ((.stages.cross_platform_interop.status // .stages.cross_platform_interoperability.status // .steps.cross_platform_interop.status // .steps.cross_platform_interoperability.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase4_windows_full_parity_handoff_role_combination_validation_ok_json="$(resolve_phase4_bool_with_fallback \
        "$phase4_windows_full_parity_handoff_source_summary_json" \
        'if (.role_combination_validation_ok | type) == "boolean" then .role_combination_validation_ok
          elif (.summary.role_combination_validation_ok | type) == "boolean" then .summary.role_combination_validation_ok
          elif (.handoff.role_combination_validation_ok | type) == "boolean" then .handoff.role_combination_validation_ok
          elif (.signals.role_combination_validation_ok | type) == "boolean" then .signals.role_combination_validation_ok
          elif (.phase4_windows_full_parity_handoff.role_combination_validation_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.role_combination_validation_ok
          elif (.vpn_track.phase4_windows_full_parity_handoff.role_combination_validation_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.role_combination_validation_ok
          else empty end' \
        '((.signals.role_combination_validation_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.role_combination_validation.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.role_combination_validation.ok
                else ((.stages.role_combination_validation.status // .stages.role_combination_matrix.status // .steps.role_combination_validation.status // .steps.role_combination_matrix.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
    fi
  else
    phase4_windows_full_parity_handoff_status_json="invalid"
  fi
fi

if [[ -z "$phase5_settlement_layer_summary_json" ]]; then
  phase5_settlement_layer_summary_json="$(find_latest_phase5_settlement_layer_summary_json)"
else
  phase5_settlement_layer_summary_json="$(abs_path "$phase5_settlement_layer_summary_json")"
fi

phase5_settlement_layer_handoff_available_json="false"
phase5_settlement_layer_handoff_input_summary_json=""
phase5_settlement_layer_handoff_source_summary_json=""
phase5_settlement_layer_handoff_source_summary_kind=""
phase5_settlement_layer_handoff_status_json="missing"
phase5_settlement_layer_handoff_rc_json="null"
phase5_settlement_layer_handoff_settlement_failsoft_ok_json="null"
phase5_settlement_layer_handoff_settlement_acceptance_ok_json="null"
phase5_settlement_layer_handoff_settlement_bridge_smoke_ok_json="null"
phase5_settlement_layer_handoff_settlement_state_persistence_ok_json="null"
phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json=""
phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="null"
phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json=""
phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json="null"
if [[ -n "$phase5_settlement_layer_summary_json" ]]; then
  phase5_settlement_layer_handoff_input_summary_json="$phase5_settlement_layer_summary_json"
  if [[ "$(phase5_settlement_layer_summary_usable_01 "$phase5_settlement_layer_summary_json")" == "1" ]]; then
    phase5_schema_id="$(jq -r '.schema.id // ""' "$phase5_settlement_layer_summary_json" 2>/dev/null || true)"
    phase5_default_source_kind="check"
    case "$phase5_schema_id" in
      *handoff*)
        phase5_default_source_kind="handoff"
        ;;
      *run*)
        phase5_default_source_kind="run"
        ;;
      *check*)
        phase5_default_source_kind="check"
        ;;
    esac
    if [[ "$phase5_schema_id" == "phase5_settlement_layer_run_summary" || "$phase5_schema_id" == "phase5_settlement_layer_handoff_run_summary" ]]; then
      phase5_nested_source_summary_json="$(jq -r '.artifacts.handoff_summary_json // .artifacts.handoff_check_summary_json // .artifacts.check_summary_json // .steps.phase5_settlement_layer_handoff_check.artifacts.summary_json // .steps.phase5_settlement_layer_check.artifacts.summary_json // ""' "$phase5_settlement_layer_summary_json" 2>/dev/null || true)"
      phase5_nested_source_summary_json="$(abs_path "$phase5_nested_source_summary_json")"
      if [[ -n "$phase5_nested_source_summary_json" ]] && [[ "$(phase5_settlement_layer_summary_usable_01 "$phase5_nested_source_summary_json")" == "1" ]]; then
        phase5_settlement_layer_handoff_source_summary_json="$phase5_nested_source_summary_json"
      fi
    fi
    if [[ -z "$phase5_settlement_layer_handoff_source_summary_json" ]]; then
      phase5_settlement_layer_handoff_source_summary_json="$phase5_settlement_layer_summary_json"
    fi
    if [[ -n "$phase5_settlement_layer_handoff_source_summary_json" ]]; then
      phase5_source_schema_id="$(jq -r '.schema.id // ""' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_source_summary_kind="$phase5_default_source_kind"
      case "$phase5_source_schema_id" in
        *handoff*)
          phase5_settlement_layer_handoff_source_summary_kind="handoff"
          ;;
        *run*)
          phase5_settlement_layer_handoff_source_summary_kind="run"
          ;;
        *check*)
          phase5_settlement_layer_handoff_source_summary_kind="check"
          ;;
      esac
      phase5_settlement_layer_handoff_status_json="$(jq -r '.status // "unknown"' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || echo "unknown")"
      phase5_settlement_layer_handoff_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase5_settlement_layer_handoff_rc_json" ]]; then
        phase5_settlement_layer_handoff_rc_json="null"
      fi
      phase5_settlement_layer_handoff_available_json="true"
      phase5_settlement_layer_handoff_settlement_failsoft_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_failsoft_ok | type) == "boolean" then .settlement_failsoft_ok
          elif (.summary.settlement_failsoft_ok | type) == "boolean" then .summary.settlement_failsoft_ok
          elif (.handoff.settlement_failsoft_ok | type) == "boolean" then .handoff.settlement_failsoft_ok
          elif (.signals.settlement_failsoft_ok | type) == "boolean" then .signals.settlement_failsoft_ok
          elif (.phase5_settlement_layer_handoff.settlement_failsoft_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_failsoft_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok
          else empty end' \
        '((.signals.settlement_failsoft_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.settlement_failsoft.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.settlement_failsoft.ok
                else ((.stages.settlement_failsoft.status // .stages.failsoft.status // .steps.settlement_failsoft.status // .steps.failsoft.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase5_settlement_layer_handoff_settlement_acceptance_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_acceptance_ok | type) == "boolean" then .settlement_acceptance_ok
          elif (.summary.settlement_acceptance_ok | type) == "boolean" then .summary.settlement_acceptance_ok
          elif (.handoff.settlement_acceptance_ok | type) == "boolean" then .handoff.settlement_acceptance_ok
          elif (.signals.settlement_acceptance_ok | type) == "boolean" then .signals.settlement_acceptance_ok
          elif (.phase5_settlement_layer_handoff.settlement_acceptance_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_acceptance_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok
          else empty end' \
        '((.signals.settlement_acceptance_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.settlement_acceptance.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.settlement_acceptance.ok
                else ((.stages.settlement_acceptance.status // .stages.acceptance_gate.status // .steps.settlement_acceptance.status // .steps.acceptance_gate.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase5_settlement_layer_handoff_settlement_bridge_smoke_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_bridge_smoke_ok | type) == "boolean" then .settlement_bridge_smoke_ok
          elif (.summary.settlement_bridge_smoke_ok | type) == "boolean" then .summary.settlement_bridge_smoke_ok
          elif (.handoff.settlement_bridge_smoke_ok | type) == "boolean" then .handoff.settlement_bridge_smoke_ok
          elif (.signals.settlement_bridge_smoke_ok | type) == "boolean" then .signals.settlement_bridge_smoke_ok
          elif (.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_bridge_smoke_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok
          else empty end' \
        '((.signals.settlement_bridge_smoke_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.settlement_bridge_smoke.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.settlement_bridge_smoke.ok
                else ((.stages.settlement_bridge_smoke.status // .stages.bridge_smoke.status // .steps.settlement_bridge_smoke.status // .steps.bridge_smoke.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase5_settlement_layer_handoff_settlement_state_persistence_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_state_persistence_ok | type) == "boolean" then .settlement_state_persistence_ok
          elif (.summary.settlement_state_persistence_ok | type) == "boolean" then .summary.settlement_state_persistence_ok
          elif (.handoff.settlement_state_persistence_ok | type) == "boolean" then .handoff.settlement_state_persistence_ok
          elif (.signals.settlement_state_persistence_ok | type) == "boolean" then .signals.settlement_state_persistence_ok
          elif (.phase5_settlement_layer_handoff.settlement_state_persistence_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_state_persistence_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok
          else empty end' \
        '((.signals.settlement_state_persistence_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.settlement_state_persistence.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.settlement_state_persistence.ok
                else ((.stages.settlement_state_persistence.status // .stages.state_persistence.status // .steps.settlement_state_persistence.status // .steps.state_persistence.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json="$(jq -r '
        if (.settlement_adapter_roundtrip_status | type) == "string" then .settlement_adapter_roundtrip_status
        elif (.summary.settlement_adapter_roundtrip_status | type) == "string" then .summary.settlement_adapter_roundtrip_status
        elif (.handoff.settlement_adapter_roundtrip_status | type) == "string" then .handoff.settlement_adapter_roundtrip_status
        elif (.signals.settlement_adapter_roundtrip_status | type) == "string" then .signals.settlement_adapter_roundtrip_status
        elif (.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status
        elif (.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status
        elif (.steps.settlement_adapter_roundtrip.status | type) == "string" then .steps.settlement_adapter_roundtrip.status
        elif (.steps.adapter_roundtrip.status | type) == "string" then .steps.adapter_roundtrip.status
        elif (.stages.settlement_adapter_roundtrip.status | type) == "string" then .stages.settlement_adapter_roundtrip.status
        elif (.stages.adapter_roundtrip.status | type) == "string" then .stages.adapter_roundtrip.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_adapter_roundtrip_ok | type) == "boolean" then .settlement_adapter_roundtrip_ok
          elif (.summary.settlement_adapter_roundtrip_ok | type) == "boolean" then .summary.settlement_adapter_roundtrip_ok
          elif (.handoff.settlement_adapter_roundtrip_ok | type) == "boolean" then .handoff.settlement_adapter_roundtrip_ok
          elif (.signals.settlement_adapter_roundtrip_ok | type) == "boolean" then .signals.settlement_adapter_roundtrip_ok
          elif (.signals.settlement_adapter_roundtrip | type) == "boolean" then .signals.settlement_adapter_roundtrip
          elif (.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok
          else empty end' \
        'if (.stages.settlement_adapter_roundtrip.ok | type) == "boolean" then .stages.settlement_adapter_roundtrip.ok
          elif (.stages.adapter_roundtrip.ok | type) == "boolean" then .stages.adapter_roundtrip.ok
          else
            ((.steps.settlement_adapter_roundtrip.status // .steps.adapter_roundtrip.status // .stages.settlement_adapter_roundtrip.status // .stages.adapter_roundtrip.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json="$(jq -r '
        if (.issuer_sponsor_api_live_smoke_status | type) == "string" then .issuer_sponsor_api_live_smoke_status
        elif (.summary.issuer_sponsor_api_live_smoke_status | type) == "string" then .summary.issuer_sponsor_api_live_smoke_status
        elif (.handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .handoff.issuer_sponsor_api_live_smoke_status
        elif (.signals.issuer_sponsor_api_live_smoke_status | type) == "string" then .signals.issuer_sponsor_api_live_smoke_status
        elif (.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status
        elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status
        elif (.steps.issuer_sponsor_api_live_smoke.status | type) == "string" then .steps.issuer_sponsor_api_live_smoke.status
        elif (.stages.issuer_sponsor_api_live_smoke.status | type) == "string" then .stages.issuer_sponsor_api_live_smoke.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .issuer_sponsor_api_live_smoke_ok
          elif (.summary.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .summary.issuer_sponsor_api_live_smoke_ok
          elif (.handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .handoff.issuer_sponsor_api_live_smoke_ok
          elif (.signals.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .signals.issuer_sponsor_api_live_smoke_ok
          elif (.signals.issuer_sponsor_api_live_smoke | type) == "boolean" then .signals.issuer_sponsor_api_live_smoke
          elif (.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok
          else empty end' \
        'if (.stages.issuer_sponsor_api_live_smoke.ok | type) == "boolean" then .stages.issuer_sponsor_api_live_smoke.ok
          else
            ((if (.issuer_sponsor_api_live_smoke_status | type) == "string" then .issuer_sponsor_api_live_smoke_status
              elif (.summary.issuer_sponsor_api_live_smoke_status | type) == "string" then .summary.issuer_sponsor_api_live_smoke_status
              elif (.handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .handoff.issuer_sponsor_api_live_smoke_status
              elif (.signals.issuer_sponsor_api_live_smoke_status | type) == "string" then .signals.issuer_sponsor_api_live_smoke_status
              elif (.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status
              elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status
              elif (.steps.issuer_sponsor_api_live_smoke.status | type) == "string" then .steps.issuer_sponsor_api_live_smoke.status
              elif (.stages.issuer_sponsor_api_live_smoke.status | type) == "string" then .stages.issuer_sponsor_api_live_smoke.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json="false"
            ;;
        esac
      fi
    fi
  else
    phase5_settlement_layer_handoff_status_json="invalid"
  fi
fi

if [[ -z "$phase6_cosmos_l1_summary_json" ]]; then
  phase6_cosmos_l1_summary_json="$(find_latest_phase6_cosmos_l1_summary_json)"
else
  phase6_cosmos_l1_summary_json="$(abs_path "$phase6_cosmos_l1_summary_json")"
fi

phase6_cosmos_l1_handoff_available_json="false"
phase6_cosmos_l1_handoff_input_summary_json=""
phase6_cosmos_l1_handoff_source_summary_json=""
phase6_cosmos_l1_handoff_source_summary_kind=""
phase6_cosmos_l1_handoff_status_json="missing"
phase6_cosmos_l1_handoff_rc_json="null"
phase6_cosmos_l1_handoff_run_pipeline_ok_json="null"
phase6_cosmos_l1_handoff_module_tx_surface_ok_json="null"
phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok_json="null"
phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok_json="null"
phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok_json="null"
if [[ -n "$phase6_cosmos_l1_summary_json" ]]; then
  phase6_cosmos_l1_handoff_input_summary_json="$phase6_cosmos_l1_summary_json"
  if [[ "$(phase6_cosmos_l1_summary_usable_01 "$phase6_cosmos_l1_summary_json")" == "1" ]]; then
    phase6_source_summary_json="$(phase6_cosmos_l1_pick_best_source_summary_json "$phase6_cosmos_l1_summary_json")"
    if [[ -z "$phase6_source_summary_json" ]]; then
      phase6_source_summary_json="$phase6_cosmos_l1_summary_json"
    fi
    phase6_source_summary_json="$(abs_path "$phase6_source_summary_json")"
    if [[ -n "$phase6_source_summary_json" ]] && [[ "$(phase6_cosmos_l1_summary_usable_01 "$phase6_source_summary_json")" == "1" ]]; then
      phase6_cosmos_l1_handoff_source_summary_json="$phase6_source_summary_json"
      phase6_cosmos_l1_handoff_source_summary_kind="$(phase6_cosmos_l1_summary_kind_from_source "$phase6_source_summary_json")"
      phase6_cosmos_l1_handoff_status_json="$(jq -r '.status // "unknown"' "$phase6_source_summary_json" 2>/dev/null || echo "unknown")"
      phase6_cosmos_l1_handoff_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase6_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase6_cosmos_l1_handoff_rc_json" ]]; then
        phase6_cosmos_l1_handoff_rc_json="null"
      fi
      phase6_cosmos_l1_handoff_available_json="true"
      phase6_cosmos_l1_handoff_run_pipeline_ok_json="$(resolve_phase6_bool_with_source_chain \
        "$phase6_source_summary_json" \
        'if (.run_pipeline_ok | type) == "boolean" then .run_pipeline_ok
          elif (.summary.run_pipeline_ok | type) == "boolean" then .summary.run_pipeline_ok
          elif (.handoff.run_pipeline_ok | type) == "boolean" then .handoff.run_pipeline_ok
          elif (.signals.run_pipeline_ok | type) == "boolean" then .signals.run_pipeline_ok
          elif (.phase6_cosmos_l1_handoff.run_pipeline_ok | type) == "boolean" then .phase6_cosmos_l1_handoff.run_pipeline_ok
          elif (.vpn_track.phase6_cosmos_l1_handoff.run_pipeline_ok | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff.run_pipeline_ok
          elif (.blockchain_track.phase6_cosmos_l1_handoff.run_pipeline_ok | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff.run_pipeline_ok
          else empty end' \
        'if (.decision.pass | type) == "boolean" then .decision.pass
          else
            ((if (.run_pipeline_status | type) == "string" then .run_pipeline_status
              elif (.summary.run_pipeline_status | type) == "string" then .summary.run_pipeline_status
              elif (.handoff.run_pipeline_status | type) == "string" then .handoff.run_pipeline_status
              elif (.signals.run_pipeline_status | type) == "string" then .signals.run_pipeline_status
              elif (.steps.phase6_cosmos_l1_build_testnet_handoff_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_handoff_check.status
              elif (.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_check.status
              elif (.steps.phase6_cosmos_l1_build_testnet_handoff_run.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_handoff_run.status
              elif (.steps.phase6_cosmos_l1_build_testnet_run.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_run.status
              elif (.steps.phase6_cosmos_l1_build_testnet_suite.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_suite.status
              elif (.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string" then .steps.ci_phase6_cosmos_l1_build_testnet.status
              elif (.status | type) == "string" then .status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      phase6_cosmos_l1_handoff_module_tx_surface_ok_json="$(resolve_phase6_bool_with_source_chain \
        "$phase6_source_summary_json" \
        'if (.module_tx_surface_ok | type) == "boolean" then .module_tx_surface_ok
          elif (.summary.module_tx_surface_ok | type) == "boolean" then .summary.module_tx_surface_ok
          elif (.handoff.module_tx_surface_ok | type) == "boolean" then .handoff.module_tx_surface_ok
          elif (.signals.module_tx_surface_ok | type) == "boolean" then .signals.module_tx_surface_ok
          elif (.phase6_cosmos_l1_handoff.module_tx_surface_ok | type) == "boolean" then .phase6_cosmos_l1_handoff.module_tx_surface_ok
          elif (.vpn_track.phase6_cosmos_l1_handoff.module_tx_surface_ok | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff.module_tx_surface_ok
          elif (.blockchain_track.phase6_cosmos_l1_handoff.module_tx_surface_ok | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff.module_tx_surface_ok
          else empty end' \
        'if (.stages.module_tx_surface.ok | type) == "boolean" then .stages.module_tx_surface.ok
          elif (.steps.module_tx_surface.ok | type) == "boolean" then .steps.module_tx_surface.ok
          else
            ((if (.module_tx_surface_status | type) == "string" then .module_tx_surface_status
              elif (.summary.module_tx_surface_status | type) == "string" then .summary.module_tx_surface_status
              elif (.handoff.module_tx_surface_status | type) == "string" then .handoff.module_tx_surface_status
              elif (.signals.module_tx_surface_status | type) == "string" then .signals.module_tx_surface_status
              elif (.stages.module_tx_surface.status | type) == "string" then .stages.module_tx_surface.status
              elif (.steps.module_tx_surface.status | type) == "string" then .steps.module_tx_surface.status
              elif (.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_check.status
              elif (.steps.phase6_cosmos_l1_build_testnet_handoff_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_handoff_check.status
              elif (.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string" then .steps.ci_phase6_cosmos_l1_build_testnet.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok_json="$(resolve_phase6_bool_with_source_chain \
        "$phase6_source_summary_json" \
        'if (.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .tdpnd_grpc_runtime_smoke_ok
          elif (.summary.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .summary.tdpnd_grpc_runtime_smoke_ok
          elif (.handoff.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .handoff.tdpnd_grpc_runtime_smoke_ok
          elif (.signals.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .signals.tdpnd_grpc_runtime_smoke_ok
          elif (.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok
          elif (.vpn_track.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok
          elif (.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok
          else empty end' \
        'if (.stages.tdpnd_grpc_runtime_smoke.ok | type) == "boolean" then .stages.tdpnd_grpc_runtime_smoke.ok
          elif (.stages.tdpnd_runtime_smoke.ok | type) == "boolean" then .stages.tdpnd_runtime_smoke.ok
          elif (.steps.tdpnd_grpc_runtime_smoke.ok | type) == "boolean" then .steps.tdpnd_grpc_runtime_smoke.ok
          elif (.steps.tdpnd_runtime_smoke.ok | type) == "boolean" then .steps.tdpnd_runtime_smoke.ok
          else
            ((if (.tdpnd_grpc_runtime_smoke_status | type) == "string" then .tdpnd_grpc_runtime_smoke_status
              elif (.summary.tdpnd_grpc_runtime_smoke_status | type) == "string" then .summary.tdpnd_grpc_runtime_smoke_status
              elif (.handoff.tdpnd_grpc_runtime_smoke_status | type) == "string" then .handoff.tdpnd_grpc_runtime_smoke_status
              elif (.signals.tdpnd_grpc_runtime_smoke_status | type) == "string" then .signals.tdpnd_grpc_runtime_smoke_status
              elif (.stages.tdpnd_grpc_runtime_smoke.status | type) == "string" then .stages.tdpnd_grpc_runtime_smoke.status
              elif (.stages.tdpnd_runtime_smoke.status | type) == "string" then .stages.tdpnd_runtime_smoke.status
              elif (.steps.tdpnd_grpc_runtime_smoke.status | type) == "string" then .steps.tdpnd_grpc_runtime_smoke.status
              elif (.steps.tdpnd_runtime_smoke.status | type) == "string" then .steps.tdpnd_runtime_smoke.status
              elif (.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_check.status
              elif (.steps.phase6_cosmos_l1_build_testnet_handoff_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_handoff_check.status
              elif (.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string" then .steps.ci_phase6_cosmos_l1_build_testnet.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok_json="$(resolve_phase6_bool_with_source_chain \
        "$phase6_source_summary_json" \
        'if (.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .tdpnd_grpc_live_smoke_ok
          elif (.summary.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .summary.tdpnd_grpc_live_smoke_ok
          elif (.handoff.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .handoff.tdpnd_grpc_live_smoke_ok
          elif (.signals.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .signals.tdpnd_grpc_live_smoke_ok
          elif (.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok
          elif (.vpn_track.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok
          elif (.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok
          else empty end' \
        'if (.stages.tdpnd_grpc_live_smoke.ok | type) == "boolean" then .stages.tdpnd_grpc_live_smoke.ok
          elif (.stages.tdpnd_live_smoke.ok | type) == "boolean" then .stages.tdpnd_live_smoke.ok
          elif (.steps.tdpnd_grpc_live_smoke.ok | type) == "boolean" then .steps.tdpnd_grpc_live_smoke.ok
          elif (.steps.tdpnd_live_smoke.ok | type) == "boolean" then .steps.tdpnd_live_smoke.ok
          else
            ((if (.tdpnd_grpc_live_smoke_status | type) == "string" then .tdpnd_grpc_live_smoke_status
              elif (.summary.tdpnd_grpc_live_smoke_status | type) == "string" then .summary.tdpnd_grpc_live_smoke_status
              elif (.handoff.tdpnd_grpc_live_smoke_status | type) == "string" then .handoff.tdpnd_grpc_live_smoke_status
              elif (.signals.tdpnd_grpc_live_smoke_status | type) == "string" then .signals.tdpnd_grpc_live_smoke_status
              elif (.stages.tdpnd_grpc_live_smoke.status | type) == "string" then .stages.tdpnd_grpc_live_smoke.status
              elif (.stages.tdpnd_live_smoke.status | type) == "string" then .stages.tdpnd_live_smoke.status
              elif (.steps.tdpnd_grpc_live_smoke.status | type) == "string" then .steps.tdpnd_grpc_live_smoke.status
              elif (.steps.tdpnd_live_smoke.status | type) == "string" then .steps.tdpnd_live_smoke.status
              elif (.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_check.status
              elif (.steps.phase6_cosmos_l1_build_testnet_handoff_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_handoff_check.status
              elif (.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string" then .steps.ci_phase6_cosmos_l1_build_testnet.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok_json="$(resolve_phase6_bool_with_source_chain \
        "$phase6_source_summary_json" \
        'if (.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .tdpnd_grpc_auth_live_smoke_ok
          elif (.summary.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .summary.tdpnd_grpc_auth_live_smoke_ok
          elif (.handoff.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .handoff.tdpnd_grpc_auth_live_smoke_ok
          elif (.signals.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .signals.tdpnd_grpc_auth_live_smoke_ok
          elif (.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok
          elif (.vpn_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok
          elif (.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok
          else empty end' \
        'if (.stages.tdpnd_grpc_auth_live_smoke.ok | type) == "boolean" then .stages.tdpnd_grpc_auth_live_smoke.ok
          elif (.stages.tdpnd_auth_live_smoke.ok | type) == "boolean" then .stages.tdpnd_auth_live_smoke.ok
          elif (.steps.tdpnd_grpc_auth_live_smoke.ok | type) == "boolean" then .steps.tdpnd_grpc_auth_live_smoke.ok
          elif (.steps.tdpnd_auth_live_smoke.ok | type) == "boolean" then .steps.tdpnd_auth_live_smoke.ok
          else
            ((if (.tdpnd_grpc_auth_live_smoke_status | type) == "string" then .tdpnd_grpc_auth_live_smoke_status
              elif (.summary.tdpnd_grpc_auth_live_smoke_status | type) == "string" then .summary.tdpnd_grpc_auth_live_smoke_status
              elif (.handoff.tdpnd_grpc_auth_live_smoke_status | type) == "string" then .handoff.tdpnd_grpc_auth_live_smoke_status
              elif (.signals.tdpnd_grpc_auth_live_smoke_status | type) == "string" then .signals.tdpnd_grpc_auth_live_smoke_status
              elif (.stages.tdpnd_grpc_auth_live_smoke.status | type) == "string" then .stages.tdpnd_grpc_auth_live_smoke.status
              elif (.stages.tdpnd_auth_live_smoke.status | type) == "string" then .stages.tdpnd_auth_live_smoke.status
              elif (.steps.tdpnd_grpc_auth_live_smoke.status | type) == "string" then .steps.tdpnd_grpc_auth_live_smoke.status
              elif (.steps.tdpnd_auth_live_smoke.status | type) == "string" then .steps.tdpnd_auth_live_smoke.status
              elif (.steps.phase6_cosmos_l1_build_testnet_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_check.status
              elif (.steps.phase6_cosmos_l1_build_testnet_handoff_check.status | type) == "string" then .steps.phase6_cosmos_l1_build_testnet_handoff_check.status
              elif (.steps.ci_phase6_cosmos_l1_build_testnet.status | type) == "string" then .steps.ci_phase6_cosmos_l1_build_testnet.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
    fi
  else
    phase6_cosmos_l1_handoff_status_json="invalid"
  fi
fi

phase7_mainnet_cutover_summary_available_json="false"
phase7_mainnet_cutover_summary_input_summary_json=""
phase7_mainnet_cutover_summary_source_summary_json=""
phase7_mainnet_cutover_summary_source_summary_kind=""
phase7_mainnet_cutover_summary_status_json="missing"
phase7_mainnet_cutover_summary_rc_json="null"
phase7_mainnet_cutover_summary_check_ok_json="null"
phase7_mainnet_cutover_summary_run_ok_json="null"
phase7_mainnet_cutover_summary_handoff_check_ok_json="null"
phase7_mainnet_cutover_summary_handoff_run_ok_json="null"
if [[ -n "$phase7_mainnet_cutover_summary_json" ]]; then
  phase7_mainnet_cutover_summary_input_summary_json="$phase7_mainnet_cutover_summary_json"
  if [[ "$(phase7_mainnet_cutover_summary_usable_01 "$phase7_mainnet_cutover_summary_json")" == "1" ]]; then
    phase7_mainnet_cutover_summary_source_summary_json="$(abs_path "$phase7_mainnet_cutover_summary_json")"
    if [[ -n "$phase7_mainnet_cutover_summary_source_summary_json" ]] && [[ "$(phase7_mainnet_cutover_summary_usable_01 "$phase7_mainnet_cutover_summary_source_summary_json")" == "1" ]]; then
      phase7_mainnet_cutover_summary_source_summary_kind="$(phase7_mainnet_cutover_summary_kind_from_source "$phase7_mainnet_cutover_summary_source_summary_json")"
      phase7_mainnet_cutover_summary_status_json="$(jq -r '.status // "unknown"' "$phase7_mainnet_cutover_summary_source_summary_json" 2>/dev/null || echo "unknown")"
      phase7_mainnet_cutover_summary_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else empty end' "$phase7_mainnet_cutover_summary_source_summary_json" 2>/dev/null || true)"
      if [[ -z "$phase7_mainnet_cutover_summary_rc_json" ]]; then
        phase7_mainnet_cutover_summary_rc_json="null"
      fi
      phase7_mainnet_cutover_summary_available_json="true"
      phase7_mainnet_cutover_summary_check_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.summaries.check.status | type) == "string" then
            ((.summaries.check.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.signals.check_ok | type) == "boolean" then .signals.check_ok
          elif (.stages.check.ok | type) == "boolean" then .stages.check.ok
          elif (.steps.phase7_mainnet_cutover_check.status | type) == "string" then
            ((.steps.phase7_mainnet_cutover_check.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.steps.phase7_mainnet_cutover_handoff_check.status | type) == "string" then
            ((.steps.phase7_mainnet_cutover_handoff_check.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.status | type) == "string" then
            ((.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          else empty end')"
      phase7_mainnet_cutover_summary_run_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.summaries.run.status | type) == "string" then
            ((.summaries.run.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.signals.run_ok | type) == "boolean" then .signals.run_ok
          elif (.stages.run.ok | type) == "boolean" then .stages.run.ok
          elif (.steps.phase7_mainnet_cutover_run.status | type) == "string" then
            ((.steps.phase7_mainnet_cutover_run.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.status | type) == "string" then
            ((.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          else empty end')"
      phase7_mainnet_cutover_summary_handoff_check_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.summaries.handoff_check.status | type) == "string" then
            ((.summaries.handoff_check.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.signals.handoff_check_ok | type) == "boolean" then .signals.handoff_check_ok
          elif (.stages.handoff_check.ok | type) == "boolean" then .stages.handoff_check.ok
          elif (.steps.phase7_mainnet_cutover_handoff_check.status | type) == "string" then
            ((.steps.phase7_mainnet_cutover_handoff_check.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.status | type) == "string" then
            ((.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          else empty end')"
      phase7_mainnet_cutover_summary_handoff_run_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.summaries.handoff_run.status | type) == "string" then
            ((.summaries.handoff_run.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.signals.handoff_run_ok | type) == "boolean" then .signals.handoff_run_ok
          elif (.stages.handoff_run.ok | type) == "boolean" then .stages.handoff_run.ok
          elif (.steps.phase7_mainnet_cutover_handoff_run.status | type) == "string" then
            ((.steps.phase7_mainnet_cutover_handoff_run.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          elif (.status | type) == "string" then
            ((.status // "") | ascii_downcase) as $s
            | if $s == "pass" then true elif $s == "fail" then false else empty end
          else empty end')"
    fi
  else
    phase7_mainnet_cutover_summary_status_json="invalid"
  fi
fi

readiness_status="$(jq -r '.report.readiness_status // "UNKNOWN"' "$manual_validation_summary_json")"
roadmap_stage="$(jq -r '.summary.roadmap_stage // "UNKNOWN"' "$manual_validation_summary_json")"
single_machine_ready_json="$(jq -r '.summary.single_machine_ready // false' "$manual_validation_summary_json")"
real_host_gate_ready_json="$(jq -r '.summary.real_host_gate.ready // false' "$manual_validation_summary_json")"
machine_c_smoke_ready_json="$(jq -r '.summary.pre_machine_c_gate.ready // false' "$manual_validation_summary_json")"

next_action_check_id="$(jq -r '.summary.next_action_check_id // ""' "$manual_validation_summary_json")"
next_action_label="$(
  jq -r --arg id "$next_action_check_id" '
    ((.checks // []) | if type == "array" then . else [] end) as $checks
    |
    (.summary.next_action_label // "" | tostring) as $next_label
    | if $next_label != "" then
        $next_label
      elif ($id | length) > 0 then
        ([$checks[] | select((.check_id // "") == $id) | .label][0] // "")
      else
        ""
      end
  ' "$manual_validation_summary_json"
)"
next_action_command="$(
  jq -r --arg id "$next_action_check_id" '
    ((.checks // []) | if type == "array" then . else [] end) as $checks
    |
    (.summary.next_action_command // "" | tostring) as $next_command
    | if $next_command != "" then
        $next_command
      elif ($id | length) > 0 then
        ([$checks[] | select((.check_id // "") == $id) | .command][0] // "")
      else
        ""
      end
  ' "$manual_validation_summary_json"
)"

blocking_check_ids_json="$(jq -c '
  (
    ((.summary.blocking_check_ids // []) | if type == "array" then . else [] end) as $blocking_ids
    | [
        $blocking_ids[] as $id
        | (.checks[]? | select(.check_id == $id) | .status) as $status
        | select(($status // "pending") != "pass" and ($status // "pending") != "skip")
        | $id
      ]
    | unique
  ) as $filtered
  | if ($filtered | length) > 0 then
      $filtered
    else
      [
        .checks[]?
        | select((.status // "") != "pass" and (.status // "") != "skip")
        | .check_id
      ]
      | unique
    end
' "$manual_validation_summary_json")"
optional_check_ids_json="$(jq -c '(.summary.optional_check_ids // []) | if type == "array" then . else [] end' "$manual_validation_summary_json")"
pending_real_host_checks_json="$(jq -c '
  . as $root
  | ((.checks // []) | if type == "array" then . else [] end) as $checks
  | (
      [
        $checks[]
        | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
        | {
            check_id: .check_id,
            label: .label,
            status: .status,
            command: .command,
            notes: .notes
          }
      ]
    ) as $from_checks
  | if ($from_checks | length) > 0 then
      $from_checks
    else
      ((.summary.real_host_gate.blockers // []) | if type == "array" then . else [] end) as $blockers
      | [
          $blockers[]
          | select(. == "machine_c_vpn_smoke" or . == "three_machine_prod_signoff")
          | {
              check_id: .,
              label: (if . == "machine_c_vpn_smoke" then "Machine C VPN smoke test" else "True 3-machine production signoff" end),
              status: "pending",
              command: (
                if . == "machine_c_vpn_smoke" then
                  ($root.summary.real_host_gate.next_command // $root.summary.next_action_command // "")
                else
                  (
                    [ $checks[] | select(.check_id == "three_machine_prod_signoff") | .command ][0]
                    // ""
                  )
                end
              ),
              notes: ""
            }
        ]
    end
' "$manual_validation_summary_json")"
pending_real_host_check_count="$(printf '%s\n' "$pending_real_host_checks_json" | jq -r 'length')"
docker_rehearsal_ready_json="$(
  jq -r '
    (([.checks[]? | select(.check_id == "three_machine_docker_readiness") | (.status // "pending")][0]) // (.summary.docker_rehearsal_gate.status // "pending")) as $status
    | ($status == "pass" or $status == "skip")
  ' "$manual_validation_summary_json"
)"
vpn_rc_done_for_phase="false"
if [[ "$single_machine_ready_json" == "true" && "$docker_rehearsal_ready_json" == "true" && "$pending_real_host_check_count" -gt 0 ]]; then
  vpn_rc_done_for_phase="true"
fi

profile_default_gate_status="$(jq -r '.summary.profile_default_gate.status // "pending"' "$manual_validation_summary_json")"
docker_rehearsal_status="$(jq -r '.summary.docker_rehearsal_gate.status // "pending"' "$manual_validation_summary_json")"
real_wg_privileged_status="$(jq -r '.summary.real_wg_privileged_gate.status // "pending"' "$manual_validation_summary_json")"

counts_total="$(jq -r '.summary.total_checks // 0' "$manual_validation_summary_json")"
counts_pass="$(jq -r '.summary.pass_checks // 0' "$manual_validation_summary_json")"
counts_warn="$(jq -r '.summary.warn_checks // 0' "$manual_validation_summary_json")"
counts_fail="$(jq -r '.summary.fail_checks // 0' "$manual_validation_summary_json")"
counts_pending="$(jq -r '.summary.pending_checks // 0' "$manual_validation_summary_json")"

phase0_summary_file_exists_json="false"
if [[ -f "$phase0_summary_json" ]]; then
  phase0_summary_file_exists_json="true"
fi

phase0_product_surface_needs_attention_json="true"
if [[ "$phase0_product_surface_available_json" == "true" \
   && "${phase0_product_surface_status_json,,}" == "pass" \
   && "$phase0_product_surface_contract_ok_json" == "true" \
   && "$phase0_product_surface_all_required_steps_ok_json" == "true" ]]; then
  phase0_product_surface_needs_attention_json="false"
fi

phase0_product_surface_reason="phase0 product surface incomplete"
if [[ "$phase0_product_surface_needs_attention_json" == "true" ]]; then
  if [[ "$phase0_summary_file_exists_json" != "true" ]]; then
    phase0_product_surface_reason="phase0 summary missing (run ci_phase0)"
  elif [[ "$phase0_product_surface_available_json" != "true" ]]; then
    phase0_product_surface_reason="phase0 summary invalid (schema/fields)"
  elif [[ "${phase0_product_surface_status_json,,}" != "pass" ]]; then
    phase0_product_surface_reason="phase0 status=${phase0_product_surface_status_json}"
  elif [[ "$phase0_product_surface_contract_ok_json" != "true" ]]; then
    phase0_product_surface_reason="phase0 contract_ok=${phase0_product_surface_contract_ok_json}"
  elif [[ "$phase0_product_surface_all_required_steps_ok_json" != "true" ]]; then
    phase0_product_surface_reason="phase0 all_required_steps_ok=${phase0_product_surface_all_required_steps_ok_json}"
  fi
fi

phase1_needs_attention_json="true"
if [[ "$phase1_resilience_handoff_available_json" == "true" && "$phase1_resilience_handoff_status_json" == "pass" ]]; then
  phase1_needs_attention_json="false"
fi
phase2_needs_attention_json="true"
if [[ "$phase2_linux_prod_candidate_handoff_available_json" == "true" \
   && "$phase2_linux_prod_candidate_handoff_status_json" == "pass" \
   && "$phase2_linux_prod_candidate_handoff_release_integrity_ok_json" == "true" \
   && "$phase2_linux_prod_candidate_handoff_release_policy_ok_json" == "true" \
   && "$phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json" == "true" \
   && "$phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json" == "true" ]]; then
  phase2_needs_attention_json="false"
fi
phase3_needs_attention_json="true"
if [[ "$phase3_windows_client_beta_handoff_available_json" == "true" \
   && "$phase3_windows_client_beta_handoff_status_json" == "pass" \
   && "$phase3_windows_client_beta_handoff_windows_parity_ok_json" == "true" \
   && "$phase3_windows_client_beta_handoff_desktop_contract_ok_json" == "true" \
   && "$phase3_windows_client_beta_handoff_installer_update_ok_json" == "true" \
   && "$phase3_windows_client_beta_handoff_telemetry_stability_ok_json" == "true" ]]; then
  phase3_needs_attention_json="false"
fi
phase4_needs_attention_json="true"
if [[ "$phase4_windows_full_parity_handoff_available_json" == "true" \
   && "$phase4_windows_full_parity_handoff_status_json" == "pass" \
   && "$phase4_windows_full_parity_handoff_windows_server_packaging_ok_json" == "true" \
   && "$phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json" == "true" \
   && "$phase4_windows_full_parity_handoff_cross_platform_interop_ok_json" == "true" \
   && "$phase4_windows_full_parity_handoff_role_combination_validation_ok_json" == "true" ]]; then
  phase4_needs_attention_json="false"
fi

phase1_actionable_reason="phase1_resilience_handoff status=${phase1_resilience_handoff_status_json}"
if [[ -n "$phase1_resilience_handoff_failure_kind_json" ]]; then
  phase1_actionable_reason="$phase1_actionable_reason failure.kind=${phase1_resilience_handoff_failure_kind_json}"
fi
if [[ -n "$phase1_resilience_handoff_policy_outcome_decision_json" ]]; then
  phase1_actionable_reason="$phase1_actionable_reason policy_outcome.decision=${phase1_resilience_handoff_policy_outcome_decision_json}"
fi
phase1_failure_signals_context=""
if [[ -n "$phase1_resilience_handoff_profile_matrix_stable_failure_kind_json" ]]; then
  phase1_failure_signals_context="${phase1_failure_signals_context:+$phase1_failure_signals_context,}profile_matrix_stable=${phase1_resilience_handoff_profile_matrix_stable_failure_kind_json}"
fi
if [[ -n "$phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind_json" ]]; then
  phase1_failure_signals_context="${phase1_failure_signals_context:+$phase1_failure_signals_context,}peer_loss_recovery_ok=${phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind_json}"
fi
if [[ -n "$phase1_resilience_handoff_session_churn_guard_ok_failure_kind_json" ]]; then
  phase1_failure_signals_context="${phase1_failure_signals_context:+$phase1_failure_signals_context,}session_churn_guard_ok=${phase1_resilience_handoff_session_churn_guard_ok_failure_kind_json}"
fi
if [[ -n "$phase1_failure_signals_context" ]]; then
  phase1_actionable_reason="$phase1_actionable_reason failure_semantics=[$phase1_failure_signals_context]"
fi
phase2_actionable_reason="phase2_linux_prod_candidate_handoff status=${phase2_linux_prod_candidate_handoff_status_json}"
if [[ "$phase2_linux_prod_candidate_handoff_release_integrity_ok_json" != "true" \
   || "$phase2_linux_prod_candidate_handoff_release_policy_ok_json" != "true" \
   || "$phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json" != "true" \
   || "$phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json" != "true" ]]; then
  phase2_actionable_reason="$phase2_actionable_reason signals=[release_integrity_ok=${phase2_linux_prod_candidate_handoff_release_integrity_ok_json},release_policy_ok=${phase2_linux_prod_candidate_handoff_release_policy_ok_json},operator_lifecycle_ok=${phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json},pilot_signoff_ok=${phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json}]"
fi
phase3_actionable_reason="phase3_windows_client_beta_handoff status=${phase3_windows_client_beta_handoff_status_json}"
if [[ "$phase3_windows_client_beta_handoff_windows_parity_ok_json" != "true" \
   || "$phase3_windows_client_beta_handoff_desktop_contract_ok_json" != "true" \
   || "$phase3_windows_client_beta_handoff_installer_update_ok_json" != "true" \
   || "$phase3_windows_client_beta_handoff_telemetry_stability_ok_json" != "true" ]]; then
  phase3_actionable_reason="$phase3_actionable_reason signals=[windows_parity_ok=${phase3_windows_client_beta_handoff_windows_parity_ok_json},desktop_contract_ok=${phase3_windows_client_beta_handoff_desktop_contract_ok_json},installer_update_ok=${phase3_windows_client_beta_handoff_installer_update_ok_json},telemetry_stability_ok=${phase3_windows_client_beta_handoff_telemetry_stability_ok_json}]"
fi
phase4_actionable_reason="phase4_windows_full_parity_handoff status=${phase4_windows_full_parity_handoff_status_json}"
if [[ "$phase4_windows_full_parity_handoff_windows_server_packaging_ok_json" != "true" \
   || "$phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json" != "true" \
   || "$phase4_windows_full_parity_handoff_cross_platform_interop_ok_json" != "true" \
   || "$phase4_windows_full_parity_handoff_role_combination_validation_ok_json" != "true" ]]; then
  phase4_actionable_reason="$phase4_actionable_reason signals=[windows_server_packaging_ok=${phase4_windows_full_parity_handoff_windows_server_packaging_ok_json},windows_role_runbooks_ok=${phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json},cross_platform_interop_ok=${phase4_windows_full_parity_handoff_cross_platform_interop_ok_json},role_combination_validation_ok=${phase4_windows_full_parity_handoff_role_combination_validation_ok_json}]"
fi

phase0_ci_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/ci_phase0.sh" ]]; then
  phase0_ci_script_exists_json="true"
fi
phase1_handoff_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/phase1_resilience_handoff_run.sh" ]]; then
  phase1_handoff_run_script_exists_json="true"
fi
phase2_handoff_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_run.sh" ]]; then
  phase2_handoff_run_script_exists_json="true"
fi
phase3_handoff_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/phase3_windows_client_beta_handoff_run.sh" ]]; then
  phase3_handoff_run_script_exists_json="true"
fi
phase4_handoff_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_run.sh" ]]; then
  phase4_handoff_run_script_exists_json="true"
fi
integration_ci_phase1_resilience_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_ci_phase1_resilience.sh" ]]; then
  integration_ci_phase1_resilience_script_exists_json="true"
fi
integration_phase1_resilience_handoff_check_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_phase1_resilience_handoff_check.sh" ]]; then
  integration_phase1_resilience_handoff_check_script_exists_json="true"
fi
integration_phase1_resilience_handoff_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_phase1_resilience_handoff_run.sh" ]]; then
  integration_phase1_resilience_handoff_run_script_exists_json="true"
fi
integration_roadmap_progress_resilience_handoff_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_roadmap_progress_resilience_handoff.sh" ]]; then
  integration_roadmap_progress_resilience_handoff_script_exists_json="true"
fi
integration_roadmap_progress_report_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_roadmap_progress_report.sh" ]]; then
  integration_roadmap_progress_report_script_exists_json="true"
fi

non_blockchain_actionable_no_sudo_or_github_json="$(
  jq -n \
    --argjson phase0_ci_script_exists "$phase0_ci_script_exists_json" \
    --argjson phase0_product_surface_needs_attention "$phase0_product_surface_needs_attention_json" \
    --arg phase0_status "$phase0_product_surface_status_json" \
    --arg phase0_reason "$phase0_product_surface_reason" \
    --argjson phase1_handoff_run_script_exists "$phase1_handoff_run_script_exists_json" \
    --argjson phase1_needs_attention "$phase1_needs_attention_json" \
    --arg phase1_status "$phase1_resilience_handoff_status_json" \
    --arg phase1_reason "$phase1_actionable_reason" \
    --argjson phase2_handoff_run_script_exists "$phase2_handoff_run_script_exists_json" \
    --argjson phase2_needs_attention "$phase2_needs_attention_json" \
    --arg phase2_reason "$phase2_actionable_reason" \
    --argjson phase3_handoff_run_script_exists "$phase3_handoff_run_script_exists_json" \
    --argjson phase3_needs_attention "$phase3_needs_attention_json" \
    --arg phase3_reason "$phase3_actionable_reason" \
    --argjson phase4_handoff_run_script_exists "$phase4_handoff_run_script_exists_json" \
    --argjson phase4_needs_attention "$phase4_needs_attention_json" \
    --arg phase4_reason "$phase4_actionable_reason" \
    --argjson integration_ci_phase1_resilience_script_exists "$integration_ci_phase1_resilience_script_exists_json" \
    --argjson integration_phase1_resilience_handoff_check_script_exists "$integration_phase1_resilience_handoff_check_script_exists_json" \
    --argjson integration_phase1_resilience_handoff_run_script_exists "$integration_phase1_resilience_handoff_run_script_exists_json" \
    --argjson integration_roadmap_progress_resilience_handoff_script_exists "$integration_roadmap_progress_resilience_handoff_script_exists_json" \
    --argjson integration_roadmap_progress_report_script_exists "$integration_roadmap_progress_report_script_exists_json" \
    --argjson phase1_completed "$( [[ "$phase1_needs_attention_json" == "false" ]] && printf 'true' || printf 'false' )" \
    --argjson phase2_completed "$( [[ "$phase2_needs_attention_json" == "false" ]] && printf 'true' || printf 'false' )" \
    --argjson phase3_completed "$( [[ "$phase3_needs_attention_json" == "false" ]] && printf 'true' || printf 'false' )" \
    '[
      (if $phase0_ci_script_exists and $phase0_product_surface_needs_attention then {
        id: "phase0_product_surface_gate",
        label: "Phase-0 product surface gate",
        command: "bash ./scripts/ci_phase0.sh --print-summary-json 1",
        reason: ($phase0_reason + " (status=" + (($phase0_status // "missing") | tostring) + ")")
      } else empty end),
      (if $phase1_handoff_run_script_exists and $phase1_needs_attention then {
        id: "phase1_resilience_handoff_run_dry",
        label: "Phase-1 resilience handoff (dry-run)",
        command: "bash ./scripts/phase1_resilience_handoff_run.sh --dry-run 1 --print-summary-json 1",
        reason: (if (($phase1_reason // "") | tostring) == "" then ("phase1_resilience_handoff status=" + (($phase1_status // "missing") | tostring)) else $phase1_reason end)
      } else empty end),
      (if $phase1_completed and $phase2_handoff_run_script_exists and $phase2_needs_attention then {
        id: "phase2_linux_prod_candidate_handoff_run_dry",
        label: "Phase-2 Linux prod candidate handoff (dry-run)",
        command: "bash ./scripts/phase2_linux_prod_candidate_handoff_run.sh --dry-run 1 --print-summary-json 1",
        reason: $phase2_reason
      } else empty end),
      (if $phase2_completed and $phase3_handoff_run_script_exists and $phase3_needs_attention then {
        id: "phase3_windows_client_beta_handoff_run_dry",
        label: "Phase-3 Windows client beta handoff (dry-run)",
        command: "bash ./scripts/phase3_windows_client_beta_handoff_run.sh --dry-run 1 --print-summary-json 1",
        reason: $phase3_reason
      } else empty end),
      (if $phase3_completed and $phase4_handoff_run_script_exists and $phase4_needs_attention then {
        id: "phase4_windows_full_parity_handoff_run_dry",
        label: "Phase-4 Windows full parity handoff (dry-run)",
        command: "bash ./scripts/phase4_windows_full_parity_handoff_run.sh --dry-run 1 --print-summary-json 1",
        reason: $phase4_reason
      } else empty end),
      (if $integration_ci_phase1_resilience_script_exists then {
        id: "integration_ci_phase1_resilience",
        label: "Phase-1 gate contract",
        command: "bash ./scripts/integration_ci_phase1_resilience.sh",
        reason: "validates non-blockchain Phase-1 wrapper contracts"
      } else empty end),
      (if $integration_phase1_resilience_handoff_check_script_exists then {
        id: "integration_phase1_resilience_handoff_check",
        label: "Phase-1 handoff check contract",
        command: "bash ./scripts/integration_phase1_resilience_handoff_check.sh",
        reason: "validates handoff fail-closed summary contract"
      } else empty end),
      (if $integration_phase1_resilience_handoff_run_script_exists then {
        id: "integration_phase1_resilience_handoff_run",
        label: "Phase-1 handoff run contract",
        command: "bash ./scripts/integration_phase1_resilience_handoff_run.sh",
        reason: "validates run/check orchestration contract"
      } else empty end),
      (if $integration_roadmap_progress_resilience_handoff_script_exists then {
        id: "integration_roadmap_progress_resilience_handoff",
        label: "Roadmap resilience ingestion contract",
        command: "bash ./scripts/integration_roadmap_progress_resilience_handoff.sh",
        reason: "validates resilience handoff ingestion in roadmap report"
      } else empty end),
      (if $integration_roadmap_progress_report_script_exists then {
        id: "integration_roadmap_progress_report",
        label: "Roadmap report contract",
        command: "bash ./scripts/integration_roadmap_progress_report.sh",
        reason: "validates roadmap summary/report contract end-to-end"
      } else empty end)
    ]'
)"
non_blockchain_recommended_gate_id="$(printf '%s\n' "$non_blockchain_actionable_no_sudo_or_github_json" | jq -r 'if length > 0 then .[0].id else "" end')"
non_blockchain_actionable_no_sudo_or_github_count="$(printf '%s\n' "$non_blockchain_actionable_no_sudo_or_github_json" | jq -r 'length')"

next_actions_json="$(jq -c --arg next_action_check_id "$next_action_check_id" --arg next_action_label "$next_action_label" --arg next_action_command "$next_action_command" '
  def unique_commands_preserve_order:
    reduce .[] as $item (
      [];
      if ($item.command // "") == "" then
        .
      elif any(.[]; (.command // "") == ($item.command // "")) then
        .
      else
        . + [$item]
      end
    );
  [
    (if ($next_action_command // "") != "" then {
      id: (if ($next_action_check_id // "") != "" then $next_action_check_id else "next_action" end),
      label: (if ($next_action_label // "") != "" then $next_action_label elif ($next_action_check_id // "") != "" then $next_action_check_id else "Next action" end),
      command: $next_action_command,
      reason: "primary roadmap gate"
    } else empty end),
    (if ((.summary.profile_default_gate.status // "pending") != "pass" and (.summary.profile_default_gate.status // "pending") != "skip" and ((.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // "") != "")) then {
      id: "profile_default_gate",
      label: "Profile default decision gate",
      command: (.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // ""),
      reason: "non-blocking profile default decision"
    } else empty end),
    (if ((.summary.docker_rehearsal_gate.status // "pending") != "pass" and (.summary.docker_rehearsal_gate.status // "pending") != "skip" and ((.summary.docker_rehearsal_gate.next_command // .summary.docker_rehearsal_gate.command // "") != "")) then {
      id: "three_machine_docker_readiness",
      label: "One-host docker 3-machine rehearsal",
      command: (.summary.docker_rehearsal_gate.next_command // .summary.docker_rehearsal_gate.command // ""),
      reason: "one-host confidence gate"
    } else empty end),
    (if ((.summary.real_wg_privileged_gate.status // "pending") != "pass" and (.summary.real_wg_privileged_gate.status // "pending") != "skip" and ((.summary.real_wg_privileged_gate.next_command // .summary.real_wg_privileged_gate.command // "") != "")) then {
      id: "real_wg_privileged_matrix",
      label: "Linux root real-WG privileged matrix",
      command: (.summary.real_wg_privileged_gate.next_command // .summary.real_wg_privileged_gate.command // ""),
      reason: "one-host dataplane confidence gate"
    } else empty end)
  ]
  | unique_commands_preserve_order
' "$manual_validation_summary_json")"

blockchain_track_status="parallel-cosmos-build"
blockchain_track_policy="canonical execution plan: docs/full-execution-plan-2026-2027.md"
blockchain_track_recommendation="Cosmos-first blockchain track: keep VPN dataplane independent, build settlement/reward/slash sponsor control-plane in parallel, keep state-dir-capable file-backed module stores available in tdpnd runtime, and avoid sidecar-chain drift."
if [[ ! -f "$product_roadmap_doc" ]]; then
  blockchain_track_policy="roadmap file missing"
fi

final_status="ok"
final_rc=0
notes="Roadmap gates are healthy."
if [[ "$manual_refresh_timed_out" == "true" || "$single_machine_refresh_timed_out" == "true" ]]; then
  final_status="fail"
  final_rc=1
  notes="One or more requested refresh steps timed out; inspect refresh logs."
elif [[ "$manual_refresh_status" == "fail" || "$single_machine_refresh_status" == "fail" ]]; then
  final_status="fail"
  final_rc=1
  notes="One or more requested refresh steps failed; inspect refresh logs."
elif [[ "$manual_refresh_status" == "warn" || "$single_machine_refresh_status" == "warn" ]]; then
  final_status="warn"
  notes="One or more requested refresh steps reported non-blocking transient warnings; latest usable summaries were retained."
elif [[ "$readiness_status" != "READY" ]]; then
  final_status="warn"
  notes="VPN production signoff is still pending external real-host gates."
fi

summary_payload="$(jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --arg notes "$notes" \
  --arg readiness_status "$readiness_status" \
  --arg roadmap_stage "$roadmap_stage" \
  --arg next_action_check_id "$next_action_check_id" \
  --arg next_action_label "$next_action_label" \
  --arg next_action_command "$next_action_command" \
  --argjson single_machine_ready "$single_machine_ready_json" \
  --argjson real_host_gate_ready "$real_host_gate_ready_json" \
  --argjson machine_c_smoke_ready "$machine_c_smoke_ready_json" \
  --argjson vpn_rc_done_for_phase "$vpn_rc_done_for_phase" \
  --argjson phase0_product_surface_available "$phase0_product_surface_available_json" \
  --arg phase0_product_surface_input_summary_json "$phase0_product_surface_input_summary_json" \
  --arg phase0_product_surface_source_summary_json "$phase0_product_surface_source_summary_json" \
  --arg phase0_product_surface_status "$phase0_product_surface_status_json" \
  --argjson phase0_product_surface_rc "$phase0_product_surface_rc_json" \
  --argjson phase0_product_surface_dry_run "$phase0_product_surface_dry_run_json" \
  --argjson phase0_product_surface_contract_ok "$phase0_product_surface_contract_ok_json" \
  --argjson phase0_product_surface_all_required_steps_ok "$phase0_product_surface_all_required_steps_ok_json" \
  --argjson phase0_product_surface_launcher_wiring_ok "$phase0_product_surface_launcher_wiring_ok_json" \
  --argjson phase0_product_surface_launcher_runtime_ok "$phase0_product_surface_launcher_runtime_ok_json" \
  --argjson phase0_product_surface_prompt_budget_ok "$phase0_product_surface_prompt_budget_ok_json" \
  --argjson phase0_product_surface_config_v1_ok "$phase0_product_surface_config_v1_ok_json" \
  --argjson phase0_product_surface_local_control_api_ok "$phase0_product_surface_local_control_api_ok_json" \
  --argjson phase1_resilience_handoff_available "$phase1_resilience_handoff_available_json" \
  --arg phase1_resilience_handoff_input_summary_json "$phase1_resilience_handoff_input_summary_json" \
  --arg phase1_resilience_handoff_source_summary_json "$phase1_resilience_handoff_source_summary_json" \
  --arg phase1_resilience_handoff_source_summary_kind "$phase1_resilience_handoff_source_summary_kind" \
  --arg phase1_resilience_handoff_status "$phase1_resilience_handoff_status_json" \
  --argjson phase1_resilience_handoff_rc "$phase1_resilience_handoff_rc_json" \
  --argjson phase1_resilience_handoff_profile_matrix_stable "$phase1_resilience_handoff_profile_matrix_stable_json" \
  --argjson phase1_resilience_handoff_peer_loss_recovery_ok "$phase1_resilience_handoff_peer_loss_recovery_ok_json" \
  --argjson phase1_resilience_handoff_session_churn_guard_ok "$phase1_resilience_handoff_session_churn_guard_ok_json" \
  --argjson phase1_resilience_handoff_automatable_without_sudo_or_github "$phase1_resilience_handoff_automatable_without_sudo_or_github_json" \
  --arg phase1_resilience_handoff_failure_kind "$phase1_resilience_handoff_failure_kind_json" \
  --arg phase1_resilience_handoff_policy_outcome_decision "$phase1_resilience_handoff_policy_outcome_decision_json" \
  --argjson phase1_resilience_handoff_policy_outcome_fail_closed_no_go "$phase1_resilience_handoff_policy_outcome_fail_closed_no_go_json" \
  --arg phase1_resilience_handoff_profile_matrix_stable_failure_kind "$phase1_resilience_handoff_profile_matrix_stable_failure_kind_json" \
  --arg phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind "$phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind_json" \
  --arg phase1_resilience_handoff_session_churn_guard_ok_failure_kind "$phase1_resilience_handoff_session_churn_guard_ok_failure_kind_json" \
  --argjson non_blockchain_actionable_no_sudo_or_github "$non_blockchain_actionable_no_sudo_or_github_json" \
  --arg non_blockchain_recommended_gate_id "$non_blockchain_recommended_gate_id" \
  --argjson resilience_handoff_available "$resilience_handoff_available_json" \
  --arg resilience_handoff_source_summary_json "$resilience_handoff_source_summary_json" \
  --argjson resilience_profile_matrix_stable "$resilience_profile_matrix_stable_json" \
  --argjson resilience_peer_loss_recovery_ok "$resilience_peer_loss_recovery_ok_json" \
  --argjson resilience_session_churn_guard_ok "$resilience_session_churn_guard_ok_json" \
  --argjson phase2_linux_prod_candidate_handoff_available "$phase2_linux_prod_candidate_handoff_available_json" \
  --arg phase2_linux_prod_candidate_handoff_input_summary_json "$phase2_linux_prod_candidate_handoff_input_summary_json" \
  --arg phase2_linux_prod_candidate_handoff_source_summary_json "$phase2_linux_prod_candidate_handoff_source_summary_json" \
  --arg phase2_linux_prod_candidate_handoff_source_summary_kind "$phase2_linux_prod_candidate_handoff_source_summary_kind" \
  --arg phase2_linux_prod_candidate_handoff_status "$phase2_linux_prod_candidate_handoff_status_json" \
  --argjson phase2_linux_prod_candidate_handoff_rc "$phase2_linux_prod_candidate_handoff_rc_json" \
  --argjson phase2_linux_prod_candidate_handoff_release_integrity_ok "$phase2_linux_prod_candidate_handoff_release_integrity_ok_json" \
  --argjson phase2_linux_prod_candidate_handoff_release_policy_ok "$phase2_linux_prod_candidate_handoff_release_policy_ok_json" \
  --argjson phase2_linux_prod_candidate_handoff_operator_lifecycle_ok "$phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json" \
  --argjson phase2_linux_prod_candidate_handoff_pilot_signoff_ok "$phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json" \
  --argjson phase3_windows_client_beta_handoff_available "$phase3_windows_client_beta_handoff_available_json" \
  --arg phase3_windows_client_beta_handoff_input_summary_json "$phase3_windows_client_beta_handoff_input_summary_json" \
  --arg phase3_windows_client_beta_handoff_source_summary_json "$phase3_windows_client_beta_handoff_source_summary_json" \
  --arg phase3_windows_client_beta_handoff_source_summary_kind "$phase3_windows_client_beta_handoff_source_summary_kind" \
  --arg phase3_windows_client_beta_handoff_status "$phase3_windows_client_beta_handoff_status_json" \
  --argjson phase3_windows_client_beta_handoff_rc "$phase3_windows_client_beta_handoff_rc_json" \
  --argjson phase3_windows_client_beta_handoff_windows_parity_ok "$phase3_windows_client_beta_handoff_windows_parity_ok_json" \
  --argjson phase3_windows_client_beta_handoff_desktop_contract_ok "$phase3_windows_client_beta_handoff_desktop_contract_ok_json" \
  --argjson phase3_windows_client_beta_handoff_installer_update_ok "$phase3_windows_client_beta_handoff_installer_update_ok_json" \
  --argjson phase3_windows_client_beta_handoff_telemetry_stability_ok "$phase3_windows_client_beta_handoff_telemetry_stability_ok_json" \
  --argjson phase4_windows_full_parity_handoff_available "$phase4_windows_full_parity_handoff_available_json" \
  --arg phase4_windows_full_parity_handoff_input_summary_json "$phase4_windows_full_parity_handoff_input_summary_json" \
  --arg phase4_windows_full_parity_handoff_source_summary_json "$phase4_windows_full_parity_handoff_source_summary_json" \
  --arg phase4_windows_full_parity_handoff_source_summary_kind "$phase4_windows_full_parity_handoff_source_summary_kind" \
  --arg phase4_windows_full_parity_handoff_status "$phase4_windows_full_parity_handoff_status_json" \
  --argjson phase4_windows_full_parity_handoff_rc "$phase4_windows_full_parity_handoff_rc_json" \
  --argjson phase4_windows_full_parity_handoff_windows_server_packaging_ok "$phase4_windows_full_parity_handoff_windows_server_packaging_ok_json" \
  --argjson phase4_windows_full_parity_handoff_windows_role_runbooks_ok "$phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json" \
  --argjson phase4_windows_full_parity_handoff_cross_platform_interop_ok "$phase4_windows_full_parity_handoff_cross_platform_interop_ok_json" \
  --argjson phase4_windows_full_parity_handoff_role_combination_validation_ok "$phase4_windows_full_parity_handoff_role_combination_validation_ok_json" \
  --argjson phase5_settlement_layer_handoff_available "$phase5_settlement_layer_handoff_available_json" \
  --arg phase5_settlement_layer_handoff_input_summary_json "$phase5_settlement_layer_handoff_input_summary_json" \
  --arg phase5_settlement_layer_handoff_source_summary_json "$phase5_settlement_layer_handoff_source_summary_json" \
  --arg phase5_settlement_layer_handoff_source_summary_kind "$phase5_settlement_layer_handoff_source_summary_kind" \
  --arg phase5_settlement_layer_handoff_status "$phase5_settlement_layer_handoff_status_json" \
  --argjson phase5_settlement_layer_handoff_rc "$phase5_settlement_layer_handoff_rc_json" \
  --argjson phase5_settlement_layer_handoff_settlement_failsoft_ok "$phase5_settlement_layer_handoff_settlement_failsoft_ok_json" \
  --argjson phase5_settlement_layer_handoff_settlement_acceptance_ok "$phase5_settlement_layer_handoff_settlement_acceptance_ok_json" \
  --argjson phase5_settlement_layer_handoff_settlement_bridge_smoke_ok "$phase5_settlement_layer_handoff_settlement_bridge_smoke_ok_json" \
  --argjson phase5_settlement_layer_handoff_settlement_state_persistence_ok "$phase5_settlement_layer_handoff_settlement_state_persistence_ok_json" \
  --arg phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json" \
  --argjson phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json" \
  --arg phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json" \
  --argjson phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json" \
  --argjson phase6_cosmos_l1_handoff_available "$phase6_cosmos_l1_handoff_available_json" \
  --arg phase6_cosmos_l1_handoff_input_summary_json "$phase6_cosmos_l1_handoff_input_summary_json" \
  --arg phase6_cosmos_l1_handoff_source_summary_json "$phase6_cosmos_l1_handoff_source_summary_json" \
  --arg phase6_cosmos_l1_handoff_source_summary_kind "$phase6_cosmos_l1_handoff_source_summary_kind" \
  --arg phase6_cosmos_l1_handoff_status "$phase6_cosmos_l1_handoff_status_json" \
  --argjson phase6_cosmos_l1_handoff_rc "$phase6_cosmos_l1_handoff_rc_json" \
  --argjson phase6_cosmos_l1_handoff_run_pipeline_ok "$phase6_cosmos_l1_handoff_run_pipeline_ok_json" \
  --argjson phase6_cosmos_l1_handoff_module_tx_surface_ok "$phase6_cosmos_l1_handoff_module_tx_surface_ok_json" \
  --argjson phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok "$phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok_json" \
  --argjson phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok "$phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok_json" \
  --argjson phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok "$phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok_json" \
  --argjson phase7_mainnet_cutover_summary_available "$phase7_mainnet_cutover_summary_available_json" \
  --arg phase7_mainnet_cutover_summary_input_summary_json "$phase7_mainnet_cutover_summary_input_summary_json" \
  --arg phase7_mainnet_cutover_summary_source_summary_json "$phase7_mainnet_cutover_summary_source_summary_json" \
  --arg phase7_mainnet_cutover_summary_source_summary_kind "$phase7_mainnet_cutover_summary_source_summary_kind" \
  --arg phase7_mainnet_cutover_summary_status "$phase7_mainnet_cutover_summary_status_json" \
  --argjson phase7_mainnet_cutover_summary_rc "$phase7_mainnet_cutover_summary_rc_json" \
  --argjson phase7_mainnet_cutover_summary_check_ok "$phase7_mainnet_cutover_summary_check_ok_json" \
  --argjson phase7_mainnet_cutover_summary_run_ok "$phase7_mainnet_cutover_summary_run_ok_json" \
  --argjson phase7_mainnet_cutover_summary_handoff_check_ok "$phase7_mainnet_cutover_summary_handoff_check_ok_json" \
  --argjson phase7_mainnet_cutover_summary_handoff_run_ok "$phase7_mainnet_cutover_summary_handoff_run_ok_json" \
  --arg profile_default_gate_status "$profile_default_gate_status" \
  --arg docker_rehearsal_status "$docker_rehearsal_status" \
  --arg real_wg_privileged_status "$real_wg_privileged_status" \
  --argjson total_checks "$counts_total" \
  --argjson pass_checks "$counts_pass" \
  --argjson warn_checks "$counts_warn" \
  --argjson fail_checks "$counts_fail" \
  --argjson pending_checks "$counts_pending" \
  --argjson blocking_check_ids "$blocking_check_ids_json" \
  --argjson optional_check_ids "$optional_check_ids_json" \
  --argjson pending_real_host_checks "$pending_real_host_checks_json" \
  --argjson next_actions "$next_actions_json" \
  --arg blockchain_track_status "$blockchain_track_status" \
  --arg blockchain_track_policy "$blockchain_track_policy" \
  --arg blockchain_track_recommendation "$blockchain_track_recommendation" \
  --arg refresh_manual_validation_status "$manual_refresh_status" \
  --argjson refresh_manual_validation_rc "$manual_refresh_rc" \
  --argjson refresh_manual_validation_timed_out "$manual_refresh_timed_out" \
  --argjson refresh_manual_validation_timeout_sec "$manual_refresh_timeout_sec" \
  --argjson refresh_manual_validation_duration_sec "$manual_refresh_duration_sec" \
  --arg refresh_manual_validation_log "$manual_refresh_log" \
  --argjson refresh_manual_validation_summary_valid_after_run "$manual_summary_valid_after_run" \
  --argjson refresh_manual_validation_summary_restored_from_snapshot "$manual_summary_restored" \
  --arg refresh_single_machine_status "$single_machine_refresh_status" \
  --argjson refresh_single_machine_rc "$single_machine_refresh_rc" \
  --argjson refresh_single_machine_timed_out "$single_machine_refresh_timed_out" \
  --argjson refresh_single_machine_timeout_sec "$single_machine_refresh_timeout_sec" \
  --argjson refresh_single_machine_duration_sec "$single_machine_refresh_duration_sec" \
  --arg refresh_single_machine_log "$single_machine_refresh_log" \
  --argjson refresh_single_machine_summary_valid_after_run "$single_machine_summary_valid_after_run" \
  --argjson refresh_single_machine_summary_restored_from_snapshot "$single_machine_summary_restored" \
  --argjson refresh_single_machine_non_blocking_transient "$single_machine_refresh_non_blocking_transient" \
  --arg refresh_single_machine_non_blocking_reason "$single_machine_refresh_non_blocking_reason" \
  --arg manual_validation_summary_json "$manual_validation_summary_json" \
  --arg manual_validation_report_md "$manual_validation_report_md" \
  --arg single_machine_summary_json "$single_machine_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: (if $status == "fail" then 1 else 0 end),
    notes: $notes,
    vpn_track: {
      readiness_status: $readiness_status,
      roadmap_stage: $roadmap_stage,
      single_machine_ready: $single_machine_ready,
      machine_c_smoke_ready: $machine_c_smoke_ready,
      real_host_gate_ready: $real_host_gate_ready,
      vpn_rc_done_for_phase: $vpn_rc_done_for_phase,
      phase0_product_surface: {
        available: $phase0_product_surface_available,
        input_summary_json: (if $phase0_product_surface_input_summary_json == "" then null else $phase0_product_surface_input_summary_json end),
        source_summary_json: (if $phase0_product_surface_source_summary_json == "" then null else $phase0_product_surface_source_summary_json end),
        status: $phase0_product_surface_status,
        rc: $phase0_product_surface_rc,
        dry_run: $phase0_product_surface_dry_run,
        contract_ok: $phase0_product_surface_contract_ok,
        all_required_steps_ok: $phase0_product_surface_all_required_steps_ok,
        launcher_wiring_ok: $phase0_product_surface_launcher_wiring_ok,
        launcher_runtime_ok: $phase0_product_surface_launcher_runtime_ok,
        prompt_budget_ok: $phase0_product_surface_prompt_budget_ok,
        config_v1_ok: $phase0_product_surface_config_v1_ok,
        local_control_api_ok: $phase0_product_surface_local_control_api_ok
      },
      phase1_resilience_handoff: {
        available: $phase1_resilience_handoff_available,
        input_summary_json: (if $phase1_resilience_handoff_input_summary_json == "" then null else $phase1_resilience_handoff_input_summary_json end),
        source_summary_json: (if $phase1_resilience_handoff_source_summary_json == "" then null else $phase1_resilience_handoff_source_summary_json end),
        source_summary_kind: (if $phase1_resilience_handoff_source_summary_kind == "" then null else $phase1_resilience_handoff_source_summary_kind end),
        status: $phase1_resilience_handoff_status,
        rc: $phase1_resilience_handoff_rc,
        profile_matrix_stable: $phase1_resilience_handoff_profile_matrix_stable,
        peer_loss_recovery_ok: $phase1_resilience_handoff_peer_loss_recovery_ok,
        session_churn_guard_ok: $phase1_resilience_handoff_session_churn_guard_ok,
        automatable_without_sudo_or_github: $phase1_resilience_handoff_automatable_without_sudo_or_github,
        failure: {
          kind: (if $phase1_resilience_handoff_failure_kind == "" then null else $phase1_resilience_handoff_failure_kind end)
        },
        policy_outcome: {
          decision: (if $phase1_resilience_handoff_policy_outcome_decision == "" then null else $phase1_resilience_handoff_policy_outcome_decision end),
          fail_closed_no_go: $phase1_resilience_handoff_policy_outcome_fail_closed_no_go
        },
        failure_semantics: {
          profile_matrix_stable: {
            kind: (if $phase1_resilience_handoff_profile_matrix_stable_failure_kind == "" then null else $phase1_resilience_handoff_profile_matrix_stable_failure_kind end)
          },
          peer_loss_recovery_ok: {
            kind: (if $phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind == "" then null else $phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind end)
          },
          session_churn_guard_ok: {
            kind: (if $phase1_resilience_handoff_session_churn_guard_ok_failure_kind == "" then null else $phase1_resilience_handoff_session_churn_guard_ok_failure_kind end)
          }
        }
      },
      non_blockchain_actionable_no_sudo_or_github: $non_blockchain_actionable_no_sudo_or_github,
      non_blockchain_recommended_gate_id: (if $non_blockchain_recommended_gate_id == "" then null else $non_blockchain_recommended_gate_id end),
      phase2_linux_prod_candidate_handoff: {
        available: $phase2_linux_prod_candidate_handoff_available,
        input_summary_json: (if $phase2_linux_prod_candidate_handoff_input_summary_json == "" then null else $phase2_linux_prod_candidate_handoff_input_summary_json end),
        source_summary_json: (if $phase2_linux_prod_candidate_handoff_source_summary_json == "" then null else $phase2_linux_prod_candidate_handoff_source_summary_json end),
        source_summary_kind: (if $phase2_linux_prod_candidate_handoff_source_summary_kind == "" then null else $phase2_linux_prod_candidate_handoff_source_summary_kind end),
        status: $phase2_linux_prod_candidate_handoff_status,
        rc: $phase2_linux_prod_candidate_handoff_rc,
        release_integrity_ok: $phase2_linux_prod_candidate_handoff_release_integrity_ok,
        release_policy_ok: $phase2_linux_prod_candidate_handoff_release_policy_ok,
        operator_lifecycle_ok: $phase2_linux_prod_candidate_handoff_operator_lifecycle_ok,
        pilot_signoff_ok: $phase2_linux_prod_candidate_handoff_pilot_signoff_ok
      },
      phase3_windows_client_beta_handoff: {
        available: $phase3_windows_client_beta_handoff_available,
        input_summary_json: (if $phase3_windows_client_beta_handoff_input_summary_json == "" then null else $phase3_windows_client_beta_handoff_input_summary_json end),
        source_summary_json: (if $phase3_windows_client_beta_handoff_source_summary_json == "" then null else $phase3_windows_client_beta_handoff_source_summary_json end),
        source_summary_kind: (if $phase3_windows_client_beta_handoff_source_summary_kind == "" then null else $phase3_windows_client_beta_handoff_source_summary_kind end),
        status: $phase3_windows_client_beta_handoff_status,
        rc: $phase3_windows_client_beta_handoff_rc,
        windows_parity_ok: $phase3_windows_client_beta_handoff_windows_parity_ok,
        desktop_contract_ok: $phase3_windows_client_beta_handoff_desktop_contract_ok,
        installer_update_ok: $phase3_windows_client_beta_handoff_installer_update_ok,
        telemetry_stability_ok: $phase3_windows_client_beta_handoff_telemetry_stability_ok
      },
      phase4_windows_full_parity_handoff: {
        available: $phase4_windows_full_parity_handoff_available,
        input_summary_json: (if $phase4_windows_full_parity_handoff_input_summary_json == "" then null else $phase4_windows_full_parity_handoff_input_summary_json end),
        source_summary_json: (if $phase4_windows_full_parity_handoff_source_summary_json == "" then null else $phase4_windows_full_parity_handoff_source_summary_json end),
        source_summary_kind: (if $phase4_windows_full_parity_handoff_source_summary_kind == "" then null else $phase4_windows_full_parity_handoff_source_summary_kind end),
        status: $phase4_windows_full_parity_handoff_status,
        rc: $phase4_windows_full_parity_handoff_rc,
        windows_server_packaging_ok: $phase4_windows_full_parity_handoff_windows_server_packaging_ok,
        windows_role_runbooks_ok: $phase4_windows_full_parity_handoff_windows_role_runbooks_ok,
        cross_platform_interop_ok: $phase4_windows_full_parity_handoff_cross_platform_interop_ok,
        role_combination_validation_ok: $phase4_windows_full_parity_handoff_role_combination_validation_ok
      },
      phase5_settlement_layer_handoff: {
        available: $phase5_settlement_layer_handoff_available,
        input_summary_json: (if $phase5_settlement_layer_handoff_input_summary_json == "" then null else $phase5_settlement_layer_handoff_input_summary_json end),
        source_summary_json: (if $phase5_settlement_layer_handoff_source_summary_json == "" then null else $phase5_settlement_layer_handoff_source_summary_json end),
        source_summary_kind: (if $phase5_settlement_layer_handoff_source_summary_kind == "" then null else $phase5_settlement_layer_handoff_source_summary_kind end),
        status: $phase5_settlement_layer_handoff_status,
        rc: $phase5_settlement_layer_handoff_rc,
        settlement_failsoft_ok: $phase5_settlement_layer_handoff_settlement_failsoft_ok,
        settlement_acceptance_ok: $phase5_settlement_layer_handoff_settlement_acceptance_ok,
        settlement_bridge_smoke_ok: $phase5_settlement_layer_handoff_settlement_bridge_smoke_ok,
        settlement_state_persistence_ok: $phase5_settlement_layer_handoff_settlement_state_persistence_ok,
        settlement_adapter_roundtrip_status: (if $phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status == "" then null else $phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status end),
        settlement_adapter_roundtrip_ok: $phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok,
        issuer_sponsor_api_live_smoke_status: (if $phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status == "" then null else $phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status end),
        issuer_sponsor_api_live_smoke_ok: $phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok
      },
      resilience_handoff: {
        available: $resilience_handoff_available,
        source_summary_json: (if $resilience_handoff_source_summary_json == "" then null else $resilience_handoff_source_summary_json end),
        profile_matrix_stable: $resilience_profile_matrix_stable,
        peer_loss_recovery_ok: $resilience_peer_loss_recovery_ok,
        session_churn_guard_ok: $resilience_session_churn_guard_ok
      },
      counts: {
        total_checks: $total_checks,
        pass_checks: $pass_checks,
        warn_checks: $warn_checks,
        fail_checks: $fail_checks,
        pending_checks: $pending_checks
      },
      blocking_check_ids: $blocking_check_ids,
      optional_check_ids: $optional_check_ids,
      pending_real_host_checks: $pending_real_host_checks,
      next_action: {
        check_id: $next_action_check_id,
        label: $next_action_label,
        command: $next_action_command
      },
      optional_gate_status: {
        profile_default_gate: $profile_default_gate_status,
        docker_rehearsal_gate: $docker_rehearsal_status,
        real_wg_privileged_gate: $real_wg_privileged_status
      }
    },
    blockchain_track: {
      status: $blockchain_track_status,
      policy: $blockchain_track_policy,
      recommendation: $blockchain_track_recommendation,
      phase6_cosmos_l1_handoff: {
        available: $phase6_cosmos_l1_handoff_available,
        input_summary_json: (if $phase6_cosmos_l1_handoff_input_summary_json == "" then null else $phase6_cosmos_l1_handoff_input_summary_json end),
        source_summary_json: (if $phase6_cosmos_l1_handoff_source_summary_json == "" then null else $phase6_cosmos_l1_handoff_source_summary_json end),
        source_summary_kind: (if $phase6_cosmos_l1_handoff_source_summary_kind == "" then null else $phase6_cosmos_l1_handoff_source_summary_kind end),
        status: $phase6_cosmos_l1_handoff_status,
        rc: $phase6_cosmos_l1_handoff_rc,
        run_pipeline_ok: $phase6_cosmos_l1_handoff_run_pipeline_ok,
        module_tx_surface_ok: $phase6_cosmos_l1_handoff_module_tx_surface_ok,
        tdpnd_grpc_runtime_smoke_ok: $phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok,
        tdpnd_grpc_live_smoke_ok: $phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok,
        tdpnd_grpc_auth_live_smoke_ok: $phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok
      },
      phase7_mainnet_cutover_summary_report: {
        available: $phase7_mainnet_cutover_summary_available,
        input_summary_json: (if $phase7_mainnet_cutover_summary_input_summary_json == "" then null else $phase7_mainnet_cutover_summary_input_summary_json end),
        source_summary_json: (if $phase7_mainnet_cutover_summary_source_summary_json == "" then null else $phase7_mainnet_cutover_summary_source_summary_json end),
        source_summary_kind: (if $phase7_mainnet_cutover_summary_source_summary_kind == "" then null else $phase7_mainnet_cutover_summary_source_summary_kind end),
        status: $phase7_mainnet_cutover_summary_status,
        rc: $phase7_mainnet_cutover_summary_rc,
        check_ok: $phase7_mainnet_cutover_summary_check_ok,
        run_ok: $phase7_mainnet_cutover_summary_run_ok,
        handoff_check_ok: $phase7_mainnet_cutover_summary_handoff_check_ok,
        handoff_run_ok: $phase7_mainnet_cutover_summary_handoff_run_ok
      }
    },
    refresh: {
      manual_validation_report: {
        enabled: ($refresh_manual_validation_status != "skip"),
        status: $refresh_manual_validation_status,
        rc: $refresh_manual_validation_rc,
        timed_out: $refresh_manual_validation_timed_out,
        timeout_sec: $refresh_manual_validation_timeout_sec,
        duration_sec: $refresh_manual_validation_duration_sec,
        log: $refresh_manual_validation_log,
        summary_valid_after_run: $refresh_manual_validation_summary_valid_after_run,
        summary_restored_from_snapshot: $refresh_manual_validation_summary_restored_from_snapshot
      },
      single_machine_prod_readiness: {
        enabled: ($refresh_single_machine_status != "skip"),
        status: $refresh_single_machine_status,
        rc: $refresh_single_machine_rc,
        timed_out: $refresh_single_machine_timed_out,
        timeout_sec: $refresh_single_machine_timeout_sec,
        duration_sec: $refresh_single_machine_duration_sec,
        log: $refresh_single_machine_log,
        summary_valid_after_run: $refresh_single_machine_summary_valid_after_run,
        summary_restored_from_snapshot: $refresh_single_machine_summary_restored_from_snapshot,
        non_blocking_transient: $refresh_single_machine_non_blocking_transient,
        non_blocking_reason: $refresh_single_machine_non_blocking_reason
      }
    },
    next_actions: $next_actions,
    artifacts: {
      manual_validation_summary_json: $manual_validation_summary_json,
      manual_validation_report_md: $manual_validation_report_md,
      single_machine_summary_json: $single_machine_summary_json,
      phase0_summary_json: (if $phase0_product_surface_source_summary_json == "" then $phase0_product_surface_input_summary_json else $phase0_product_surface_source_summary_json end),
      phase1_resilience_handoff_summary_json: (if $phase1_resilience_handoff_source_summary_json == "" then null else $phase1_resilience_handoff_source_summary_json end),
      phase2_linux_prod_candidate_summary_json: (if $phase2_linux_prod_candidate_handoff_input_summary_json == "" then null else $phase2_linux_prod_candidate_handoff_input_summary_json end),
      phase3_windows_client_beta_summary_json: (if $phase3_windows_client_beta_handoff_source_summary_json == "" then null else $phase3_windows_client_beta_handoff_source_summary_json end),
      phase4_windows_full_parity_summary_json: (if $phase4_windows_full_parity_handoff_source_summary_json == "" then null else $phase4_windows_full_parity_handoff_source_summary_json end),
      phase5_settlement_layer_summary_json: (if $phase5_settlement_layer_handoff_source_summary_json == "" then null else $phase5_settlement_layer_handoff_source_summary_json end),
      phase6_cosmos_l1_summary_json: (if $phase6_cosmos_l1_handoff_source_summary_json == "" then null else $phase6_cosmos_l1_handoff_source_summary_json end),
      phase7_mainnet_cutover_summary_json: (if $phase7_mainnet_cutover_summary_source_summary_json == "" then null else $phase7_mainnet_cutover_summary_source_summary_json end),
      vpn_rc_resilience_summary_json: (if $resilience_handoff_source_summary_json == "" then null else $resilience_handoff_source_summary_json end),
      summary_json: $summary_json_path,
      report_md: $report_md_path
    }
  }')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
printf '%s\n' "$summary_payload" >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

next_actions_md="$(printf '%s\n' "$next_actions_json" | jq -r 'if length == 0 then "- none" else .[] | "- `\(.id)`: `\(.command)` (\(.reason))" end')"
non_blockchain_actionable_no_sudo_or_github_md="$(printf '%s\n' "$non_blockchain_actionable_no_sudo_or_github_json" | jq -r 'if length == 0 then "- none" else .[] | "- `\(.id)`: `\(.command)` (\(.reason))" end')"
pending_real_host_checks_md="$(printf '%s\n' "$pending_real_host_checks_json" | jq -r '
  if length == 0 then
    "- none"
  else
    .[]
    | "- `\(.check_id)`: `\(.status // "")` - \(.label // "") - command: `\(.command // "")`"
      + (if (.notes // "") != "" then " - notes: \(.notes)" else "" end)
  end
')"

report_tmp="$(mktemp "${report_md}.tmp.XXXXXX")"
cat >"$report_tmp" <<EOF_MD
# Roadmap Progress Report

- Generated at (UTC): $(jq -r '.generated_at_utc' "$summary_json")
- Status: $(jq -r '.status' "$summary_json")
- Notes: $(jq -r '.notes' "$summary_json")

## VPN Track

- Readiness: $(jq -r '.vpn_track.readiness_status' "$summary_json")
- Roadmap stage: $(jq -r '.vpn_track.roadmap_stage' "$summary_json")
- Single-machine ready: $(jq -r '.vpn_track.single_machine_ready' "$summary_json")
- Machine-C smoke ready: $(jq -r '.vpn_track.machine_c_smoke_ready' "$summary_json")
- Real-host gate ready: $(jq -r '.vpn_track.real_host_gate_ready' "$summary_json")
- VPN RC done for phase: \`$(jq -r '.vpn_track.vpn_rc_done_for_phase' "$summary_json")\`
- Phase-0 product surface available: $(jq -r '.vpn_track.phase0_product_surface.available' "$summary_json")
- Phase-0 input summary: $(jq -r '.vpn_track.phase0_product_surface.input_summary_json // "none"' "$summary_json")
- Phase-0 source summary: $(jq -r '.vpn_track.phase0_product_surface.source_summary_json // "none"' "$summary_json")
- Phase-0 status: $(jq -r '.vpn_track.phase0_product_surface.status // "missing"' "$summary_json")
- Phase-0 rc: $(jq -r '.vpn_track.phase0_product_surface.rc // "null"' "$summary_json")
- Phase-0 dry_run: $(jq -r '.vpn_track.phase0_product_surface.dry_run | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 contract_ok: $(jq -r '.vpn_track.phase0_product_surface.contract_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 all_required_steps_ok: $(jq -r '.vpn_track.phase0_product_surface.all_required_steps_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 launcher_wiring_ok: $(jq -r '.vpn_track.phase0_product_surface.launcher_wiring_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 launcher_runtime_ok: $(jq -r '.vpn_track.phase0_product_surface.launcher_runtime_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 prompt_budget_ok: $(jq -r '.vpn_track.phase0_product_surface.prompt_budget_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 config_v1_ok: $(jq -r '.vpn_track.phase0_product_surface.config_v1_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-0 local_control_api_ok: $(jq -r '.vpn_track.phase0_product_surface.local_control_api_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-1 handoff available: $(jq -r '.vpn_track.phase1_resilience_handoff.available' "$summary_json")
- Phase-1 handoff input: $(jq -r '.vpn_track.phase1_resilience_handoff.input_summary_json // "none"' "$summary_json")
- Phase-1 handoff source: $(jq -r '.vpn_track.phase1_resilience_handoff.source_summary_json // "none"' "$summary_json")
- Phase-1 handoff source kind: $(jq -r '.vpn_track.phase1_resilience_handoff.source_summary_kind // "none"' "$summary_json")
- Phase-1 handoff status: $(jq -r '.vpn_track.phase1_resilience_handoff.status // "missing"' "$summary_json")
- Phase-1 handoff rc: $(jq -r '.vpn_track.phase1_resilience_handoff.rc // "null"' "$summary_json")
- Phase-1 profile_matrix_stable: $(jq -r '.vpn_track.phase1_resilience_handoff.profile_matrix_stable | if . == null then "null" else tostring end' "$summary_json")
- Phase-1 peer_loss_recovery_ok: $(jq -r '.vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-1 session_churn_guard_ok: $(jq -r '.vpn_track.phase1_resilience_handoff.session_churn_guard_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-1 automatable_without_sudo_or_github: $(jq -r '.vpn_track.phase1_resilience_handoff.automatable_without_sudo_or_github | if . == null then "null" else tostring end' "$summary_json")
- Phase-1 failure.kind: $(jq -r '.vpn_track.phase1_resilience_handoff.failure.kind // "null"' "$summary_json")
- Phase-1 policy_outcome.decision: $(jq -r '.vpn_track.phase1_resilience_handoff.policy_outcome.decision // "null"' "$summary_json")
- Phase-1 policy_outcome.fail_closed_no_go: $(jq -r '.vpn_track.phase1_resilience_handoff.policy_outcome.fail_closed_no_go | if . == null then "null" else tostring end' "$summary_json")
- Phase-1 failure_semantics.profile_matrix_stable.kind: $(jq -r '.vpn_track.phase1_resilience_handoff.failure_semantics.profile_matrix_stable.kind // "null"' "$summary_json")
- Phase-1 failure_semantics.peer_loss_recovery_ok.kind: $(jq -r '.vpn_track.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind // "null"' "$summary_json")
- Phase-1 failure_semantics.session_churn_guard_ok.kind: $(jq -r '.vpn_track.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind // "null"' "$summary_json")
- Non-blockchain recommended gate (no sudo/GitHub): $(jq -r '.vpn_track.non_blockchain_recommended_gate_id // "none"' "$summary_json")
- Phase-2 handoff available: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.available' "$summary_json")
- Phase-2 handoff input: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.input_summary_json // "none"' "$summary_json")
- Phase-2 handoff source: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.source_summary_json // "none"' "$summary_json")
- Phase-2 handoff source kind: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.source_summary_kind // "none"' "$summary_json")
- Phase-2 release_integrity_ok: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-2 release_policy_ok: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-2 operator_lifecycle_ok: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-2 pilot_signoff_ok: $(jq -r '.vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-3 handoff available: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.available' "$summary_json")
- Phase-3 handoff input: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.input_summary_json // "none"' "$summary_json")
- Phase-3 handoff source: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.source_summary_json // "none"' "$summary_json")
- Phase-3 handoff source kind: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.source_summary_kind // "none"' "$summary_json")
- Phase-3 handoff status: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.status // "missing"' "$summary_json")
- Phase-3 handoff rc: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.rc // "null"' "$summary_json")
- Phase-3 windows_parity_ok: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.windows_parity_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-3 desktop_contract_ok: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.desktop_contract_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-3 installer_update_ok: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.installer_update_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-3 telemetry_stability_ok: $(jq -r '.vpn_track.phase3_windows_client_beta_handoff.telemetry_stability_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-4 handoff available: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.available' "$summary_json")
- Phase-4 handoff input: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.input_summary_json // "none"' "$summary_json")
- Phase-4 handoff source: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.source_summary_json // "none"' "$summary_json")
- Phase-4 handoff source kind: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.source_summary_kind // "none"' "$summary_json")
- Phase-4 handoff status: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.status // "missing"' "$summary_json")
- Phase-4 handoff rc: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.rc // "null"' "$summary_json")
- Phase-4 windows_server_packaging_ok: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-4 windows_role_runbooks_ok: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.windows_role_runbooks_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-4 cross_platform_interop_ok: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.cross_platform_interop_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-4 role_combination_validation_ok: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.role_combination_validation_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 handoff available: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.available' "$summary_json")
- Phase-5 handoff input: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.input_summary_json // "none"' "$summary_json")
- Phase-5 handoff source: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.source_summary_json // "none"' "$summary_json")
- Phase-5 handoff source kind: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.source_summary_kind // "none"' "$summary_json")
- Phase-5 handoff status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.status // "missing"' "$summary_json")
- Phase-5 handoff rc: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.rc // "null"' "$summary_json")
- Phase-5 settlement_failsoft_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_acceptance_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_bridge_smoke_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_state_persistence_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_adapter_roundtrip_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status // "null"' "$summary_json")
- Phase-5 settlement_adapter_roundtrip_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 issuer_sponsor_api_live_smoke_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status // "null"' "$summary_json")
- Phase-5 issuer_sponsor_api_live_smoke_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Resilience handoff available: $(jq -r '.vpn_track.resilience_handoff.available' "$summary_json")
- Resilience handoff source: $(jq -r '.vpn_track.resilience_handoff.source_summary_json // "none"' "$summary_json")
- profile_matrix_stable: $(jq -r '.vpn_track.resilience_handoff.profile_matrix_stable | if . == null then "null" else tostring end' "$summary_json")
- peer_loss_recovery_ok: $(jq -r '.vpn_track.resilience_handoff.peer_loss_recovery_ok | if . == null then "null" else tostring end' "$summary_json")
- session_churn_guard_ok: $(jq -r '.vpn_track.resilience_handoff.session_churn_guard_ok | if . == null then "null" else tostring end' "$summary_json")
- Checks: total=$(jq -r '.vpn_track.counts.total_checks' "$summary_json"), pass=$(jq -r '.vpn_track.counts.pass_checks' "$summary_json"), warn=$(jq -r '.vpn_track.counts.warn_checks' "$summary_json"), fail=$(jq -r '.vpn_track.counts.fail_checks' "$summary_json"), pending=$(jq -r '.vpn_track.counts.pending_checks' "$summary_json")
- Blocking checks: $(jq -r '(.vpn_track.blocking_check_ids // []) | if length == 0 then "none" else join(",") end' "$summary_json")
- Pending real-host checks: $(jq -r '(.vpn_track.pending_real_host_checks // []) | if length == 0 then "none" else map(.check_id) | join(",") end' "$summary_json")
- Optional gate status: profile=$(jq -r '.vpn_track.optional_gate_status.profile_default_gate' "$summary_json"), docker-rehearsal=$(jq -r '.vpn_track.optional_gate_status.docker_rehearsal_gate' "$summary_json"), real-wg=$(jq -r '.vpn_track.optional_gate_status.real_wg_privileged_gate' "$summary_json")
- Primary next action: $(jq -r '.vpn_track.next_action.command // ""' "$summary_json")

## Pending Real-Host Checks

$pending_real_host_checks_md

## Blockchain Track

- Status: $(jq -r '.blockchain_track.status' "$summary_json")
- Policy: $(jq -r '.blockchain_track.policy' "$summary_json")
- Recommendation: $(jq -r '.blockchain_track.recommendation' "$summary_json")
- Phase-6 Cosmos L1 handoff available: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.available' "$summary_json")
- Phase-6 Cosmos L1 handoff input: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.input_summary_json // "none"' "$summary_json")
- Phase-6 Cosmos L1 handoff source: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.source_summary_json // "none"' "$summary_json")
- Phase-6 Cosmos L1 handoff source kind: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.source_summary_kind // "none"' "$summary_json")
- Phase-6 Cosmos L1 handoff status: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.status // "missing"' "$summary_json")
- Phase-6 Cosmos L1 handoff rc: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.rc // "null"' "$summary_json")
- Phase-6 Cosmos L1 run_pipeline_ok: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.run_pipeline_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-6 Cosmos L1 module_tx_surface_ok: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.module_tx_surface_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-6 Cosmos L1 tdpnd_grpc_runtime_smoke_ok: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-6 Cosmos L1 tdpnd_grpc_live_smoke_ok: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-6 Cosmos L1 tdpnd_grpc_auth_live_smoke_ok: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover summary available: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.available' "$summary_json")
- Phase-7 mainnet cutover summary input: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.input_summary_json // "none"' "$summary_json")
- Phase-7 mainnet cutover summary source: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.source_summary_json // "none"' "$summary_json")
- Phase-7 mainnet cutover summary source kind: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.source_summary_kind // "none"' "$summary_json")
- Phase-7 mainnet cutover summary status: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.status // "missing"' "$summary_json")
- Phase-7 mainnet cutover summary rc: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.rc // "null"' "$summary_json")
- Phase-7 mainnet cutover check_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.check_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover run_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.run_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover handoff_check_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.handoff_check_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover handoff_run_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.handoff_run_ok | if . == null then "null" else tostring end' "$summary_json")

## Next Actions

$next_actions_md

## Non-Blockchain Actionable Gates (No sudo/GitHub)

$non_blockchain_actionable_no_sudo_or_github_md

## Refresh Steps

- Manual validation refresh: $(jq -r '.refresh.manual_validation_report.status' "$summary_json") (rc=$(jq -r '.refresh.manual_validation_report.rc' "$summary_json"))
- Manual validation refresh timeout: $(jq -r '.refresh.manual_validation_report.timed_out' "$summary_json") (limit=$(jq -r '.refresh.manual_validation_report.timeout_sec' "$summary_json")s, duration=$(jq -r '.refresh.manual_validation_report.duration_sec' "$summary_json")s)
- Single-machine refresh: $(jq -r '.refresh.single_machine_prod_readiness.status' "$summary_json") (rc=$(jq -r '.refresh.single_machine_prod_readiness.rc' "$summary_json"))
- Single-machine refresh timeout: $(jq -r '.refresh.single_machine_prod_readiness.timed_out' "$summary_json") (limit=$(jq -r '.refresh.single_machine_prod_readiness.timeout_sec' "$summary_json")s, duration=$(jq -r '.refresh.single_machine_prod_readiness.duration_sec' "$summary_json")s)
- Single-machine refresh non-blocking transient: $(jq -r '.refresh.single_machine_prod_readiness.non_blocking_transient' "$summary_json")
- Single-machine refresh warning reason: $(jq -r '.refresh.single_machine_prod_readiness.non_blocking_reason // ""' "$summary_json")

## Artifacts

- Summary JSON: $(jq -r '.artifacts.summary_json' "$summary_json")
- Report Markdown: $(jq -r '.artifacts.report_md' "$summary_json")
- Manual validation summary: $(jq -r '.artifacts.manual_validation_summary_json' "$summary_json")
- Manual validation report: $(jq -r '.artifacts.manual_validation_report_md' "$summary_json")
- Single-machine summary: $(jq -r '.artifacts.single_machine_summary_json' "$summary_json")
- Phase-0 summary: $(jq -r '.artifacts.phase0_summary_json // "none"' "$summary_json")
- Phase-1 resilience handoff summary source: $(jq -r '.artifacts.phase1_resilience_handoff_summary_json // "none"' "$summary_json")
- Phase-2 candidate summary: $(jq -r '.artifacts.phase2_linux_prod_candidate_summary_json // "none"' "$summary_json")
- Phase-3 Windows client beta summary source: $(jq -r '.artifacts.phase3_windows_client_beta_summary_json // "none"' "$summary_json")
- Phase-4 Windows full parity summary source: $(jq -r '.artifacts.phase4_windows_full_parity_summary_json // "none"' "$summary_json")
- Phase-5 settlement layer summary source: $(jq -r '.artifacts.phase5_settlement_layer_summary_json // "none"' "$summary_json")
- Phase-6 Cosmos L1 summary source: $(jq -r '.artifacts.phase6_cosmos_l1_summary_json // "none"' "$summary_json")
- Phase-7 mainnet cutover summary source: $(jq -r '.artifacts.phase7_mainnet_cutover_summary_json // "none"' "$summary_json")
- VPN RC resilience summary: $(jq -r '.artifacts.vpn_rc_resilience_summary_json // "none"' "$summary_json")
EOF_MD
mv -f "$report_tmp" "$report_md"

echo "[roadmap-progress-report] status=$final_status rc=$final_rc"
echo "[roadmap-progress-report] readiness_status=$readiness_status"
echo "[roadmap-progress-report] roadmap_stage=$roadmap_stage"
echo "[roadmap-progress-report] next_action_check_id=${next_action_check_id:-}"
echo "[roadmap-progress-report] next_action_command=${next_action_command:-}"
echo "[roadmap-progress-report] manual_validation_refresh_status=$manual_refresh_status rc=$manual_refresh_rc"
echo "[roadmap-progress-report] single_machine_refresh_status=$single_machine_refresh_status rc=$single_machine_refresh_rc"
echo "[roadmap-progress-report] single_machine_refresh_non_blocking_transient=$single_machine_refresh_non_blocking_transient reason=$single_machine_refresh_non_blocking_reason"
echo "[roadmap-progress-report] manual_validation_summary_valid_after_run=$manual_summary_valid_after_run restored_from_snapshot=$manual_summary_restored"
echo "[roadmap-progress-report] single_machine_summary_valid_after_run=$single_machine_summary_valid_after_run restored_from_snapshot=$single_machine_summary_restored"
echo "[roadmap-progress-report] phase0_product_surface_available=$phase0_product_surface_available_json source_summary_json=${phase0_product_surface_source_summary_json:-} input_summary_json=${phase0_product_surface_input_summary_json:-}"
echo "[roadmap-progress-report] phase0_product_surface_status=$phase0_product_surface_status_json contract_ok=$phase0_product_surface_contract_ok_json all_required_steps_ok=$phase0_product_surface_all_required_steps_ok_json launcher_wiring_ok=$phase0_product_surface_launcher_wiring_ok_json launcher_runtime_ok=$phase0_product_surface_launcher_runtime_ok_json prompt_budget_ok=$phase0_product_surface_prompt_budget_ok_json config_v1_ok=$phase0_product_surface_config_v1_ok_json local_control_api_ok=$phase0_product_surface_local_control_api_ok_json"
echo "[roadmap-progress-report] phase1_resilience_handoff_available=$phase1_resilience_handoff_available_json source_summary_json=${phase1_resilience_handoff_source_summary_json:-} source_kind=${phase1_resilience_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase1_resilience_handoff_profile_matrix_stable=$phase1_resilience_handoff_profile_matrix_stable_json peer_loss_recovery_ok=$phase1_resilience_handoff_peer_loss_recovery_ok_json session_churn_guard_ok=$phase1_resilience_handoff_session_churn_guard_ok_json automatable_without_sudo_or_github=$phase1_resilience_handoff_automatable_without_sudo_or_github_json"
echo "[roadmap-progress-report] phase1_resilience_handoff_failure_kind=${phase1_resilience_handoff_failure_kind_json:-} policy_outcome_decision=${phase1_resilience_handoff_policy_outcome_decision_json:-} policy_outcome_fail_closed_no_go=$phase1_resilience_handoff_policy_outcome_fail_closed_no_go_json"
echo "[roadmap-progress-report] phase1_resilience_handoff_failure_semantics_profile_matrix_stable_kind=${phase1_resilience_handoff_profile_matrix_stable_failure_kind_json:-} peer_loss_recovery_ok_kind=${phase1_resilience_handoff_peer_loss_recovery_ok_failure_kind_json:-} session_churn_guard_ok_kind=${phase1_resilience_handoff_session_churn_guard_ok_failure_kind_json:-}"
echo "[roadmap-progress-report] non_blockchain_actionable_no_sudo_or_github_count=$non_blockchain_actionable_no_sudo_or_github_count recommended_gate_id=${non_blockchain_recommended_gate_id:-}"
echo "[roadmap-progress-report] phase2_linux_prod_candidate_handoff_available=$phase2_linux_prod_candidate_handoff_available_json source_summary_json=${phase2_linux_prod_candidate_handoff_source_summary_json:-}"
echo "[roadmap-progress-report] phase2_linux_prod_candidate_handoff_release_integrity_ok=$phase2_linux_prod_candidate_handoff_release_integrity_ok_json release_policy_ok=$phase2_linux_prod_candidate_handoff_release_policy_ok_json operator_lifecycle_ok=$phase2_linux_prod_candidate_handoff_operator_lifecycle_ok_json pilot_signoff_ok=$phase2_linux_prod_candidate_handoff_pilot_signoff_ok_json"
echo "[roadmap-progress-report] phase3_windows_client_beta_handoff_available=$phase3_windows_client_beta_handoff_available_json source_summary_json=${phase3_windows_client_beta_handoff_source_summary_json:-} source_kind=${phase3_windows_client_beta_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase3_windows_client_beta_handoff_windows_parity_ok=$phase3_windows_client_beta_handoff_windows_parity_ok_json desktop_contract_ok=$phase3_windows_client_beta_handoff_desktop_contract_ok_json installer_update_ok=$phase3_windows_client_beta_handoff_installer_update_ok_json telemetry_stability_ok=$phase3_windows_client_beta_handoff_telemetry_stability_ok_json"
echo "[roadmap-progress-report] phase4_windows_full_parity_handoff_available=$phase4_windows_full_parity_handoff_available_json source_summary_json=${phase4_windows_full_parity_handoff_source_summary_json:-} source_kind=${phase4_windows_full_parity_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase4_windows_full_parity_handoff_windows_server_packaging_ok=$phase4_windows_full_parity_handoff_windows_server_packaging_ok_json windows_role_runbooks_ok=$phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json cross_platform_interop_ok=$phase4_windows_full_parity_handoff_cross_platform_interop_ok_json role_combination_validation_ok=$phase4_windows_full_parity_handoff_role_combination_validation_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_available=$phase5_settlement_layer_handoff_available_json source_summary_json=${phase5_settlement_layer_handoff_source_summary_json:-} source_kind=${phase5_settlement_layer_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_failsoft_ok=$phase5_settlement_layer_handoff_settlement_failsoft_ok_json settlement_acceptance_ok=$phase5_settlement_layer_handoff_settlement_acceptance_ok_json settlement_bridge_smoke_ok=$phase5_settlement_layer_handoff_settlement_bridge_smoke_ok_json settlement_state_persistence_ok=$phase5_settlement_layer_handoff_settlement_state_persistence_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status=${phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json:-null} settlement_adapter_roundtrip_ok=$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status=${phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json:-null} issuer_sponsor_api_live_smoke_ok=$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json"
echo "[roadmap-progress-report] phase6_cosmos_l1_handoff_available=$phase6_cosmos_l1_handoff_available_json source_summary_json=${phase6_cosmos_l1_handoff_source_summary_json:-} source_kind=${phase6_cosmos_l1_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase6_cosmos_l1_handoff_status=$phase6_cosmos_l1_handoff_status_json rc=$phase6_cosmos_l1_handoff_rc_json run_pipeline_ok=$phase6_cosmos_l1_handoff_run_pipeline_ok_json module_tx_surface_ok=$phase6_cosmos_l1_handoff_module_tx_surface_ok_json tdpnd_grpc_runtime_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok_json tdpnd_grpc_live_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok_json tdpnd_grpc_auth_live_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok_json"
echo "[roadmap-progress-report] phase7_mainnet_cutover_summary_available=$phase7_mainnet_cutover_summary_available_json source_summary_json=${phase7_mainnet_cutover_summary_source_summary_json:-} source_kind=${phase7_mainnet_cutover_summary_source_summary_kind:-}"
echo "[roadmap-progress-report] phase7_mainnet_cutover_summary_status=$phase7_mainnet_cutover_summary_status_json rc=$phase7_mainnet_cutover_summary_rc_json check_ok=$phase7_mainnet_cutover_summary_check_ok_json run_ok=$phase7_mainnet_cutover_summary_run_ok_json handoff_check_ok=$phase7_mainnet_cutover_summary_handoff_check_ok_json handoff_run_ok=$phase7_mainnet_cutover_summary_handoff_run_ok_json"
echo "[roadmap-progress-report] resilience_handoff_available=$resilience_handoff_available_json source_summary_json=${resilience_handoff_source_summary_json:-}"
echo "[roadmap-progress-report] profile_matrix_stable=$resilience_profile_matrix_stable_json peer_loss_recovery_ok=$resilience_peer_loss_recovery_ok_json session_churn_guard_ok=$resilience_session_churn_guard_ok_json"
echo "[roadmap-progress-report] summary_json=$summary_json"
echo "[roadmap-progress-report] report_md=$report_md"

if [[ "$print_report" == "1" ]]; then
  echo "[roadmap-progress-report] report_markdown:"
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[roadmap-progress-report] summary_json_payload:"
  cat "$summary_json"
fi

if [[ -n "$manual_summary_snapshot" ]]; then
  rm -f "$manual_summary_snapshot" 2>/dev/null || true
fi
if [[ -n "$single_machine_summary_snapshot" ]]; then
  rm -f "$single_machine_summary_snapshot" 2>/dev/null || true
fi

exit "$final_rc"
