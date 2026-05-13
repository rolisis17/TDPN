#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/gpm_gap_scan.sh \
    [--status-doc PATH] \
    [--roadmap-summary-json PATH] \
    [--summary-json PATH] \
    [--reports-dir DIR] \
    [--print-summary-json [0|1]]

Description:
  Scans docs/gpm-productization-status.md and emits a deterministic markdown
  summary focused on In-Progress and Missing / Next roadmap gaps. When a
  roadmap summary JSON is provided, adds selected machine-readable blockers
  from the live roadmap artifact. The summary JSON includes backward-compatible
  item metadata for actionability classification.

Defaults:
  --status-doc docs/gpm-productization-status.md
  --roadmap-summary-json unset
  --reports-dir .easy-node-logs
  --summary-json <reports-dir>/gpm_gap_scan_summary.json
  --print-summary-json 0

Failure mode:
  Fails closed when the status doc is missing or malformed (for example when
  required headings are not present).
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

collapse_whitespace() {
  local value="${1:-}"
  value="$(printf '%s' "$value" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
  printf '%s' "$value"
}

normalize_heading_key() {
  local value="${1:-}"
  value="$(trim "$value")"
  value="${value,,}"
  value="$(printf '%s' "$value" | sed -E 's/[^a-z0-9]+/ /g; s/[[:space:]]+/ /g; s/^ //; s/ $//')"
  printf '%s' "$value"
}

normalize_item_text() {
  local value="${1:-}"
  value="$(collapse_whitespace "$value")"
  value="${value,,}"
  printf '%s' "$value"
}

strip_heading_markers() {
  local value="${1:-}"
  value="$(trim "$value")"
  value="${value%%#*}"
  value="${value%%:*}"
  value="$(trim "$value")"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* || "$path" =~ ^[A-Za-z]:[\\/] || "$path" == \\\\* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

display_path() {
  local path="${1:-}"
  if [[ "$path" == "$ROOT_DIR/"* ]]; then
    printf '%s' "${path#"$ROOT_DIR"/}"
  else
    printf '%s' "$path"
  fi
}

require_value_or_die() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "$flag requires a value"
    exit 2
  fi
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
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

fail_closed() {
  local message="${1:-malformed status document}"
  echo "[gpm-gap-scan] $message" >&2
  exit 1
}

need_cmd sed
need_cmd tr
need_cmd grep
need_cmd date
need_cmd mkdir
need_cmd mktemp
need_cmd mv
need_cmd cat

status_doc="${GPM_GAP_SCAN_STATUS_DOC:-$ROOT_DIR/docs/gpm-productization-status.md}"
roadmap_summary_json="${GPM_GAP_SCAN_ROADMAP_SUMMARY_JSON:-}"
reports_dir="${GPM_GAP_SCAN_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
summary_json="${GPM_GAP_SCAN_SUMMARY_JSON:-}"
summary_json_set_by_flag="0"
if [[ -n "$summary_json" ]]; then
  summary_json_set_by_flag="1"
fi
print_summary_json="${GPM_GAP_SCAN_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --status-doc)
      require_value_or_die "$1" "${2:-}"
      status_doc="${2:-}"
      shift 2
      ;;
    --status-doc=*)
      status_doc="${1#*=}"
      shift
      ;;
    --roadmap-summary-json)
      require_value_or_die "$1" "${2:-}"
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-summary-json=*)
      roadmap_summary_json="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      summary_json_set_by_flag="1"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      summary_json_set_by_flag="1"
      shift
      ;;
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
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
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"

status_doc="$(abs_path "$status_doc")"
if [[ -n "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
fi
reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/gpm_gap_scan_summary.json"
fi
summary_json="$(abs_path "$summary_json")"

[[ -f "$status_doc" ]] || fail_closed "status doc missing: $status_doc"
if [[ -n "$roadmap_summary_json" && ! -f "$roadmap_summary_json" ]]; then
  fail_closed "roadmap summary JSON missing: $roadmap_summary_json"
fi
if [[ -n "$roadmap_summary_json" ]]; then
  need_cmd jq
fi

declare -a ITEM_SECTIONS=()
declare -a ITEM_TEXTS=()
declare -a ITEM_NORMALIZED_TEXTS=()
declare -a ITEM_SEVERITIES=()
declare -a ITEM_RECOMMENDED_ACTIONS=()
declare -a ITEM_CLOSURE_MODES=()
declare -a ITEM_BLOCKED_BYS=()
declare -a ITEM_REQUIRES_REAL_HOSTS=()
declare -a ITEM_SUGGESTED_TESTS=()
declare -a ITEM_SUGGESTED_FILES=()
declare -a ITEM_ACTIONABLES=()

in_progress_count=0
missing_next_count=0
saw_in_progress=0
saw_missing_next=0
current_section=""
pending_section=""
pending_text=""
line_number=0

flush_pending_item() {
  local item_clean=""
  local item_normalized=""
  item_clean="$(collapse_whitespace "$pending_text")"
  if [[ -n "$pending_section" && -n "$item_clean" ]]; then
    ITEM_SECTIONS+=("$pending_section")
    ITEM_TEXTS+=("$item_clean")
    item_normalized="$(normalize_item_text "$item_clean")"
    ITEM_NORMALIZED_TEXTS+=("$item_normalized")
    ITEM_SEVERITIES+=("$(infer_item_severity "$pending_section" "$item_normalized")")
    ITEM_RECOMMENDED_ACTIONS+=("$(infer_item_recommended_action "$pending_section" "$item_normalized")")
    ITEM_CLOSURE_MODES+=("$(infer_item_closure_mode "$pending_section" "$item_normalized")")
    ITEM_BLOCKED_BYS+=("$(infer_item_blocked_by "$pending_section" "$item_normalized")")
    ITEM_REQUIRES_REAL_HOSTS+=("$(infer_item_requires_real_hosts "$pending_section" "$item_normalized")")
    ITEM_SUGGESTED_TESTS+=("$(infer_item_suggested_tests "$pending_section" "$item_normalized")")
    ITEM_SUGGESTED_FILES+=("$(infer_item_suggested_files "$pending_section" "$item_normalized")")
    ITEM_ACTIONABLES+=("$(infer_item_actionable "$pending_section" "$item_normalized")")
    if [[ "$pending_section" == "in_progress" ]]; then
      in_progress_count=$((in_progress_count + 1))
    elif [[ "$pending_section" == "missing_next" ]]; then
      missing_next_count=$((missing_next_count + 1))
    fi
  fi
  pending_section=""
  pending_text=""
}

append_gap_item() {
  local section="$1"
  local item_clean="$2"
  local item_normalized=""
  item_clean="$(collapse_whitespace "$item_clean")"
  if [[ -z "$section" || -z "$item_clean" ]]; then
    return 0
  fi
  ITEM_SECTIONS+=("$section")
  ITEM_TEXTS+=("$item_clean")
  item_normalized="$(normalize_item_text "$item_clean")"
  ITEM_NORMALIZED_TEXTS+=("$item_normalized")
  ITEM_SEVERITIES+=("$(infer_item_severity "$section" "$item_normalized")")
  ITEM_RECOMMENDED_ACTIONS+=("$(infer_item_recommended_action "$section" "$item_normalized")")
  ITEM_CLOSURE_MODES+=("$(infer_item_closure_mode "$section" "$item_normalized")")
  ITEM_BLOCKED_BYS+=("$(infer_item_blocked_by "$section" "$item_normalized")")
  ITEM_REQUIRES_REAL_HOSTS+=("$(infer_item_requires_real_hosts "$section" "$item_normalized")")
  ITEM_SUGGESTED_TESTS+=("$(infer_item_suggested_tests "$section" "$item_normalized")")
  ITEM_SUGGESTED_FILES+=("$(infer_item_suggested_files "$section" "$item_normalized")")
  ITEM_ACTIONABLES+=("$(infer_item_actionable "$section" "$item_normalized")")
  if [[ "$section" == "in_progress" ]]; then
    in_progress_count=$((in_progress_count + 1))
  elif [[ "$section" == "missing_next" ]]; then
    missing_next_count=$((missing_next_count + 1))
  fi
}

is_informational_gap_item() {
  local normalized_text="${1:-}"
  if [[ "$normalized_text" == "tooling note:"* \
     || "$normalized_text" == "tooling note "* \
     || "$normalized_text" == "operator note:"* \
     || "$normalized_text" == "operator note "* \
     || "$normalized_text" == "compatibility note:"* \
     || "$normalized_text" == "compatibility note "* ]]; then
    return 0
  fi
  return 1
}

is_auth_wallet_gap_item() {
  local normalized_text="${1:-}"
  if [[ "$normalized_text" == *"auth hardening"* \
     || "$normalized_text" == *"keplr"* \
     || "$normalized_text" == *"leap"* \
     || ( "$normalized_text" == *"wallet-extension"* && "$normalized_text" == *"secp256k1"* ) \
     || ( "$normalized_text" == *"wallet extension"* && "$normalized_text" == *"secp256k1"* ) ]]; then
    return 0
  fi
  return 1
}

is_profile_default_subject_gap_item() {
  local normalized_text="${1:-}"
  if [[ "$normalized_text" == *"invite_key"* \
     || "$normalized_text" == *"campaign-subject"* \
     || "$normalized_text" == *"campaign subject"* \
     || "$normalized_text" == *"profile-default"* ]]; then
    return 0
  fi
  return 1
}

is_reservation_evidence_gap_item() {
  local normalized_text="${1:-}"
  if [[ "$normalized_text" == *"reservation-write"* \
     || "$normalized_text" == *"reservation write"* \
     || "$normalized_text" == *"vpnbilling/reservations"* \
     || "$normalized_text" == *"reserve-and-connect"* \
     || ( "$normalized_text" == *"reservefunds"* && "$normalized_text" == *"chain"* ) \
     || ( "$normalized_text" == *"api-to-chain"* && "$normalized_text" == *"reservation"* ) \
     || ( "$normalized_text" == *"api-to-chain"* && "$normalized_text" == *"reserve"* ) ]]; then
    return 0
  fi
  return 1
}

is_real_host_validation_gap_item() {
  local normalized_text="${1:-}"
  if [[ "$normalized_text" == *"real-host"* \
     || "$normalized_text" == *"real host"* \
     || "$normalized_text" == *"live conditions"* \
     || "$normalized_text" == *"live/published evidence"* \
     || "$normalized_text" == *"real scheduler"* \
     || "$normalized_text" == *"end-to-end validation artifacts"* ]]; then
    return 0
  fi
  return 1
}

is_access_recovery_gap_item() {
  local normalized_text="${1:-}"
  if [[ "$normalized_text" == *"access recovery"* \
     || "$normalized_text" == *"access-recovery"* \
     || "$normalized_text" == *"trusted verifier receipt"* \
     || "$normalized_text" == *"trusted_pilot_receipt_ready"* \
     || "$normalized_text" == *"verifier_pilot_handoff_ready"* \
     || "$normalized_text" == *"pilot handoff"* \
     || "$normalized_text" == *"pilot_handoff_ready"* ]]; then
    return 0
  fi
  return 1
}

infer_item_actionable() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' "false"
    return
  fi
  printf '%s' "true"
}

infer_item_severity() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' "p3"
    return
  fi
  if [[ "$normalized_text" == *"blocked"* \
     || "$normalized_text" == *"blocker"* \
     || "$normalized_text" == *"no-go"* \
     || "$normalized_text" == *"unresolved"* \
     || "$normalized_text" == *"cannot"* \
     || "$normalized_text" == *"failed"* \
     || "$normalized_text" == *"missing"* ]]; then
    printf '%s' "p1"
    return
  fi
  if [[ "$normalized_text" == *"validation debt"* \
     || "$normalized_text" == *"partial"* \
     || "$normalized_text" == *"in progress"* \
     || "$section" == "missing_next" ]]; then
    printf '%s' "p2"
    return
  fi
  printf '%s' "p3"
}

infer_item_recommended_action() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' "No direct closure action; use this note as operator guidance for related roadmap blockers."
    return
  fi
  if is_access_recovery_gap_item "$normalized_text"; then
    printf '%s' "Complete Access Recovery real-helper evidence and trusted verifier receipt, then refresh roadmap handoff state."
    return
  fi
  local reservation_signal="0"
  if is_reservation_evidence_gap_item "$normalized_text"; then
    reservation_signal="1"
  fi
  local proof_signal="0"
  if [[ ( "$normalized_text" == *"reward proof"* || "$normalized_text" == *"objective proof"* || "$normalized_text" == *"proof reference"* || "$normalized_text" == *"proof-reference"* || "$normalized_text" == *"proof-validation"* || "$normalized_text" == *"proof verification"* || "$normalized_text" == *"proof-registry"* ) \
     && ( "$normalized_text" == *"trust"* || "$normalized_text" == *"shape"* || "$normalized_text" == *"unverified"* || "$normalized_text" == *"verification"* || "$normalized_text" == *"registry"* || "$normalized_text" == *"blocked"* || "$normalized_text" == *"signoff"* ) ]]; then
    proof_signal="1"
  fi
  local confirmation_signal="0"
  if [[ ( "$normalized_text" == *"confirmation"* || "$normalized_text" == *"confirmed"* || "$normalized_text" == *"reconcile"* || "$normalized_text" == *"chain state"* || "$normalized_text" == *"chain-status"* || "$normalized_text" == *"chain status"* ) \
     && ( "$normalized_text" == *"existence"* || "$normalized_text" == *"pending"* || "$normalized_text" == *"submitted"* || "$normalized_text" == *"promot"* || "$normalized_text" == *"final"* ) ]]; then
    confirmation_signal="1"
  fi
  if [[ "$reservation_signal" == "1" && ( "$proof_signal" == "1" || "$confirmation_signal" == "1" ) ]]; then
    printf '%s' "Close live-chain reservation evidence, objective proof verification, and finalized chain confirmation before payout signoff."
    return
  fi
  if [[ "$reservation_signal" == "1" ]]; then
    if [[ "$normalized_text" == *"still missing"* \
       || "$normalized_text" == *"api subject_id reservation binding"* \
       || "$normalized_text" == *"add authenticated local gpm reservefunds"* \
       || "$normalized_text" == *"local gpm api"* && "$normalized_text" == *"missing"* ]]; then
      printf '%s' "Wire the local GPM ReserveFunds API path, then archive API-to-chain reservation evidence."
      return
    fi
    printf '%s' "Archive API-to-chain ReserveFunds reservation evidence, then rerun live bridge reservation/settlement smoke."
    return
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"anti-downgrade"* || "$normalized_text" == *"downgrad"* || "$normalized_text" == *"path/profile"* || "$normalized_text" == *"strict"* ) ]]; then
    printf '%s' "Close M3 exit-side anti-downgrade binding with path/profile/middle assertions and focused route tests."
    return
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"middle relay"* || "$normalized_text" == *"middle role"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"production"* || "$normalized_text" == *"control-plane"* || "$normalized_text" == *"data service"* || "$normalized_text" == *"service contract"* || "$normalized_text" == *"deployment"* || "$normalized_text" == *"admission policy"* ) ]]; then
    printf '%s' "Validate the local production middle role contract, then publish real-host middle-hop evidence and deployment admission policy."
    return
  fi
  if [[ ( "$normalized_text" == *"reward proof"* || "$normalized_text" == *"objective proof"* || "$normalized_text" == *"proof reference"* || "$normalized_text" == *"proof-reference"* || "$normalized_text" == *"proof-validation"* || "$normalized_text" == *"proof verification"* || "$normalized_text" == *"proof-registry"* ) \
     && ( "$normalized_text" == *"trust"* || "$normalized_text" == *"shape"* || "$normalized_text" == *"unverified"* || "$normalized_text" == *"verification"* || "$normalized_text" == *"registry"* || "$normalized_text" == *"blocked"* ) ]]; then
    printf '%s' "Promote reward/slashing proof references from shape checks to objective proof registry verification before payout signoff."
    return
  fi
  if [[ ( "$normalized_text" == *"confirmation"* || "$normalized_text" == *"confirmed"* || "$normalized_text" == *"reconcile"* || "$normalized_text" == *"chain state"* || "$normalized_text" == *"chain-status"* || "$normalized_text" == *"chain status"* ) \
     && ( "$normalized_text" == *"existence"* || "$normalized_text" == *"pending"* || "$normalized_text" == *"submitted"* || "$normalized_text" == *"promot"* || "$normalized_text" == *"final"* ) ]]; then
    printf '%s' "Require finalized chain status during settlement reconciliation; do not promote submitted records from existence alone."
    return
  fi
  if [[ ( "$normalized_text" == *"replay guard"* || "$normalized_text" == *"replay-guard"* || "$normalized_text" == *"replay storage"* || "$normalized_text" == *"replay-storage"* || "$normalized_text" == *"replay cache"* || "$normalized_text" == *"replay-cache"* ) \
     && ( "$normalized_text" == *"durable"* || "$normalized_text" == *"strict"* || "$normalized_text" == *"multi-instance"* || "$normalized_text" == *"production"* ) ]]; then
    printf '%s' "Require durable shared replay storage for strict production exit deployments and add restart/multi-instance regressions."
    return
  fi
  if [[ "$normalized_text" == *"invite_key"* \
     || "$normalized_text" == *"campaign-subject"* \
     || "$normalized_text" == *"campaign subject"* \
     || "$normalized_text" == *"a_host"* \
     || "$normalized_text" == *"b_host"* ]]; then
    printf '%s' "Populate A_HOST/B_HOST and campaign subject, then rerun profile-default gate cycle."
    return
  fi
  if [[ "$normalized_text" == *"vm command"* \
     || "$normalized_text" == *"--vm-command"* \
     || "$normalized_text" == *"multi-vm"* ]]; then
    printf '%s' "Set --vm-command/--vm-command-file and rerun multi-VM stability cycle + promotion evidence pack."
    return
  fi
  if [[ "$normalized_text" == *"runtime-actuation"* \
     || "$normalized_text" == *"promotion"* ]]; then
    printf '%s' "Rerun runtime-actuation promotion cycle until thresholds pass, then publish evidence pack."
    return
  fi
  if [[ "$normalized_text" == *"evidence pack"* \
     || "$normalized_text" == *"publish"* ]]; then
    printf '%s' "Generate and publish deterministic evidence-pack artifacts with fail-closed checks."
    return
  fi
  if [[ "$normalized_text" == *"real-host"* ]]; then
    printf '%s' "Capture real-host validation artifacts and attach them to the promoted summary path."
    return
  fi
  if [[ "$normalized_text" == *"direct-exit fallback"* \
     || "$normalized_text" == *"direct exit fallback"* \
     || "$normalized_text" == *"explicit 1hop"* \
     || ( "$normalized_text" == *"route hardening"* && "$normalized_text" == *"fallback"* ) ]]; then
    printf '%s' "Close the direct-exit fallback ambiguity with a fail-closed runtime gate and profile contract regression."
    return
  fi
  if is_auth_wallet_gap_item "$normalized_text"; then
    printf '%s' "Archive Keplr/Leap wallet-extension auth evidence for secp256k1 binding and mismatched-wallet rejection."
    return
  fi
  if ! is_auth_wallet_gap_item "$normalized_text" && [[ "$normalized_text" == *"admin console"* \
     || "$normalized_text" == *"admin"* \
     || "$normalized_text" == *"settlement"* \
     || "$normalized_text" == *"payout"* \
     || "$normalized_text" == *"slashing"* \
     || "$normalized_text" == *"slash"* \
     || "$normalized_text" == *"dispute"* \
     || "$normalized_text" == *"finalization"* \
     || "$normalized_text" == *"finalize"* ]]; then
    printf '%s' "Run Admin Console settlement/slashing validation, then archive live-chain payout evidence."
    return
  fi
  if [[ "$section" == "missing_next" ]]; then
    printf '%s' "Close this missing/next gap with one deterministic command and summary artifact."
    return
  fi
  printf '%s' "Continue implementation and refresh summary artifacts for this in-progress item."
}

infer_item_closure_mode() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' "local_only"
    return
  fi
  if [[ "$normalized_text" == *"a_host"* \
     || "$normalized_text" == *"b_host"* \
     || "$normalized_text" == *"vm command"* \
     || "$normalized_text" == *"--vm-command"* \
     || "$normalized_text" == *"multi-vm"* ]] \
     || is_access_recovery_gap_item "$normalized_text" \
     || is_real_host_validation_gap_item "$normalized_text"; then
    printf '%s' "real_host_required"
    return
  fi
  if [[ "$normalized_text" == *"runtime-actuation"* \
     || "$normalized_text" == *"promotion cycle"* \
     || "$normalized_text" == *"live stability"* \
     || "$normalized_text" == *"live wg"* \
     || "$normalized_text" == *"wireguard"* \
     || "$normalized_text" == *"network"* \
     || "$normalized_text" == *"live chain"* \
     || "$normalized_text" == *"chain-bound"* \
     || "$normalized_text" == *"chain settlement"* \
     || "$normalized_text" == *"proof registry"* \
     || "$normalized_text" == *"proof-registry"* \
     || "$normalized_text" == *"proof verification"* \
     || "$normalized_text" == *"cosmos"* ]]; then
    printf '%s' "network_required"
    return
  fi
  printf '%s' "local_only"
}

infer_item_blocked_by() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  local blockers=()
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' ""
    return
  fi
  if [[ "$normalized_text" == *"unresolved placeholder"* \
     || "$normalized_text" == *"placeholder_unresolved=true"* \
     || "$normalized_text" == *"invite_key"* \
     || "$normalized_text" == *"campaign-subject"* \
     || "$normalized_text" == *"a_host"* \
     || "$normalized_text" == *"b_host"* ]]; then
    blockers+=("unresolved_placeholders")
  fi
  if [[ "$normalized_text" == *"a_host"* \
     || "$normalized_text" == *"b_host"* ]] \
     || is_real_host_validation_gap_item "$normalized_text"; then
    blockers+=("real_hosts")
  fi
  if [[ "$normalized_text" == *"vm command"* \
     || "$normalized_text" == *"--vm-command"* \
     || "$normalized_text" == *"multi-vm"* ]]; then
    blockers+=("vm_command_source")
  fi
  if [[ "$normalized_text" == *"runtime-actuation"* \
     || "$normalized_text" == *"promotion is not green"* \
     || "$normalized_text" == *"decision=no-go"* \
     || "$normalized_text" == *"threshold"* ]]; then
    blockers+=("promotion_thresholds")
  fi
  if [[ "$normalized_text" == *"live stability"* \
     || "$normalized_text" == *"live wg"* \
     || "$normalized_text" == *"wireguard"* \
     || "$normalized_text" == *"network"* ]]; then
    blockers+=("network")
  fi
  if [[ "$normalized_text" == *"direct-exit fallback"* \
     || "$normalized_text" == *"direct exit fallback"* \
     || "$normalized_text" == *"explicit 1hop"* \
     || ( "$normalized_text" == *"route hardening"* && "$normalized_text" == *"fallback"* ) \
     || ( ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
       && ( "$normalized_text" == *"anti-downgrade"* || "$normalized_text" == *"downgrad"* || "$normalized_text" == *"path/profile"* || "$normalized_text" == *"strict"* ) ) \
     || ( ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"middle relay"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
       && ( "$normalized_text" == *"production"* || "$normalized_text" == *"control-plane"* || "$normalized_text" == *"data service"* || "$normalized_text" == *"service contract"* ) ) ]]; then
    blockers+=("route_policy")
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"middle relay"* || "$normalized_text" == *"middle role"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"production"* || "$normalized_text" == *"control-plane"* || "$normalized_text" == *"data service"* || "$normalized_text" == *"service contract"* ) \
     && "$normalized_text" != *"available via go run ./cmd/node --middle"* \
     && "$normalized_text" != *"production middle role"* \
     && "$normalized_text" != *"local middle role"* ]]; then
    blockers+=("middle_service_contract")
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"middle relay"* || "$normalized_text" == *"middle role"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"deployment"* || "$normalized_text" == *"admission policy"* ) ]]; then
    blockers+=("production_admission_policy")
  fi
  if [[ "$normalized_text" == *"evidence pack"* \
     || "$normalized_text" == *"evidence-pack"* \
     || "$normalized_text" == *"capture/publish"* \
     || "$normalized_text" == *"published evidence"* \
     || "$normalized_text" == *"validation artifacts"* ]]; then
    blockers+=("evidence_pack_artifacts")
  fi
  if is_auth_wallet_gap_item "$normalized_text"; then
    blockers+=("wallet_extension_evidence")
  fi
  if is_access_recovery_gap_item "$normalized_text"; then
    blockers+=("access_recovery_handoff")
    if [[ "$normalized_text" == *"real helper"* \
       || "$normalized_text" == *"real-helper"* \
       || "$normalized_text" == *"https"* \
       || "$normalized_text" == *"installed-host"* \
       || "$normalized_text" == *"installed host"* ]]; then
      blockers+=("real_helper_evidence")
    fi
    if [[ "$normalized_text" == *"trusted verifier"* \
       || "$normalized_text" == *"trusted_pilot_receipt_ready"* \
       || "$normalized_text" == *"verifier_pilot_handoff_ready"* ]]; then
      blockers+=("trusted_verifier_receipt")
    fi
  fi
  if ! is_auth_wallet_gap_item "$normalized_text" && [[ "$normalized_text" == *"admin console"* \
     || "$normalized_text" == *"admin"* \
     || "$normalized_text" == *"settlement"* \
     || "$normalized_text" == *"payout"* \
     || "$normalized_text" == *"slashing"* \
     || "$normalized_text" == *"slash"* \
     || "$normalized_text" == *"dispute"* \
     || "$normalized_text" == *"finalization"* \
     || "$normalized_text" == *"finalize"* ]]; then
    blockers+=("admin_settlement_validation")
  fi
  if is_reservation_evidence_gap_item "$normalized_text"; then
    blockers+=("local_api_reservation_evidence")
  fi
  if [[ ( "$normalized_text" == *"reward proof"* || "$normalized_text" == *"objective proof"* || "$normalized_text" == *"proof reference"* || "$normalized_text" == *"proof-reference"* || "$normalized_text" == *"proof-validation"* || "$normalized_text" == *"proof verification"* || "$normalized_text" == *"proof-registry"* ) \
     && ( "$normalized_text" == *"trust"* || "$normalized_text" == *"shape"* || "$normalized_text" == *"unverified"* || "$normalized_text" == *"verification"* || "$normalized_text" == *"registry"* || "$normalized_text" == *"blocked"* ) ]]; then
    blockers+=("objective_proof_verification")
  fi
  if [[ ( "$normalized_text" == *"confirmation"* || "$normalized_text" == *"confirmed"* || "$normalized_text" == *"reconcile"* || "$normalized_text" == *"chain state"* || "$normalized_text" == *"chain-status"* || "$normalized_text" == *"chain status"* ) \
     && ( "$normalized_text" == *"existence"* || "$normalized_text" == *"pending"* || "$normalized_text" == *"submitted"* || "$normalized_text" == *"promot"* || "$normalized_text" == *"final"* ) ]]; then
    blockers+=("chain_confirmation_status")
  fi
  if [[ ( "$normalized_text" == *"replay guard"* || "$normalized_text" == *"replay-guard"* || "$normalized_text" == *"replay storage"* || "$normalized_text" == *"replay-storage"* || "$normalized_text" == *"replay cache"* || "$normalized_text" == *"replay-cache"* ) \
     && ( "$normalized_text" == *"durable"* || "$normalized_text" == *"strict"* || "$normalized_text" == *"multi-instance"* || "$normalized_text" == *"production"* ) ]]; then
    blockers+=("durable_replay_storage")
  fi
  if [[ "$normalized_text" == *"live chain"* \
     || "$normalized_text" == *"chain-bound"* \
     || "$normalized_text" == *"chain settlement"* \
     || "$normalized_text" == *"proof registry"* \
     || "$normalized_text" == *"proof-registry"* \
     || "$normalized_text" == *"proof verification"* \
     || "$normalized_text" == *"reservation-write"* \
     || "$normalized_text" == *"reservation write"* \
     || "$normalized_text" == *"vpnbilling/reservations"* \
     || "$normalized_text" == *"cosmos"* ]]; then
    blockers+=("live_chain")
  fi
  if (( ${#blockers[@]} > 0 )); then
    local IFS=","
    printf '%s' "${blockers[*]}"
    return
  fi
  printf '%s' ""
}

infer_item_requires_real_hosts() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  local closure_mode
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' "false"
    return
  fi
  closure_mode="$(infer_item_closure_mode "$section" "$normalized_text")"
  if [[ "$closure_mode" == "real_host_required" ]]; then
    printf '%s' "true"
  else
    printf '%s' "false"
  fi
}

infer_item_suggested_tests() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  local tests=()
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' ""
    return
  fi
  if is_auth_wallet_gap_item "$normalized_text"; then
    tests+=("scripts/gpm_wallet_auth_evidence.sh --print-summary-json 1")
    tests+=("go test ./services/localapi -run 'GPM.*Auth|Wallet|Keplr|Leap|Secp' -count=1")
  fi
  if is_profile_default_subject_gap_item "$normalized_text"; then
    tests+=("scripts/integration_client_vpn_path_profile_wiring.sh")
  fi
  if is_access_recovery_gap_item "$normalized_text"; then
    tests+=("scripts/access_recovery_real_helper_evidence_run.sh")
    tests+=("scripts/access_bridge_pilot_evidence_bundle_verify.sh")
  fi
  if [[ "$normalized_text" == *"vm command"* \
     || "$normalized_text" == *"--vm-command"* \
     || "$normalized_text" == *"multi-vm"* ]]; then
    tests+=("scripts/integration_3machine_prod_wg_validate.sh")
  fi
  if [[ "$normalized_text" == *"runtime-actuation"* \
     || "$normalized_text" == *"promotion"* \
     || "$normalized_text" == *"live wg"* \
     || "$normalized_text" == *"wireguard"* ]]; then
    tests+=("scripts/integration_client_3hop_runtime.sh")
    tests+=("scripts/integration_live_wg_full_path_strict.sh")
  fi
  if [[ "$normalized_text" == *"direct-exit fallback"* \
     || "$normalized_text" == *"direct exit fallback"* \
     || "$normalized_text" == *"explicit 1hop"* \
     || ( "$normalized_text" == *"route hardening"* && "$normalized_text" == *"fallback"* ) ]]; then
    tests+=("go test ./internal/app -run 'DirectExitFallback|ValidateRuntimeConfig' -count=1")
    tests+=("scripts/integration_client_vpn_path_profile_wiring.sh")
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"anti-downgrade"* || "$normalized_text" == *"downgrad"* || "$normalized_text" == *"path/profile"* || "$normalized_text" == *"strict"* ) ]]; then
    tests+=("go test ./internal/app ./services/entry -run 'PathOpen|3Hop|Middle|Profile|Downgrade' -count=1")
    tests+=("scripts/integration_client_3hop_runtime.sh")
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"middle relay"* || "$normalized_text" == *"middle role"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"production"* || "$normalized_text" == *"control-plane"* || "$normalized_text" == *"data service"* || "$normalized_text" == *"service contract"* || "$normalized_text" == *"deployment"* || "$normalized_text" == *"admission policy"* ) ]]; then
    tests+=("go test ./services/middle ./services/entry ./services/exit -run 'Middle|Relay|Ready|Stats|PathOpen|ServiceContract' -count=1")
    tests+=("scripts/integration_middle_service_contract.sh")
    tests+=("scripts/integration_client_3hop_runtime.sh")
  fi
  if [[ "$normalized_text" == *"evidence pack"* \
     || "$normalized_text" == *"evidence-pack"* \
     || "$normalized_text" == *"publish"* ]]; then
    tests+=("scripts/integration_roadmap_progress_report.sh")
  fi
  if ! is_auth_wallet_gap_item "$normalized_text" && [[ "$normalized_text" == *"admin console"* \
     || "$normalized_text" == *"admin"* \
     || "$normalized_text" == *"settlement"* \
     || "$normalized_text" == *"reservation-write"* \
     || "$normalized_text" == *"reservation write"* \
     || "$normalized_text" == *"vpnbilling/reservations"* \
     || "$normalized_text" == *"payout"* \
     || "$normalized_text" == *"slashing"* \
     || "$normalized_text" == *"slash"* \
     || "$normalized_text" == *"dispute"* \
     || "$normalized_text" == *"finalization"* \
     || "$normalized_text" == *"finalize"* ]]; then
    tests+=("scripts/gpm_admin_settlement_live_evidence.sh --start-local-tdpnd 1 --print-summary-json 1")
    tests+=("scripts/integration_gpm_admin_settlement_contract.sh")
    tests+=("go test ./services/localapi -run GPMAdminRewardFinalize -count=1")
    tests+=("go test ./pkg/settlement -run 'IssueReward|SubmitSlashEvidence' -count=1")
  fi
  if is_reservation_evidence_gap_item "$normalized_text"; then
    tests+=("go test ./services/localapi -run 'ReserveFunds|SettlementReservation|GPM.*Reservation' -count=1")
    tests+=("go test ./pkg/settlement -run 'ReserveFunds|CosmosAdapter' -count=1")
    tests+=("go test ./blockchain/tdpn-chain/cmd/tdpnd -run 'Settlement.*Reservation|BillingReservation' -count=1")
  fi
  if [[ ( "$normalized_text" == *"reward proof"* || "$normalized_text" == *"objective proof"* || "$normalized_text" == *"proof reference"* || "$normalized_text" == *"proof-reference"* || "$normalized_text" == *"proof-validation"* || "$normalized_text" == *"proof verification"* || "$normalized_text" == *"proof-registry"* ) \
     && ( "$normalized_text" == *"trust"* || "$normalized_text" == *"shape"* || "$normalized_text" == *"unverified"* || "$normalized_text" == *"verification"* || "$normalized_text" == *"registry"* || "$normalized_text" == *"blocked"* ) ]]; then
    tests+=("go test ./pkg/settlement -run 'IssueReward|Proof|Objective|FinalizeWeekly' -count=1")
    tests+=("go test ./services/localapi -run 'GPMAdminRewardFinalize|RewardProof' -count=1")
    tests+=("go test ./blockchain/tdpn-chain/cmd/tdpnd -run 'Reward|Proof|Settlement' -count=1")
  fi
  if [[ ( "$normalized_text" == *"confirmation"* || "$normalized_text" == *"confirmed"* || "$normalized_text" == *"reconcile"* || "$normalized_text" == *"chain state"* || "$normalized_text" == *"chain-status"* || "$normalized_text" == *"chain status"* ) \
     && ( "$normalized_text" == *"existence"* || "$normalized_text" == *"pending"* || "$normalized_text" == *"submitted"* || "$normalized_text" == *"promot"* || "$normalized_text" == *"final"* ) ]]; then
    tests+=("go test ./pkg/settlement -run 'Reconcile|Confirmation|Pending|Submitted' -count=1")
    tests+=("go test ./services/localapi -run 'Reconcile|RewardFinalize' -count=1")
  fi
  if [[ ( "$normalized_text" == *"replay guard"* || "$normalized_text" == *"replay-guard"* || "$normalized_text" == *"replay storage"* || "$normalized_text" == *"replay-storage"* || "$normalized_text" == *"replay cache"* || "$normalized_text" == *"replay-cache"* ) \
     && ( "$normalized_text" == *"durable"* || "$normalized_text" == *"strict"* || "$normalized_text" == *"multi-instance"* || "$normalized_text" == *"production"* ) ]]; then
    tests+=("go test ./services/exit -run 'Replay|Guard|Durable|Strict' -count=1")
    tests+=("scripts/integration_live_wg_full_path_strict.sh")
  fi
  if (( ${#tests[@]} > 0 )); then
    dedupe_csv_from_args "${tests[@]}"
    return
  fi
  printf '%s' ""
}

infer_item_suggested_files() {
  local section="${1:-}"
  local normalized_text="${2:-}"
  local files=("docs/gpm-productization-status.md")
  if is_informational_gap_item "$normalized_text"; then
    printf '%s' "docs/gpm-productization-status.md"
    return
  fi
  if is_auth_wallet_gap_item "$normalized_text"; then
    files+=("docs/local-control-api.md")
    files+=("scripts/gpm_wallet_auth_evidence.sh")
    files+=("services/localapi/gpm_api.go")
    files+=("services/localapi/gpm_api_test.go")
  fi
  if [[ "$normalized_text" == *"roadmap"* \
     || "$normalized_text" == *"promotion"* \
     || "$normalized_text" == *"evidence pack"* \
     || "$normalized_text" == *"evidence-pack"* ]] \
     || is_access_recovery_gap_item "$normalized_text"; then
    files+=("docs/global-privacy-mesh-track.md")
    files+=("docs/product-roadmap.md")
  fi
  if is_access_recovery_gap_item "$normalized_text"; then
    files+=("docs/access-recovery-toolkit-track.md")
    files+=("docs/access-recovery-operator-runbook.md")
    files+=("scripts/access_recovery_real_helper_evidence_run.sh")
    files+=("scripts/access_bridge_pilot_evidence_bundle_verify.sh")
    files+=("scripts/roadmap_progress_report.sh")
  fi
  if [[ "$normalized_text" == *"profile-default"* \
     || "$normalized_text" == *"profile compare"* \
     || "$normalized_text" == *"multi-vm"* ]]; then
    files+=("scripts/profile_compare_local.sh")
  fi
  if [[ "$normalized_text" == *"vm command"* \
     || "$normalized_text" == *"--vm-command"* \
     || "$normalized_text" == *"real-host"* \
     || "$normalized_text" == *"real host"* ]] \
     || is_real_host_validation_gap_item "$normalized_text"; then
    files+=("scripts/integration_3machine_prod_wg_validate.sh")
  fi
  if [[ "$normalized_text" == *"runtime-actuation"* \
     || "$normalized_text" == *"live wg"* \
     || "$normalized_text" == *"wireguard"* ]]; then
    files+=("scripts/integration_client_3hop_runtime.sh")
  fi
  if [[ "$normalized_text" == *"direct-exit fallback"* \
     || "$normalized_text" == *"direct exit fallback"* \
     || "$normalized_text" == *"explicit 1hop"* \
     || ( "$normalized_text" == *"route hardening"* && "$normalized_text" == *"fallback"* ) ]]; then
    files+=("internal/app/client.go")
    files+=("internal/app/client_mode_test.go")
    files+=("scripts/integration_client_vpn_path_profile_wiring.sh")
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"anti-downgrade"* || "$normalized_text" == *"downgrad"* || "$normalized_text" == *"path/profile"* || "$normalized_text" == *"strict"* ) ]]; then
    files+=("internal/app/client.go")
    files+=("internal/app/selection_test.go")
    files+=("services/entry/service.go")
    files+=("services/entry/path_open_test.go")
    files+=("scripts/integration_client_3hop_runtime.sh")
  fi
  if [[ ( "$normalized_text" == *"middle-hop"* || "$normalized_text" == *"middle hop"* || "$normalized_text" == *"middle relay"* || "$normalized_text" == *"middle role"* || "$normalized_text" == *"3-hop"* || "$normalized_text" == *"3hop"* ) \
     && ( "$normalized_text" == *"production"* || "$normalized_text" == *"control-plane"* || "$normalized_text" == *"data service"* || "$normalized_text" == *"service contract"* || "$normalized_text" == *"deployment"* || "$normalized_text" == *"admission policy"* ) ]]; then
    files+=("services/middle/service.go")
    files+=("services/middle/service_test.go")
    files+=("services/entry/service.go")
    files+=("services/exit/service.go")
    files+=("internal/app/client.go")
    files+=("scripts/integration_middle_service_contract.sh")
    files+=("scripts/integration_client_3hop_runtime.sh")
  fi
  if [[ "$normalized_text" == *"evidence pack"* \
     || "$normalized_text" == *"evidence-pack"* \
     || "$normalized_text" == *"publish"* ]]; then
    files+=("scripts/roadmap_progress_report.sh")
  fi
  if ! is_auth_wallet_gap_item "$normalized_text" && [[ "$normalized_text" == *"admin console"* \
     || "$normalized_text" == *"admin"* \
     || "$normalized_text" == *"settlement"* \
     || "$normalized_text" == *"reservation-write"* \
     || "$normalized_text" == *"reservation write"* \
     || "$normalized_text" == *"vpnbilling/reservations"* \
     || "$normalized_text" == *"payout"* \
     || "$normalized_text" == *"slashing"* \
     || "$normalized_text" == *"slash"* \
     || "$normalized_text" == *"dispute"* \
     || "$normalized_text" == *"finalization"* \
     || "$normalized_text" == *"finalize"* ]]; then
    files+=("docs/local-control-api.md")
    files+=("scripts/gpm_admin_settlement_live_evidence.sh")
    files+=("scripts/integration_gpm_admin_settlement_contract.sh")
    files+=("services/localapi/gpm_api.go")
    files+=("pkg/settlement/memory.go")
  fi
  if is_reservation_evidence_gap_item "$normalized_text"; then
    files+=("services/localapi/service.go")
    files+=("pkg/settlement/types.go")
    files+=("pkg/settlement/cosmos_adapter.go")
    files+=("blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go")
    files+=("blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge_test.go")
  fi
  if [[ ( "$normalized_text" == *"reward proof"* || "$normalized_text" == *"objective proof"* || "$normalized_text" == *"proof reference"* || "$normalized_text" == *"proof-reference"* || "$normalized_text" == *"proof-validation"* || "$normalized_text" == *"proof verification"* || "$normalized_text" == *"proof-registry"* ) \
     && ( "$normalized_text" == *"trust"* || "$normalized_text" == *"shape"* || "$normalized_text" == *"unverified"* || "$normalized_text" == *"verification"* || "$normalized_text" == *"registry"* || "$normalized_text" == *"blocked"* ) ]]; then
    files+=("pkg/settlement/memory.go")
    files+=("pkg/settlement/reward_proof_trust.md")
    files+=("services/localapi/gpm_api.go")
    files+=("blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go")
  fi
  if [[ ( "$normalized_text" == *"confirmation"* || "$normalized_text" == *"confirmed"* || "$normalized_text" == *"reconcile"* || "$normalized_text" == *"chain state"* || "$normalized_text" == *"chain-status"* || "$normalized_text" == *"chain status"* ) \
     && ( "$normalized_text" == *"existence"* || "$normalized_text" == *"pending"* || "$normalized_text" == *"submitted"* || "$normalized_text" == *"promot"* || "$normalized_text" == *"final"* ) ]]; then
    files+=("pkg/settlement/types.go")
    files+=("pkg/settlement/memory.go")
    files+=("pkg/settlement/cosmos_adapter.go")
  fi
  if [[ ( "$normalized_text" == *"replay guard"* || "$normalized_text" == *"replay-guard"* || "$normalized_text" == *"replay storage"* || "$normalized_text" == *"replay-storage"* || "$normalized_text" == *"replay cache"* || "$normalized_text" == *"replay-cache"* ) \
     && ( "$normalized_text" == *"durable"* || "$normalized_text" == *"strict"* || "$normalized_text" == *"multi-instance"* || "$normalized_text" == *"production"* ) ]]; then
    files+=("services/exit/service.go")
    files+=("services/exit/service_test.go")
  fi
  dedupe_csv_from_args "${files[@]}"
}

dedupe_csv_from_args() {
  local seen="|"
  local value=""
  local unique=()
  for value in "$@"; do
    value="$(trim "$value")"
    if [[ -z "$value" ]]; then
      continue
    fi
    if [[ "$seen" == *"|$value|"* ]]; then
      continue
    fi
    seen+="$value|"
    unique+=("$value")
  done
  local IFS=","
  printf '%s' "${unique[*]}"
}

print_json_string_array() {
  local csv="${1:-}"
  local first=1
  local value=""
  printf '['
  if [[ -n "$csv" ]]; then
    local IFS=","
    read -r -a values <<<"$csv"
    for value in "${values[@]}"; do
      value="$(trim "$value")"
      if [[ -z "$value" ]]; then
        continue
      fi
      if (( first == 0 )); then
        printf ', '
      fi
      printf '"%s"' "$(json_escape "$value")"
      first=0
    done
  fi
  printf ']'
}

print_json_bool_or_null() {
  local value="${1:-}"
  if [[ "$value" == "true" || "$value" == "false" ]]; then
    printf '%s' "$value"
  else
    printf 'null'
  fi
}

while IFS= read -r line || [[ -n "$line" ]]; do
  line_number=$((line_number + 1))
  line="${line%$'\r'}"
  if [[ "$line_number" -eq 1 ]]; then
    line="${line#$'\xEF\xBB\xBF'}"
  fi
  line_trimmed="$(trim "$line")"

  if [[ "$line_trimmed" =~ ^##[[:space:]]*([^#].*)?$ ]]; then
    flush_pending_item
    heading_text="$(strip_heading_markers "${BASH_REMATCH[1]}")"
    heading_norm="$(normalize_heading_key "$heading_text")"
    case "$heading_norm" in
      "in progress")
        current_section="in_progress"
        saw_in_progress=1
        ;;
      "missing next")
        current_section="missing_next"
        saw_missing_next=1
        ;;
      *)
        current_section=""
        ;;
    esac
    continue
  fi

  if [[ -z "$current_section" ]]; then
    continue
  fi

  if [[ "$line" =~ ^[[:space:]]*-[[:space:]]+(.+)$ ]]; then
    flush_pending_item
    pending_section="$current_section"
    pending_text="$(trim "${BASH_REMATCH[1]}")"
    continue
  fi

  if [[ -n "$pending_section" ]]; then
    if [[ "$line_trimmed" == \#* ]]; then
      flush_pending_item
    elif [[ -z "$line_trimmed" ]]; then
      continue
    else
      pending_text="${pending_text} ${line_trimmed}"
    fi
  fi
done <"$status_doc"
flush_pending_item

if [[ "$saw_in_progress" != "1" ]]; then
  fail_closed "required heading not found: In-Progress"
fi
if [[ "$saw_missing_next" != "1" ]]; then
  fail_closed "required heading not found: Missing / Next"
fi

roadmap_access_recovery_present="false"
access_recovery_track_status=""
access_recovery_pilot_handoff_ready="unknown"
access_recovery_track_pilot_handoff_ready="unknown"
access_recovery_needs_attention="unknown"
access_recovery_trusted_verifier_receipt_valid="unknown"
access_recovery_trusted_pilot_receipt_ready="unknown"
access_recovery_verifier_pilot_handoff_ready="unknown"
access_recovery_operator_next_action_source=""
access_recovery_operator_next_action_id=""
access_recovery_operator_next_action_command=""
access_recovery_operator_next_action_reason=""
access_recovery_operator_next_action_placeholder_unresolved="unknown"
access_recovery_operator_next_action_placeholder_keys=""
access_recovery_operator_next_action_safe_to_execute="unknown"

if [[ -n "$roadmap_summary_json" ]]; then
  if ! jq -e 'type == "object"' "$roadmap_summary_json" >/dev/null 2>&1; then
    fail_closed "roadmap summary JSON is malformed: $roadmap_summary_json"
  fi

  roadmap_access_recovery_present="$(jq -r '(.access_recovery_track | type) == "object"' "$roadmap_summary_json")"
  if [[ "$roadmap_access_recovery_present" == "true" ]]; then
    access_recovery_track_status="$(jq -r '.access_recovery_track.status // "unknown"' "$roadmap_summary_json")"
    access_recovery_pilot_handoff_ready="$(jq -r 'if (.access_recovery_pilot_handoff_ready | type) == "boolean" then .access_recovery_pilot_handoff_ready elif (.access_recovery_track.pilot_handoff_ready | type) == "boolean" then .access_recovery_track.pilot_handoff_ready else "unknown" end' "$roadmap_summary_json")"
    access_recovery_track_pilot_handoff_ready="$(jq -r 'if (.access_recovery_track.pilot_handoff_ready | type) == "boolean" then .access_recovery_track.pilot_handoff_ready else "unknown" end' "$roadmap_summary_json")"
    access_recovery_needs_attention="$(jq -r 'if (.access_recovery_track.needs_attention | type) == "boolean" then .access_recovery_track.needs_attention else "unknown" end' "$roadmap_summary_json")"
    access_recovery_trusted_verifier_receipt_valid="$(jq -r 'if (.access_recovery_track.trusted_verifier_receipt_valid | type) == "boolean" then .access_recovery_track.trusted_verifier_receipt_valid elif (.access_recovery_track.trusted_verifier_ready | type) == "boolean" then .access_recovery_track.trusted_verifier_ready else "unknown" end' "$roadmap_summary_json")"
    access_recovery_trusted_pilot_receipt_ready="$(jq -r 'if (.access_recovery_track.trusted_pilot_receipt_ready | type) == "boolean" then .access_recovery_track.trusted_pilot_receipt_ready else "unknown" end' "$roadmap_summary_json")"
    access_recovery_verifier_pilot_handoff_ready="$(jq -r 'if (.access_recovery_track.verifier_pilot_handoff_ready | type) == "boolean" then .access_recovery_track.verifier_pilot_handoff_ready else "unknown" end' "$roadmap_summary_json")"
    access_recovery_operator_next_action_source="$(jq -r 'if ((.access_recovery_track.preferred_operator_next_action.command // "") != "") then "preferred_operator_next_action" elif ((.access_recovery_track.recommended_next_action.command // "") != "") then "recommended_next_action" else "" end' "$roadmap_summary_json")"
    if [[ -n "$access_recovery_operator_next_action_source" ]]; then
      access_recovery_operator_next_action_id="$(jq -r --arg source "$access_recovery_operator_next_action_source" '.access_recovery_track[$source].id // ""' "$roadmap_summary_json")"
      access_recovery_operator_next_action_command="$(jq -r --arg source "$access_recovery_operator_next_action_source" '.access_recovery_track[$source].command // ""' "$roadmap_summary_json")"
      access_recovery_operator_next_action_reason="$(jq -r --arg source "$access_recovery_operator_next_action_source" '.access_recovery_track[$source].reason // ""' "$roadmap_summary_json")"
      access_recovery_operator_next_action_placeholder_unresolved="$(jq -r --arg source "$access_recovery_operator_next_action_source" 'if (.access_recovery_track[$source].placeholder_unresolved | type) == "boolean" then .access_recovery_track[$source].placeholder_unresolved else "unknown" end' "$roadmap_summary_json")"
      access_recovery_operator_next_action_placeholder_keys="$(jq -r --arg source "$access_recovery_operator_next_action_source" '[.access_recovery_track[$source].placeholder_keys[]?] | join(",")' "$roadmap_summary_json")"
      access_recovery_operator_next_action_safe_to_execute="$(jq -r --arg source "$access_recovery_operator_next_action_source" 'if (.access_recovery_track[$source].safe_to_execute_as_is | type) == "boolean" then .access_recovery_track[$source].safe_to_execute_as_is else "unknown" end' "$roadmap_summary_json")"
    fi
    if [[ "$access_recovery_pilot_handoff_ready" != "true" \
       || "$access_recovery_trusted_verifier_receipt_valid" != "true" \
       || "$access_recovery_trusted_pilot_receipt_ready" != "true" \
       || "$access_recovery_verifier_pilot_handoff_ready" != "true" \
       || "$access_recovery_needs_attention" != "false" ]]; then
      access_recovery_gap_text="Roadmap Access Recovery handoff state is not ready (status=${access_recovery_track_status:-unknown}, access_recovery_pilot_handoff_ready=${access_recovery_pilot_handoff_ready}, access_recovery_track.pilot_handoff_ready=${access_recovery_track_pilot_handoff_ready}, trusted_verifier_receipt_valid=${access_recovery_trusted_verifier_receipt_valid}, trusted_pilot_receipt_ready=${access_recovery_trusted_pilot_receipt_ready}, verifier_pilot_handoff_ready=${access_recovery_verifier_pilot_handoff_ready}); verifier authority and synced roadmap status are both required before handoff is complete."
      if [[ -n "$access_recovery_operator_next_action_command" ]]; then
        access_recovery_gap_text+=" Operator next action (${access_recovery_operator_next_action_source}"
        if [[ -n "$access_recovery_operator_next_action_id" ]]; then
          access_recovery_gap_text+="/${access_recovery_operator_next_action_id}"
        fi
        access_recovery_gap_text+="): ${access_recovery_operator_next_action_command}"
        if [[ -n "$access_recovery_operator_next_action_reason" ]]; then
          access_recovery_gap_text+=" Reason: ${access_recovery_operator_next_action_reason}"
        fi
        if [[ "$access_recovery_operator_next_action_placeholder_unresolved" == "true" ]]; then
          access_recovery_gap_text+=" placeholder_unresolved=true"
          if [[ -n "$access_recovery_operator_next_action_placeholder_keys" ]]; then
            access_recovery_gap_text+=" (${access_recovery_operator_next_action_placeholder_keys})"
          fi
        fi
        if [[ "$access_recovery_operator_next_action_safe_to_execute" == "false" ]]; then
          access_recovery_gap_text+=" safe_to_execute_as_is=false"
        fi
        access_recovery_gap_text+="."
      fi
      append_gap_item "missing_next" "$access_recovery_gap_text"
    fi
  else
    append_gap_item "missing_next" "Roadmap Access Recovery handoff state is missing; provide a roadmap summary with access_recovery_track before pilot handoff."
  fi

  profile_unresolved_placeholders="$(jq -r '.vpn_track.profile_default_gate.unresolved_placeholders // false' "$roadmap_summary_json")"
  if [[ "$profile_unresolved_placeholders" == "true" ]]; then
    profile_placeholder_keys="$(jq -r '[.vpn_track.profile_default_gate.unresolved_placeholder_keys[]?] | join(",")' "$roadmap_summary_json")"
    if [[ -z "$profile_placeholder_keys" ]]; then
      profile_placeholder_keys="unknown"
    fi
    append_gap_item "missing_next" "Roadmap profile-default gate next action has unresolved placeholders (${profile_placeholder_keys}); run gpm-endpoint-posture-remediate or export A_HOST/B_HOST/CAMPAIGN_SUBJECT before the live stability cycle."
  fi

  multi_vm_source_ready="$(jq -r 'if (.vpn_track.profile_compare_multi_vm_stability | type) == "object" and (.vpn_track.profile_compare_multi_vm_stability.vm_command_source_ready | type) == "boolean" then .vpn_track.profile_compare_multi_vm_stability.vm_command_source_ready else "unknown" end' "$roadmap_summary_json")"
  multi_vm_actionable="$(jq -r 'if (.vpn_track.profile_compare_multi_vm_stability | type) == "object" and (.vpn_track.profile_compare_multi_vm_stability.next_command_actionable | type) == "boolean" then .vpn_track.profile_compare_multi_vm_stability.next_command_actionable else "unknown" end' "$roadmap_summary_json")"
  if [[ "$multi_vm_source_ready" != "true" || "$multi_vm_actionable" != "true" ]]; then
    append_gap_item "missing_next" "Roadmap multi-VM stability command source is not actionable (vm_command_source_ready=${multi_vm_source_ready}, next_command_actionable=${multi_vm_actionable}); generate a VM command file or pass --vm-command VM_ID::COMMAND before running the M5 stability cycle."
  fi

  runtime_status="$(jq -r '.vpn_track.runtime_actuation_promotion.status // ""' "$roadmap_summary_json")"
  runtime_decision="$(jq -r '.vpn_track.runtime_actuation_promotion.decision // ""' "$roadmap_summary_json")"
  if [[ "$runtime_status" == "fail" || "$runtime_decision" == "NO-GO" ]]; then
    append_gap_item "missing_next" "Roadmap runtime-actuation promotion is not green (status=${runtime_status:-unknown}, decision=${runtime_decision:-unknown}); rerun promotion cycle until thresholds pass, then publish evidence pack."
  fi

  for evidence_path in \
    '.vpn_track.profile_default_gate_evidence_pack' \
    '.vpn_track.runtime_actuation_promotion_evidence_pack' \
    '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack'; do
    evidence_type="$(jq -r "${evidence_path} | type" "$roadmap_summary_json")"
    if [[ "$evidence_type" != "object" ]]; then
      evidence_status="missing"
      evidence_needs_attention="true"
    else
      evidence_status="$(jq -r "${evidence_path}.status // \"missing\"" "$roadmap_summary_json")"
      evidence_needs_attention="$(jq -r "${evidence_path}.needs_attention // false" "$roadmap_summary_json")"
    fi
    if [[ "$evidence_needs_attention" == "true" || "$evidence_status" == "missing" || "$evidence_status" == "invalid" || "$evidence_status" == "stale" || "$evidence_status" == "fail" ]]; then
      evidence_id="${evidence_path##*.}"
      append_gap_item "missing_next" "Roadmap evidence pack ${evidence_id} needs attention (status=${evidence_status:-unknown}); refresh source artifacts and rerun the corresponding evidence-pack helper."
    fi
  done
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
total_count=$((in_progress_count + missing_next_count))
item_count="${#ITEM_TEXTS[@]}"

summary_tmp="$(mktemp "$reports_dir/gpm_gap_scan_summary.tmp.XXXXXX")"
in_progress_ordinal=0
missing_next_ordinal=0
declare -a sorted_actionable_ids=()
for wanted_severity in p1 p2 p3; do
  for idx in "${!ITEM_TEXTS[@]}"; do
    if [[ "${ITEM_SEVERITIES[$idx]:-}" != "$wanted_severity" ]]; then
      continue
    fi
    if [[ "${ITEM_ACTIONABLES[$idx]:-true}" != "true" ]]; then
      continue
    fi
    section="${ITEM_SECTIONS[$idx]}"
    if [[ "$section" == "in_progress" ]]; then
      ordinal=$((idx + 1))
      item_id="$(printf 'in_progress_%02d' "$(( $(printf '%s\n' "${ITEM_SECTIONS[@]:0:$idx}" | grep -c '^in_progress$' 2>/dev/null || true) + 1 ))")"
    else
      ordinal=$((idx + 1))
      item_id="$(printf 'missing_next_%02d' "$(( $(printf '%s\n' "${ITEM_SECTIONS[@]:0:$idx}" | grep -c '^missing_next$' 2>/dev/null || true) + 1 ))")"
    fi
    sorted_actionable_ids+=("$item_id")
  done
done

{
  printf '{\n'
  printf '  "version": 1,\n'
  printf '  "schema": {\n'
  printf '    "id": "gpm_gap_scan_summary",\n'
  printf '    "major": 1,\n'
  printf '    "minor": 1\n'
  printf '  },\n'
  printf '  "generated_at_utc": "%s",\n' "$(json_escape "$generated_at_utc")"
  printf '  "status": "ok",\n'
  printf '  "inputs": {\n'
  printf '    "status_doc": "%s",\n' "$(json_escape "$status_doc")"
  printf '    "roadmap_summary_json": '
  if [[ -n "$roadmap_summary_json" ]]; then
    printf '"%s",\n' "$(json_escape "$roadmap_summary_json")"
  else
    printf 'null,\n'
  fi
  printf '    "reports_dir": "%s",\n' "$(json_escape "$reports_dir")"
  printf '    "summary_json": "%s"\n' "$(json_escape "$summary_json")"
  printf '  },\n'
  printf '  "roadmap_status": {\n'
  printf '    "access_recovery": '
  if [[ "$roadmap_access_recovery_present" == "true" ]]; then
    printf '{\n'
    printf '      "status": "%s",\n' "$(json_escape "${access_recovery_track_status:-unknown}")"
    printf '      "access_recovery_pilot_handoff_ready": '
    print_json_bool_or_null "$access_recovery_pilot_handoff_ready"
    printf ',\n'
    printf '      "track_pilot_handoff_ready": '
    print_json_bool_or_null "$access_recovery_track_pilot_handoff_ready"
    printf ',\n'
    printf '      "needs_attention": '
    print_json_bool_or_null "$access_recovery_needs_attention"
    printf ',\n'
    printf '      "trusted_verifier_receipt_valid": '
    print_json_bool_or_null "$access_recovery_trusted_verifier_receipt_valid"
    printf ',\n'
    printf '      "trusted_pilot_receipt_ready": '
    print_json_bool_or_null "$access_recovery_trusted_pilot_receipt_ready"
    printf ',\n'
    printf '      "verifier_pilot_handoff_ready": '
    print_json_bool_or_null "$access_recovery_verifier_pilot_handoff_ready"
    printf ',\n'
    printf '      "operator_next_action": '
    if [[ -n "$access_recovery_operator_next_action_command" ]]; then
      printf '{\n'
      printf '        "source": "%s",\n' "$(json_escape "$access_recovery_operator_next_action_source")"
      printf '        "id": "%s",\n' "$(json_escape "$access_recovery_operator_next_action_id")"
      printf '        "command": "%s",\n' "$(json_escape "$access_recovery_operator_next_action_command")"
      printf '        "reason": "%s",\n' "$(json_escape "$access_recovery_operator_next_action_reason")"
      printf '        "placeholder_unresolved": '
      print_json_bool_or_null "$access_recovery_operator_next_action_placeholder_unresolved"
      printf ',\n'
      printf '        "placeholder_keys": '
      print_json_string_array "$access_recovery_operator_next_action_placeholder_keys"
      printf ',\n'
      printf '        "safe_to_execute_as_is": '
      print_json_bool_or_null "$access_recovery_operator_next_action_safe_to_execute"
      printf '\n'
      printf '      }\n'
    else
      printf 'null\n'
    fi
    printf '    }'
  else
    printf 'null'
  fi
  printf '\n'
  printf '  },\n'
  printf '  "counts": {\n'
  printf '    "in_progress": %d,\n' "$in_progress_count"
  printf '    "missing_next": %d,\n' "$missing_next_count"
  printf '    "total": %d\n' "$total_count"
  printf '  },\n'
  printf '  "items": [\n'
  if (( item_count > 0 )); then
    for idx in "${!ITEM_TEXTS[@]}"; do
      section="${ITEM_SECTIONS[$idx]}"
      text="${ITEM_TEXTS[$idx]}"
      normalized_text="${ITEM_NORMALIZED_TEXTS[$idx]}"
      severity="${ITEM_SEVERITIES[$idx]}"
      recommended_action="${ITEM_RECOMMENDED_ACTIONS[$idx]}"
      closure_mode="${ITEM_CLOSURE_MODES[$idx]}"
      blocked_by="${ITEM_BLOCKED_BYS[$idx]}"
      requires_real_hosts="${ITEM_REQUIRES_REAL_HOSTS[$idx]}"
      suggested_tests="${ITEM_SUGGESTED_TESTS[$idx]}"
      suggested_files="${ITEM_SUGGESTED_FILES[$idx]}"
      actionable="${ITEM_ACTIONABLES[$idx]}"
      if [[ "$section" == "in_progress" ]]; then
        in_progress_ordinal=$((in_progress_ordinal + 1))
        ordinal="$in_progress_ordinal"
        item_id="$(printf 'in_progress_%02d' "$in_progress_ordinal")"
      else
        missing_next_ordinal=$((missing_next_ordinal + 1))
        ordinal="$missing_next_ordinal"
        item_id="$(printf 'missing_next_%02d' "$missing_next_ordinal")"
      fi
      if (( idx > 0 )); then
        printf ',\n'
      fi
      printf '    {\n'
      printf '      "id": "%s",\n' "$(json_escape "$item_id")"
      printf '      "section": "%s",\n' "$(json_escape "$section")"
      printf '      "ordinal": %d,\n' "$ordinal"
      printf '      "text": "%s",\n' "$(json_escape "$text")"
      printf '      "normalized_text": "%s",\n' "$(json_escape "$normalized_text")"
      printf '      "severity": "%s",\n' "$(json_escape "$severity")"
      printf '      "actionable": %s,\n' "$actionable"
      printf '      "recommended_action": "%s",\n' "$(json_escape "$recommended_action")"
      printf '      "closure_mode": "%s",\n' "$(json_escape "$closure_mode")"
      printf '      "blocked_by": '
      print_json_string_array "$blocked_by"
      printf ',\n'
      printf '      "requires_real_hosts": %s,\n' "$requires_real_hosts"
      printf '      "suggested_tests": '
      print_json_string_array "$suggested_tests"
      printf ',\n'
      printf '      "suggested_files": '
      print_json_string_array "$suggested_files"
      printf '\n'
      printf '    }'
    done
    printf '\n'
  fi
  printf '  ],\n'
  printf '  "top_actionable_item_ids": [\n'
  if (( ${#sorted_actionable_ids[@]} > 0 )); then
    for idx in "${!sorted_actionable_ids[@]}"; do
      if (( idx > 0 )); then
        printf ',\n'
      fi
      printf '    "%s"' "$(json_escape "${sorted_actionable_ids[$idx]}")"
    done
    printf '\n'
  fi
  printf '  ]\n'
  printf '}\n'
} >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

print_markdown_section_items() {
  local target_section="$1"
  local idx
  local ordinal=0
  for idx in "${!ITEM_TEXTS[@]}"; do
    if [[ "${ITEM_SECTIONS[$idx]}" == "$target_section" ]]; then
      ordinal=$((ordinal + 1))
      printf '%d. %s\n' "$ordinal" "${ITEM_TEXTS[$idx]}"
    fi
  done
  if (( ordinal == 0 )); then
    printf '_None._\n'
  fi
}

status_doc_display="$(display_path "$status_doc")"
summary_json_display="$(display_path "$summary_json")"

printf '# GPM Roadmap Gap Scan\n\n'
printf 'Source: `%s`\n\n' "$status_doc_display"
printf 'Summary JSON: `%s`\n\n' "$summary_json_display"

printf '## In-Progress (%d)\n\n' "$in_progress_count"
print_markdown_section_items "in_progress"
printf '\n'

printf '## Missing / Next (%d)\n\n' "$missing_next_count"
print_markdown_section_items "missing_next"
printf '\n'

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit 0
