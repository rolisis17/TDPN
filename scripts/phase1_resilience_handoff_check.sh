#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase1_resilience_handoff_check.sh \
    [--ci-phase1-summary-json PATH] \
    [--vpn-rc-resilience-summary-json PATH] \
    [--require-profile-matrix-stable [0|1]] \
    [--require-peer-loss-recovery-ok [0|1]] \
    [--require-session-churn-guard-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for Phase-1 resilience handoff.
  Evaluates required booleans:
    - profile_matrix_stable
    - peer_loss_recovery_ok
    - session_churn_guard_ok

Inputs:
  Provide at least one source:
    - --ci-phase1-summary-json
    - --vpn-rc-resilience-summary-json

Output:
  - Writes summary JSON to --summary-json.
  - Returns rc=0 only when all required booleans resolve to true.
  - Returns rc=1 on fail-closed gate failure (false/unresolved/missing artifacts).
USAGE
}

trim() {
  local value="${1:-}"
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
  local candidate="${1:-}"
  local base_file="${2:-}"
  local base_dir=""
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

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value"
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

json_file_valid_01() {
  local path="${1:-}"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

json_bool_value_or_empty() {
  local path="${1:-}"
  local jq_expr="${2:-}"
  local value=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
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

step_status_to_bool_or_empty() {
  local status="${1:-}"
  case "$status" in
    pass|ok)
      printf '%s' "true"
      ;;
    fail|error|skip|skipped|timeout|timed_out|timed-out)
      printf '%s' "false"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

normalize_failure_kind() {
  local kind="${1:-}"
  case "$kind" in
    policy_no_go|policy-no-go|no_go|no-go)
      printf '%s' "policy_no_go"
      ;;
    timeout|timed_out|timed-out)
      printf '%s' "timeout"
      ;;
    execution_failure|execution-failure|command_failed|command-failed|error)
      printf '%s' "execution_failure"
      ;;
    none|"")
      printf '%s' "none"
      ;;
    *)
      printf '%s' "execution_failure"
      ;;
  esac
}

ci_step_name_for_signal() {
  local signal="${1:-}"
  case "$signal" in
    profile_matrix_stable)
      printf '%s' "three_machine_docker_profile_matrix"
      ;;
    peer_loss_recovery_ok)
      printf '%s' "vpn_rc_resilience_path"
      ;;
    session_churn_guard_ok)
      printf '%s' "session_churn_guard"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

vpn_step_name_for_signal() {
  local signal="${1:-}"
  case "$signal" in
    profile_matrix_stable|peer_loss_recovery_ok)
      printf '%s' "three_machine_docker_profile_matrix"
      ;;
    session_churn_guard_ok)
      printf '%s' "vpn_rc_matrix_path"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

json_step_status_or_empty() {
  local path="${1:-}"
  local step_name="${2:-}"
  if [[ "$(json_file_valid_01 "$path")" != "1" || -z "$step_name" ]]; then
    printf '%s' ""
    return
  fi
  jq -r --arg step_name "$step_name" '.steps[$step_name].status // ""' "$path" 2>/dev/null || true
}

step_status_implies_timeout_01() {
  local status="${1:-}"
  case "$status" in
    timeout|timed_out|timed-out)
      printf '%s' "1"
      ;;
    *)
      printf '%s' "0"
      ;;
  esac
}

step_status_implies_execution_failure_01() {
  local status="${1:-}"
  case "$status" in
    skip|skipped|error)
      printf '%s' "1"
      ;;
    *)
      printf '%s' "0"
      ;;
  esac
}

json_step_failure_kind_or_empty() {
  local path="${1:-}"
  local step_name="${2:-}"
  local raw_kind=""
  if [[ "$(json_file_valid_01 "$path")" != "1" || -z "$step_name" ]]; then
    printf '%s' ""
    return
  fi
  raw_kind="$(jq -r --arg step_name "$step_name" '
    if (.steps[$step_name].failure_semantics.kind | type) == "string" then .steps[$step_name].failure_semantics.kind
    elif (.steps[$step_name].timed_out // false) == true then "timeout"
    elif (.steps[$step_name].reason // "") == "timeout" then "timeout"
    elif (.steps[$step_name].reason // "") == "policy-no-go" then "policy_no_go"
    elif (.steps[$step_name].reason // "") == "command-failed" then "execution_failure"
    elif (.steps[$step_name].status // "") == "timeout" then "timeout"
    elif (.steps[$step_name].status // "") == "timed_out" then "timeout"
    elif (.steps[$step_name].status // "") == "timed-out" then "timeout"
    else "" end
  ' "$path" 2>/dev/null || true)"
  raw_kind="$(trim "$raw_kind")"
  if [[ -z "$raw_kind" ]]; then
    printf '%s' ""
    return
  fi
  normalize_failure_kind "$raw_kind"
}

ci_step_status_bool_or_empty() {
  local path="${1:-}"
  local step_name="${2:-}"
  local status=""
  status="$(json_step_status_or_empty "$path" "$step_name")"
  step_status_to_bool_or_empty "$status"
}

extract_vpn_bool_or_empty() {
  local path="${1:-}"
  local signal="${2:-}"
  case "$signal" in
    profile_matrix_stable)
      json_bool_value_or_empty "$path" 'if (.profile_matrix_stable | type) == "boolean" then .profile_matrix_stable
        elif (.summary.profile_matrix_stable | type) == "boolean" then .summary.profile_matrix_stable
        elif (.handoff.profile_matrix_stable | type) == "boolean" then .handoff.profile_matrix_stable
        elif (.signals.profile_matrix_stable | type) == "boolean" then .signals.profile_matrix_stable
        elif (.resilience_handoff.profile_matrix_stable | type) == "boolean" then .resilience_handoff.profile_matrix_stable
        elif (.vpn_track.resilience_handoff.profile_matrix_stable | type) == "boolean" then .vpn_track.resilience_handoff.profile_matrix_stable
        else empty end'
      ;;
    peer_loss_recovery_ok)
      json_bool_value_or_empty "$path" 'if (.peer_loss_recovery_ok | type) == "boolean" then .peer_loss_recovery_ok
        elif (.summary.peer_loss_recovery_ok | type) == "boolean" then .summary.peer_loss_recovery_ok
        elif (.handoff.peer_loss_recovery_ok | type) == "boolean" then .handoff.peer_loss_recovery_ok
        elif (.signals.peer_loss_recovery_ok | type) == "boolean" then .signals.peer_loss_recovery_ok
        elif (.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .resilience_handoff.peer_loss_recovery_ok
        elif (.vpn_track.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .vpn_track.resilience_handoff.peer_loss_recovery_ok
        else empty end'
      ;;
    session_churn_guard_ok)
      json_bool_value_or_empty "$path" 'if (.session_churn_guard_ok | type) == "boolean" then .session_churn_guard_ok
        elif (.summary.session_churn_guard_ok | type) == "boolean" then .summary.session_churn_guard_ok
        elif (.handoff.session_churn_guard_ok | type) == "boolean" then .handoff.session_churn_guard_ok
        elif (.signals.session_churn_guard_ok | type) == "boolean" then .signals.session_churn_guard_ok
        elif (.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .resilience_handoff.session_churn_guard_ok
        elif (.vpn_track.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .vpn_track.resilience_handoff.session_churn_guard_ok
        else empty end'
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

extract_ci_explicit_bool_or_empty() {
  local path="${1:-}"
  local signal="${2:-}"
  case "$signal" in
    profile_matrix_stable)
      json_bool_value_or_empty "$path" 'if (.profile_matrix_stable | type) == "boolean" then .profile_matrix_stable
        elif (.summary.profile_matrix_stable | type) == "boolean" then .summary.profile_matrix_stable
        elif (.handoff.profile_matrix_stable | type) == "boolean" then .handoff.profile_matrix_stable
        elif (.signals.profile_matrix_stable | type) == "boolean" then .signals.profile_matrix_stable
        elif (.resilience_handoff.profile_matrix_stable | type) == "boolean" then .resilience_handoff.profile_matrix_stable
        elif (.vpn_track.resilience_handoff.profile_matrix_stable | type) == "boolean" then .vpn_track.resilience_handoff.profile_matrix_stable
        else empty end'
      ;;
    peer_loss_recovery_ok)
      json_bool_value_or_empty "$path" 'if (.peer_loss_recovery_ok | type) == "boolean" then .peer_loss_recovery_ok
        elif (.summary.peer_loss_recovery_ok | type) == "boolean" then .summary.peer_loss_recovery_ok
        elif (.handoff.peer_loss_recovery_ok | type) == "boolean" then .handoff.peer_loss_recovery_ok
        elif (.signals.peer_loss_recovery_ok | type) == "boolean" then .signals.peer_loss_recovery_ok
        elif (.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .resilience_handoff.peer_loss_recovery_ok
        elif (.vpn_track.resilience_handoff.peer_loss_recovery_ok | type) == "boolean" then .vpn_track.resilience_handoff.peer_loss_recovery_ok
        else empty end'
      ;;
    session_churn_guard_ok)
      json_bool_value_or_empty "$path" 'if (.session_churn_guard_ok | type) == "boolean" then .session_churn_guard_ok
        elif (.summary.session_churn_guard_ok | type) == "boolean" then .summary.session_churn_guard_ok
        elif (.handoff.session_churn_guard_ok | type) == "boolean" then .handoff.session_churn_guard_ok
        elif (.signals.session_churn_guard_ok | type) == "boolean" then .signals.session_churn_guard_ok
        elif (.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .resilience_handoff.session_churn_guard_ok
        elif (.vpn_track.resilience_handoff.session_churn_guard_ok | type) == "boolean" then .vpn_track.resilience_handoff.session_churn_guard_ok
        else empty end'
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

resolve_signal_from_ci_steps_or_empty() {
  local path="${1:-}"
  local signal="${2:-}"
  case "$signal" in
    profile_matrix_stable)
      ci_step_status_bool_or_empty "$path" "three_machine_docker_profile_matrix"
      ;;
    peer_loss_recovery_ok)
      ci_step_status_bool_or_empty "$path" "vpn_rc_resilience_path"
      ;;
    session_churn_guard_ok)
      ci_step_status_bool_or_empty "$path" "session_churn_guard"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

resolve_signal_failure_kind() {
  local signal="${1:-}"
  local value="${2:-}"
  local source="${3:-}"
  local step_name=""
  local step_status=""
  local step_failure_kind=""

  if [[ "$value" == "true" ]]; then
    printf '%s' "none"
    return
  fi

  if [[ "$value" == "null" || "$source" == "unresolved" ]]; then
    printf '%s' "execution_failure"
    return
  fi

  if [[ "$source" == "ci_phase1_summary" ]]; then
    printf '%s' "policy_no_go"
    return
  fi

  if [[ "$source" == ci_phase1_summary.steps.* ]]; then
    step_name="$(ci_step_name_for_signal "$signal")"
    step_status="$(json_step_status_or_empty "$ci_phase1_summary_json" "$step_name")"
    step_failure_kind="$(json_step_failure_kind_or_empty "$ci_phase1_summary_json" "$step_name")"
    if [[ -n "$step_failure_kind" && "$step_failure_kind" != "none" ]]; then
      printf '%s' "$step_failure_kind"
      return
    fi
    if [[ "$(step_status_implies_timeout_01 "$step_status")" == "1" ]]; then
      printf '%s' "timeout"
      return
    fi
    if [[ "$(step_status_implies_execution_failure_01 "$step_status")" == "1" ]]; then
      printf '%s' "execution_failure"
      return
    fi
    printf '%s' "policy_no_go"
    return
  fi

  if [[ "$source" == "vpn_rc_resilience_summary" || "$source" == "ci_phase1_summary.steps.vpn_rc_resilience_path.artifacts.summary_json" ]]; then
    step_name="$(vpn_step_name_for_signal "$signal")"
    step_status="$(json_step_status_or_empty "$vpn_rc_resilience_summary_json" "$step_name")"
    step_failure_kind="$(json_step_failure_kind_or_empty "$vpn_rc_resilience_summary_json" "$step_name")"
    if [[ -n "$step_failure_kind" && "$step_failure_kind" != "none" ]]; then
      printf '%s' "$step_failure_kind"
      return
    fi
    if [[ "$(step_status_implies_timeout_01 "$step_status")" == "1" ]]; then
      printf '%s' "timeout"
      return
    fi
    if [[ "$(step_status_implies_execution_failure_01 "$step_status")" == "1" ]]; then
      printf '%s' "execution_failure"
      return
    fi
    printf '%s' "policy_no_go"
    return
  fi

  printf '%s' "execution_failure"
}

need_cmd jq
need_cmd date
need_cmd mktemp

ci_phase1_summary_json="${PHASE1_RESILIENCE_HANDOFF_CHECK_CI_PHASE1_SUMMARY_JSON:-}"
vpn_rc_resilience_summary_json="${PHASE1_RESILIENCE_HANDOFF_CHECK_VPN_RC_RESILIENCE_SUMMARY_JSON:-}"
summary_json="${PHASE1_RESILIENCE_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase1_resilience_handoff_check_summary.json}"
show_json="${PHASE1_RESILIENCE_HANDOFF_CHECK_SHOW_JSON:-0}"
require_profile_matrix_stable="${PHASE1_RESILIENCE_HANDOFF_CHECK_REQUIRE_PROFILE_MATRIX_STABLE:-1}"
require_peer_loss_recovery_ok="${PHASE1_RESILIENCE_HANDOFF_CHECK_REQUIRE_PEER_LOSS_RECOVERY_OK:-1}"
require_session_churn_guard_ok="${PHASE1_RESILIENCE_HANDOFF_CHECK_REQUIRE_SESSION_CHURN_GUARD_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-phase1-summary-json)
      require_value_or_die "$1" "${2:-}"
      ci_phase1_summary_json="${2:-}"
      shift 2
      ;;
    --vpn-rc-resilience-summary-json)
      require_value_or_die "$1" "${2:-}"
      vpn_rc_resilience_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --require-profile-matrix-stable)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_profile_matrix_stable="${2:-}"
        shift 2
      else
        require_profile_matrix_stable="1"
        shift
      fi
      ;;
    --require-peer-loss-recovery-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_peer_loss_recovery_ok="${2:-}"
        shift 2
      else
        require_peer_loss_recovery_ok="1"
        shift
      fi
      ;;
    --require-session-churn-guard-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_session_churn_guard_ok="${2:-}"
        shift 2
      else
        require_session_churn_guard_ok="1"
        shift
      fi
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
        shift
      fi
      ;;
    -h|--help)
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

bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--require-profile-matrix-stable" "$require_profile_matrix_stable"
bool_arg_or_die "--require-peer-loss-recovery-ok" "$require_peer_loss_recovery_ok"
bool_arg_or_die "--require-session-churn-guard-ok" "$require_session_churn_guard_ok"

ci_phase1_summary_json="$(abs_path "$ci_phase1_summary_json")"
vpn_rc_resilience_summary_json="$(abs_path "$vpn_rc_resilience_summary_json")"
summary_json="$(abs_path "$summary_json")"

if [[ -z "$ci_phase1_summary_json" && -z "$vpn_rc_resilience_summary_json" ]]; then
  echo "missing required input: provide --ci-phase1-summary-json and/or --vpn-rc-resilience-summary-json"
  usage
  exit 2
fi

mkdir -p "$(dirname "$summary_json")"

declare -a reasons=()
declare -a warnings=()

ci_provided="false"
vpn_provided="false"
ci_usable="false"
vpn_usable="false"
vpn_from_ci_artifacts="false"

if [[ -n "$ci_phase1_summary_json" ]]; then
  ci_provided="true"
  if [[ ! -f "$ci_phase1_summary_json" ]]; then
    reasons+=("ci_phase1 summary file not found: $ci_phase1_summary_json")
  elif ! jq -e . "$ci_phase1_summary_json" >/dev/null 2>&1; then
    reasons+=("ci_phase1 summary is not valid JSON: $ci_phase1_summary_json")
  else
    ci_usable="true"
  fi
fi

if [[ -n "$vpn_rc_resilience_summary_json" ]]; then
  vpn_provided="true"
  if [[ ! -f "$vpn_rc_resilience_summary_json" ]]; then
    reasons+=("vpn_rc_resilience summary file not found: $vpn_rc_resilience_summary_json")
  elif ! jq -e . "$vpn_rc_resilience_summary_json" >/dev/null 2>&1; then
    reasons+=("vpn_rc_resilience summary is not valid JSON: $vpn_rc_resilience_summary_json")
  else
    vpn_usable="true"
  fi
fi

if [[ "$vpn_usable" != "true" && "$ci_usable" == "true" ]]; then
  ci_referenced_vpn_path="$(jq -r '.steps.vpn_rc_resilience_path.artifacts.summary_json // empty' "$ci_phase1_summary_json" 2>/dev/null || true)"
  if [[ -n "$ci_referenced_vpn_path" ]]; then
    resolved_ci_referenced_vpn_path="$(resolve_path_with_base "$ci_referenced_vpn_path" "$ci_phase1_summary_json")"
    if [[ -f "$resolved_ci_referenced_vpn_path" ]] && jq -e . "$resolved_ci_referenced_vpn_path" >/dev/null 2>&1; then
      vpn_rc_resilience_summary_json="$resolved_ci_referenced_vpn_path"
      vpn_usable="true"
      vpn_from_ci_artifacts="true"
    else
      warnings+=("ci_phase1 summary references vpn_rc_resilience artifact that is missing or invalid: $resolved_ci_referenced_vpn_path")
    fi
  fi
fi

resolve_signal_value() {
  local signal="${1:-}"
  local value=""
  local source=""
  local ci_explicit_value=""
  local ci_step_value=""

  # session_churn_guard_ok is measured directly by the dedicated CI stage; when
  # that stage reports pass, treat it as authoritative even if a linked VPN
  # resilience artifact carries a conservative false fallback.
  if [[ "$signal" == "session_churn_guard_ok" && "$ci_usable" == "true" ]]; then
    ci_explicit_value="$(extract_ci_explicit_bool_or_empty "$ci_phase1_summary_json" "$signal")"
    if [[ "$ci_explicit_value" == "true" ]]; then
      value="true"
      source="ci_phase1_summary"
    else
      ci_step_value="$(resolve_signal_from_ci_steps_or_empty "$ci_phase1_summary_json" "$signal")"
      if [[ "$ci_step_value" == "true" ]]; then
        value="true"
        source="ci_phase1_summary.steps.session_churn_guard.status"
      fi
    fi
  fi

  if [[ -z "$value" && "$vpn_usable" == "true" ]]; then
    value="$(extract_vpn_bool_or_empty "$vpn_rc_resilience_summary_json" "$signal")"
    if [[ -n "$value" ]]; then
      if [[ "$vpn_from_ci_artifacts" == "true" ]]; then
        source="ci_phase1_summary.steps.vpn_rc_resilience_path.artifacts.summary_json"
      else
        source="vpn_rc_resilience_summary"
      fi
    fi
  fi

  if [[ -z "$value" && "$ci_usable" == "true" ]]; then
    value="$(extract_ci_explicit_bool_or_empty "$ci_phase1_summary_json" "$signal")"
    if [[ -n "$value" ]]; then
      source="ci_phase1_summary"
    fi
  fi

  if [[ -z "$value" && "$ci_usable" == "true" ]]; then
    value="$(resolve_signal_from_ci_steps_or_empty "$ci_phase1_summary_json" "$signal")"
    if [[ -n "$value" ]]; then
      case "$signal" in
        profile_matrix_stable)
          source="ci_phase1_summary.steps.three_machine_docker_profile_matrix.status"
          ;;
        peer_loss_recovery_ok)
          source="ci_phase1_summary.steps.vpn_rc_resilience_path.status"
          ;;
        session_churn_guard_ok)
          source="ci_phase1_summary.steps.session_churn_guard.status"
          ;;
      esac
    fi
  fi

  if [[ -z "$value" ]]; then
    value="null"
    source="unresolved"
  fi

  printf '%s|%s\n' "$value" "$source"
}

profile_pair="$(resolve_signal_value "profile_matrix_stable")"
peer_pair="$(resolve_signal_value "peer_loss_recovery_ok")"
session_pair="$(resolve_signal_value "session_churn_guard_ok")"

profile_matrix_stable_json="${profile_pair%%|*}"
profile_matrix_stable_source="${profile_pair#*|}"

peer_loss_recovery_ok_json="${peer_pair%%|*}"
peer_loss_recovery_ok_source="${peer_pair#*|}"

session_churn_guard_ok_json="${session_pair%%|*}"
session_churn_guard_ok_source="${session_pair#*|}"

profile_matrix_stable_failure_kind="$(resolve_signal_failure_kind "profile_matrix_stable" "$profile_matrix_stable_json" "$profile_matrix_stable_source")"
peer_loss_recovery_ok_failure_kind="$(resolve_signal_failure_kind "peer_loss_recovery_ok" "$peer_loss_recovery_ok_json" "$peer_loss_recovery_ok_source")"
session_churn_guard_ok_failure_kind="$(resolve_signal_failure_kind "session_churn_guard_ok" "$session_churn_guard_ok_json" "$session_churn_guard_ok_source")"

if [[ "$require_profile_matrix_stable" == "1" ]]; then
  if [[ "$profile_matrix_stable_json" == "null" ]]; then
    reasons+=("profile_matrix_stable unresolved from provided artifacts")
  elif [[ "$profile_matrix_stable_json" != "true" ]]; then
    reasons+=("profile_matrix_stable is false (source=$profile_matrix_stable_source)")
  fi
fi

if [[ "$require_peer_loss_recovery_ok" == "1" ]]; then
  if [[ "$peer_loss_recovery_ok_json" == "null" ]]; then
    reasons+=("peer_loss_recovery_ok unresolved from provided artifacts")
  elif [[ "$peer_loss_recovery_ok_json" != "true" ]]; then
    reasons+=("peer_loss_recovery_ok is false (source=$peer_loss_recovery_ok_source)")
  fi
fi

if [[ "$require_session_churn_guard_ok" == "1" ]]; then
  if [[ "$session_churn_guard_ok_json" == "null" ]]; then
    reasons+=("session_churn_guard_ok unresolved from provided artifacts")
  elif [[ "$session_churn_guard_ok_json" != "true" ]]; then
    reasons+=("session_churn_guard_ok is false (source=$session_churn_guard_ok_source)")
  fi
fi

reasons_json="$(printf '%s\n' "${reasons[@]:-}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
warnings_json="$(printf '%s\n' "${warnings[@]:-}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

failure_kind_candidates=()
if [[ "$require_profile_matrix_stable" == "1" && "$profile_matrix_stable_json" != "true" ]]; then
  failure_kind_candidates+=("$profile_matrix_stable_failure_kind")
fi
if [[ "$require_peer_loss_recovery_ok" == "1" && "$peer_loss_recovery_ok_json" != "true" ]]; then
  failure_kind_candidates+=("$peer_loss_recovery_ok_failure_kind")
fi
if [[ "$require_session_churn_guard_ok" == "1" && "$session_churn_guard_ok_json" != "true" ]]; then
  failure_kind_candidates+=("$session_churn_guard_ok_failure_kind")
fi

final_status="pass"
final_rc=0
if ((${#reasons[@]} > 0)); then
  final_status="fail"
  final_rc=1
fi

final_failure_kind="none"
if [[ "$final_status" == "fail" ]]; then
  final_failure_kind="execution_failure"
  for failure_kind_candidate in "${failure_kind_candidates[@]:-}"; do
    if [[ "$failure_kind_candidate" == "timeout" ]]; then
      final_failure_kind="timeout"
      break
    fi
  done
  if [[ "$final_failure_kind" != "timeout" ]]; then
    for failure_kind_candidate in "${failure_kind_candidates[@]:-}"; do
      if [[ "$failure_kind_candidate" == "execution_failure" ]]; then
        final_failure_kind="execution_failure"
        break
      fi
      if [[ "$failure_kind_candidate" == "policy_no_go" ]]; then
        final_failure_kind="policy_no_go"
      fi
    done
  fi
fi

policy_outcome_decision="GO"
if [[ "$final_status" == "fail" ]]; then
  policy_outcome_decision="ERROR"
  if [[ "$final_failure_kind" == "policy_no_go" ]]; then
    policy_outcome_decision="NO-GO"
  fi
fi

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg ci_phase1_summary_json "$ci_phase1_summary_json" \
  --arg vpn_rc_resilience_summary_json "$vpn_rc_resilience_summary_json" \
  --arg summary_json "$summary_json" \
  --arg show_json "$show_json" \
  --arg require_profile_matrix_stable "$require_profile_matrix_stable" \
  --arg require_peer_loss_recovery_ok "$require_peer_loss_recovery_ok" \
  --arg require_session_churn_guard_ok "$require_session_churn_guard_ok" \
  --arg ci_provided "$ci_provided" \
  --arg vpn_provided "$vpn_provided" \
  --arg ci_usable "$ci_usable" \
  --arg vpn_usable "$vpn_usable" \
  --arg vpn_from_ci_artifacts "$vpn_from_ci_artifacts" \
  --argjson profile_matrix_stable "$profile_matrix_stable_json" \
  --arg profile_matrix_stable_source "$profile_matrix_stable_source" \
  --arg profile_matrix_stable_failure_kind "$profile_matrix_stable_failure_kind" \
  --argjson peer_loss_recovery_ok "$peer_loss_recovery_ok_json" \
  --arg peer_loss_recovery_ok_source "$peer_loss_recovery_ok_source" \
  --arg peer_loss_recovery_ok_failure_kind "$peer_loss_recovery_ok_failure_kind" \
  --argjson session_churn_guard_ok "$session_churn_guard_ok_json" \
  --arg session_churn_guard_ok_source "$session_churn_guard_ok_source" \
  --arg session_churn_guard_ok_failure_kind "$session_churn_guard_ok_failure_kind" \
  --arg final_failure_kind "$final_failure_kind" \
  --arg policy_outcome_decision "$policy_outcome_decision" \
  --argjson reasons "$reasons_json" \
  --argjson warnings "$warnings_json" \
  '{
    version: 1,
    schema: {
      id: "phase1_resilience_handoff_check_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    fail_closed: true,
    automation: {
      track: "non_blockchain",
      requires_sudo: false,
      requires_github: false,
      automatable_without_sudo_or_github: true
    },
    inputs: {
      ci_phase1_summary_json: (if $ci_phase1_summary_json == "" then null else $ci_phase1_summary_json end),
      vpn_rc_resilience_summary_json: (if $vpn_rc_resilience_summary_json == "" then null else $vpn_rc_resilience_summary_json end),
      show_json: ($show_json == "1"),
      requirements: {
        profile_matrix_stable: ($require_profile_matrix_stable == "1"),
        peer_loss_recovery_ok: ($require_peer_loss_recovery_ok == "1"),
        session_churn_guard_ok: ($require_session_churn_guard_ok == "1")
      },
      provided: {
        ci_phase1_summary_json: ($ci_provided == "true"),
        vpn_rc_resilience_summary_json: ($vpn_provided == "true")
      },
      usable: {
        ci_phase1_summary_json: ($ci_usable == "true"),
        vpn_rc_resilience_summary_json: ($vpn_usable == "true")
      },
      vpn_source_from_ci_artifacts: ($vpn_from_ci_artifacts == "true")
    },
    handoff: {
      profile_matrix_stable: $profile_matrix_stable,
      peer_loss_recovery_ok: $peer_loss_recovery_ok,
      session_churn_guard_ok: $session_churn_guard_ok,
      sources: {
        profile_matrix_stable: $profile_matrix_stable_source,
        peer_loss_recovery_ok: $peer_loss_recovery_ok_source,
        session_churn_guard_ok: $session_churn_guard_ok_source
      },
      failure_semantics: {
        profile_matrix_stable: {
          kind: $profile_matrix_stable_failure_kind,
          policy_no_go: ($profile_matrix_stable_failure_kind == "policy_no_go"),
          execution_failure: ($profile_matrix_stable_failure_kind == "execution_failure"),
          timeout: ($profile_matrix_stable_failure_kind == "timeout")
        },
        peer_loss_recovery_ok: {
          kind: $peer_loss_recovery_ok_failure_kind,
          policy_no_go: ($peer_loss_recovery_ok_failure_kind == "policy_no_go"),
          execution_failure: ($peer_loss_recovery_ok_failure_kind == "execution_failure"),
          timeout: ($peer_loss_recovery_ok_failure_kind == "timeout")
        },
        session_churn_guard_ok: {
          kind: $session_churn_guard_ok_failure_kind,
          policy_no_go: ($session_churn_guard_ok_failure_kind == "policy_no_go"),
          execution_failure: ($session_churn_guard_ok_failure_kind == "execution_failure"),
          timeout: ($session_churn_guard_ok_failure_kind == "timeout")
        }
      }
    },
    failure: {
      kind: $final_failure_kind,
      policy_no_go: ($final_failure_kind == "policy_no_go"),
      execution_failure: ($final_failure_kind == "execution_failure"),
      timeout: ($final_failure_kind == "timeout")
    },
    policy_outcome: {
      decision: $policy_outcome_decision,
      fail_closed_no_go: ($final_failure_kind == "policy_no_go")
    },
    decision: {
      pass: ($status == "pass"),
      reasons: $reasons,
      warnings: $warnings
    },
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[phase1-resilience-handoff-check] status=$final_status rc=$final_rc"
echo "[phase1-resilience-handoff-check] ci_phase1_summary_json=${ci_phase1_summary_json:-none} usable=$ci_usable"
echo "[phase1-resilience-handoff-check] vpn_rc_resilience_summary_json=${vpn_rc_resilience_summary_json:-none} usable=$vpn_usable source_from_ci_artifacts=$vpn_from_ci_artifacts"
echo "[phase1-resilience-handoff-check] summary_json=$summary_json"

if ((${#warnings[@]} > 0)); then
  echo "[phase1-resilience-handoff-check] warning_count=${#warnings[@]}"
  for warning in "${warnings[@]}"; do
    echo "  - $warning"
  done
fi

if ((${#reasons[@]} > 0)); then
  echo "[phase1-resilience-handoff-check] fail_reason_count=${#reasons[@]}"
  for reason in "${reasons[@]}"; do
    echo "  - $reason"
  done
fi

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
