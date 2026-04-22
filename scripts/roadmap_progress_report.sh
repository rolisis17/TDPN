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
    [--profile-compare-multi-vm-stability-check-summary-json PATH] \
    [--profile-compare-multi-vm-stability-promotion-summary-json PATH] \
    [--runtime-actuation-promotion-summary-json PATH] \
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
    [--blockchain-mainnet-activation-gate-summary-json PATH] \
    [--blockchain-bootstrap-governance-graduation-gate-summary-json PATH] \
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

path_arg_or_die() {
  local name="$1"
  local value="$2"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "$name requires a value"
    exit 2
  fi
  case "$value" in
    -*)
      echo "$name requires a path value, got flag-like token: $value"
      exit 2
      ;;
  esac
}

value_arg_or_die() {
  local name="$1"
  local value="$2"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "$name requires a value"
    exit 2
  fi
  case "$value" in
    -*)
      echo "$name requires a value, got flag-like token: $value"
      exit 2
      ;;
  esac
}

optional_path_arg_or_die() {
  local name="$1"
  local argc="${2:-0}"
  local value="$3"
  if (( argc < 2 )); then
    echo "$name requires a value"
    exit 2
  fi
  value="$(trim "$value")"
  case "$value" in
    -*)
      echo "$name requires a path value, got flag-like token: $value"
      exit 2
      ;;
  esac
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

json_first_string_field_from_path() {
  local path="$1"
  shift || true
  local field=""
  local value=""

  if [[ -z "$path" || ! -f "$path" ]] || ! jq -e . "$path" >/dev/null 2>&1; then
    printf '%s' ""
    return
  fi

  for field in "$@"; do
    value="$(jq -r --arg field "$field" '
      .[$field]
      | if type == "string" then . else "" end
    ' "$path" 2>/dev/null || true)"
    value="$(trim "$value")"
    if [[ "$value" == "null" ]]; then
      value=""
    fi
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
      return
    fi
  done

  printf '%s' ""
}

timestamp_epoch_utc_or_empty() {
  local timestamp
  local epoch=""
  timestamp="$(trim "${1:-}")"
  if [[ -z "$timestamp" ]]; then
    printf '%s' ""
    return
  fi
  if ! [[ "$timestamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,9})?([Zz]|[+]00:00|[+]0000|[+]00)$ ]]; then
    printf '%s' ""
    return
  fi
  if epoch="$(date -u -d "$timestamp" +%s 2>/dev/null)" && [[ "$epoch" =~ ^[0-9]+$ ]]; then
    printf '%s' "$epoch"
    return
  fi
  printf '%s' ""
}

summary_age_sec_from_path() {
  local path="$1"
  local now_epoch=""
  local reference_epoch=""
  local known_timestamp_present="0"
  local known_timestamp_invalid="0"
  local timestamp_field=""
  local timestamp_type=""
  local timestamp_raw=""
  local timestamp_epoch=""
  local age_sec=""

  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi

  now_epoch="$(date -u +%s)"
  if [[ ! "$now_epoch" =~ ^[0-9]+$ ]]; then
    printf '%s' ""
    return
  fi

  for timestamp_field in generated_at_utc generated_at summary_generated_at_utc summary_generated_at; do
    if jq -e --arg field "$timestamp_field" 'has($field)' "$path" >/dev/null 2>&1; then
      known_timestamp_present="1"
      timestamp_type="$(jq -r --arg field "$timestamp_field" '.[$field] | type' "$path" 2>/dev/null || true)"
      if [[ "$timestamp_type" != "string" ]]; then
        known_timestamp_invalid="1"
        continue
      fi
      timestamp_raw="$(jq -r --arg field "$timestamp_field" '
        .[$field]
        | if type == "string" then . else "" end
      ' "$path" 2>/dev/null || true)"
      timestamp_raw="$(trim "$timestamp_raw")"
      if [[ -z "$timestamp_raw" ]]; then
        known_timestamp_invalid="1"
        continue
      fi
      timestamp_epoch="$(timestamp_epoch_utc_or_empty "$timestamp_raw")"
      if [[ -n "$timestamp_epoch" ]]; then
        if [[ -z "$reference_epoch" ]]; then
          reference_epoch="$timestamp_epoch"
        fi
      else
        known_timestamp_invalid="1"
      fi
    fi
  done

  if [[ "$known_timestamp_invalid" == "1" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$known_timestamp_present" != "1" ]]; then
    reference_epoch="$(file_mtime_epoch "$path")"
  fi
  if [[ -z "$reference_epoch" ]]; then
    printf '%s' ""
    return
  fi
  if [[ ! "$reference_epoch" =~ ^[0-9]+$ ]]; then
    printf '%s' ""
    return
  fi

  age_sec="$((now_epoch - reference_epoch))"
  if (( age_sec < 0 )); then
    printf '%s' ""
    return
  fi

  printf '%s' "$age_sec"
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

profile_default_gate_status_from_signoff_summary() {
  local path="$1"
  local status=""
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    status="$(
      jq -r '
        ((.status // "") | ascii_downcase) as $summary_status
        | (if (.decision.go | type) == "boolean" then (.decision.go | tostring) else "" end) as $go
        | ((.decision.decision // "") | ascii_upcase | gsub("[[:space:]_-]"; "")) as $decision
        | if $summary_status == "ok" then
            if $go == "true" or $decision == "GO" then "pass"
            elif $go == "false" or $decision == "NOGO" then "warn"
            else "warn"
            end
          elif $summary_status == "fail" then
            if $go == "false" or $decision == "NOGO" then "warn"
            else "fail"
            end
          elif $summary_status == "pass" then
            "pass"
          elif $summary_status == "warn" then
            "warn"
          elif $summary_status == "skip" then
            "pending"
          else
            "pending"
          end
      ' "$path" 2>/dev/null || true
    )"
    if [[ "$status" == "warn" ]] \
       && [[ "$(profile_default_gate_signoff_decision_no_go_01 "$path")" == "1" ]] \
       && [[ "$(profile_default_gate_no_go_insufficient_evidence_01 "$path")" == "1" ]]; then
      # NO-GO due to insufficient campaign evidence should remain actionable but
      # non-advisory until enough evidence is collected.
      status="pending"
    fi
  fi
  case "$status" in
    pass|warn|fail|pending|skip)
      printf '%s' "$status"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

profile_default_gate_signoff_decision_no_go_01() {
  local signoff_summary_path="$1"
  if [[ ! -f "$signoff_summary_path" ]] || ! jq -e . "$signoff_summary_path" >/dev/null 2>&1; then
    printf '0'
    return
  fi
  if jq -e '
    ((.decision.go | type) == "boolean" and .decision.go == false)
    or (((.decision.decision // "") | ascii_upcase | gsub("[[:space:]_-]"; "")) == "NOGO")
  ' "$signoff_summary_path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

profile_default_gate_campaign_check_summary_from_signoff() {
  local signoff_summary_path="$1"
  local candidate=""
  local resolved=""
  if [[ ! -f "$signoff_summary_path" ]] || ! jq -e . "$signoff_summary_path" >/dev/null 2>&1; then
    printf '%s' ""
    return
  fi
  while IFS= read -r candidate; do
    candidate="$(trim "$candidate")"
    if [[ -z "$candidate" ]]; then
      continue
    fi
    resolved="$(resolve_path_with_base "$candidate" "$signoff_summary_path")"
    if [[ -n "$resolved" ]]; then
      printf '%s' "$resolved"
      return
    fi
  done < <(jq -r '
    [
      (.artifacts.campaign_check_summary_json // ""),
      (.stages.campaign_check.summary_json // ""),
      (.inputs.campaign_check_summary_json // "")
    ]
    | .[]
    | strings
    | select(length > 0)
  ' "$signoff_summary_path" 2>/dev/null || true)
  printf '%s' ""
}

selection_policy_state_from_summary_json() {
  local summary_json_path="$1"
  local state=""
  if [[ ! -f "$summary_json_path" ]] || ! jq -e . "$summary_json_path" >/dev/null 2>&1; then
    printf 'null\x1fnull'
    return
  fi
  state="$(jq -r '
    def scalar:
      if type == "array" then (.[0] // null) else . end;
    def to_num:
      scalar
      | if . == null then null
        elif type == "number" then .
        elif type == "string" and test("^-?[0-9]+([.][0-9]+)?$") then tonumber
        else null
        end;
    def to_str:
      scalar
      | if . == null then null
        elif type == "string" then .
        elif type == "number" then tostring
        else null
        end;
    def normalize($p):
      {
        sticky_pair_sec: ($p.sticky_pair_sec | to_num),
        entry_rotation_sec: ($p.entry_rotation_sec | to_num),
        entry_rotation_jitter_pct: ($p.entry_rotation_jitter_pct | to_num),
        exit_exploration_pct: ($p.exit_exploration_pct | to_num),
        path_profile: ($p.path_profile | to_str)
      };
    def valid_policy($p):
      ($p.sticky_pair_sec != null)
      and ($p.entry_rotation_sec != null)
      and ($p.entry_rotation_jitter_pct != null)
      and ($p.exit_exploration_pct != null)
      and ($p.path_profile != null)
      and (($p.path_profile | length) > 0);
    ([
      (.summary.selection_policy // empty),
      (.selection_policy // empty),
      (.trend.selection_policy // empty),
      ((.runs // [])[]?.selection_policy // empty)
    ] | map(normalize(.))) as $policies
    | (if ($policies | length) > 0 then "true" else "false" end) as $present
    | (if ($policies | any(valid_policy(.))) then "true" else "false" end) as $valid
    | ($present + "\u001f" + $valid)
  ' "$summary_json_path" 2>/dev/null || true)"
  if [[ "$state" != *$'\x1f'* ]]; then
    printf 'null\x1fnull'
    return
  fi
  printf '%s' "$state"
}

profile_default_gate_campaign_summary_from_signoff() {
  local signoff_summary_path="$1"
  local candidate=""
  local resolved=""
  if [[ ! -f "$signoff_summary_path" ]] || ! jq -e . "$signoff_summary_path" >/dev/null 2>&1; then
    printf '%s' ""
    return
  fi
  while IFS= read -r candidate; do
    candidate="$(trim "$candidate")"
    if [[ -z "$candidate" ]]; then
      continue
    fi
    resolved="$(resolve_path_with_base "$candidate" "$signoff_summary_path")"
    if [[ -n "$resolved" ]]; then
      printf '%s' "$resolved"
      return
    fi
  done < <(jq -r '
    [
      (.artifacts.campaign_summary_json // ""),
      (.stages.campaign.summary_json // ""),
      (.inputs.campaign_summary_json // "")
    ]
    | .[]
    | strings
    | select(length > 0)
  ' "$signoff_summary_path" 2>/dev/null || true)
  printf '%s' ""
}

micro_relay_m4_state_from_summary_json() {
  local summary_json_path="$1"
  local state=""
  if [[ ! -f "$summary_json_path" ]] || ! jq -e . "$summary_json_path" >/dev/null 2>&1; then
    printf 'false\x1fnull\x1ffalse\x1ffalse\x1ffalse'
    return
  fi
  state="$(jq -r '
    def scalar:
      if type == "array" then (.[0] // null) else . end;
    def to_boolish:
      scalar
      | if . == null then null
        elif type == "boolean" then .
        elif type == "number" then (. != 0)
        elif type == "string" then
          (. | ascii_downcase) as $text
          | if ($text == "1" or $text == "true" or $text == "yes" or $text == "pass" or $text == "ok" or $text == "go" or $text == "healthy" or $text == "enabled") then true
            elif ($text == "0" or $text == "false" or $text == "no" or $text == "fail" or $text == "warn" or $text == "disabled") then false
            else null
            end
        else null
        end;
    def first_non_null($values):
      reduce $values[] as $value (null; if . == null and $value != null then $value else . end);
    def first_boolish($values):
      first_non_null($values | map(to_boolish));
    def canonical_m4_evidence:
      first_non_null([
        .summary.m4_micro_relay_evidence,
        .m4_micro_relay_evidence,
        .summary.m4.micro_relay_evidence,
        .m4.micro_relay_evidence
      ]);
    def candidate_present($candidate):
      if $candidate == null then null
      elif ($candidate | type) == "object" then
        if ($candidate.available? != null) then (($candidate.available // false) | to_boolish)
        elif ($candidate.present? != null) then (($candidate.present // false) | to_boolish)
        else true
        end
      elif ($candidate | type) == "array" then (($candidate | length) > 0)
      else
        ($candidate | to_boolish)
      end;
    def signal_present($candidate):
      if $candidate == null then null
      elif ($candidate | type) == "boolean" then $candidate
      elif ($candidate | type) == "number" then ($candidate != 0)
      elif ($candidate | type) == "string" then
        ($candidate | to_boolish) as $boolish
        | if $boolish != null then $boolish else (($candidate | length) > 0) end
      elif ($candidate | type) == "array" then (($candidate | length) > 0)
      elif ($candidate | type) == "object" then
        if ($candidate.available? != null) then (($candidate.available // false) | to_boolish)
        elif ($candidate.present? != null) then (($candidate.present // false) | to_boolish)
        elif ($candidate.evidence_hits? != null and (($candidate.evidence_hits | type) == "number")) then (($candidate.evidence_hits // 0) > 0)
        else true
        end
      else true
      end;
    def quality_candidate:
      first_non_null([
        (canonical_m4_evidence | if type == "object" then .micro_relay_quality else null end),
        canonical_m4_evidence,
        .decision.micro_relay_quality_evidence,
        .decision.micro_relay_evidence.quality,
        .decision.micro_relay_evidence,
        .observed.micro_relay_quality_evidence,
        .observed.micro_relay_evidence.quality,
        .observed.micro_relay_evidence,
        .summary.micro_relay_quality_evidence,
        .summary.micro_relay_quality,
        .summary.m4.micro_relay_quality_evidence,
        .summary.m4.micro_relay_quality,
        .summary.m4.quality_scoring,
        .m4.micro_relay_quality_evidence,
        .m4.micro_relay_quality,
        .micro_relay_quality_evidence,
        .micro_relay_quality
      ]);
    def quality_status_from_candidate($candidate):
      if $candidate == null then null
      elif ($candidate | type) == "object" then
        first_boolish([
          $candidate.status_pass,
          $candidate.pass,
          $candidate.quality_ok,
          $candidate.healthy,
          (
            ($candidate.quality_band // "" | tostring | ascii_downcase) as $quality_band
            | if ($quality_band == "excellent" or $quality_band == "good" or $quality_band == "pass" or $quality_band == "ok" or $quality_band == "healthy") then true
              elif ($quality_band == "degraded" or $quality_band == "poor" or $quality_band == "warn" or $quality_band == "fail") then false
              else null
              end
          ),
          (
            ($candidate.quality_score // null) as $quality_score
            | if ($quality_score | type) == "number" then ($quality_score >= 85) else null end
          ),
          $candidate.quality_status,
          $candidate.status
        ])
      else
        ($candidate | to_boolish)
      end;
    def quality_status_direct:
      first_boolish([
        .decision.micro_relay_quality_status_pass,
        .decision.micro_relay_quality_evidence.status_pass,
        .decision.micro_relay_quality_evidence.pass,
        .decision.micro_relay_policy_evidence.quality_status_pass,
        .decision.micro_relay_evidence.quality_status_pass,
        .observed.micro_relay_quality_status_pass,
        .observed.micro_relay_quality_evidence.status_pass,
        .observed.micro_relay_quality_evidence.pass,
        .observed.micro_relay_policy_evidence.quality_status_pass,
        .observed.micro_relay_evidence.quality_status_pass,
        .summary.m4.micro_relay_quality_status_pass,
        .summary.micro_relay_quality_status_pass,
        .m4.micro_relay_quality_status_pass
      ]);
    def demotion_candidate:
      first_non_null([
        (canonical_m4_evidence | if type == "object" then .adaptive_demotion_promotion else null end),
        .decision.micro_relay_demotion_policy,
        .decision.micro_relay_policy_evidence.demotion_policy_present,
        .decision.micro_relay_evidence.demotion_policy_present,
        .observed.micro_relay_demotion_policy,
        .observed.micro_relay_policy_evidence.demotion_policy_present,
        .observed.micro_relay_evidence.demotion_policy_present,
        .summary.micro_relay_demotion_policy,
        .summary.m4.micro_relay_demotion_policy,
        .summary.m4.demotion_policy,
        .summary.micro_relay_policy.demotion,
        .summary.relay_policy.demotion,
        .m4.micro_relay_demotion_policy,
        .m4.demotion_policy
      ]);
    def promotion_candidate:
      first_non_null([
        (canonical_m4_evidence | if type == "object" then .adaptive_demotion_promotion else null end),
        .decision.micro_relay_promotion_policy,
        .decision.micro_relay_policy_evidence.promotion_policy_present,
        .decision.micro_relay_evidence.promotion_policy_present,
        .observed.micro_relay_promotion_policy,
        .observed.micro_relay_policy_evidence.promotion_policy_present,
        .observed.micro_relay_evidence.promotion_policy_present,
        .summary.micro_relay_promotion_policy,
        .summary.m4.micro_relay_promotion_policy,
        .summary.m4.promotion_policy,
        .summary.micro_relay_policy.promotion,
        .summary.relay_policy.promotion,
        .m4.micro_relay_promotion_policy,
        .m4.promotion_policy
      ]);
    def trust_tier_port_unlock_candidate:
      first_non_null([
        (canonical_m4_evidence | if type == "object" then .trust_tier_port_unlock_wiring else null end),
        .decision.trust_tier_port_unlock_policy,
        .decision.micro_relay_policy_evidence.trust_tier_port_unlock_policy_present,
        .decision.micro_relay_evidence.trust_tier_port_unlock_policy_present,
        .observed.trust_tier_port_unlock_policy,
        .observed.micro_relay_policy_evidence.trust_tier_port_unlock_policy_present,
        .observed.micro_relay_evidence.trust_tier_port_unlock_policy_present,
        .summary.trust_tier_port_unlock_policy,
        .summary.m4.trust_tier_port_unlock_policy,
        .summary.port_unlock_policy,
        .summary.port_unlock.trust_tier_policy,
        .summary.exit_policy.trust_tier_port_unlock_policy,
        .m4.trust_tier_port_unlock_policy
      ]);
    (quality_candidate) as $quality_candidate
    | (quality_status_direct) as $quality_status_direct
    | (demotion_candidate) as $demotion_candidate
    | (promotion_candidate) as $promotion_candidate
    | (trust_tier_port_unlock_candidate) as $trust_tier_port_unlock_candidate
    | (if $quality_status_direct != null then $quality_status_direct else quality_status_from_candidate($quality_candidate) end) as $quality_status_pass
    | (
        [
          $quality_status_direct,
          candidate_present($quality_candidate),
          signal_present($demotion_candidate),
          signal_present($promotion_candidate),
          signal_present($trust_tier_port_unlock_candidate)
        ] | any(. == true)
      ) as $evidence_available
    | [
        (if $evidence_available then "true" else "false" end),
        (if $quality_status_pass == null then "null" elif $quality_status_pass then "true" else "false" end),
        (if (signal_present($demotion_candidate) == null) then "false" elif signal_present($demotion_candidate) then "true" else "false" end),
        (if (signal_present($promotion_candidate) == null) then "false" elif signal_present($promotion_candidate) then "true" else "false" end),
        (if (signal_present($trust_tier_port_unlock_candidate) == null) then "false" elif signal_present($trust_tier_port_unlock_candidate) then "true" else "false" end)
      ]
    | join("\u001f")
  ' "$summary_json_path" 2>/dev/null || true)"
  if [[ "$state" != *$'\x1f'* ]]; then
    printf 'false\x1fnull\x1ffalse\x1ffalse\x1ffalse'
    return
  fi
  printf '%s' "$state"
}

profile_default_gate_micro_relay_evidence_from_signoff() {
  local signoff_summary_path="$1"
  local state=""
  local available="false"
  local quality_status_pass="null"
  local demotion_policy_present="false"
  local promotion_policy_present="false"
  local trust_tier_port_unlock_policy_present="false"
  local fallback_state=""
  local fallback_available="false"
  local fallback_quality_status_pass="null"
  local fallback_demotion_policy_present="false"
  local fallback_promotion_policy_present="false"
  local fallback_trust_tier_port_unlock_policy_present="false"
  local campaign_check_summary_path=""
  local campaign_summary_path=""

  if [[ ! -f "$signoff_summary_path" ]] || ! jq -e . "$signoff_summary_path" >/dev/null 2>&1; then
    printf 'false\x1fnull\x1ffalse\x1ffalse\x1ffalse'
    return
  fi

  state="$(micro_relay_m4_state_from_summary_json "$signoff_summary_path")"
  if [[ "$state" == *$'\x1f'* ]]; then
    available="${state%%$'\x1f'*}"
    state="${state#*$'\x1f'}"
    quality_status_pass="${state%%$'\x1f'*}"
    state="${state#*$'\x1f'}"
    demotion_policy_present="${state%%$'\x1f'*}"
    state="${state#*$'\x1f'}"
    promotion_policy_present="${state%%$'\x1f'*}"
    trust_tier_port_unlock_policy_present="${state#*$'\x1f'}"
  fi

  campaign_check_summary_path="$(profile_default_gate_campaign_check_summary_from_signoff "$signoff_summary_path")"
  if [[ "$(json_file_valid_01 "$campaign_check_summary_path")" == "1" ]]; then
    fallback_state="$(micro_relay_m4_state_from_summary_json "$campaign_check_summary_path")"
    if [[ "$fallback_state" == *$'\x1f'* ]]; then
      fallback_available="${fallback_state%%$'\x1f'*}"
      fallback_state="${fallback_state#*$'\x1f'}"
      fallback_quality_status_pass="${fallback_state%%$'\x1f'*}"
      fallback_state="${fallback_state#*$'\x1f'}"
      fallback_demotion_policy_present="${fallback_state%%$'\x1f'*}"
      fallback_state="${fallback_state#*$'\x1f'}"
      fallback_promotion_policy_present="${fallback_state%%$'\x1f'*}"
      fallback_trust_tier_port_unlock_policy_present="${fallback_state#*$'\x1f'}"
      if [[ "$available" != "true" && "$fallback_available" == "true" ]]; then
        available="$fallback_available"
        quality_status_pass="$fallback_quality_status_pass"
        demotion_policy_present="$fallback_demotion_policy_present"
        promotion_policy_present="$fallback_promotion_policy_present"
        trust_tier_port_unlock_policy_present="$fallback_trust_tier_port_unlock_policy_present"
      else
        if [[ "$quality_status_pass" == "null" && "$fallback_quality_status_pass" != "null" ]]; then
          quality_status_pass="$fallback_quality_status_pass"
        fi
        if [[ "$fallback_demotion_policy_present" == "true" ]]; then
          demotion_policy_present="true"
        fi
        if [[ "$fallback_promotion_policy_present" == "true" ]]; then
          promotion_policy_present="true"
        fi
        if [[ "$fallback_trust_tier_port_unlock_policy_present" == "true" ]]; then
          trust_tier_port_unlock_policy_present="true"
        fi
      fi
    fi
  fi

  campaign_summary_path="$(profile_default_gate_campaign_summary_from_signoff "$signoff_summary_path")"
  if [[ "$(json_file_valid_01 "$campaign_summary_path")" == "1" ]]; then
    fallback_state="$(micro_relay_m4_state_from_summary_json "$campaign_summary_path")"
    if [[ "$fallback_state" == *$'\x1f'* ]]; then
      fallback_available="${fallback_state%%$'\x1f'*}"
      fallback_state="${fallback_state#*$'\x1f'}"
      fallback_quality_status_pass="${fallback_state%%$'\x1f'*}"
      fallback_state="${fallback_state#*$'\x1f'}"
      fallback_demotion_policy_present="${fallback_state%%$'\x1f'*}"
      fallback_state="${fallback_state#*$'\x1f'}"
      fallback_promotion_policy_present="${fallback_state%%$'\x1f'*}"
      fallback_trust_tier_port_unlock_policy_present="${fallback_state#*$'\x1f'}"
      if [[ "$available" != "true" && "$fallback_available" == "true" ]]; then
        available="$fallback_available"
        quality_status_pass="$fallback_quality_status_pass"
        demotion_policy_present="$fallback_demotion_policy_present"
        promotion_policy_present="$fallback_promotion_policy_present"
        trust_tier_port_unlock_policy_present="$fallback_trust_tier_port_unlock_policy_present"
      else
        if [[ "$quality_status_pass" == "null" && "$fallback_quality_status_pass" != "null" ]]; then
          quality_status_pass="$fallback_quality_status_pass"
        fi
        if [[ "$fallback_demotion_policy_present" == "true" ]]; then
          demotion_policy_present="true"
        fi
        if [[ "$fallback_promotion_policy_present" == "true" ]]; then
          promotion_policy_present="true"
        fi
        if [[ "$fallback_trust_tier_port_unlock_policy_present" == "true" ]]; then
          trust_tier_port_unlock_policy_present="true"
        fi
      fi
    fi
  fi

  case "$available" in
    true|false) ;;
    *) available="false" ;;
  esac
  case "$quality_status_pass" in
    true|false|null) ;;
    *) quality_status_pass="null" ;;
  esac
  case "$demotion_policy_present" in
    true|false) ;;
    *) demotion_policy_present="false" ;;
  esac
  case "$promotion_policy_present" in
    true|false) ;;
    *) promotion_policy_present="false" ;;
  esac
  case "$trust_tier_port_unlock_policy_present" in
    true|false) ;;
    *) trust_tier_port_unlock_policy_present="false" ;;
  esac

  if [[ "$available" != "true" ]]; then
    quality_status_pass="null"
  fi

  printf '%s\x1f%s\x1f%s\x1f%s\x1f%s' \
    "$available" \
    "$quality_status_pass" \
    "$demotion_policy_present" \
    "$promotion_policy_present" \
    "$trust_tier_port_unlock_policy_present"
}

profile_default_gate_micro_relay_evidence_note_text() {
  local available="$1"
  local quality_status_pass="$2"
  local demotion_policy_present="$3"
  local promotion_policy_present="$4"
  local trust_tier_port_unlock_policy_present="$5"
  local issues=()
  local joined=""

  if [[ "$available" != "true" ]]; then
    printf '%s' "micro-relay M4 evidence unavailable from profile-compare campaign signoff summary; verify summary path and rerun profile-compare-campaign-signoff with --refresh-campaign 1"
    return
  fi

  if [[ "$quality_status_pass" == "null" ]]; then
    issues+=("quality status/pass indicator unavailable")
  elif [[ "$quality_status_pass" != "true" ]]; then
    issues+=("quality status/pass is not pass")
  fi
  if [[ "$demotion_policy_present" != "true" ]]; then
    issues+=("demotion policy evidence missing")
  fi
  if [[ "$promotion_policy_present" != "true" ]]; then
    issues+=("promotion policy evidence missing")
  fi
  if [[ "$trust_tier_port_unlock_policy_present" != "true" ]]; then
    issues+=("trust-tier port-unlock policy evidence missing")
  fi
  if ((${#issues[@]} == 0)); then
    printf '%s' ""
    return
  fi
  joined="$(printf '%s; ' "${issues[@]}")"
  joined="${joined%"; "}"
  printf '%s' "$joined"
}

profile_default_gate_runtime_actuation_reason_text() {
  local ready="$1"
  local micro_relay_evidence_note="$2"
  if [[ "$ready" == "true" ]]; then
    printf '%s' ""
    return
  fi
  if [[ -n "$micro_relay_evidence_note" ]]; then
    printf '%s' "runtime-actuation readiness pending: $micro_relay_evidence_note"
    return
  fi
  printf '%s' "runtime-actuation readiness pending: micro-relay/trust-tier policy evidence incomplete; rerun profile-compare-campaign-signoff with --refresh-campaign 1 and verify M4 policy diagnostics"
}

profile_default_gate_selection_policy_evidence_from_signoff() {
  local signoff_summary_path="$1"
  local present="null"
  local valid="null"
  local fallback_present="null"
  local fallback_valid="null"
  local state=""
  local campaign_summary_path=""

  if [[ ! -f "$signoff_summary_path" ]] || ! jq -e . "$signoff_summary_path" >/dev/null 2>&1; then
    printf 'null\x1fnull'
    return
  fi

  present="$(jq -r '
    if (.decision.selection_policy_evidence.present | type) == "boolean"
    then (.decision.selection_policy_evidence.present | tostring)
    else "null"
    end
  ' "$signoff_summary_path" 2>/dev/null || true)"
  valid="$(jq -r '
    if (.decision.selection_policy_evidence.valid | type) == "boolean"
    then (.decision.selection_policy_evidence.valid | tostring)
    else "null"
    end
  ' "$signoff_summary_path" 2>/dev/null || true)"

  state="$(selection_policy_state_from_summary_json "$signoff_summary_path")"
  if [[ "$state" == *$'\x1f'* ]]; then
    fallback_present="${state%%$'\x1f'*}"
    fallback_valid="${state#*$'\x1f'}"
  fi
  if [[ "$present" == "null" ]]; then
    present="$fallback_present"
  fi
  if [[ "$valid" == "null" ]]; then
    valid="$fallback_valid"
  fi

  campaign_summary_path="$(profile_default_gate_campaign_summary_from_signoff "$signoff_summary_path")"
  if [[ "$(json_file_valid_01 "$campaign_summary_path")" == "1" ]]; then
    state="$(selection_policy_state_from_summary_json "$campaign_summary_path")"
    if [[ "$state" == *$'\x1f'* ]]; then
      fallback_present="${state%%$'\x1f'*}"
      fallback_valid="${state#*$'\x1f'}"
      if [[ "$present" == "null" ]]; then
        present="$fallback_present"
      fi
      if [[ "$valid" == "null" ]]; then
        valid="$fallback_valid"
      fi
    fi
  fi

  case "$present" in
    true|false|null) ;;
    *) present="null" ;;
  esac
  case "$valid" in
    true|false|null) ;;
    *) valid="null" ;;
  esac

  printf '%s\x1f%s' "$present" "$valid"
}

profile_default_gate_selection_policy_evidence_note_text() {
  local present="$1"
  local valid="$2"
  if [[ "$present" == "false" ]]; then
    printf '%s' "selection-policy evidence missing in profile-compare campaign signoff summary; rerun profile-compare-campaign-signoff with --refresh-campaign 1"
    return
  fi
  if [[ "$present" == "null" ]]; then
    printf '%s' "selection-policy evidence unavailable from profile-compare campaign signoff summary; verify summary path and rerun profile-compare-campaign-signoff with --refresh-campaign 1"
    return
  fi
  if [[ "$valid" == "false" ]]; then
    printf '%s' "selection-policy evidence invalid in profile-compare campaign signoff summary; rerun profile-compare-campaign-signoff with --refresh-campaign 1"
    return
  fi
  if [[ "$valid" == "null" ]]; then
    printf '%s' "selection-policy evidence validity unavailable in profile-compare campaign signoff summary; rerun profile-compare-campaign-signoff with --refresh-campaign 1"
    return
  fi
  printf '%s' ""
}

profile_default_gate_no_go_insufficient_evidence_01() {
  local signoff_summary_path="$1"
  local campaign_check_summary_path=""
  local insufficient_evidence="0"
  if [[ "$(profile_default_gate_signoff_decision_no_go_01 "$signoff_summary_path")" != "1" ]]; then
    printf '0'
    return
  fi
  campaign_check_summary_path="$(profile_default_gate_campaign_check_summary_from_signoff "$signoff_summary_path")"
  if [[ -z "$campaign_check_summary_path" ]] || [[ "$(json_file_valid_01 "$campaign_check_summary_path")" != "1" ]]; then
    # Fail closed for NO-GO decisions when campaign-check evidence is missing/invalid.
    printf '1'
    return
  fi
  insufficient_evidence="$(
    jq -r '
      def to_bool:
        if type == "boolean" then .
        elif type == "number" then . != 0
        elif type == "string" then ((ascii_downcase == "true") or (. == "1"))
        else false
        end;
      def to_num:
        if type == "number" then .
        elif type == "string" then (if test("^-?[0-9]+(\\.[0-9]+)?$") then tonumber else null end)
        else null
        end;
      try (
        (.inputs.policy // {}) as $policy
        | (.observed // {}) as $observed
        | ($policy.require_status_pass | to_bool) as $require_campaign_status_pass
        | ($policy.require_trend_status_pass | to_bool) as $require_trend_status_pass
        | ($policy.require_min_runs_total | to_num) as $min_runs_total
        | ($policy.require_min_runs_with_summary | to_num) as $min_runs_with_summary
        | ($observed.runs_total | to_num) as $runs_total
        | ($observed.runs_with_summary | to_num) as $runs_with_summary
        | (if $require_campaign_status_pass then (($observed.campaign_status // "") | ascii_downcase) == "pass" else true end) as $campaign_status_ok
        | (if $require_trend_status_pass then (($observed.trend_status // "") | ascii_downcase) == "pass" else true end) as $trend_status_ok
        | (if $min_runs_total == null then true else ($runs_total != null and $runs_total >= $min_runs_total) end) as $runs_total_ok
        | (if $min_runs_with_summary == null then true else ($runs_with_summary != null and $runs_with_summary >= $min_runs_with_summary) end) as $runs_with_summary_ok
        | (($campaign_status_ok and $trend_status_ok and $runs_total_ok and $runs_with_summary_ok) | not)
      ) catch true
      | if . then "1" else "0" end
    ' "$campaign_check_summary_path" 2>/dev/null || echo 1
  )"
  case "$insufficient_evidence" in
    1|0) ;;
    *) insufficient_evidence="1" ;;
  esac
  printf '%s' "$insufficient_evidence"
}

resolve_profile_default_gate_signoff_status() {
  local explicit_path="$1"
  local manual_summary_path="$2"
  local candidate=""
  local candidate_abs=""
  local status=""
  local fallback_status=""
  local fallback_path=""
  local seen_paths_nl=$'\n'
  local -a candidates=()
  if [[ -n "$explicit_path" ]]; then
    candidates+=("$explicit_path")
  fi
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" ]]; then
        candidates+=("$candidate")
      fi
    done < <(jq -r '
      [
        (.summary.profile_default_gate.signoff_summary_json // ""),
        (.summary.profile_default_gate.summary_json // ""),
        (.summary.profile_default_gate.source_summary_json // ""),
        (.summary.profile_default_gate.artifacts.signoff_summary_json // ""),
        (.artifacts.profile_compare_signoff_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  for candidate in "${candidates[@]}"; do
    candidate_abs="$(abs_path "$candidate")"
    if [[ -z "$candidate_abs" ]]; then
      continue
    fi
    if [[ "$seen_paths_nl" == *$'\n'"$candidate_abs"$'\n'* ]]; then
      continue
    fi
    seen_paths_nl+="$candidate_abs"$'\n'
    status="$(profile_default_gate_status_from_signoff_summary "$candidate_abs")"
    case "$status" in
      pass|warn|fail)
        printf '%s\x1f%s' "$status" "$candidate_abs"
        return
        ;;
      pending|skip)
        if [[ -z "$fallback_status" ]]; then
          fallback_status="$status"
          fallback_path="$candidate_abs"
        fi
        ;;
    esac
  done
  printf '%s\x1f%s' "$fallback_status" "$fallback_path"
}

profile_default_gate_stability_summary_usable_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    (.schema | type == "object")
    and ((.schema.id // "") == "profile_default_gate_stability_summary")
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

profile_default_gate_stability_check_summary_usable_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    (.version == 1)
    and ((.decision | type) == "string")
    and ((.status | type) == "string")
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

profile_default_gate_stability_cycle_summary_usable_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    (.schema | type == "object")
    and ((.schema.id // "") == "profile_default_gate_stability_cycle_summary")
    and (.version == 1)
    and ((.decision | type) == "string")
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

resolve_profile_default_gate_stability_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    candidate="$(jq -r '
      .summary.profile_default_gate.artifacts.profile_default_gate_stability_summary_json
      // ""
    ' "$manual_summary_path" 2>/dev/null || true)"
    candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
  fi
  if [[ -z "$candidate" && -n "$reports_dir" ]]; then
    candidate="$(abs_path "$reports_dir/profile_default_gate_stability_summary.json")"
  fi
  printf '%s' "$candidate"
}

resolve_profile_default_gate_stability_check_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    candidate="$(jq -r '
      .summary.profile_default_gate.artifacts.profile_default_gate_stability_check_summary_json
      // ""
    ' "$manual_summary_path" 2>/dev/null || true)"
    candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
  fi
  if [[ -z "$candidate" && -n "$reports_dir" ]]; then
    candidate="$(abs_path "$reports_dir/profile_default_gate_stability_check_summary.json")"
  fi
  printf '%s' "$candidate"
}

resolve_profile_default_gate_stability_cycle_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    candidate="$(jq -r '
      .summary.profile_default_gate.artifacts.profile_default_gate_stability_cycle_summary_json
      // .report.profile_default_gate.artifacts.profile_default_gate_stability_cycle_summary_json
      // .summary.profile_default_gate.cycle_summary_json
      // .summary.profile_default_gate.stability_cycle_summary_json
      // ""
    ' "$manual_summary_path" 2>/dev/null || true)"
    candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
  fi
  if [[ -z "$candidate" && -n "$reports_dir" ]]; then
    candidate="$(abs_path "$reports_dir/profile_default_gate_stability_cycle_summary.json")"
  fi
  printf '%s' "$candidate"
}

profile_compare_multi_vm_stability_check_summary_usable_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    (.version == 1)
    and ((.decision | type) == "string")
    and ((.status | type) == "string")
    and (
      (.schema == null)
      or ((.schema.id // "") == "profile_compare_multi_vm_stability_check_summary")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

resolve_profile_compare_multi_vm_stability_check_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" ]]; then
        printf '%s' "$candidate"
        return
      fi
    done < <(jq -r '
      [
        (.summary.profile_compare_multi_vm_stability.summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_check_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_check_summary_json // ""),
        (.summary.profile_default_gate.artifacts.multi_vm_stability_check_summary_json // ""),
        (.artifacts.profile_compare_multi_vm_stability_check_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  if [[ -n "$reports_dir" ]]; then
    candidate="$(abs_path "$reports_dir/profile_compare_multi_vm_stability_check_summary.json")"
  fi
  printf '%s' "$candidate"
}

profile_compare_multi_vm_stability_summary_kind_from_path() {
  local path="$1"
  local base_name=""
  base_name="$(basename "$path" 2>/dev/null || true)"
  case "$base_name" in
    profile_compare_multi_vm_stability_check_summary.json) printf '%s' "check" ; return ;;
    profile_compare_multi_vm_stability_cycle_summary.json) printf '%s' "cycle" ; return ;;
    profile_compare_multi_vm_stability_summary.json) printf '%s' "run" ; return ;;
  esac
  printf '%s' "check"
}

profile_compare_multi_vm_stability_promotion_summary_usable_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    def norm_decision:
      ascii_upcase | gsub("[[:space:]_-]"; "");
    def decision_allowed:
      ((. | norm_decision) == "GO")
      or ((. | norm_decision) == "NOGO")
      or ((. | norm_decision) == "PENDING");
    def norm_status:
      ascii_downcase | gsub("[[:space:]_-]"; "");
    def status_allowed:
      ((. | norm_status) == "ok")
      or ((. | norm_status) == "pass")
      or ((. | norm_status) == "fail")
      or ((. | norm_status) == "warn")
      or ((. | norm_status) == "pending")
      or ((. | norm_status) == "go")
      or ((. | norm_status) == "nogo")
      or ((. | norm_status) == "runtimefail");
    def schema_id:
      (.schema.id // "");
    (.version == 1)
    and ((.decision | type) == "string")
    and ((.status | type) == "string")
    and (.decision | decision_allowed)
    and (.status | status_allowed)
    and (
      if (.schema == null) then
        true
      elif (.schema | type) == "object" then
        (
          (schema_id == "profile_compare_multi_vm_stability_promotion_check_summary")
          or (schema_id == "profile_compare_multi_vm_stability_promotion_summary")
          or (schema_id == "profile_compare_multi_vm_stability_promotion_cycle_summary")
        )
      else
        false
      end
    )
    and (
      if (schema_id == "profile_compare_multi_vm_stability_promotion_cycle_summary") then
        ((.promotion.summary_exists // false) == true)
        and ((.promotion.summary_valid_json // false) == true)
        and ((.promotion.summary_fresh // false) == true)
        and ((.promotion.decision | type) == "string")
        and ((.promotion.status | type) == "string")
        and (.promotion.decision | decision_allowed)
        and (.promotion.status | status_allowed)
        and ((.promotion.decision | norm_decision) == (.decision | norm_decision))
        and ((.promotion.status | norm_status) == (.status | norm_status))
      else
        true
      end
    )
  ' "$path" >/dev/null 2>&1 \
    && [[ "$(profile_compare_multi_vm_stability_promotion_summary_stale_01 "$path")" == "0" ]]; then
    printf '1'
  else
    printf '0'
  fi
}

profile_compare_multi_vm_stability_promotion_summary_stale_01() {
  local path="$1"
  local stale_flag="null"
  local max_age_sec="${ROADMAP_PROGRESS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_MAX_AGE_SEC:-86400}"
  local age_sec=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '1'
    return
  fi
  stale_flag="$(jq -r '
    if (.stale | type) == "boolean" then (.stale | tostring)
    elif (.summary_stale | type) == "boolean" then (.summary_stale | tostring)
    elif (.fresh | type) == "boolean" then (if .fresh then "false" else "true" end)
    elif (.summary_fresh | type) == "boolean" then (if .summary_fresh then "false" else "true" end)
    elif (.promotion.summary_fresh | type) == "boolean" then (if .promotion.summary_fresh then "false" else "true" end)
    else "null"
    end
  ' "$path" 2>/dev/null || printf '%s' "null")"
  if [[ "$stale_flag" == "true" ]]; then
    printf '1'
    return
  fi
  if ! [[ "$max_age_sec" =~ ^[0-9]+$ ]]; then
    max_age_sec=86400
  fi
  age_sec="$(summary_age_sec_from_path "$path")"
  if [[ "$age_sec" =~ ^[0-9]+$ ]]; then
    if (( age_sec > max_age_sec )); then
      printf '1'
      return
    fi
  else
    # Fail closed when summary age cannot be computed.
    printf '1'
    return
  fi
  printf '0'
}

resolve_profile_compare_multi_vm_stability_promotion_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  local fallback_candidate=""
  local -a fallback_candidates=()
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" && "$(profile_compare_multi_vm_stability_promotion_summary_usable_01 "$candidate")" == "1" ]]; then
        printf '%s' "$candidate"
        return
      fi
    done < <(jq -r '
      [
        (.summary.profile_compare_multi_vm_stability_promotion_cycle.summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion_cycle.latest_summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion_cycle_latest_summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion_cycle_summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion.summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion_summary_json // ""),
        (.summary.profile_default_gate.profile_compare_multi_vm_stability_promotion_cycle_summary_json // ""),
        (.summary.profile_default_gate.profile_compare_multi_vm_stability_promotion_cycle_latest_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_promotion_cycle_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_promotion_cycle_latest_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_promotion_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_promotion_check_summary_json // ""),
        (.artifacts.profile_compare_multi_vm_stability_promotion_cycle_summary_json // ""),
        (.artifacts.profile_compare_multi_vm_stability_promotion_cycle_latest_summary_json // ""),
        (.artifacts.profile_compare_multi_vm_stability_promotion_summary_json // ""),
        (.artifacts.profile_compare_multi_vm_stability_promotion_check_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  if [[ -n "$reports_dir" ]]; then
    fallback_candidates+=("$reports_dir/profile_compare_multi_vm_stability_promotion_cycle_summary.json")
    fallback_candidates+=("$reports_dir/profile_compare_multi_vm_stability_promotion_check_summary.json")
    fallback_candidates+=("$reports_dir/profile_compare_multi_vm_stability_promotion_summary.json")
    for fallback_candidate in "${fallback_candidates[@]}"; do
      candidate="$(abs_path "$fallback_candidate")"
      if [[ "$(profile_compare_multi_vm_stability_promotion_summary_usable_01 "$candidate")" == "1" ]]; then
        printf '%s' "$candidate"
        return
      fi
    done
    candidate="$(abs_path "$reports_dir/profile_compare_multi_vm_stability_promotion_cycle_summary.json")"
  fi
  printf '%s' "$candidate"
}

runtime_actuation_promotion_summary_stale_01() {
  local path="$1"
  local stale_flag="null"
  local max_age_sec="${ROADMAP_PROGRESS_RUNTIME_ACTUATION_PROMOTION_MAX_AGE_SEC:-86400}"
  local age_sec=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '1'
    return
  fi
  stale_flag="$(jq -r '
    if (.stale | type) == "boolean" then (.stale | tostring)
    elif (.summary_stale | type) == "boolean" then (.summary_stale | tostring)
    elif (.fresh | type) == "boolean" then (if .fresh then "false" else "true" end)
    elif (.summary_fresh | type) == "boolean" then (if .summary_fresh then "false" else "true" end)
    elif (.stages.promotion_check.summary_fresh | type) == "boolean" then
      (if .stages.promotion_check.summary_fresh then "false" else "true" end)
    else "null"
    end
  ' "$path" 2>/dev/null || printf '%s' "null")"
  if [[ "$stale_flag" == "true" ]]; then
    printf '1'
    return
  fi
  if ! [[ "$max_age_sec" =~ ^[0-9]+$ ]]; then
    max_age_sec=86400
  fi
  age_sec="$(summary_age_sec_from_path "$path")"
  if [[ "$age_sec" =~ ^[0-9]+$ ]]; then
    if (( age_sec > max_age_sec )); then
      printf '1'
      return
    fi
  else
    # Fail closed when summary age cannot be computed.
    printf '1'
    return
  fi
  printf '0'
}

runtime_actuation_promotion_summary_usable_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    def norm_decision:
      ascii_upcase | gsub("[[:space:]_-]"; "");
    def decision_allowed:
      ((. | norm_decision) == "GO")
      or ((. | norm_decision) == "NOGO")
      or ((. | norm_decision) == "PENDING");
    def norm_status:
      ascii_downcase | gsub("[[:space:]_-]"; "");
    def status_allowed:
      ((. | norm_status) == "ok")
      or ((. | norm_status) == "pass")
      or ((. | norm_status) == "fail")
      or ((. | norm_status) == "warn")
      or ((. | norm_status) == "pending")
      or ((. | norm_status) == "go")
      or ((. | norm_status) == "nogo")
      or ((. | norm_status) == "runtimefail");
    def schema_id:
      (.schema.id // "");
    (.version == 1)
    and ((.decision | type) == "string")
    and ((.status | type) == "string")
    and (.decision | decision_allowed)
    and (.status | status_allowed)
    and (
      if (.schema == null) then
        true
      elif (.schema | type) == "object" then
        (
          (schema_id == "runtime_actuation_promotion_check_summary")
          or (schema_id == "runtime_actuation_promotion_summary")
          or (schema_id == "profile_default_gate_runtime_actuation_promotion_check_summary")
          or (schema_id == "runtime_actuation_promotion_cycle_summary")
        )
      else
        false
      end
    )
    and (
      if (schema_id == "runtime_actuation_promotion_cycle_summary") then
        ((.stages.promotion_check.summary_exists // false) == true)
        and ((.stages.promotion_check.summary_valid_json // false) == true)
        and ((.stages.promotion_check.summary_fresh // false) == true)
        and ((.stages.promotion_check.has_usable_decision // false) == true)
        and ((.promotion_check.status | type) == "string")
        and ((.promotion_check.decision | type) == "string")
        and ((.promotion_check.rc | type) == "number")
        and (.promotion_check.decision | decision_allowed)
        and (.promotion_check.status | status_allowed)
        and ((.promotion_check.decision | norm_decision) == (.decision | norm_decision))
        and ((.promotion_check.status | norm_status) == (.status | norm_status))
      else
        true
      end
    )
  ' "$path" >/dev/null 2>&1 \
    && [[ "$(runtime_actuation_promotion_summary_stale_01 "$path")" == "0" ]]; then
    printf '1'
  else
    printf '0'
  fi
}

resolve_runtime_actuation_promotion_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  local fallback_candidate=""
  local -a fallback_candidates=()
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" && "$(runtime_actuation_promotion_summary_usable_01 "$candidate")" == "1" ]]; then
        printf '%s' "$candidate"
        return
      fi
    done < <(jq -r '
      [
        (.summary.runtime_actuation_promotion_cycle.latest_aliases.promotion_check_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle_latest_promotion_check_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle_promotion_check_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle_promotion_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle.latest_aliases.cycle_orchestrator_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle.latest_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle.summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle_latest_summary_json // ""),
        (.summary.runtime_actuation_promotion_cycle_summary_json // ""),
        (.summary.runtime_actuation_promotion.summary_json // ""),
        (.summary.runtime_actuation_promotion.latest_summary_json // ""),
        (.summary.runtime_actuation_promotion_summary_json // ""),
        (.summary.runtime_actuation_promotion_latest_summary_json // ""),
        (.summary.profile_default_gate.runtime_actuation_promotion_summary_json // ""),
        (.summary.profile_default_gate.runtime_actuation_promotion_cycle_summary_json // ""),
        (.summary.profile_default_gate.runtime_actuation_promotion_cycle_latest_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_cycle_latest_promotion_check_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_cycle_promotion_check_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_cycle_promotion_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_cycle_latest_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_cycle_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_check_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_cycle_latest_signoff_summaries_list // ""),
        (.artifacts.latest_aliases.promotion_check_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_cycle_latest_promotion_check_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_cycle_promotion_check_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_cycle_promotion_summary_json // ""),
        (.artifacts.latest_aliases.cycle_orchestrator_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_cycle_latest_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_cycle_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_check_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  if [[ -n "$reports_dir" ]]; then
    fallback_candidates+=("$reports_dir/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json")
    fallback_candidates+=("$reports_dir/runtime_actuation_promotion_check_summary.json")
    fallback_candidates+=("$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json")
    fallback_candidates+=("$reports_dir/runtime_actuation_promotion_cycle_summary.json")
    for fallback_candidate in "${fallback_candidates[@]}"; do
      candidate="$(abs_path "$fallback_candidate")"
      if [[ "$(runtime_actuation_promotion_summary_usable_01 "$candidate")" == "1" ]]; then
        printf '%s' "$candidate"
        return
      fi
    done
    candidate="$(abs_path "$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json")"
  fi
  printf '%s' "$candidate"
}

easy_node_supports_subcommand_01() {
  local subcommand="$1"
  local easy_node_script="$ROOT_DIR/scripts/easy_node.sh"
  if [[ -z "$subcommand" ]] || [[ ! -f "$easy_node_script" ]]; then
    printf '0'
    return
  fi
  if grep -Fq "${subcommand})" "$easy_node_script"; then
    printf '1'
  else
    printf '0'
  fi
}

evidence_pack_summary_stale_01() {
  local path="$1"
  local max_age_sec_raw="${2:-86400}"
  local max_age_sec=86400
  local stale_flag="null"
  local age_sec=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '1'
    return
  fi
  if [[ "$max_age_sec_raw" =~ ^[0-9]+$ ]]; then
    max_age_sec="$max_age_sec_raw"
  fi
  stale_flag="$(jq -r '
    if (.stale | type) == "boolean" then (.stale | tostring)
    elif (.summary_stale | type) == "boolean" then (.summary_stale | tostring)
    elif (.fresh | type) == "boolean" then (if .fresh then "false" else "true" end)
    elif (.summary_fresh | type) == "boolean" then (if .summary_fresh then "false" else "true" end)
    else "null"
    end
  ' "$path" 2>/dev/null || printf '%s' "null")"
  if [[ "$stale_flag" == "true" ]]; then
    printf '1'
    return
  fi
  age_sec="$(summary_age_sec_from_path "$path")"
  if [[ "$age_sec" =~ ^[0-9]+$ ]]; then
    if (( age_sec > max_age_sec )); then
      printf '1'
      return
    fi
  else
    printf '1'
    return
  fi
  printf '0'
}

resolve_profile_default_gate_evidence_pack_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  local first_candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" ]]; then
        if [[ -z "$first_candidate" ]]; then
          first_candidate="$candidate"
        fi
        if [[ -f "$candidate" ]]; then
          printf '%s' "$candidate"
          return
        fi
      fi
    done < <(jq -r '
      [
        (.summary.profile_default_gate_stability_evidence_pack.summary_json // ""),
        (.summary.profile_default_gate_stability_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_default_gate_stability_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate_evidence_pack.summary_json // ""),
        (.summary.profile_default_gate_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_default_gate_evidence_pack_summary_json // ""),
        (.artifacts.profile_default_gate_stability_evidence_pack_summary_json // ""),
        (.artifacts.profile_default_gate_evidence_pack_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  if [[ -z "$first_candidate" ]] && [[ -n "$reports_dir" ]]; then
    if [[ -f "$reports_dir/profile_default_gate_stability_evidence_pack_summary.json" ]]; then
      first_candidate="$(abs_path "$reports_dir/profile_default_gate_stability_evidence_pack_summary.json")"
    elif [[ -f "$reports_dir/profile_default_gate_evidence_pack_summary.json" ]]; then
      first_candidate="$(abs_path "$reports_dir/profile_default_gate_evidence_pack_summary.json")"
    else
      first_candidate="$(abs_path "$reports_dir/profile_default_gate_stability_evidence_pack_summary.json")"
    fi
  fi
  printf '%s' "$first_candidate"
}

resolve_runtime_actuation_promotion_evidence_pack_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  local first_candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" ]]; then
        if [[ -z "$first_candidate" ]]; then
          first_candidate="$candidate"
        fi
        if [[ -f "$candidate" ]]; then
          printf '%s' "$candidate"
          return
        fi
      fi
    done < <(jq -r '
      [
        (.summary.runtime_actuation_multi_vm_evidence_pack.summary_json // ""),
        (.summary.runtime_actuation_multi_vm_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_multi_vm_evidence_pack_summary_json // ""),
        (.summary.runtime_actuation_promotion_evidence_pack.summary_json // ""),
        (.summary.runtime_actuation_promotion_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_promotion_evidence_pack_summary_json // ""),
        (.artifacts.runtime_actuation_multi_vm_evidence_pack_summary_json // ""),
        (.artifacts.runtime_actuation_promotion_evidence_pack_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  if [[ -z "$first_candidate" ]] && [[ -n "$reports_dir" ]]; then
    if [[ -f "$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json" ]]; then
      first_candidate="$(abs_path "$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json")"
    elif [[ -f "$reports_dir/runtime_actuation_promotion_evidence_pack_summary.json" ]]; then
      first_candidate="$(abs_path "$reports_dir/runtime_actuation_promotion_evidence_pack_summary.json")"
    else
      first_candidate="$(abs_path "$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json")"
    fi
  fi
  printf '%s' "$first_candidate"
}

resolve_profile_compare_multi_vm_stability_promotion_evidence_pack_summary_path() {
  local manual_summary_path="$1"
  local reports_dir="$2"
  local candidate=""
  local first_candidate=""
  if [[ "$(json_file_valid_01 "$manual_summary_path")" == "1" ]]; then
    while IFS= read -r candidate; do
      candidate="$(resolve_path_with_base "$candidate" "$manual_summary_path")"
      if [[ -n "$candidate" ]]; then
        if [[ -z "$first_candidate" ]]; then
          first_candidate="$candidate"
        fi
        if [[ -f "$candidate" ]]; then
          printf '%s' "$candidate"
          return
        fi
      fi
    done < <(jq -r '
      [
        (.summary.runtime_actuation_multi_vm_evidence_pack.summary_json // ""),
        (.summary.runtime_actuation_multi_vm_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate.artifacts.runtime_actuation_multi_vm_evidence_pack_summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion_evidence_pack.summary_json // ""),
        (.summary.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json // ""),
        (.summary.profile_default_gate.artifacts.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json // ""),
        (.artifacts.runtime_actuation_multi_vm_evidence_pack_summary_json // ""),
        (.artifacts.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json // "")
      ]
      | .[]
      | strings
      | select(length > 0)
    ' "$manual_summary_path" 2>/dev/null || true)
  fi
  if [[ -z "$first_candidate" ]] && [[ -n "$reports_dir" ]]; then
    if [[ -f "$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json" ]]; then
      first_candidate="$(abs_path "$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json")"
    elif [[ -f "$reports_dir/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json" ]]; then
      first_candidate="$(abs_path "$reports_dir/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json")"
    else
      first_candidate="$(abs_path "$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json")"
    fi
  fi
  printf '%s' "$first_candidate"
}

profile_default_gate_command_supports_subject_placeholder_01() {
  local cmd
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '0'
    return
  fi
  if [[ "$cmd" =~ ^(sudo[[:space:]]+)?\./scripts/easy_node\.sh[[:space:]]+(profile-default-gate-live|profile-default-gate-run|profile-compare-campaign-signoff)([[:space:]]|$) ]]; then
    printf '1'
  else
    printf '0'
  fi
}

profile_default_gate_command_has_credential_args_01() {
  local cmd
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '0'
    return
  fi
  if [[ "$cmd" =~ (^|[[:space:]])(--campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred)([[:space:]=]|$) ]]; then
    printf '1'
  else
    printf '0'
  fi
}

profile_default_gate_command_redact_credentials_parse_fail_closed() {
  local cmd
  local sudo_prefix=""
  local subcommand="profile-compare-campaign-signoff"
  local safe_cmd=""
  local has_primary_credential="0"
  local has_anon_credential="0"
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$cmd" =~ ^sudo[[:space:]]+ ]]; then
    sudo_prefix="sudo "
  fi
  if [[ "$cmd" =~ (^|[[:space:]])\./scripts/easy_node\.sh[[:space:]]+([A-Za-z0-9._-]+) ]]; then
    subcommand="${BASH_REMATCH[2]}"
  fi
  if [[ "$cmd" =~ (^|[[:space:]])(--campaign-subject|--subject|--key|--invite-key)([[:space:]=]|$) ]]; then
    has_primary_credential="1"
  fi
  if [[ "$cmd" =~ (^|[[:space:]])(--campaign-anon-cred|--anon-cred)([[:space:]=]|$) ]]; then
    has_anon_credential="1"
  fi
  safe_cmd="${sudo_prefix}./scripts/easy_node.sh ${subcommand}"
  if [[ "$has_primary_credential" == "1" ]]; then
    safe_cmd="$safe_cmd --subject INVITE_KEY"
  fi
  if [[ "$has_anon_credential" == "1" ]]; then
    safe_cmd="$safe_cmd --anon-cred ANON_CRED"
  fi
  printf '%s' "$safe_cmd"
}

profile_default_gate_command_redact_credentials_best_effort() {
  local cmd
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  printf '%s' "$cmd" | sed -E \
    -e 's@(^|[[:space:]])(--campaign-subject|--subject|--key|--invite-key)=([^[:space:]]+)@\1\2=INVITE_KEY@g' \
    -e 's@(^|[[:space:]])(--campaign-anon-cred|--anon-cred)=([^[:space:]]+)@\1\2=ANON_CRED@g' \
    -e 's@(^|[[:space:]])(--campaign-subject|--subject|--key|--invite-key)[[:space:]]+([^[:space:]]+)@\1\2 INVITE_KEY@g' \
    -e 's@(^|[[:space:]])(--campaign-anon-cred|--anon-cred)[[:space:]]+([^[:space:]]+)@\1\2 ANON_CRED@g'
}

profile_default_gate_command_redact_credentials() {
  local cmd
  local token=""
  local next_token=""
  local redacted_parse_fail_cmd=""
  local idx=0
  local -a redacted_argv=()
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    if [[ "$(profile_default_gate_command_has_credential_args_01 "$cmd")" == "1" ]]; then
      redacted_parse_fail_cmd="$(profile_default_gate_command_redact_credentials_parse_fail_closed "$cmd" || true)"
      if [[ -z "$redacted_parse_fail_cmd" ]]; then
        redacted_parse_fail_cmd="./scripts/easy_node.sh profile-compare-campaign-signoff"
        if [[ "$cmd" =~ (^|[[:space:]])(--campaign-subject|--subject|--key|--invite-key)([[:space:]=]|$) ]]; then
          redacted_parse_fail_cmd="$redacted_parse_fail_cmd --subject INVITE_KEY"
        fi
        if [[ "$cmd" =~ (^|[[:space:]])(--campaign-anon-cred|--anon-cred)([[:space:]=]|$) ]]; then
          redacted_parse_fail_cmd="$redacted_parse_fail_cmd --anon-cred ANON_CRED"
        fi
        if [[ "$cmd" =~ ^sudo[[:space:]]+ ]]; then
          redacted_parse_fail_cmd="sudo $redacted_parse_fail_cmd"
        fi
      fi
      printf '%s' "$redacted_parse_fail_cmd"
      return 0
    fi
    profile_default_gate_command_redact_credentials_best_effort "$cmd"
    return 0
  fi
  while (( idx < ${#COMMAND_STRING_ARGV[@]} )); do
    token="${COMMAND_STRING_ARGV[$idx]}"
    case "$token" in
      --campaign-subject|--subject|--key|--invite-key)
        redacted_argv+=("$token")
        if (( idx + 1 < ${#COMMAND_STRING_ARGV[@]} )); then
          next_token="${COMMAND_STRING_ARGV[$((idx + 1))]}"
          if [[ "$next_token" != --* ]]; then
            redacted_argv+=("INVITE_KEY")
            idx=$((idx + 2))
            continue
          fi
        fi
        ;;
      --campaign-anon-cred|--anon-cred)
        redacted_argv+=("$token")
        if (( idx + 1 < ${#COMMAND_STRING_ARGV[@]} )); then
          next_token="${COMMAND_STRING_ARGV[$((idx + 1))]}"
          if [[ "$next_token" != --* ]]; then
            redacted_argv+=("ANON_CRED")
            idx=$((idx + 2))
            continue
          fi
        fi
        ;;
      --campaign-subject=*|--subject=*|--key=*|--invite-key=*)
        redacted_argv+=("${token%%=*}=INVITE_KEY")
        ;;
      --campaign-anon-cred=*|--anon-cred=*)
        redacted_argv+=("${token%%=*}=ANON_CRED")
        ;;
      *)
        redacted_argv+=("$token")
        ;;
    esac
    idx=$((idx + 1))
  done
  profile_default_gate_command_from_argv "${redacted_argv[@]}"
  return 0
}

profile_default_gate_command_with_subject_placeholder() {
  local cmd
  local sanitized_cmd
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  sanitized_cmd="$(profile_default_gate_command_redact_credentials "$cmd")"
  if [[ -z "$sanitized_cmd" ]]; then
    if [[ "$(profile_default_gate_command_has_credential_args_01 "$cmd")" == "1" ]]; then
      sanitized_cmd="$(profile_default_gate_command_redact_credentials_parse_fail_closed "$cmd")"
    else
      sanitized_cmd="$cmd"
    fi
  fi
  if [[ "$(profile_default_gate_command_supports_subject_placeholder_01 "$cmd")" != "1" ]]; then
    printf '%s' "$sanitized_cmd"
    return
  fi
  if [[ "$(profile_default_gate_command_has_credential_args_01 "$sanitized_cmd")" == "1" ]]; then
    printf '%s' "$sanitized_cmd"
    return
  fi
  printf '%s --subject INVITE_KEY' "$sanitized_cmd"
}

command_string_to_argv() {
  local command_text="${1:-}"
  COMMAND_STRING_ARGV=()
  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi
  if ! mapfile -d '' -t COMMAND_STRING_ARGV < <(
    python3 - "$command_text" <<'PY'
import shlex
import sys

try:
    for token in shlex.split(sys.argv[1], posix=True):
        sys.stdout.write(token)
        sys.stdout.write("\0")
except ValueError:
    sys.exit(1)
PY
  ); then
    COMMAND_STRING_ARGV=()
    return 1
  fi
  return 0
}

profile_default_gate_command_from_argv() {
  local token
  local out=""
  for token in "$@"; do
    out="${out}${out:+ }$(printf '%q' "$token")"
  done
  printf '%s' "$out"
}

profile_default_gate_extract_arg_value_from_cmd() {
  local cmd
  local opt
  local token
  local idx=0
  local next_token=""
  cmd="$(trim "${1:-}")"
  opt="${2:-}"
  if [[ -z "$cmd" || -z "$opt" ]]; then
    printf '%s' ""
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' ""
    return
  fi
  for token in "${COMMAND_STRING_ARGV[@]}"; do
    if [[ "$token" == "$opt" ]]; then
      if (( idx + 1 < ${#COMMAND_STRING_ARGV[@]} )); then
        next_token="${COMMAND_STRING_ARGV[$((idx + 1))]}"
        if [[ "$next_token" == --* ]]; then
          printf '%s' ""
        else
          printf '%s' "$next_token"
        fi
      else
        printf '%s' ""
      fi
      return
    fi
    if [[ "$token" == "$opt="* ]]; then
      printf '%s' "${token#"$opt="}"
      return
    fi
    idx=$((idx + 1))
  done
  printf '%s' ""
}

profile_default_gate_host_from_directory_arg_value() {
  local raw_value
  local value
  raw_value="$(trim "${1:-}")"
  if [[ -z "$raw_value" ]]; then
    printf '%s' ""
    return
  fi
  value="$raw_value"
  if [[ "$value" =~ ^\"(.*)\"$ ]]; then
    value="${BASH_REMATCH[1]}"
  elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
    value="${BASH_REMATCH[1]}"
  fi
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  value="${value%%\?*}"
  value="${value%%\#*}"
  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$value" =~ ^(\[[^][]+\])(:[0-9]+)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  if [[ "$value" =~ ^([^:]+):([0-9]+)$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return
  fi
  if [[ "$value" =~ ^[^:]+$ ]]; then
    printf '%s' "$value"
    return
  fi
  printf '%s' ""
}

profile_default_gate_extract_directory_host_from_cmd() {
  local cmd
  local directory_flag
  local directory_value=""
  cmd="$(trim "${1:-}")"
  directory_flag="${2:-}"
  if [[ -z "$cmd" || -z "$directory_flag" ]]; then
    printf '%s' ""
    return
  fi
  directory_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "$directory_flag")"
  if [[ -z "$directory_value" ]]; then
    printf '%s' ""
    return
  fi
  profile_default_gate_host_from_directory_arg_value "$directory_value"
}

profile_default_gate_extract_host_from_directory_urls_value() {
  local raw_value
  local value
  local index
  local candidate=""
  local -a directory_urls_parts=()
  raw_value="$(trim "${1:-}")"
  index="$(trim "${2:-0}")"
  if [[ -z "$raw_value" ]]; then
    printf '%s' ""
    return
  fi
  if ! [[ "$index" =~ ^[0-9]+$ ]]; then
    index="0"
  fi
  value="$raw_value"
  if [[ "$value" =~ ^\"(.*)\"$ ]]; then
    value="${BASH_REMATCH[1]}"
  elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
    value="${BASH_REMATCH[1]}"
  fi
  IFS=',' read -r -a directory_urls_parts <<< "$value"
  if (( index >= ${#directory_urls_parts[@]} )); then
    printf '%s' ""
    return
  fi
  candidate="$(trim "${directory_urls_parts[$index]}")"
  profile_default_gate_host_from_directory_arg_value "$candidate"
}

profile_default_gate_extract_live_wrapper_host_from_cmd() {
  local cmd
  local lane
  local host=""
  local directory_urls_value=""
  local bootstrap_directory_value=""
  cmd="$(trim "${1:-}")"
  lane="$(trim "${2:-}")"
  if [[ -z "$cmd" || -z "$lane" ]]; then
    printf '%s' ""
    return
  fi
  case "$lane" in
    a)
      host="$(profile_default_gate_extract_directory_host_from_cmd "$cmd" "--host-a")"
      if [[ -z "$host" ]]; then
        host="$(profile_default_gate_extract_directory_host_from_cmd "$cmd" "--directory-a")"
      fi
      if [[ -z "$host" ]]; then
        directory_urls_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-directory-urls")"
        host="$(profile_default_gate_extract_host_from_directory_urls_value "$directory_urls_value" "0")"
      fi
      if [[ -z "$host" ]]; then
        bootstrap_directory_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-bootstrap-directory")"
        host="$(profile_default_gate_host_from_directory_arg_value "$bootstrap_directory_value")"
      fi
      ;;
    b)
      host="$(profile_default_gate_extract_directory_host_from_cmd "$cmd" "--host-b")"
      if [[ -z "$host" ]]; then
        host="$(profile_default_gate_extract_directory_host_from_cmd "$cmd" "--directory-b")"
      fi
      if [[ -z "$host" ]]; then
        directory_urls_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-directory-urls")"
        host="$(profile_default_gate_extract_host_from_directory_urls_value "$directory_urls_value" "1")"
      fi
      ;;
    *)
      host=""
      ;;
  esac
  printf '%s' "$host"
}

profile_default_gate_host_is_non_localhost_01() {
  local host
  host="$(trim "${1:-}")"
  if [[ -z "$host" ]]; then
    printf '%s' "0"
    return
  fi
  case "${host,,}" in
    localhost|127.*|[::1]|::1)
      printf '%s' "0"
      ;;
    *)
      printf '%s' "1"
      ;;
  esac
}

profile_default_gate_command_is_localhost_profile_default_run_01() {
  local cmd
  local token
  local has_profile_default_gate_run="0"
  local directory_a=""
  local directory_b=""
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' "0"
    return
  fi
  if command_string_to_argv "$cmd"; then
    for token in "${COMMAND_STRING_ARGV[@]}"; do
      if [[ "$token" == "profile-default-gate-run" ]]; then
        has_profile_default_gate_run="1"
        break
      fi
    done
    if [[ "$has_profile_default_gate_run" != "1" ]]; then
      printf '%s' "0"
      return
    fi
    directory_a="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--directory-a")"
    directory_b="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--directory-b")"
    if [[ "$directory_a" =~ ^https?://127\.0\.0\.1:[0-9]+$ \
       && "$directory_b" =~ ^https?://127\.0\.0\.1:[0-9]+$ ]]; then
      printf '%s' "1"
    else
      printf '%s' "0"
    fi
    return
  fi
  if [[ ! "$cmd" =~ ^(sudo[[:space:]]+)?\./scripts/easy_node\.sh[[:space:]]+profile-default-gate-run([[:space:]]|$) ]]; then
    printf '%s' "0"
    return
  fi
  if [[ "$cmd" =~ (^|[[:space:]])--directory-a([[:space:]]+|=)https?://127\.0\.0\.1:[0-9]+([[:space:]]|$) \
     && "$cmd" =~ (^|[[:space:]])--directory-b([[:space:]]+|=)https?://127\.0\.0\.1:[0-9]+([[:space:]]|$) ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

profile_default_gate_command_is_profile_default_run_01() {
  local cmd
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' "0"
    return
  fi
  if [[ "$cmd" =~ ^(sudo[[:space:]]+)?\./scripts/easy_node\.sh[[:space:]]+profile-default-gate-run([[:space:]]|$) ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

profile_default_gate_command_is_profile_compare_signoff_01() {
  local cmd
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' "0"
    return
  fi
  if [[ "$cmd" =~ ^(sudo[[:space:]]+)?\./scripts/easy_node\.sh[[:space:]]+profile-compare-campaign-signoff([[:space:]]|$) ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

profile_default_gate_command_localhost_run_to_live_wrapper() {
  local cmd
  local host_a
  local host_b
  local cmd_source
  local docker_hint_available
  local -a rebuilt_argv=()
  local reports_dir=""
  local summary_json=""
  local print_summary_json=""
  local campaign_timeout_sec=""
  local heartbeat_interval_sec=""
  local refresh_campaign=""
  local fail_on_no_go=""
  local campaign_execution_mode=""
  local campaign_start_local_stack=""
  local primary_credential_flag=""
  local primary_credential_value=""
  local campaign_anon_cred_value=""
  local anon_cred_value=""
  local has_anon_credential="0"
  local convert_localhost_run="0"
  local convert_signoff="0"
  local convert_allowed="0"
  local supported_primary_credential_flags=("--campaign-subject" "--subject" "--key" "--invite-key")
  local flag=""
  local rebuilt=""
  cmd="$(trim "${1:-}")"
  host_a="$(trim "${2:-}")"
  host_b="$(trim "${3:-}")"
  cmd_source="$(trim "${4:-}")"
  docker_hint_available="$(trim "${5:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  if [[ -z "$host_a" || -z "$host_b" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if [[ "${cmd_source,,}" == *docker* ]]; then
    convert_allowed="1"
  fi
  case "${docker_hint_available,,}" in
    1|true|yes|on)
      convert_allowed="1"
      ;;
  esac
  if [[ "$convert_allowed" != "1" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if [[ "$(profile_default_gate_command_is_profile_default_run_01 "$cmd")" == "1" ]]; then
    convert_localhost_run="1"
  fi
  if [[ "$(profile_default_gate_command_is_profile_compare_signoff_01 "$cmd")" == "1" ]]; then
    convert_signoff="1"
  fi
  if [[ "$convert_localhost_run" != "1" && "$convert_signoff" != "1" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' "$cmd"
    return
  fi
  if [[ "$cmd" =~ ^sudo[[:space:]]+ ]]; then
    rebuilt_argv+=("sudo")
  fi
  reports_dir="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--reports-dir")"
  summary_json="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--summary-json")"
  print_summary_json="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--print-summary-json")"
  campaign_timeout_sec="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-timeout-sec")"
  heartbeat_interval_sec="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--heartbeat-interval-sec")"
  refresh_campaign="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--refresh-campaign")"
  fail_on_no_go="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--fail-on-no-go")"
  campaign_execution_mode="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-execution-mode")"
  campaign_start_local_stack="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-start-local-stack")"
  for flag in "${supported_primary_credential_flags[@]}"; do
    primary_credential_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "$flag")"
    if [[ -n "$primary_credential_value" ]]; then
      primary_credential_flag="$flag"
      break
    fi
  done
  if [[ "$cmd" =~ (^|[[:space:]])(--campaign-anon-cred|--anon-cred)([[:space:]=]|$) ]]; then
    has_anon_credential="1"
  fi
  campaign_anon_cred_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--campaign-anon-cred")"
  anon_cred_value="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--anon-cred")"
  if [[ -n "$campaign_anon_cred_value" || -n "$anon_cred_value" ]]; then
    has_anon_credential="1"
  fi
  if [[ "$has_anon_credential" == "1" ]]; then
    # profile-default-gate-live only supports invite-subject credentials.
    # Keep anon-credential commands in their original mode.
    printf '%s' "$cmd"
    return
  fi
  rebuilt_argv+=("./scripts/easy_node.sh" "profile-default-gate-live" "--host-a" "$host_a" "--host-b" "$host_b")
  if [[ -n "$reports_dir" ]]; then
    rebuilt_argv+=("--reports-dir" "$reports_dir")
  fi
  if [[ -n "$campaign_timeout_sec" ]]; then
    rebuilt_argv+=("--campaign-timeout-sec" "$campaign_timeout_sec")
  fi
  if [[ -n "$heartbeat_interval_sec" ]]; then
    rebuilt_argv+=("--heartbeat-interval-sec" "$heartbeat_interval_sec")
  fi
  if [[ -n "$summary_json" ]]; then
    rebuilt_argv+=("--summary-json" "$summary_json")
  fi
  if [[ -n "$print_summary_json" ]]; then
    rebuilt_argv+=("--print-summary-json" "$print_summary_json")
  fi
  if [[ -n "$refresh_campaign" ]]; then
    rebuilt_argv+=("--refresh-campaign" "$refresh_campaign")
  fi
  if [[ -n "$fail_on_no_go" ]]; then
    rebuilt_argv+=("--fail-on-no-go" "$fail_on_no_go")
  fi
  if [[ -n "$campaign_execution_mode" ]]; then
    rebuilt_argv+=("--campaign-execution-mode" "$campaign_execution_mode")
  fi
  if [[ -n "$campaign_start_local_stack" ]]; then
    rebuilt_argv+=("--campaign-start-local-stack" "$campaign_start_local_stack")
  fi
  if [[ -n "$primary_credential_flag" && -n "$primary_credential_value" ]]; then
    rebuilt_argv+=("$primary_credential_flag" "$primary_credential_value")
  fi
  rebuilt="$(profile_default_gate_command_from_argv "${rebuilt_argv[@]}")"
  printf '%s' "$rebuilt"
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
  local logs_root="${ROADMAP_PROGRESS_LOGS_ROOT:-${ROADMAP_PROGRESS_LOG_DIR:-${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}}}"
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
  local logs_root
  logs_root="$(roadmap_resilience_logs_root)"
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

candidate_bool_signal_value_or_empty() {
  local path="$1"
  local signal="$2"
  local value=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  value="$(jq -r --arg signal "$signal" '
    def status_to_bool:
      ((. // "") | ascii_downcase) as $s
      | if ($s == "pass" or $s == "ok" or $s == "success" or $s == "true" or $s == "healthy") then true
        elif ($s == "fail" or $s == "failed" or $s == "error" or $s == "false" or $s == "degraded" or $s == "unhealthy") then false
        else empty
        end;
    ($signal | if endswith("_status") then .[0:(length - 7)] elif endswith("_ok") then .[0:(length - 3)] else "" end) as $base_signal
    | if (.[$signal] | type) == "boolean" then .[$signal]
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
      elif (($signal | endswith("_ok")) and ((.signals[$base_signal].status | type) == "string")) then (.signals[$base_signal].status | status_to_bool)
      elif (($signal | endswith("_ok")) and ((.steps[$base_signal].ok | type) == "boolean")) then .steps[$base_signal].ok
      elif (($signal | endswith("_ok")) and ((.steps[$base_signal].status | type) == "string")) then (.steps[$base_signal].status | status_to_bool)
      elif (($signal | endswith("_ok")) and ((.stages[$base_signal].ok | type) == "boolean")) then .stages[$base_signal].ok
      elif (($signal | endswith("_ok")) and ((.stages[$base_signal].status | type) == "string")) then (.stages[$base_signal].status | status_to_bool)
      else empty
      end
  ' "$path" 2>/dev/null || true)"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

candidate_bool_signal_present_01() {
  local path="$1"
  local signal="$2"
  local value=""
  value="$(candidate_bool_signal_value_or_empty "$path" "$signal")"
  if [[ "$value" == "true" || "$value" == "false" ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

candidate_string_signal_value_or_empty() {
  local path="$1"
  local signal="$2"
  local value=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  value="$(jq -r --arg signal "$signal" '
    def bool_to_status:
      if . == true then "pass"
      elif . == false then "fail"
      else empty
      end;
    ($signal | if endswith("_status") then .[0:(length - 7)] elif endswith("_ok") then .[0:(length - 3)] else "" end) as $base_signal
    | if (.[$signal] | type) == "string" then .[$signal]
      elif (.summary[$signal] | type) == "string" then .summary[$signal]
      elif (.handoff[$signal] | type) == "string" then .handoff[$signal]
      elif (.signals[$signal] | type) == "string" then .signals[$signal]
      elif (.automation[$signal] | type) == "string" then .automation[$signal]
      elif (.phase1_resilience_handoff[$signal] | type) == "string" then .phase1_resilience_handoff[$signal]
      elif (.phase2_linux_prod_candidate_handoff[$signal] | type) == "string" then .phase2_linux_prod_candidate_handoff[$signal]
      elif (.phase3_windows_client_beta_handoff[$signal] | type) == "string" then .phase3_windows_client_beta_handoff[$signal]
      elif (.phase4_windows_full_parity_handoff[$signal] | type) == "string" then .phase4_windows_full_parity_handoff[$signal]
      elif (.phase5_settlement_layer_handoff[$signal] | type) == "string" then .phase5_settlement_layer_handoff[$signal]
      elif (.phase6_cosmos_l1_handoff[$signal] | type) == "string" then .phase6_cosmos_l1_handoff[$signal]
      elif (.vpn_track.phase1_resilience_handoff[$signal] | type) == "string" then .vpn_track.phase1_resilience_handoff[$signal]
      elif (.vpn_track.phase2_linux_prod_candidate_handoff[$signal] | type) == "string" then .vpn_track.phase2_linux_prod_candidate_handoff[$signal]
      elif (.vpn_track.phase3_windows_client_beta_handoff[$signal] | type) == "string" then .vpn_track.phase3_windows_client_beta_handoff[$signal]
      elif (.vpn_track.phase4_windows_full_parity_handoff[$signal] | type) == "string" then .vpn_track.phase4_windows_full_parity_handoff[$signal]
      elif (.vpn_track.phase5_settlement_layer_handoff[$signal] | type) == "string" then .vpn_track.phase5_settlement_layer_handoff[$signal]
      elif (.vpn_track.phase6_cosmos_l1_handoff[$signal] | type) == "string" then .vpn_track.phase6_cosmos_l1_handoff[$signal]
      elif (.blockchain_track.phase6_cosmos_l1_handoff[$signal] | type) == "string" then .blockchain_track.phase6_cosmos_l1_handoff[$signal]
      elif (($signal | endswith("_status")) and ((.signals[$base_signal].status | type) == "string")) then .signals[$base_signal].status
      elif (($signal | endswith("_status")) and ((.steps[$base_signal].status | type) == "string")) then .steps[$base_signal].status
      elif (($signal | endswith("_status")) and ((.steps[$base_signal].ok | type) == "boolean")) then (.steps[$base_signal].ok | bool_to_status)
      elif (($signal | endswith("_status")) and ((.stages[$base_signal].status | type) == "string")) then .stages[$base_signal].status
      elif (($signal | endswith("_status")) and ((.stages[$base_signal].ok | type) == "boolean")) then (.stages[$base_signal].ok | bool_to_status)
      else empty
      end
  ' "$path" 2>/dev/null || true)"
  if [[ -n "$value" && "$value" != "null" ]]; then
    printf '%s' "$value"
  else
    printf '%s' ""
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
  for signal in settlement_failsoft_ok settlement_acceptance_ok settlement_bridge_smoke_ok settlement_state_persistence_ok settlement_dual_asset_parity_ok settlement_adapter_roundtrip_ok settlement_adapter_signed_tx_roundtrip_ok settlement_shadow_env_ok settlement_shadow_status_surface_ok issuer_sponsor_api_live_smoke_ok issuer_sponsor_vpn_session_live_smoke_ok issuer_settlement_status_live_smoke_ok issuer_admin_blockchain_handlers_coverage_ok exit_settlement_status_live_smoke_ok; do
    if [[ "$(candidate_bool_signal_present_01 "$path" "$signal")" == "1" ]]; then
      score=$((score + 1))
    fi
  done
  printf '%s' "$score"
}

phase5_settlement_layer_summary_quality_score() {
  local path="$1"
  local score=0
  local signal=""
  local value=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' "0"
    return
  fi
  for signal in settlement_failsoft_ok settlement_acceptance_ok settlement_bridge_smoke_ok settlement_state_persistence_ok settlement_dual_asset_parity_ok settlement_adapter_roundtrip_ok settlement_adapter_signed_tx_roundtrip_ok settlement_shadow_env_ok settlement_shadow_status_surface_ok issuer_sponsor_api_live_smoke_ok issuer_sponsor_vpn_session_live_smoke_ok issuer_settlement_status_live_smoke_ok issuer_admin_blockchain_handlers_coverage_ok exit_settlement_status_live_smoke_ok; do
    value="$(candidate_bool_signal_value_or_empty "$path" "$signal")"
    case "$value" in
      true)
        score=$((score + 2))
        ;;
      false)
        score=$((score - 3))
        ;;
    esac
  done
  value="$(candidate_string_signal_value_or_empty "$path" "status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 3))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 3))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_adapter_roundtrip_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_adapter_signed_tx_roundtrip_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_shadow_env_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_shadow_status_surface_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_dual_asset_parity_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_sponsor_api_live_smoke_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_sponsor_vpn_session_live_smoke_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_settlement_status_live_smoke_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_admin_blockchain_handlers_coverage_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "exit_settlement_status_live_smoke_status")"
  case "${value,,}" in
    pass|ok|success)
      score=$((score + 2))
      ;;
    fail|failed|error|invalid|degraded)
      score=$((score - 2))
      ;;
  esac
  printf '%s' "$score"
}

phase5_settlement_layer_summary_obviously_degraded_01() {
  local path="$1"
  local signal=""
  local value=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' "0"
    return
  fi
  value="$(candidate_string_signal_value_or_empty "$path" "status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  for signal in settlement_failsoft_ok settlement_acceptance_ok settlement_bridge_smoke_ok settlement_state_persistence_ok settlement_dual_asset_parity_ok settlement_adapter_roundtrip_ok settlement_adapter_signed_tx_roundtrip_ok settlement_shadow_env_ok settlement_shadow_status_surface_ok issuer_sponsor_api_live_smoke_ok issuer_sponsor_vpn_session_live_smoke_ok issuer_settlement_status_live_smoke_ok issuer_admin_blockchain_handlers_coverage_ok exit_settlement_status_live_smoke_ok; do
    value="$(candidate_bool_signal_value_or_empty "$path" "$signal")"
    if [[ "$value" == "false" ]]; then
      printf '%s' "1"
      return
    fi
  done
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_adapter_roundtrip_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_adapter_signed_tx_roundtrip_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_shadow_env_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_shadow_status_surface_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "settlement_dual_asset_parity_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_sponsor_api_live_smoke_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_sponsor_vpn_session_live_smoke_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_settlement_status_live_smoke_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "issuer_admin_blockchain_handlers_coverage_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  value="$(candidate_string_signal_value_or_empty "$path" "exit_settlement_status_live_smoke_status")"
  case "${value,,}" in
    fail|failed|error|invalid|degraded)
      printf '%s' "1"
      return
      ;;
  esac
  printf '%s' "0"
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
  local logs_root
  logs_root="$(roadmap_resilience_logs_root)"
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
  local logs_root
  logs_root="$(roadmap_resilience_logs_root)"
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
  local logs_root
  logs_root="$(roadmap_resilience_logs_root)"
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

phase4_windows_full_parity_windows_native_bootstrap_guardrails_source_label() {
  local path="$1"
  local label=""
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  label="$(jq -r '
    if (.signals.windows_native_bootstrap_guardrails_ok | type) == "boolean" then "signals.windows_native_bootstrap_guardrails_ok"
    elif (.summary.windows_native_bootstrap_guardrails_ok | type) == "boolean" then "summary.windows_native_bootstrap_guardrails_ok"
    elif (.handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then "handoff.windows_native_bootstrap_guardrails_ok"
    elif (.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then "phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok"
    elif (.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then "vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok"
    elif (.stages.windows_native_bootstrap_guardrails.ok | type) == "boolean" then "stages.windows_native_bootstrap_guardrails.ok"
    elif (.stages.windows_native_bootstrap_guardrails.status | type) == "string" then "stages.windows_native_bootstrap_guardrails.status"
    elif (.steps.windows_native_bootstrap_guardrails.ok | type) == "boolean" then "steps.windows_native_bootstrap_guardrails.ok"
    elif (.steps.windows_native_bootstrap_guardrails.status | type) == "string" then "steps.windows_native_bootstrap_guardrails.status"
    else empty end
  ' "$path" 2>/dev/null || true)"
  printf '%s' "$label"
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
  local logs_root
  local candidate=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local candidate_non_degraded=1
  local candidate_quality=0
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  local best_non_degraded=-1
  local best_quality=-999999
  logs_root="$(roadmap_resilience_logs_root)"
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
    candidate_non_degraded=1
    if [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$candidate")" == "1" ]]; then
      candidate_non_degraded=0
    fi
    candidate_quality="$(phase5_settlement_layer_summary_quality_score "$candidate")"
    if ! [[ "$candidate_quality" =~ ^-?[0-9]+$ ]]; then
      candidate_quality=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    if (( candidate_non_dry > best_non_dry )); then
      best_non_dry="$candidate_non_dry"
      best_non_degraded="$candidate_non_degraded"
      best_score="$candidate_score"
      best_quality="$candidate_quality"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_non_dry == best_non_dry )); then
      if (( candidate_non_degraded > best_non_degraded )); then
        best_non_degraded="$candidate_non_degraded"
        best_score="$candidate_score"
        best_quality="$candidate_quality"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_non_degraded == best_non_degraded )); then
        if (( candidate_score > best_score )); then
          best_score="$candidate_score"
          best_quality="$candidate_quality"
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_score == best_score )); then
          if (( candidate_quality > best_quality )); then
            best_quality="$candidate_quality"
            best_mtime="$candidate_mtime"
            best_path="$candidate"
          elif (( candidate_quality == best_quality )); then
            if (( candidate_mtime > best_mtime )); then
              best_mtime="$candidate_mtime"
              best_path="$candidate"
            elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
              # Deterministic tie-break when dryness/degradation/score/quality/mtime are equal.
              best_path="$candidate"
            fi
          fi
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

phase5_settlement_adapter_roundtrip_status_from_summary() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  jq -r '
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
  ' "$path" 2>/dev/null || true
}

phase5_settlement_adapter_roundtrip_ok_from_summary() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' "null"
    return
  fi
  resolve_phase5_bool_with_fallback \
    "$path" \
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
      end'
}

phase5_linked_summary_candidates_from_source() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    return
  fi
  jq -r '
    [
      .inputs.phase5_run_summary_json,
      .inputs.phase4_run_summary_json,
      .artifacts.phase5_run_summary_json,
      .artifacts.run_summary_json,
      .artifacts.handoff_summary_json,
      .artifacts.handoff_check_summary_json,
      .inputs.phase5_check_summary_json,
      .steps.phase5_settlement_layer_check.artifacts.summary_json,
      .artifacts.phase5_check_summary_json,
      .artifacts.check_summary_json,
      .inputs.ci_phase5_summary_json,
      .steps.ci_phase5_settlement_layer.artifacts.summary_json,
      .artifacts.ci_phase5_summary_json,
      .artifacts.ci_summary_json
    ]
    | .[]
    | select(type == "string" and length > 0)
  ' "$path" 2>/dev/null || true
}

phase5_settlement_adapter_roundtrip_status_from_summary_chain() {
  local start_path
  start_path="$(abs_path "$1")"
  local start_non_degraded=0
  local queue_nl=""
  local seen_nl=$'\n'
  local candidate=""
  local linked=""
  local value=""
  local loops=0
  local max_loops=64

  if [[ -z "$start_path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$(phase5_settlement_layer_summary_usable_01 "$start_path")" == "1" ]] \
    && [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$start_path")" != "1" ]]; then
    start_non_degraded=1
  fi
  queue_nl+="$start_path"$'\n'

  while [[ -n "$queue_nl" ]] && (( loops < max_loops )); do
    loops=$((loops + 1))
    candidate="${queue_nl%%$'\n'*}"
    if [[ "$queue_nl" == *$'\n'* ]]; then
      queue_nl="${queue_nl#*$'\n'}"
    else
      queue_nl=""
    fi
    if [[ -z "$candidate" ]]; then
      continue
    fi
    candidate="$(abs_path "$candidate")"
    if [[ -z "$candidate" ]]; then
      continue
    fi
    if [[ "$seen_nl" == *$'\n'"$candidate"$'\n'* ]]; then
      continue
    fi
    seen_nl+="$candidate"$'\n'
    if [[ "$(json_file_valid_01 "$candidate")" != "1" ]]; then
      continue
    fi
    if [[ "$start_non_degraded" == "1" ]] \
      && [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$candidate")" == "1" ]]; then
      continue
    fi
    value="$(phase5_settlement_adapter_roundtrip_status_from_summary "$candidate")"
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
      return
    fi
    while IFS= read -r linked; do
      if [[ -z "$linked" ]]; then
        continue
      fi
      linked="$(resolve_path_with_base "$linked" "$candidate")"
      linked="$(abs_path "$linked")"
      if [[ -z "$linked" ]]; then
        continue
      fi
      if [[ "$seen_nl" == *$'\n'"$linked"$'\n'* ]]; then
        continue
      fi
      queue_nl+="$linked"$'\n'
    done < <(phase5_linked_summary_candidates_from_source "$candidate")
  done

  printf '%s' ""
}

phase5_settlement_adapter_roundtrip_ok_from_summary_chain() {
  local start_path
  start_path="$(abs_path "$1")"
  local start_non_degraded=0
  local queue_nl=""
  local seen_nl=$'\n'
  local candidate=""
  local linked=""
  local value=""
  local loops=0
  local max_loops=64

  if [[ -z "$start_path" ]]; then
    printf '%s' "null"
    return
  fi
  if [[ "$(phase5_settlement_layer_summary_usable_01 "$start_path")" == "1" ]] \
    && [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$start_path")" != "1" ]]; then
    start_non_degraded=1
  fi
  queue_nl+="$start_path"$'\n'

  while [[ -n "$queue_nl" ]] && (( loops < max_loops )); do
    loops=$((loops + 1))
    candidate="${queue_nl%%$'\n'*}"
    if [[ "$queue_nl" == *$'\n'* ]]; then
      queue_nl="${queue_nl#*$'\n'}"
    else
      queue_nl=""
    fi
    if [[ -z "$candidate" ]]; then
      continue
    fi
    candidate="$(abs_path "$candidate")"
    if [[ -z "$candidate" ]]; then
      continue
    fi
    if [[ "$seen_nl" == *$'\n'"$candidate"$'\n'* ]]; then
      continue
    fi
    seen_nl+="$candidate"$'\n'
    if [[ "$(json_file_valid_01 "$candidate")" != "1" ]]; then
      continue
    fi
    if [[ "$start_non_degraded" == "1" ]] \
      && [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$candidate")" == "1" ]]; then
      continue
    fi
    value="$(phase5_settlement_adapter_roundtrip_ok_from_summary "$candidate")"
    if [[ "$value" == "true" || "$value" == "false" ]]; then
      printf '%s' "$value"
      return
    fi
    while IFS= read -r linked; do
      if [[ -z "$linked" ]]; then
        continue
      fi
      linked="$(resolve_path_with_base "$linked" "$candidate")"
      linked="$(abs_path "$linked")"
      if [[ -z "$linked" ]]; then
        continue
      fi
      if [[ "$seen_nl" == *$'\n'"$linked"$'\n'* ]]; then
        continue
      fi
      queue_nl+="$linked"$'\n'
    done < <(phase5_linked_summary_candidates_from_source "$candidate")
  done

  printf '%s' "null"
}

phase5_best_signal_source_summary_json() {
  local preferred_path="$1"
  local signal="$2"
  local signal_kind="$3"
  local logs_root=""
  local candidate=""
  local candidate_abs=""
  local candidate_value=""
  local candidate_mtime=0
  local candidate_score=0
  local candidate_non_dry=1
  local candidate_non_degraded=1
  local candidate_quality=0
  local best_path=""
  local best_mtime=-1
  local best_score=-1
  local best_non_dry=-1
  local best_non_degraded=-1
  local best_quality=-999999
  local preferred_non_degraded=0
  local seen_paths_nl=$'\n'
  local -a candidates=()

  preferred_path="$(abs_path "$preferred_path")"
  if [[ -n "$preferred_path" ]] \
    && [[ "$(phase5_settlement_layer_summary_usable_01 "$preferred_path")" == "1" ]] \
    && [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$preferred_path")" != "1" ]]; then
    preferred_non_degraded=1
  fi
  if [[ -n "$preferred_path" ]]; then
    candidates+=("$preferred_path")
  fi

  logs_root="$(roadmap_resilience_logs_root)"
  if [[ -d "$logs_root" ]]; then
    while IFS= read -r -d '' candidate; do
      candidates+=("$candidate")
    done < <(find "$logs_root" -type f \
      \( -name 'phase5_settlement_layer_handoff_check_summary.json' \
         -o -name 'phase5_settlement_layer_handoff_summary.json' \
         -o -name 'phase5_settlement_layer_handoff_run_summary.json' \
         -o -name 'phase5_settlement_layer_check_summary.json' \
         -o -name 'phase5_settlement_layer_run_summary.json' \
         -o -name 'ci_phase5_settlement_layer_summary.json' \
         -o -name 'phase5_settlement_layer_ci_summary.json' \) \
      -print0 2>/dev/null || true)
  fi

  for candidate in "${candidates[@]}"; do
    candidate_abs="$(abs_path "$candidate")"
    if [[ -z "$candidate_abs" ]]; then
      continue
    fi
    if [[ "$seen_paths_nl" == *$'\n'"$candidate_abs"$'\n'* ]]; then
      continue
    fi
    seen_paths_nl+="$candidate_abs"$'\n'
    if [[ "$(phase5_settlement_layer_summary_usable_01 "$candidate_abs")" != "1" ]]; then
      continue
    fi

    candidate_value=""
    case "$signal_kind" in
      bool)
        if [[ "$signal" == "settlement_adapter_roundtrip_ok" ]]; then
          candidate_value="$(phase5_settlement_adapter_roundtrip_ok_from_summary_chain "$candidate_abs")"
          if [[ "$candidate_value" == "null" ]]; then
            candidate_value=""
          fi
        else
          candidate_value="$(candidate_bool_signal_value_or_empty "$candidate_abs" "$signal")"
        fi
        ;;
      string)
        if [[ "$signal" == "settlement_adapter_roundtrip_status" ]]; then
          candidate_value="$(phase5_settlement_adapter_roundtrip_status_from_summary_chain "$candidate_abs")"
        else
          candidate_value="$(candidate_string_signal_value_or_empty "$candidate_abs" "$signal")"
        fi
        ;;
      *)
        continue
        ;;
    esac
    if [[ -z "$candidate_value" ]]; then
      continue
    fi

    candidate_score="$(phase5_settlement_layer_summary_completeness_score "$candidate_abs")"
    if ! [[ "$candidate_score" =~ ^[0-9]+$ ]]; then
      candidate_score=0
    fi
    candidate_non_dry=1
    if [[ "$(summary_effective_dry_run_01 "$candidate_abs")" == "1" ]]; then
      candidate_non_dry=0
    fi
    candidate_non_degraded=1
    if [[ "$(phase5_settlement_layer_summary_obviously_degraded_01 "$candidate_abs")" == "1" ]]; then
      candidate_non_degraded=0
    fi
    if [[ "$preferred_non_degraded" == "1" && "$candidate_non_degraded" == "0" ]]; then
      # Do not backfill missing signal values from degraded artifacts when the
      # selected phase5 source is healthy; preserve coherence with the chosen
      # pass artifact.
      continue
    fi
    candidate_quality="$(phase5_settlement_layer_summary_quality_score "$candidate_abs")"
    if ! [[ "$candidate_quality" =~ ^-?[0-9]+$ ]]; then
      candidate_quality=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate_abs")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi

    if (( candidate_non_dry > best_non_dry )); then
      best_non_dry="$candidate_non_dry"
      best_non_degraded="$candidate_non_degraded"
      best_score="$candidate_score"
      best_quality="$candidate_quality"
      best_mtime="$candidate_mtime"
      best_path="$candidate_abs"
    elif (( candidate_non_dry == best_non_dry )); then
      if (( candidate_non_degraded > best_non_degraded )); then
        best_non_degraded="$candidate_non_degraded"
        best_score="$candidate_score"
        best_quality="$candidate_quality"
        best_mtime="$candidate_mtime"
        best_path="$candidate_abs"
      elif (( candidate_non_degraded == best_non_degraded )); then
        if (( candidate_score > best_score )); then
          best_score="$candidate_score"
          best_quality="$candidate_quality"
          best_mtime="$candidate_mtime"
          best_path="$candidate_abs"
        elif (( candidate_score == best_score )); then
          if (( candidate_quality > best_quality )); then
            best_quality="$candidate_quality"
            best_mtime="$candidate_mtime"
            best_path="$candidate_abs"
          elif (( candidate_quality == best_quality )); then
            if (( candidate_mtime > best_mtime )); then
              best_mtime="$candidate_mtime"
              best_path="$candidate_abs"
            elif (( candidate_mtime == best_mtime )) && [[ "$candidate_abs" > "$best_path" ]]; then
              # Deterministic tie-break when dryness/degradation/score/quality/mtime are equal.
              best_path="$candidate_abs"
            fi
          fi
        fi
      fi
    fi
  done

  printf '%s' "$best_path"
}

phase5_best_string_signal_from_available() {
  local preferred_path="$1"
  local signal="$2"
  local source_path=""
  local value=""
  source_path="$(phase5_best_signal_source_summary_json "$preferred_path" "$signal" "string")"
  if [[ -z "$source_path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$signal" == "settlement_adapter_roundtrip_status" ]]; then
    value="$(phase5_settlement_adapter_roundtrip_status_from_summary_chain "$source_path")"
  else
    value="$(candidate_string_signal_value_or_empty "$source_path" "$signal")"
  fi
  printf '%s' "$value"
}

phase5_best_bool_signal_from_available() {
  local preferred_path="$1"
  local signal="$2"
  local source_path=""
  local value=""
  source_path="$(phase5_best_signal_source_summary_json "$preferred_path" "$signal" "bool")"
  if [[ -z "$source_path" ]]; then
    printf '%s' "null"
    return
  fi
  if [[ "$signal" == "settlement_adapter_roundtrip_ok" ]]; then
    value="$(phase5_settlement_adapter_roundtrip_ok_from_summary_chain "$source_path")"
  else
    value="$(candidate_bool_signal_value_or_empty "$source_path" "$signal")"
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
  for signal in run_pipeline_ok module_tx_surface_ok tdpnd_grpc_runtime_smoke_ok tdpnd_grpc_live_smoke_ok tdpnd_grpc_auth_live_smoke_ok tdpnd_comet_runtime_smoke_ok; do
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

blockchain_gate_summary_freshness_fields() {
  local path="$1"
  local max_age_sec="$2"
  local generated_at=""
  local reference_epoch=""
  local age_sec=""
  local stale="null"
  local now_epoch=""
  local known_timestamp_present="0"
  local known_timestamp_invalid="0"
  local timestamp_field=""
  local timestamp_type=""
  local timestamp_raw=""
  local timestamp_epoch=""

  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    for timestamp_field in generated_at_utc generated_at summary_generated_at_utc summary_generated_at; do
      if jq -e --arg field "$timestamp_field" 'has($field)' "$path" >/dev/null 2>&1; then
        known_timestamp_present="1"
        timestamp_type="$(jq -r --arg field "$timestamp_field" '.[$field] | type' "$path" 2>/dev/null || true)"
        if [[ "$timestamp_type" != "string" ]]; then
          known_timestamp_invalid="1"
          continue
        fi
        timestamp_raw="$(jq -r --arg field "$timestamp_field" '
          .[$field]
          | if type == "string" then . else "" end
        ' "$path" 2>/dev/null || true)"
        timestamp_raw="$(trim "$timestamp_raw")"
        if [[ -z "$timestamp_raw" ]]; then
          known_timestamp_invalid="1"
          continue
        fi
        if [[ -z "$generated_at" && -n "$timestamp_raw" ]]; then
          generated_at="$timestamp_raw"
        fi
        timestamp_epoch="$(timestamp_epoch_utc_or_empty "$timestamp_raw")"
        if [[ -n "$timestamp_epoch" ]]; then
          if [[ -z "$reference_epoch" ]]; then
            reference_epoch="$timestamp_epoch"
          fi
        else
          known_timestamp_invalid="1"
        fi
      fi
    done
  fi

  if [[ "$known_timestamp_invalid" == "1" ]]; then
    reference_epoch=""
  fi

  if [[ -z "$reference_epoch" && "$known_timestamp_present" != "1" ]]; then
    reference_epoch="$(file_mtime_epoch "$path")"
    if ! [[ "$reference_epoch" =~ ^[0-9]+$ ]] || [[ "$reference_epoch" == "0" ]]; then
      reference_epoch=""
    fi
  fi

  if [[ -n "$reference_epoch" ]]; then
    now_epoch="$(date -u +%s 2>/dev/null || true)"
    if [[ "$now_epoch" =~ ^[0-9]+$ ]]; then
      age_sec=$(( now_epoch - reference_epoch ))
      if (( age_sec < 0 )); then
        age_sec=""
        stale="true"
      elif [[ "$max_age_sec" =~ ^[0-9]+$ ]]; then
        if (( age_sec > max_age_sec )); then
          stale="true"
        else
          stale="false"
        fi
      fi
    fi
  fi

  printf '%s\n%s\n%s\n%s\n' "$generated_at" "${age_sec:-}" "$stale" "$max_age_sec"
}

blockchain_mainnet_activation_gate_summary_kind_from_source() {
  local path="$1"
  local schema_id=""
  local file_name=""
  if [[ -f "$path" ]]; then
    schema_id="$(jq -r '.schema.id // ""' "$path" 2>/dev/null || true)"
  fi
  case "$schema_id" in
    blockchain_mainnet_activation_gate_summary) printf '%s' "mainnet-activation-gate-summary"; return ;;
    mainnet_activation_gate_summary) printf '%s' "mainnet-activation-gate-summary"; return ;;
    mainnet_activation_gate_gate_summary) printf '%s' "mainnet-activation-gate-summary"; return ;;
  esac
  file_name="$(basename "$path")"
  case "$file_name" in
    blockchain_mainnet_activation_gate_summary.json) printf '%s' "mainnet-activation-gate-summary" ;;
    mainnet_activation_gate_summary.json) printf '%s' "mainnet-activation-gate-summary" ;;
    *activation*gate*summary*.json) printf '%s' "mainnet-activation-gate-summary" ;;
    *) printf '%s' "unknown" ;;
  esac
}

blockchain_gate_candidate_missing_metrics_no_go_01() {
  local path="$1"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '0'
    return
  fi

  if jq -e '
    def as_array($value):
      if ($value | type) == "array" then
        $value
      elif $value == null then
        []
      else
        [$value]
      end;
    def string_items($value):
      as_array($value)
      | map(tostring)
      | map(ascii_downcase)
      | map(select(length > 0));
    def no_go_flag:
      ((.no_go // false) == true)
      or ((if (.decision | type) == "object" then (.decision.no_go // false) else false end) == true)
      or ((.go // true) == false)
      or ((if (.decision | type) == "object" then (.decision.go // true) else true end) == false)
      or (
        ((.decision // "") | tostring | ascii_downcase)
        | test("^no-go$|^nogo$|^fail$|^failed$|^block$|^blocked$|^reject$")
      )
      or (
        ((.status // "") | tostring | ascii_downcase)
        | test("^no-go$|^nogo$|^fail$|^failed$|^invalid$|^error$")
      );
    def missing_metrics_signal:
      (
        string_items(.input.reason // "")
        + string_items(.input.metrics_json // "")
        + string_items(.metrics_json // "")
        + string_items((if (.artifacts | type) == "object" then (.artifacts.metrics_json // "") else "" end))
        + string_items(.reasons // [])
        + string_items(.failed_reasons // [])
        + string_items(.failed_gate_ids // [])
        + string_items((if (.decision | type) == "object" then (.decision.reasons // []) else [] end))
        + string_items((if (.decision | type) == "object" then (.decision.failed_reasons // []) else [] end))
        + string_items((if (.decision | type) == "object" then (.decision.failed_gate_ids // []) else [] end))
      )
      | any(test("missing or invalid metric|missing required metrics|missing metrics|invalid metrics|required_metrics|metrics_json|metrics json|metrics_input"));
    no_go_flag and missing_metrics_signal
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

find_latest_blockchain_mainnet_activation_gate_summary_json() {
  local logs_root
  local candidate=""
  local candidate_age_sec=0
  local candidate_has_age=0
  local candidate_mtime=0
  local candidate_preferred=1
  local best_path=""
  local best_age_sec=0
  local best_has_age=-1
  local best_mtime=-1
  local best_preferred=-1
  logs_root="$(roadmap_resilience_logs_root)"
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(json_file_valid_01 "$candidate")" != "1" ]]; then
      continue
    fi
    if [[ "$(blockchain_gate_candidate_is_seeded_01 "$candidate")" == "1" ]]; then
      continue
    fi
    candidate_age_sec="$(summary_age_sec_from_path "$candidate")"
    if [[ "$candidate_age_sec" =~ ^[0-9]+$ ]]; then
      candidate_has_age=1
    else
      candidate_has_age=0
      candidate_age_sec=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    candidate_preferred=1
    if [[ "$(blockchain_gate_candidate_missing_metrics_no_go_01 "$candidate")" == "1" ]]; then
      candidate_preferred=0
    fi
    # Prefer evidence-backed gate summaries (GO or evidence-based NO-GO) over
    # missing-metrics NO-GO artifacts that are typically produced by fail-close
    # invocations without a metrics JSON input.
    if (( candidate_preferred > best_preferred )); then
      best_preferred="$candidate_preferred"
      best_has_age="$candidate_has_age"
      best_age_sec="$candidate_age_sec"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_preferred == best_preferred )); then
      if (( candidate_has_age > best_has_age )); then
        best_has_age="$candidate_has_age"
        best_age_sec="$candidate_age_sec"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_has_age == best_has_age )); then
        if (( candidate_has_age == 1 )); then
          if (( candidate_age_sec < best_age_sec )); then
            best_age_sec="$candidate_age_sec"
            best_mtime="$candidate_mtime"
            best_path="$candidate"
          elif (( candidate_age_sec == best_age_sec )) && [[ "$candidate" > "$best_path" ]]; then
            best_mtime="$candidate_mtime"
            best_path="$candidate"
          fi
        elif (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'blockchain_mainnet_activation_gate_summary.json' \
       -o -name 'mainnet_activation_gate_summary.json' \
       -o -name '*activation*gate*summary*.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

blockchain_gate_candidate_is_seeded_01() {
  local path="$1"
  local path_lc=""
  path_lc="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"

  case "$path_lc" in
    *blockchain_mainnet_activation_gate_cycle_seeded*|*blockchain-mainnet-activation-gate-cycle-seeded*|*blockchain_mainnet_activation_gate_seeded*|*blockchain_bootstrap_governance_graduation_gate_seeded*)
      printf '1'
      return
      ;;
  esac

  if [[ -f "$path" ]] && jq -e '
    ((.inputs.seed_example_input // false) | type == "boolean" and . == true)
    or ((.inputs.include_example_values // false) | type == "boolean" and . == true)
    or ((.include_example_values // false) | type == "boolean" and . == true)
    or (((.artifacts.summary_json // "") | tostring | ascii_downcase) | contains("cycle_seeded"))
    or (((.artifacts.canonical_summary_json // "") | tostring | ascii_downcase) | contains("cycle_seeded"))
  ' "$path" >/dev/null 2>&1; then
    printf '1'
    return
  fi

  printf '0'
}

blockchain_mainnet_activation_gate_summary_normalize_json() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    jq -n '{
      available: false,
      status: "missing",
      decision: null,
      go: null,
      no_go: null,
      reasons: [],
      source_paths: []
    }'
    return
  fi
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    jq -n '{
      available: false,
      status: "invalid",
      decision: null,
      go: null,
      no_go: null,
      reasons: [],
      source_paths: []
    }'
    return
  fi
  jq -c '
    def string_array_from($items):
      [$items[]?]
      | map(if type == "array" then .[] else . end)
      | map(select(type == "string" and . != ""))
      | unique;
    def decision_from_string($value):
      ($value | ascii_downcase) as $s
      | if $s == "go" or $s == "pass" or $s == "yes" or $s == "allow" or $s == "approved" or $s == "ready" then "GO"
        elif $s == "no-go" or $s == "nogo" or $s == "fail" or $s == "block" or $s == "blocked" or $s == "reject" then "NO-GO"
        else null end;
    def decision_text:
      if (.decision | type) == "object" then
        if (.decision.go | type) == "boolean" then (if .decision.go then "GO" else "NO-GO" end)
        elif (.decision.pass | type) == "boolean" then (if .decision.pass then "GO" else "NO-GO" end)
        elif (.decision.no_go | type) == "boolean" then (if .decision.no_go then "NO-GO" else "GO" end)
        else decision_from_string(.decision.decision // .decision.outcome // .decision.value // .decision.status // empty) end
      elif (.decision | type) == "string" then decision_from_string(.decision)
      elif (.decision | type) == "boolean" then (if .decision then "GO" else "NO-GO" end)
      elif (.status | type) == "string" then decision_from_string(.status)
      else null end;
    def go_bool:
      if (.decision | type) == "object" then
        if (.decision.go | type) == "boolean" then .decision.go
        elif (.decision.pass | type) == "boolean" then .decision.pass
        elif (.decision.no_go | type) == "boolean" then (if .decision.no_go then false else true end)
        else (decision_text | if . == "GO" then true elif . == "NO-GO" then false else null end) end
      elif (.go | type) == "boolean" then .go
      elif (.no_go | type) == "boolean" then (if .no_go then false else true end)
      elif (.decision | type) == "boolean" then .decision
      else (decision_text | if . == "GO" then true elif . == "NO-GO" then false else null end) end;
    def no_go_bool:
      if (.decision | type) == "object" then
        if (.decision.no_go | type) == "boolean" then .decision.no_go
        elif (.decision.go | type) == "boolean" then (if .decision.go then false else true end)
        elif (.decision.pass | type) == "boolean" then (if .decision.pass then false else true end)
        else (go_bool | if . == null then null else (not) end) end
      elif (.no_go | type) == "boolean" then .no_go
      elif (.go | type) == "boolean" then (if .go then false else true end)
      else (go_bool | if . == null then null else (not) end) end;
    def reason_text_candidates:
      string_array_from([
        (if (.decision | type) == "object" then (.decision.reasons // []) else [] end),
        (.reasons // []),
        (if (.decision | type) == "object" then (.decision.reason // []) else [] end),
        (.go_reasons // []),
        (.no_go_reasons // []),
        (.failed_reasons // []),
        (if (.decision | type) == "object" then (.decision.failed_reasons // []) else [] end),
        (if (.decision | type) == "object" then (.decision.notes // []) else [] end)
      ]);
    def failed_gate_reason_fallback:
      string_array_from([
        (.failed_gate_ids // []),
        (if (.decision | type) == "object" then (.decision.failed_gate_ids // []) else [] end)
      ]);
    def source_path_candidates:
      string_array_from([
        (.source_paths // []),
        (.evidence_paths // []),
        (if (.artifacts | type) == "object" then (.artifacts.source_paths // []) else [] end),
        (if (.artifacts | type) == "object" then (.artifacts.evidence_paths // []) else [] end),
        (if (.decision | type) == "object" then (.decision.source_paths // []) else [] end),
        (if (.decision | type) == "object" then (.decision.evidence_paths // []) else [] end)
      ]);
    def metrics_source_path_fallback:
      string_array_from([
        (if (.input | type) == "object" then (.input.metrics_json // []) else [] end),
        (if (.artifacts | type) == "object" then (.artifacts.metrics_json // []) else [] end),
        (.metrics_json // []),
        (if (.decision | type) == "object" then (.decision.metrics_json // []) else [] end)
      ]);
    {
      available: true,
      status: (if (.status | type) == "string" and .status != "" then .status else "unknown" end),
      decision: decision_text,
      go: go_bool,
      no_go: no_go_bool,
      reasons: (
        reason_text_candidates as $reasons
        | if ($reasons | length) > 0 then $reasons else failed_gate_reason_fallback end
      ),
      source_paths: (
        source_path_candidates as $source_paths
        | if ($source_paths | length) > 0 then $source_paths else metrics_source_path_fallback end
      )
    }
  ' "$path"
}

blockchain_bootstrap_governance_graduation_gate_summary_kind_from_source() {
  local path="$1"
  local schema_id=""
  local file_name=""
  if [[ -f "$path" ]]; then
    schema_id="$(jq -r '.schema.id // ""' "$path" 2>/dev/null || true)"
  fi
  case "$schema_id" in
    blockchain_bootstrap_governance_graduation_gate_summary) printf '%s' "bootstrap-governance-graduation-gate-summary"; return ;;
    bootstrap_governance_graduation_gate_summary) printf '%s' "bootstrap-governance-graduation-gate-summary"; return ;;
    bootstrap_governance_graduation_summary) printf '%s' "bootstrap-governance-graduation-gate-summary"; return ;;
  esac
  file_name="$(basename "$path")"
  case "$file_name" in
    blockchain_bootstrap_governance_graduation_gate_summary.json) printf '%s' "bootstrap-governance-graduation-gate-summary" ;;
    bootstrap_governance_graduation_gate_summary.json) printf '%s' "bootstrap-governance-graduation-gate-summary" ;;
    *bootstrap*governance*graduation*gate*summary*.json) printf '%s' "bootstrap-governance-graduation-gate-summary" ;;
    *) printf '%s' "unknown" ;;
  esac
}

find_latest_blockchain_bootstrap_governance_graduation_gate_summary_json() {
  local logs_root
  local candidate=""
  local candidate_age_sec=0
  local candidate_has_age=0
  local candidate_mtime=0
  local candidate_preferred=1
  local best_path=""
  local best_age_sec=0
  local best_has_age=-1
  local best_mtime=-1
  local best_preferred=-1
  logs_root="$(roadmap_resilience_logs_root)"
  if [[ ! -d "$logs_root" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r -d '' candidate; do
    if [[ "$(json_file_valid_01 "$candidate")" != "1" ]]; then
      continue
    fi
    if [[ "$(blockchain_gate_candidate_is_seeded_01 "$candidate")" == "1" ]]; then
      continue
    fi
    candidate_age_sec="$(summary_age_sec_from_path "$candidate")"
    if [[ "$candidate_age_sec" =~ ^[0-9]+$ ]]; then
      candidate_has_age=1
    else
      candidate_has_age=0
      candidate_age_sec=0
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if ! [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      candidate_mtime=0
    fi
    candidate_preferred=1
    if [[ "$(blockchain_gate_candidate_missing_metrics_no_go_01 "$candidate")" == "1" ]]; then
      candidate_preferred=0
    fi
    if (( candidate_preferred > best_preferred )); then
      best_preferred="$candidate_preferred"
      best_has_age="$candidate_has_age"
      best_age_sec="$candidate_age_sec"
      best_mtime="$candidate_mtime"
      best_path="$candidate"
    elif (( candidate_preferred == best_preferred )); then
      if (( candidate_has_age > best_has_age )); then
        best_has_age="$candidate_has_age"
        best_age_sec="$candidate_age_sec"
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_has_age == best_has_age )); then
        if (( candidate_has_age == 1 )); then
          if (( candidate_age_sec < best_age_sec )); then
            best_age_sec="$candidate_age_sec"
            best_mtime="$candidate_mtime"
            best_path="$candidate"
          elif (( candidate_age_sec == best_age_sec )) && [[ "$candidate" > "$best_path" ]]; then
            best_mtime="$candidate_mtime"
            best_path="$candidate"
          fi
        elif (( candidate_mtime > best_mtime )); then
          best_mtime="$candidate_mtime"
          best_path="$candidate"
        elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
          best_path="$candidate"
        fi
      fi
    fi
  done < <(find "$logs_root" -type f \
    \( -name 'blockchain_bootstrap_governance_graduation_gate_summary.json' \
       -o -name 'bootstrap_governance_graduation_gate_summary.json' \
       -o -name '*bootstrap*governance*graduation*gate*summary*.json' \) \
    -print0 2>/dev/null || true)
  printf '%s' "$best_path"
}

blockchain_bootstrap_governance_graduation_gate_summary_normalize_json() {
  local path="$1"
  blockchain_mainnet_activation_gate_summary_normalize_json "$path"
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
  local logs_root
  logs_root="$(roadmap_resilience_logs_root)"
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

default_log_dir="${ROADMAP_PROGRESS_LOG_DIR:-${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}}"
default_log_dir="$(abs_path "$default_log_dir")"

summary_json="$default_log_dir/roadmap_progress_summary.json"
report_md="$default_log_dir/roadmap_progress_report.md"
manual_validation_summary_json="$default_log_dir/manual_validation_readiness_summary.json"
manual_validation_report_md="$default_log_dir/manual_validation_readiness_report.md"
profile_compare_signoff_summary_json="$default_log_dir/profile_compare_campaign_signoff_summary.json"
profile_compare_multi_vm_stability_check_summary_json="${ROADMAP_PROGRESS_PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SUMMARY_JSON:-}"
if [[ -n "$(trim "$profile_compare_multi_vm_stability_check_summary_json")" ]]; then
  path_arg_or_die "--profile-compare-multi-vm-stability-check-summary-json" "$profile_compare_multi_vm_stability_check_summary_json"
fi
profile_compare_multi_vm_stability_check_summary_json="$(abs_path "$profile_compare_multi_vm_stability_check_summary_json")"
profile_compare_multi_vm_stability_promotion_summary_json="${ROADMAP_PROGRESS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_SUMMARY_JSON:-}"
if [[ -n "$(trim "$profile_compare_multi_vm_stability_promotion_summary_json")" ]]; then
  path_arg_or_die "--profile-compare-multi-vm-stability-promotion-summary-json" "$profile_compare_multi_vm_stability_promotion_summary_json"
fi
profile_compare_multi_vm_stability_promotion_summary_json="$(abs_path "$profile_compare_multi_vm_stability_promotion_summary_json")"
runtime_actuation_promotion_summary_json="${ROADMAP_PROGRESS_RUNTIME_ACTUATION_PROMOTION_SUMMARY_JSON:-}"
if [[ -n "$(trim "$runtime_actuation_promotion_summary_json")" ]]; then
  path_arg_or_die "--runtime-actuation-promotion-summary-json" "$runtime_actuation_promotion_summary_json"
fi
runtime_actuation_promotion_summary_json="$(abs_path "$runtime_actuation_promotion_summary_json")"
single_machine_summary_json="$default_log_dir/single_machine_prod_readiness_latest.json"
phase0_summary_json="${ROADMAP_PROGRESS_PHASE0_SUMMARY_JSON:-$default_log_dir/ci_phase0_summary.json}"
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
phase7_mainnet_cutover_summary_json="${ROADMAP_PROGRESS_PHASE7_MAINNET_CUTOVER_SUMMARY_JSON:-$default_log_dir/phase7_mainnet_cutover_summary_report.json}"
if [[ -n "$(trim "$phase7_mainnet_cutover_summary_json")" ]]; then
  path_arg_or_die "--phase7-mainnet-cutover-summary-json" "$phase7_mainnet_cutover_summary_json"
fi
phase7_mainnet_cutover_summary_json="$(abs_path "$phase7_mainnet_cutover_summary_json")"
blockchain_mainnet_activation_gate_summary_json="${ROADMAP_PROGRESS_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON:-}"
if [[ -n "$(trim "$blockchain_mainnet_activation_gate_summary_json")" ]]; then
  path_arg_or_die "--blockchain-mainnet-activation-gate-summary-json" "$blockchain_mainnet_activation_gate_summary_json"
fi
blockchain_mainnet_activation_gate_summary_json="$(abs_path "$blockchain_mainnet_activation_gate_summary_json")"
blockchain_bootstrap_governance_graduation_gate_summary_json="${ROADMAP_PROGRESS_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON:-}"
if [[ -n "$(trim "$blockchain_bootstrap_governance_graduation_gate_summary_json")" ]]; then
  path_arg_or_die "--blockchain-bootstrap-governance-graduation-gate-summary-json" "$blockchain_bootstrap_governance_graduation_gate_summary_json"
fi
blockchain_bootstrap_governance_graduation_gate_summary_json="$(abs_path "$blockchain_bootstrap_governance_graduation_gate_summary_json")"

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
      optional_path_arg_or_die "--manual-validation-summary-json" "$#" "${2:-}"
      manual_validation_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --manual-refresh-timeout-sec)
      value_arg_or_die "--manual-refresh-timeout-sec" "${2:-}"
      manual_refresh_timeout_sec="${2:-}"
      shift 2
      ;;
    --single-machine-refresh-timeout-sec)
      value_arg_or_die "--single-machine-refresh-timeout-sec" "${2:-}"
      single_machine_refresh_timeout_sec="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      optional_path_arg_or_die "--manual-validation-report-md" "$#" "${2:-}"
      manual_validation_report_md="$(abs_path "${2:-}")"
      shift 2
      ;;
    --profile-compare-signoff-summary-json)
      optional_path_arg_or_die "--profile-compare-signoff-summary-json" "$#" "${2:-}"
      profile_compare_signoff_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --profile-compare-multi-vm-stability-check-summary-json)
      optional_path_arg_or_die "--profile-compare-multi-vm-stability-check-summary-json" "$#" "${2:-}"
      profile_compare_multi_vm_stability_check_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --profile-compare-multi-vm-stability-promotion-summary-json)
      optional_path_arg_or_die "--profile-compare-multi-vm-stability-promotion-summary-json" "$#" "${2:-}"
      profile_compare_multi_vm_stability_promotion_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --runtime-actuation-promotion-summary-json)
      optional_path_arg_or_die "--runtime-actuation-promotion-summary-json" "$#" "${2:-}"
      runtime_actuation_promotion_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --single-machine-summary-json)
      optional_path_arg_or_die "--single-machine-summary-json" "$#" "${2:-}"
      single_machine_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase0-summary-json)
      optional_path_arg_or_die "--phase0-summary-json" "$#" "${2:-}"
      phase0_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase1-resilience-handoff-summary-json)
      optional_path_arg_or_die "--phase1-resilience-handoff-summary-json" "$#" "${2:-}"
      phase1_resilience_handoff_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --vpn-rc-resilience-summary-json)
      optional_path_arg_or_die "--vpn-rc-resilience-summary-json" "$#" "${2:-}"
      vpn_rc_resilience_summary_json="$(abs_path "${2:-}")"
      vpn_rc_resilience_summary_explicit_01="1"
      shift 2
      ;;
    --phase2-linux-prod-candidate-summary-json)
      optional_path_arg_or_die "--phase2-linux-prod-candidate-summary-json" "$#" "${2:-}"
      phase2_linux_prod_candidate_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase3-windows-client-beta-summary-json)
      optional_path_arg_or_die "--phase3-windows-client-beta-summary-json" "$#" "${2:-}"
      phase3_windows_client_beta_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase4-windows-full-parity-summary-json)
      optional_path_arg_or_die "--phase4-windows-full-parity-summary-json" "$#" "${2:-}"
      phase4_windows_full_parity_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase5-settlement-layer-summary-json)
      optional_path_arg_or_die "--phase5-settlement-layer-summary-json" "$#" "${2:-}"
      phase5_settlement_layer_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase6-cosmos-l1-summary-json)
      optional_path_arg_or_die "--phase6-cosmos-l1-summary-json" "$#" "${2:-}"
      phase6_cosmos_l1_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --phase7-mainnet-cutover-summary-json)
      optional_path_arg_or_die "--phase7-mainnet-cutover-summary-json" "$#" "${2:-}"
      phase7_mainnet_cutover_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --blockchain-mainnet-activation-gate-summary-json)
      optional_path_arg_or_die "--blockchain-mainnet-activation-gate-summary-json" "$#" "${2:-}"
      blockchain_mainnet_activation_gate_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --blockchain-bootstrap-governance-graduation-gate-summary-json)
      optional_path_arg_or_die "--blockchain-bootstrap-governance-graduation-gate-summary-json" "$#" "${2:-}"
      blockchain_bootstrap_governance_graduation_gate_summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --summary-json)
      path_arg_or_die "--summary-json" "${2:-}"
      summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --report-md)
      path_arg_or_die "--report-md" "${2:-}"
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

log_dir="$default_log_dir"
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
phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json="null"
phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source_json=""
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
      phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json="$(resolve_phase4_bool_with_fallback \
        "$phase4_windows_full_parity_handoff_source_summary_json" \
        'if (.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .windows_native_bootstrap_guardrails_ok
          elif (.summary.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .summary.windows_native_bootstrap_guardrails_ok
          elif (.handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .handoff.windows_native_bootstrap_guardrails_ok
          elif (.signals.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .signals.windows_native_bootstrap_guardrails_ok
          elif (.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok
          elif (.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok
          else empty end' \
        '((.signals.windows_native_bootstrap_guardrails_ok | type) == "boolean") as $direct
          | if $direct then empty
            else
              ((.stages.windows_native_bootstrap_guardrails.ok | type) == "boolean") as $has_ok
              | if $has_ok then .stages.windows_native_bootstrap_guardrails.ok
                else ((.stages.windows_native_bootstrap_guardrails.status // .steps.windows_native_bootstrap_guardrails.status // "") | ascii_downcase) as $s
                  | if $s == "pass" then true
                    elif $s == "fail" then false
                    else empty end
                end
            end')"
      phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source_json="$(phase4_windows_full_parity_windows_native_bootstrap_guardrails_source_label "$phase4_windows_full_parity_handoff_source_summary_json")"
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
phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json=""
phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json="null"
phase5_settlement_layer_handoff_settlement_shadow_env_status_json=""
phase5_settlement_layer_handoff_settlement_shadow_env_ok_json="null"
phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json=""
phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json="null"
phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json=""
phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json="null"
phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json=""
phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json="null"
phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json=""
phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json="null"
phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json=""
phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json="null"
phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json=""
phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json="null"
phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json=""
phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json="null"
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
      phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json="$(phase5_settlement_adapter_roundtrip_status_from_summary_chain "$phase5_settlement_layer_handoff_source_summary_json")"
      phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="$(phase5_settlement_adapter_roundtrip_ok_from_summary_chain "$phase5_settlement_layer_handoff_source_summary_json")"
      if [[ -z "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json" ]]; then
        phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json="$(phase5_settlement_adapter_roundtrip_status_from_summary_chain "$phase5_settlement_layer_summary_json")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="$(phase5_settlement_adapter_roundtrip_ok_from_summary_chain "$phase5_settlement_layer_summary_json")"
      fi
      if [[ -z "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json" || "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json" == "null" ]]; then
        phase5_run_summary_chain_json=""
        phase5_run_summary_chain_json="$(jq -r '
          if (.schema.id // "") == "phase5_settlement_layer_run_summary" then input_filename
          elif (.schema.id // "") == "phase5_settlement_layer_handoff_run_summary" then (.inputs.phase5_run_summary_json // .artifacts.phase5_run_summary_json // "")
          elif (.inputs.phase5_run_summary_json | type) == "string" then .inputs.phase5_run_summary_json
          elif (.inputs.phase4_run_summary_json | type) == "string" then .inputs.phase4_run_summary_json
          elif (.artifacts.phase5_run_summary_json | type) == "string" then .artifacts.phase5_run_summary_json
          elif (.artifacts.run_summary_json | type) == "string" then .artifacts.run_summary_json
          else "" end
        ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
        if [[ -n "$phase5_run_summary_chain_json" ]]; then
          phase5_run_summary_chain_json="$(resolve_path_with_base "$phase5_run_summary_chain_json" "$phase5_settlement_layer_handoff_source_summary_json")"
          if [[ "$(json_file_valid_01 "$phase5_run_summary_chain_json")" == "1" ]]; then
            phase5_ci_summary_chain_json=""
            phase5_ci_summary_chain_json="$(jq -r '
              if (.inputs.ci_phase5_summary_json | type) == "string" then .inputs.ci_phase5_summary_json
              elif (.steps.ci_phase5_settlement_layer.artifacts.summary_json | type) == "string" then .steps.ci_phase5_settlement_layer.artifacts.summary_json
              elif (.artifacts.ci_phase5_summary_json | type) == "string" then .artifacts.ci_phase5_summary_json
              elif (.artifacts.ci_summary_json | type) == "string" then .artifacts.ci_summary_json
              else "" end
            ' "$phase5_run_summary_chain_json" 2>/dev/null || true)"
            if [[ -n "$phase5_ci_summary_chain_json" ]]; then
              phase5_ci_summary_chain_json="$(resolve_path_with_base "$phase5_ci_summary_chain_json" "$phase5_run_summary_chain_json")"
              if [[ "$(json_file_valid_01 "$phase5_ci_summary_chain_json")" == "1" ]]; then
                if [[ -z "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json" ]]; then
                  phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json="$(jq -r '
                    if (.settlement_adapter_roundtrip_status | type) == "string" then .settlement_adapter_roundtrip_status
                    elif (.summary.settlement_adapter_roundtrip_status | type) == "string" then .summary.settlement_adapter_roundtrip_status
                    elif (.signals.settlement_adapter_roundtrip_status | type) == "string" then .signals.settlement_adapter_roundtrip_status
                    elif (.steps.settlement_adapter_roundtrip.status | type) == "string" then .steps.settlement_adapter_roundtrip.status
                    elif (.steps.adapter_roundtrip.status | type) == "string" then .steps.adapter_roundtrip.status
                    elif (.stages.settlement_adapter_roundtrip.status | type) == "string" then .stages.settlement_adapter_roundtrip.status
                    elif (.stages.adapter_roundtrip.status | type) == "string" then .stages.adapter_roundtrip.status
                    else empty end
                  ' "$phase5_ci_summary_chain_json" 2>/dev/null || true)"
                fi
                if [[ "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json" == "null" ]]; then
                  phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="$(resolve_phase5_bool_with_fallback \
                    "$phase5_ci_summary_chain_json" \
                    'if (.settlement_adapter_roundtrip_ok | type) == "boolean" then .settlement_adapter_roundtrip_ok
                      elif (.summary.settlement_adapter_roundtrip_ok | type) == "boolean" then .summary.settlement_adapter_roundtrip_ok
                      elif (.signals.settlement_adapter_roundtrip_ok | type) == "boolean" then .signals.settlement_adapter_roundtrip_ok
                      elif (.signals.settlement_adapter_roundtrip | type) == "boolean" then .signals.settlement_adapter_roundtrip
                      else empty end' \
                    'if (.stages.settlement_adapter_roundtrip.ok | type) == "boolean" then .stages.settlement_adapter_roundtrip.ok
                      elif (.stages.adapter_roundtrip.ok | type) == "boolean" then .stages.adapter_roundtrip.ok
                      else
                        ((.steps.settlement_adapter_roundtrip.status // .steps.adapter_roundtrip.status // .stages.settlement_adapter_roundtrip.status // .stages.adapter_roundtrip.status // "") | ascii_downcase) as $s
                        | if $s == "pass" then true
                          elif $s == "fail" then false
                          else empty end
                      end')"
                fi
              fi
            fi
          fi
        fi
      fi
      if [[ -z "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json" ]]; then
        phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_adapter_roundtrip_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_adapter_roundtrip_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json="$(jq -r '
        if (.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .settlement_adapter_signed_tx_roundtrip_status
        elif (.summary.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .summary.settlement_adapter_signed_tx_roundtrip_status
        elif (.handoff.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .handoff.settlement_adapter_signed_tx_roundtrip_status
        elif (.signals.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .signals.settlement_adapter_signed_tx_roundtrip_status
        elif (.signals.settlement_adapter_signed_tx_roundtrip.status | type) == "string" then .signals.settlement_adapter_signed_tx_roundtrip.status
        elif (.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status
        elif (.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status
        elif (.steps.settlement_adapter_signed_tx_roundtrip.status | type) == "string" then .steps.settlement_adapter_signed_tx_roundtrip.status
        elif (.stages.settlement_adapter_signed_tx_roundtrip.status | type) == "string" then .stages.settlement_adapter_signed_tx_roundtrip.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_adapter_signed_tx_roundtrip_ok | type) == "boolean" then .settlement_adapter_signed_tx_roundtrip_ok
          elif (.summary.settlement_adapter_signed_tx_roundtrip_ok | type) == "boolean" then .summary.settlement_adapter_signed_tx_roundtrip_ok
          elif (.handoff.settlement_adapter_signed_tx_roundtrip_ok | type) == "boolean" then .handoff.settlement_adapter_signed_tx_roundtrip_ok
          elif (.signals.settlement_adapter_signed_tx_roundtrip_ok | type) == "boolean" then .signals.settlement_adapter_signed_tx_roundtrip_ok
          elif (.signals.settlement_adapter_signed_tx_roundtrip | type) == "boolean" then .signals.settlement_adapter_signed_tx_roundtrip
          elif (.signals.settlement_adapter_signed_tx_roundtrip.ok | type) == "boolean" then .signals.settlement_adapter_signed_tx_roundtrip.ok
          elif (.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok
          else empty end' \
        'if (.stages.settlement_adapter_signed_tx_roundtrip.ok | type) == "boolean" then .stages.settlement_adapter_signed_tx_roundtrip.ok
          else
            ((if (.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .settlement_adapter_signed_tx_roundtrip_status
              elif (.summary.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .summary.settlement_adapter_signed_tx_roundtrip_status
              elif (.handoff.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .handoff.settlement_adapter_signed_tx_roundtrip_status
              elif (.signals.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .signals.settlement_adapter_signed_tx_roundtrip_status
              elif (.signals.settlement_adapter_signed_tx_roundtrip.status | type) == "string" then .signals.settlement_adapter_signed_tx_roundtrip.status
              elif (.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status
              elif (.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status
              elif (.steps.settlement_adapter_signed_tx_roundtrip.status | type) == "string" then .steps.settlement_adapter_signed_tx_roundtrip.status
              elif (.stages.settlement_adapter_signed_tx_roundtrip.status | type) == "string" then .stages.settlement_adapter_signed_tx_roundtrip.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json" ]]; then
        phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_adapter_signed_tx_roundtrip_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_adapter_signed_tx_roundtrip_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_settlement_shadow_env_status_json="$(jq -r '
        if (.settlement_shadow_env_status | type) == "string" then .settlement_shadow_env_status
        elif (.summary.settlement_shadow_env_status | type) == "string" then .summary.settlement_shadow_env_status
        elif (.handoff.settlement_shadow_env_status | type) == "string" then .handoff.settlement_shadow_env_status
        elif (.signals.settlement_shadow_env_status | type) == "string" then .signals.settlement_shadow_env_status
        elif (.signals.settlement_shadow_env.status | type) == "string" then .signals.settlement_shadow_env.status
        elif (.phase5_settlement_layer_handoff.settlement_shadow_env_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_shadow_env_status
        elif (.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status
        elif (.steps.settlement_shadow_env.status | type) == "string" then .steps.settlement_shadow_env.status
        elif (.stages.settlement_shadow_env.status | type) == "string" then .stages.settlement_shadow_env.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_settlement_shadow_env_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_shadow_env_ok | type) == "boolean" then .settlement_shadow_env_ok
          elif (.summary.settlement_shadow_env_ok | type) == "boolean" then .summary.settlement_shadow_env_ok
          elif (.handoff.settlement_shadow_env_ok | type) == "boolean" then .handoff.settlement_shadow_env_ok
          elif (.signals.settlement_shadow_env_ok | type) == "boolean" then .signals.settlement_shadow_env_ok
          elif (.signals.settlement_shadow_env | type) == "boolean" then .signals.settlement_shadow_env
          elif (.signals.settlement_shadow_env.ok | type) == "boolean" then .signals.settlement_shadow_env.ok
          elif (.phase5_settlement_layer_handoff.settlement_shadow_env_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_shadow_env_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok
          else empty end' \
        'if (.stages.settlement_shadow_env.ok | type) == "boolean" then .stages.settlement_shadow_env.ok
          else
            ((if (.settlement_shadow_env_status | type) == "string" then .settlement_shadow_env_status
              elif (.summary.settlement_shadow_env_status | type) == "string" then .summary.settlement_shadow_env_status
              elif (.handoff.settlement_shadow_env_status | type) == "string" then .handoff.settlement_shadow_env_status
              elif (.signals.settlement_shadow_env_status | type) == "string" then .signals.settlement_shadow_env_status
              elif (.signals.settlement_shadow_env.status | type) == "string" then .signals.settlement_shadow_env.status
              elif (.phase5_settlement_layer_handoff.settlement_shadow_env_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_shadow_env_status
              elif (.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status
              elif (.steps.settlement_shadow_env.status | type) == "string" then .steps.settlement_shadow_env.status
              elif (.stages.settlement_shadow_env.status | type) == "string" then .stages.settlement_shadow_env.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_settlement_shadow_env_status_json" ]]; then
        phase5_settlement_layer_handoff_settlement_shadow_env_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_shadow_env_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_shadow_env_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_settlement_shadow_env_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_shadow_env_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_shadow_env_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_settlement_shadow_env_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_settlement_shadow_env_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_settlement_shadow_env_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json="$(jq -r '
        if (.settlement_shadow_status_surface_status | type) == "string" then .settlement_shadow_status_surface_status
        elif (.summary.settlement_shadow_status_surface_status | type) == "string" then .summary.settlement_shadow_status_surface_status
        elif (.handoff.settlement_shadow_status_surface_status | type) == "string" then .handoff.settlement_shadow_status_surface_status
        elif (.signals.settlement_shadow_status_surface_status | type) == "string" then .signals.settlement_shadow_status_surface_status
        elif (.signals.settlement_shadow_status_surface.status | type) == "string" then .signals.settlement_shadow_status_surface.status
        elif (.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_shadow_status_surface_status
        elif (.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status
        elif (.steps.settlement_shadow_status_surface.status | type) == "string" then .steps.settlement_shadow_status_surface.status
        elif (.stages.settlement_shadow_status_surface.status | type) == "string" then .stages.settlement_shadow_status_surface.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_shadow_status_surface_ok | type) == "boolean" then .settlement_shadow_status_surface_ok
          elif (.summary.settlement_shadow_status_surface_ok | type) == "boolean" then .summary.settlement_shadow_status_surface_ok
          elif (.handoff.settlement_shadow_status_surface_ok | type) == "boolean" then .handoff.settlement_shadow_status_surface_ok
          elif (.signals.settlement_shadow_status_surface_ok | type) == "boolean" then .signals.settlement_shadow_status_surface_ok
          elif (.signals.settlement_shadow_status_surface | type) == "boolean" then .signals.settlement_shadow_status_surface
          elif (.signals.settlement_shadow_status_surface.ok | type) == "boolean" then .signals.settlement_shadow_status_surface.ok
          elif (.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok
          else empty end' \
        'if (.stages.settlement_shadow_status_surface.ok | type) == "boolean" then .stages.settlement_shadow_status_surface.ok
          else
            ((if (.settlement_shadow_status_surface_status | type) == "string" then .settlement_shadow_status_surface_status
              elif (.summary.settlement_shadow_status_surface_status | type) == "string" then .summary.settlement_shadow_status_surface_status
              elif (.handoff.settlement_shadow_status_surface_status | type) == "string" then .handoff.settlement_shadow_status_surface_status
              elif (.signals.settlement_shadow_status_surface_status | type) == "string" then .signals.settlement_shadow_status_surface_status
              elif (.signals.settlement_shadow_status_surface.status | type) == "string" then .signals.settlement_shadow_status_surface.status
              elif (.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_shadow_status_surface_status
              elif (.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status
              elif (.steps.settlement_shadow_status_surface.status | type) == "string" then .steps.settlement_shadow_status_surface.status
              elif (.stages.settlement_shadow_status_surface.status | type) == "string" then .stages.settlement_shadow_status_surface.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json" ]]; then
        phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_shadow_status_surface_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_shadow_status_surface_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json="false"
            ;;
        esac
      fi
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
      if [[ -z "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json" ]]; then
        phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_sponsor_api_live_smoke_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_sponsor_api_live_smoke_ok")"
      fi
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
      phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json="$(jq -r '
        if (.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .issuer_sponsor_vpn_session_live_smoke_status
        elif (.summary.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .summary.issuer_sponsor_vpn_session_live_smoke_status
        elif (.handoff.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .handoff.issuer_sponsor_vpn_session_live_smoke_status
        elif (.signals.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .signals.issuer_sponsor_vpn_session_live_smoke_status
        elif (.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status
        elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status
        elif (.steps.issuer_sponsor_vpn_session_live_smoke.status | type) == "string" then .steps.issuer_sponsor_vpn_session_live_smoke.status
        elif (.stages.issuer_sponsor_vpn_session_live_smoke.status | type) == "string" then .stages.issuer_sponsor_vpn_session_live_smoke.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.issuer_sponsor_vpn_session_live_smoke_ok | type) == "boolean" then .issuer_sponsor_vpn_session_live_smoke_ok
          elif (.summary.issuer_sponsor_vpn_session_live_smoke_ok | type) == "boolean" then .summary.issuer_sponsor_vpn_session_live_smoke_ok
          elif (.handoff.issuer_sponsor_vpn_session_live_smoke_ok | type) == "boolean" then .handoff.issuer_sponsor_vpn_session_live_smoke_ok
          elif (.signals.issuer_sponsor_vpn_session_live_smoke_ok | type) == "boolean" then .signals.issuer_sponsor_vpn_session_live_smoke_ok
          elif (.signals.issuer_sponsor_vpn_session_live_smoke | type) == "boolean" then .signals.issuer_sponsor_vpn_session_live_smoke
          elif (.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok | type) == "boolean" then .phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok
          else empty end' \
        'if (.stages.issuer_sponsor_vpn_session_live_smoke.ok | type) == "boolean" then .stages.issuer_sponsor_vpn_session_live_smoke.ok
          else
            ((if (.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .issuer_sponsor_vpn_session_live_smoke_status
              elif (.summary.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .summary.issuer_sponsor_vpn_session_live_smoke_status
              elif (.handoff.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .handoff.issuer_sponsor_vpn_session_live_smoke_status
              elif (.signals.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .signals.issuer_sponsor_vpn_session_live_smoke_status
              elif (.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status
              elif (.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status
              elif (.steps.issuer_sponsor_vpn_session_live_smoke.status | type) == "string" then .steps.issuer_sponsor_vpn_session_live_smoke.status
              elif (.stages.issuer_sponsor_vpn_session_live_smoke.status | type) == "string" then .stages.issuer_sponsor_vpn_session_live_smoke.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
                  elif $s == "fail" then false
                  else empty end
              end')"
      if [[ -z "$phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json" ]]; then
        phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_sponsor_vpn_session_live_smoke_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_sponsor_vpn_session_live_smoke_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json="$(jq -r '
        if (.issuer_settlement_status_live_smoke_status | type) == "string" then .issuer_settlement_status_live_smoke_status
        elif (.summary.issuer_settlement_status_live_smoke_status | type) == "string" then .summary.issuer_settlement_status_live_smoke_status
        elif (.handoff.issuer_settlement_status_live_smoke_status | type) == "string" then .handoff.issuer_settlement_status_live_smoke_status
        elif (.signals.issuer_settlement_status_live_smoke_status | type) == "string" then .signals.issuer_settlement_status_live_smoke_status
        elif (.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status
        elif (.vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status
        elif (.steps.issuer_settlement_status_live_smoke.status | type) == "string" then .steps.issuer_settlement_status_live_smoke.status
        elif (.stages.issuer_settlement_status_live_smoke.status | type) == "string" then .stages.issuer_settlement_status_live_smoke.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.issuer_settlement_status_live_smoke_ok | type) == "boolean" then .issuer_settlement_status_live_smoke_ok
          elif (.summary.issuer_settlement_status_live_smoke_ok | type) == "boolean" then .summary.issuer_settlement_status_live_smoke_ok
          elif (.handoff.issuer_settlement_status_live_smoke_ok | type) == "boolean" then .handoff.issuer_settlement_status_live_smoke_ok
          elif (.signals.issuer_settlement_status_live_smoke_ok | type) == "boolean" then .signals.issuer_settlement_status_live_smoke_ok
          elif (.signals.issuer_settlement_status_live_smoke | type) == "boolean" then .signals.issuer_settlement_status_live_smoke
          elif (.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok | type) == "boolean" then .phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok
          else empty end' \
        'if (.stages.issuer_settlement_status_live_smoke.ok | type) == "boolean" then .stages.issuer_settlement_status_live_smoke.ok
          else
            ((if (.issuer_settlement_status_live_smoke_status | type) == "string" then .issuer_settlement_status_live_smoke_status
              elif (.summary.issuer_settlement_status_live_smoke_status | type) == "string" then .summary.issuer_settlement_status_live_smoke_status
              elif (.handoff.issuer_settlement_status_live_smoke_status | type) == "string" then .handoff.issuer_settlement_status_live_smoke_status
              elif (.signals.issuer_settlement_status_live_smoke_status | type) == "string" then .signals.issuer_settlement_status_live_smoke_status
              elif (.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status
              elif (.vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status
              elif (.steps.issuer_settlement_status_live_smoke.status | type) == "string" then .steps.issuer_settlement_status_live_smoke.status
              elif (.stages.issuer_settlement_status_live_smoke.status | type) == "string" then .stages.issuer_settlement_status_live_smoke.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json" ]]; then
        phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_settlement_status_live_smoke_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_settlement_status_live_smoke_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json="$(jq -r '
        if (.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .issuer_admin_blockchain_handlers_coverage_status
        elif (.summary.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .summary.issuer_admin_blockchain_handlers_coverage_status
        elif (.handoff.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .handoff.issuer_admin_blockchain_handlers_coverage_status
        elif (.signals.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .signals.issuer_admin_blockchain_handlers_coverage_status
        elif (.signals.issuer_admin_blockchain_handlers_coverage.status | type) == "string" then .signals.issuer_admin_blockchain_handlers_coverage.status
        elif (.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status
        elif (.vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status
        elif (.steps.issuer_admin_blockchain_handlers_coverage.status | type) == "string" then .steps.issuer_admin_blockchain_handlers_coverage.status
        elif (.stages.issuer_admin_blockchain_handlers_coverage.status | type) == "string" then .stages.issuer_admin_blockchain_handlers_coverage.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.issuer_admin_blockchain_handlers_coverage_ok | type) == "boolean" then .issuer_admin_blockchain_handlers_coverage_ok
          elif (.summary.issuer_admin_blockchain_handlers_coverage_ok | type) == "boolean" then .summary.issuer_admin_blockchain_handlers_coverage_ok
          elif (.handoff.issuer_admin_blockchain_handlers_coverage_ok | type) == "boolean" then .handoff.issuer_admin_blockchain_handlers_coverage_ok
          elif (.signals.issuer_admin_blockchain_handlers_coverage_ok | type) == "boolean" then .signals.issuer_admin_blockchain_handlers_coverage_ok
          elif (.signals.issuer_admin_blockchain_handlers_coverage | type) == "boolean" then .signals.issuer_admin_blockchain_handlers_coverage
          elif (.signals.issuer_admin_blockchain_handlers_coverage.ok | type) == "boolean" then .signals.issuer_admin_blockchain_handlers_coverage.ok
          elif (.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok | type) == "boolean" then .phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok
          else empty end' \
        'if (.stages.issuer_admin_blockchain_handlers_coverage.ok | type) == "boolean" then .stages.issuer_admin_blockchain_handlers_coverage.ok
          else
            ((if (.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .issuer_admin_blockchain_handlers_coverage_status
              elif (.summary.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .summary.issuer_admin_blockchain_handlers_coverage_status
              elif (.handoff.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .handoff.issuer_admin_blockchain_handlers_coverage_status
              elif (.signals.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .signals.issuer_admin_blockchain_handlers_coverage_status
              elif (.signals.issuer_admin_blockchain_handlers_coverage.status | type) == "string" then .signals.issuer_admin_blockchain_handlers_coverage.status
              elif (.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status
              elif (.vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status
              elif (.steps.issuer_admin_blockchain_handlers_coverage.status | type) == "string" then .steps.issuer_admin_blockchain_handlers_coverage.status
              elif (.stages.issuer_admin_blockchain_handlers_coverage.status | type) == "string" then .stages.issuer_admin_blockchain_handlers_coverage.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json" ]]; then
        phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_admin_blockchain_handlers_coverage_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "issuer_admin_blockchain_handlers_coverage_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json="$(jq -r '
        if (.exit_settlement_status_live_smoke_status | type) == "string" then .exit_settlement_status_live_smoke_status
        elif (.summary.exit_settlement_status_live_smoke_status | type) == "string" then .summary.exit_settlement_status_live_smoke_status
        elif (.handoff.exit_settlement_status_live_smoke_status | type) == "string" then .handoff.exit_settlement_status_live_smoke_status
        elif (.signals.exit_settlement_status_live_smoke_status | type) == "string" then .signals.exit_settlement_status_live_smoke_status
        elif (.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status
        elif (.vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status
        elif (.steps.exit_settlement_status_live_smoke.status | type) == "string" then .steps.exit_settlement_status_live_smoke.status
        elif (.stages.exit_settlement_status_live_smoke.status | type) == "string" then .stages.exit_settlement_status_live_smoke.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.exit_settlement_status_live_smoke_ok | type) == "boolean" then .exit_settlement_status_live_smoke_ok
          elif (.summary.exit_settlement_status_live_smoke_ok | type) == "boolean" then .summary.exit_settlement_status_live_smoke_ok
          elif (.handoff.exit_settlement_status_live_smoke_ok | type) == "boolean" then .handoff.exit_settlement_status_live_smoke_ok
          elif (.signals.exit_settlement_status_live_smoke_ok | type) == "boolean" then .signals.exit_settlement_status_live_smoke_ok
          elif (.signals.exit_settlement_status_live_smoke | type) == "boolean" then .signals.exit_settlement_status_live_smoke
          elif (.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok | type) == "boolean" then .phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok
          else empty end' \
        'if (.stages.exit_settlement_status_live_smoke.ok | type) == "boolean" then .stages.exit_settlement_status_live_smoke.ok
          else
            ((if (.exit_settlement_status_live_smoke_status | type) == "string" then .exit_settlement_status_live_smoke_status
              elif (.summary.exit_settlement_status_live_smoke_status | type) == "string" then .summary.exit_settlement_status_live_smoke_status
              elif (.handoff.exit_settlement_status_live_smoke_status | type) == "string" then .handoff.exit_settlement_status_live_smoke_status
              elif (.signals.exit_settlement_status_live_smoke_status | type) == "string" then .signals.exit_settlement_status_live_smoke_status
              elif (.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status | type) == "string" then .phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status
              elif (.vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status
              elif (.steps.exit_settlement_status_live_smoke.status | type) == "string" then .steps.exit_settlement_status_live_smoke.status
              elif (.stages.exit_settlement_status_live_smoke.status | type) == "string" then .stages.exit_settlement_status_live_smoke.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json" ]]; then
        phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "exit_settlement_status_live_smoke_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "exit_settlement_status_live_smoke_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json="false"
            ;;
        esac
      fi
      phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json="$(jq -r '
        if (.settlement_dual_asset_parity_status | type) == "string" then .settlement_dual_asset_parity_status
        elif (.summary.settlement_dual_asset_parity_status | type) == "string" then .summary.settlement_dual_asset_parity_status
        elif (.handoff.settlement_dual_asset_parity_status | type) == "string" then .handoff.settlement_dual_asset_parity_status
        elif (.signals.settlement_dual_asset_parity_status | type) == "string" then .signals.settlement_dual_asset_parity_status
        elif (.signals.settlement_dual_asset_parity.status | type) == "string" then .signals.settlement_dual_asset_parity.status
        elif (.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_dual_asset_parity_status
        elif (.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status
        elif (.steps.settlement_dual_asset_parity.status | type) == "string" then .steps.settlement_dual_asset_parity.status
        elif (.stages.settlement_dual_asset_parity.status | type) == "string" then .stages.settlement_dual_asset_parity.status
        else empty end
      ' "$phase5_settlement_layer_handoff_source_summary_json" 2>/dev/null || true)"
      phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json="$(resolve_phase5_bool_with_fallback \
        "$phase5_settlement_layer_handoff_source_summary_json" \
        'if (.settlement_dual_asset_parity_ok | type) == "boolean" then .settlement_dual_asset_parity_ok
          elif (.summary.settlement_dual_asset_parity_ok | type) == "boolean" then .summary.settlement_dual_asset_parity_ok
          elif (.handoff.settlement_dual_asset_parity_ok | type) == "boolean" then .handoff.settlement_dual_asset_parity_ok
          elif (.signals.settlement_dual_asset_parity_ok | type) == "boolean" then .signals.settlement_dual_asset_parity_ok
          elif (.signals.settlement_dual_asset_parity | type) == "boolean" then .signals.settlement_dual_asset_parity
          elif (.signals.settlement_dual_asset_parity.ok | type) == "boolean" then .signals.settlement_dual_asset_parity.ok
          elif (.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | type) == "boolean" then .phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok
          elif (.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | type) == "boolean" then .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok
          else empty end' \
        'if (.stages.settlement_dual_asset_parity.ok | type) == "boolean" then .stages.settlement_dual_asset_parity.ok
          else
            ((if (.settlement_dual_asset_parity_status | type) == "string" then .settlement_dual_asset_parity_status
              elif (.summary.settlement_dual_asset_parity_status | type) == "string" then .summary.settlement_dual_asset_parity_status
              elif (.handoff.settlement_dual_asset_parity_status | type) == "string" then .handoff.settlement_dual_asset_parity_status
              elif (.signals.settlement_dual_asset_parity_status | type) == "string" then .signals.settlement_dual_asset_parity_status
              elif (.signals.settlement_dual_asset_parity.status | type) == "string" then .signals.settlement_dual_asset_parity.status
              elif (.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status | type) == "string" then .phase5_settlement_layer_handoff.settlement_dual_asset_parity_status
              elif (.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status | type) == "string" then .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status
              elif (.steps.settlement_dual_asset_parity.status | type) == "string" then .steps.settlement_dual_asset_parity.status
              elif (.stages.settlement_dual_asset_parity.status | type) == "string" then .stages.settlement_dual_asset_parity.status
              else "" end) | ascii_downcase) as $s
            | if $s == "pass" then true
              elif $s == "fail" then false
              else empty end
          end')"
      if [[ -z "$phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json" ]]; then
        phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json="$(phase5_best_string_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_dual_asset_parity_status")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json" == "null" ]]; then
        phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json="$(phase5_best_bool_signal_from_available \
          "$phase5_settlement_layer_handoff_source_summary_json" \
          "settlement_dual_asset_parity_ok")"
      fi
      if [[ "$phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json" == "null" ]]; then
        case "${phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json,,}" in
          pass)
            phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json="true"
            ;;
          fail)
            phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json="false"
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
phase6_cosmos_l1_handoff_tdpnd_comet_runtime_smoke_ok_json="null"
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
      phase6_cosmos_l1_handoff_tdpnd_comet_runtime_smoke_ok_json="$(resolve_phase6_bool_with_source_chain \
        "$phase6_source_summary_json" \
        'if (.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .tdpnd_comet_runtime_smoke_ok
          elif (.summary.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .summary.tdpnd_comet_runtime_smoke_ok
          elif (.handoff.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .handoff.tdpnd_comet_runtime_smoke_ok
          elif (.signals.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .signals.tdpnd_comet_runtime_smoke_ok
          elif (.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok
          elif (.vpn_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .vpn_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok
          elif (.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok
          else empty end' \
        'if (.stages.tdpnd_comet_runtime_smoke.ok | type) == "boolean" then .stages.tdpnd_comet_runtime_smoke.ok
          elif (.steps.tdpnd_comet_runtime_smoke.ok | type) == "boolean" then .steps.tdpnd_comet_runtime_smoke.ok
          else
            ((if (.tdpnd_comet_runtime_smoke_status | type) == "string" then .tdpnd_comet_runtime_smoke_status
              elif (.summary.tdpnd_comet_runtime_smoke_status | type) == "string" then .summary.tdpnd_comet_runtime_smoke_status
              elif (.handoff.tdpnd_comet_runtime_smoke_status | type) == "string" then .handoff.tdpnd_comet_runtime_smoke_status
              elif (.signals.tdpnd_comet_runtime_smoke_status | type) == "string" then .signals.tdpnd_comet_runtime_smoke_status
              elif (.stages.tdpnd_comet_runtime_smoke.status | type) == "string" then .stages.tdpnd_comet_runtime_smoke.status
              elif (.steps.tdpnd_comet_runtime_smoke.status | type) == "string" then .steps.tdpnd_comet_runtime_smoke.status
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
phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json="null"
phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json="null"
phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source_json=""
phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source_json=""
phase7_mainnet_cutover_summary_tdpnd_grpc_live_smoke_ok_json="null"
phase7_mainnet_cutover_summary_module_tx_surface_ok_json="null"
phase7_mainnet_cutover_summary_tdpnd_grpc_auth_live_smoke_ok_json="null"
phase7_mainnet_cutover_summary_tdpnd_comet_runtime_smoke_ok_json="null"
phase7_mainnet_cutover_summary_cosmos_module_coverage_floor_ok_json="null"
phase7_mainnet_cutover_summary_cosmos_keeper_coverage_floor_ok_json="null"
phase7_mainnet_cutover_summary_cosmos_app_coverage_floor_ok_json="null"
phase7_mainnet_cutover_summary_dual_write_parity_ok_json="null"
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
      phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.summaries.check.signal_snapshot.mainnet_activation_gate_go_ok | type) == "boolean" then .summaries.check.signal_snapshot.mainnet_activation_gate_go_ok
          elif (.summaries.check.signal_snapshot.mainnet_activation_gate_go | type) == "boolean" then .summaries.check.signal_snapshot.mainnet_activation_gate_go
          elif (.summaries.run.signal_snapshot.mainnet_activation_gate_go_ok | type) == "boolean" then .summaries.run.signal_snapshot.mainnet_activation_gate_go_ok
          elif (.summaries.run.signal_snapshot.mainnet_activation_gate_go | type) == "boolean" then .summaries.run.signal_snapshot.mainnet_activation_gate_go
          elif (.summaries.handoff_check.signal_snapshot.mainnet_activation_gate_go_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.mainnet_activation_gate_go_ok
          elif (.summaries.handoff_check.signal_snapshot.mainnet_activation_gate_go | type) == "boolean" then .summaries.handoff_check.signal_snapshot.mainnet_activation_gate_go
          elif (.summaries.handoff_run.signal_snapshot.mainnet_activation_gate_go_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.mainnet_activation_gate_go_ok
          elif (.summaries.handoff_run.signal_snapshot.mainnet_activation_gate_go | type) == "boolean" then .summaries.handoff_run.signal_snapshot.mainnet_activation_gate_go
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go
          elif (.handoff.mainnet_activation_gate_go_ok | type) == "boolean" then .handoff.mainnet_activation_gate_go_ok
          elif (.handoff.mainnet_activation_gate_go | type) == "boolean" then .handoff.mainnet_activation_gate_go
          elif (.signals.mainnet_activation_gate_go_ok | type) == "boolean" then .signals.mainnet_activation_gate_go_ok
          elif (.signals.mainnet_activation_gate_go | type) == "boolean" then .signals.mainnet_activation_gate_go
          elif (.mainnet_activation_gate_go_ok | type) == "boolean" then .mainnet_activation_gate_go_ok
          elif (.mainnet_activation_gate_go | type) == "boolean" then .mainnet_activation_gate_go
          else empty end')"
      phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.summaries.check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .summaries.check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok
          elif (.summaries.check.signal_snapshot.bootstrap_governance_graduation_gate_go | type) == "boolean" then .summaries.check.signal_snapshot.bootstrap_governance_graduation_gate_go
          elif (.summaries.run.signal_snapshot.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .summaries.run.signal_snapshot.bootstrap_governance_graduation_gate_go_ok
          elif (.summaries.run.signal_snapshot.bootstrap_governance_graduation_gate_go | type) == "boolean" then .summaries.run.signal_snapshot.bootstrap_governance_graduation_gate_go
          elif (.summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok
          elif (.summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go | type) == "boolean" then .summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go
          elif (.summaries.handoff_run.signal_snapshot.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.bootstrap_governance_graduation_gate_go_ok
          elif (.summaries.handoff_run.signal_snapshot.bootstrap_governance_graduation_gate_go | type) == "boolean" then .summaries.handoff_run.signal_snapshot.bootstrap_governance_graduation_gate_go
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.bootstrap_governance_graduation_gate_go | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.bootstrap_governance_graduation_gate_go
          elif (.handoff.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .handoff.bootstrap_governance_graduation_gate_go_ok
          elif (.handoff.bootstrap_governance_graduation_gate_go | type) == "boolean" then .handoff.bootstrap_governance_graduation_gate_go
          elif (.signals.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .signals.bootstrap_governance_graduation_gate_go_ok
          elif (.signals.bootstrap_governance_graduation_gate_go | type) == "boolean" then .signals.bootstrap_governance_graduation_gate_go
          elif (.bootstrap_governance_graduation_gate_go_ok | type) == "boolean" then .bootstrap_governance_graduation_gate_go_ok
          elif (.bootstrap_governance_graduation_gate_go | type) == "boolean" then .bootstrap_governance_graduation_gate_go
          else empty end')"
      phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source_json="phase7-mainnet-cutover-summary-signal"
      phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source_json="phase7-mainnet-cutover-summary-signal"
      phase7_mainnet_cutover_summary_tdpnd_grpc_live_smoke_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .signals.tdpnd_grpc_live_smoke_ok
          elif (.signals.tdpnd_grpc_live_smoke | type) == "boolean" then .signals.tdpnd_grpc_live_smoke
          elif (.summaries.check.signal_snapshot.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .summaries.check.signal_snapshot.tdpnd_grpc_live_smoke_ok
          elif (.summaries.check.signal_snapshot.tdpnd_grpc_live_smoke | type) == "boolean" then .summaries.check.signal_snapshot.tdpnd_grpc_live_smoke
          elif (.summaries.run.signal_snapshot.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .summaries.run.signal_snapshot.tdpnd_grpc_live_smoke_ok
          elif (.summaries.run.signal_snapshot.tdpnd_grpc_live_smoke | type) == "boolean" then .summaries.run.signal_snapshot.tdpnd_grpc_live_smoke
          elif (.summaries.handoff_check.signal_snapshot.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.tdpnd_grpc_live_smoke_ok
          elif (.summaries.handoff_check.signal_snapshot.tdpnd_grpc_live_smoke | type) == "boolean" then .summaries.handoff_check.signal_snapshot.tdpnd_grpc_live_smoke
          elif (.summaries.handoff_run.signal_snapshot.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.tdpnd_grpc_live_smoke_ok
          elif (.summaries.handoff_run.signal_snapshot.tdpnd_grpc_live_smoke | type) == "boolean" then .summaries.handoff_run.signal_snapshot.tdpnd_grpc_live_smoke
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_live_smoke_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_live_smoke | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_live_smoke
          elif (.handoff.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .handoff.tdpnd_grpc_live_smoke_ok
          elif (.handoff.tdpnd_grpc_live_smoke | type) == "boolean" then .handoff.tdpnd_grpc_live_smoke
          elif (.tdpnd_grpc_live_smoke_ok | type) == "boolean" then .tdpnd_grpc_live_smoke_ok
          elif (.tdpnd_grpc_live_smoke | type) == "boolean" then .tdpnd_grpc_live_smoke
          else empty end')"
      phase7_mainnet_cutover_summary_module_tx_surface_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.module_tx_surface_ok | type) == "boolean" then .signals.module_tx_surface_ok
          elif (.signals.module_tx_surface | type) == "boolean" then .signals.module_tx_surface
          elif (.summaries.check.signal_snapshot.module_tx_surface_ok | type) == "boolean" then .summaries.check.signal_snapshot.module_tx_surface_ok
          elif (.summaries.check.signal_snapshot.module_tx_surface | type) == "boolean" then .summaries.check.signal_snapshot.module_tx_surface
          elif (.summaries.run.signal_snapshot.module_tx_surface_ok | type) == "boolean" then .summaries.run.signal_snapshot.module_tx_surface_ok
          elif (.summaries.run.signal_snapshot.module_tx_surface | type) == "boolean" then .summaries.run.signal_snapshot.module_tx_surface
          elif (.summaries.handoff_check.signal_snapshot.module_tx_surface_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.module_tx_surface_ok
          elif (.summaries.handoff_check.signal_snapshot.module_tx_surface | type) == "boolean" then .summaries.handoff_check.signal_snapshot.module_tx_surface
          elif (.summaries.handoff_run.signal_snapshot.module_tx_surface_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.module_tx_surface_ok
          elif (.summaries.handoff_run.signal_snapshot.module_tx_surface | type) == "boolean" then .summaries.handoff_run.signal_snapshot.module_tx_surface
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface
          elif (.handoff.module_tx_surface_ok | type) == "boolean" then .handoff.module_tx_surface_ok
          elif (.handoff.module_tx_surface | type) == "boolean" then .handoff.module_tx_surface
          elif (.module_tx_surface_ok | type) == "boolean" then .module_tx_surface_ok
          elif (.module_tx_surface | type) == "boolean" then .module_tx_surface
          else empty end')"
      phase7_mainnet_cutover_summary_tdpnd_grpc_auth_live_smoke_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .signals.tdpnd_grpc_auth_live_smoke_ok
          elif (.signals.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .signals.tdpnd_grpc_auth_live_smoke
          elif (.summaries.check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .summaries.check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok
          elif (.summaries.check.signal_snapshot.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .summaries.check.signal_snapshot.tdpnd_grpc_auth_live_smoke
          elif (.summaries.run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .summaries.run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok
          elif (.summaries.run.signal_snapshot.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .summaries.run.signal_snapshot.tdpnd_grpc_auth_live_smoke
          elif (.summaries.handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok
          elif (.summaries.handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .summaries.handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke
          elif (.summaries.handoff_run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok
          elif (.summaries.handoff_run.signal_snapshot.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .summaries.handoff_run.signal_snapshot.tdpnd_grpc_auth_live_smoke
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke
          elif (.handoff.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .handoff.tdpnd_grpc_auth_live_smoke_ok
          elif (.handoff.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .handoff.tdpnd_grpc_auth_live_smoke
          elif (.tdpnd_grpc_auth_live_smoke_ok | type) == "boolean" then .tdpnd_grpc_auth_live_smoke_ok
          elif (.tdpnd_grpc_auth_live_smoke | type) == "boolean" then .tdpnd_grpc_auth_live_smoke
          else empty end')"
      phase7_mainnet_cutover_summary_tdpnd_comet_runtime_smoke_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .signals.tdpnd_comet_runtime_smoke_ok
          elif (.signals.tdpnd_comet_runtime_smoke | type) == "boolean" then .signals.tdpnd_comet_runtime_smoke
          elif (.summaries.check.signal_snapshot.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .summaries.check.signal_snapshot.tdpnd_comet_runtime_smoke_ok
          elif (.summaries.check.signal_snapshot.tdpnd_comet_runtime_smoke | type) == "boolean" then .summaries.check.signal_snapshot.tdpnd_comet_runtime_smoke
          elif (.summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke_ok
          elif (.summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke | type) == "boolean" then .summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke
          elif (.summaries.handoff_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok
          elif (.summaries.handoff_check.signal_snapshot.tdpnd_comet_runtime_smoke | type) == "boolean" then .summaries.handoff_check.signal_snapshot.tdpnd_comet_runtime_smoke
          elif (.summaries.handoff_run.signal_snapshot.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.tdpnd_comet_runtime_smoke_ok
          elif (.summaries.handoff_run.signal_snapshot.tdpnd_comet_runtime_smoke | type) == "boolean" then .summaries.handoff_run.signal_snapshot.tdpnd_comet_runtime_smoke
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke
          elif (.handoff.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .handoff.tdpnd_comet_runtime_smoke_ok
          elif (.handoff.tdpnd_comet_runtime_smoke | type) == "boolean" then .handoff.tdpnd_comet_runtime_smoke
          elif (.tdpnd_comet_runtime_smoke_ok | type) == "boolean" then .tdpnd_comet_runtime_smoke_ok
          elif (.tdpnd_comet_runtime_smoke | type) == "boolean" then .tdpnd_comet_runtime_smoke
          else empty end')"
      phase7_mainnet_cutover_summary_cosmos_module_coverage_floor_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.cosmos_module_coverage_floor_ok | type) == "boolean" then .signals.cosmos_module_coverage_floor_ok
          elif (.summaries.check.signal_snapshot.cosmos_module_coverage_floor_ok | type) == "boolean" then .summaries.check.signal_snapshot.cosmos_module_coverage_floor_ok
          elif (.summaries.run.signal_snapshot.cosmos_module_coverage_floor_ok | type) == "boolean" then .summaries.run.signal_snapshot.cosmos_module_coverage_floor_ok
          elif (.summaries.handoff_check.signal_snapshot.cosmos_module_coverage_floor_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.cosmos_module_coverage_floor_ok
          elif (.summaries.handoff_run.signal_snapshot.cosmos_module_coverage_floor_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.cosmos_module_coverage_floor_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_module_coverage_floor_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_module_coverage_floor_ok
          elif (.handoff.cosmos_module_coverage_floor_ok | type) == "boolean" then .handoff.cosmos_module_coverage_floor_ok
          elif (.cosmos_module_coverage_floor_ok | type) == "boolean" then .cosmos_module_coverage_floor_ok
          else empty end')"
      phase7_mainnet_cutover_summary_cosmos_keeper_coverage_floor_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .signals.cosmos_keeper_coverage_floor_ok
          elif (.summaries.check.signal_snapshot.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .summaries.check.signal_snapshot.cosmos_keeper_coverage_floor_ok
          elif (.summaries.run.signal_snapshot.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .summaries.run.signal_snapshot.cosmos_keeper_coverage_floor_ok
          elif (.summaries.handoff_check.signal_snapshot.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.cosmos_keeper_coverage_floor_ok
          elif (.summaries.handoff_run.signal_snapshot.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.cosmos_keeper_coverage_floor_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_keeper_coverage_floor_ok
          elif (.handoff.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .handoff.cosmos_keeper_coverage_floor_ok
          elif (.cosmos_keeper_coverage_floor_ok | type) == "boolean" then .cosmos_keeper_coverage_floor_ok
          else empty end')"
      phase7_mainnet_cutover_summary_cosmos_app_coverage_floor_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.cosmos_app_coverage_floor_ok | type) == "boolean" then .signals.cosmos_app_coverage_floor_ok
          elif (.summaries.check.signal_snapshot.cosmos_app_coverage_floor_ok | type) == "boolean" then .summaries.check.signal_snapshot.cosmos_app_coverage_floor_ok
          elif (.summaries.run.signal_snapshot.cosmos_app_coverage_floor_ok | type) == "boolean" then .summaries.run.signal_snapshot.cosmos_app_coverage_floor_ok
          elif (.summaries.handoff_check.signal_snapshot.cosmos_app_coverage_floor_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.cosmos_app_coverage_floor_ok
          elif (.summaries.handoff_run.signal_snapshot.cosmos_app_coverage_floor_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.cosmos_app_coverage_floor_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_app_coverage_floor_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_app_coverage_floor_ok
          elif (.handoff.cosmos_app_coverage_floor_ok | type) == "boolean" then .handoff.cosmos_app_coverage_floor_ok
          elif (.cosmos_app_coverage_floor_ok | type) == "boolean" then .cosmos_app_coverage_floor_ok
          else empty end')"
      phase7_mainnet_cutover_summary_dual_write_parity_ok_json="$(phase7_mainnet_cutover_bool_value_or_null \
        "$phase7_mainnet_cutover_summary_source_summary_json" \
        'if (.signals.dual_write_parity_ok | type) == "boolean" then .signals.dual_write_parity_ok
          elif (.signals.dual_write_parity | type) == "boolean" then .signals.dual_write_parity
          elif (.summaries.check.signal_snapshot.dual_write_parity_ok | type) == "boolean" then .summaries.check.signal_snapshot.dual_write_parity_ok
          elif (.summaries.check.signal_snapshot.dual_write_parity | type) == "boolean" then .summaries.check.signal_snapshot.dual_write_parity
          elif (.summaries.run.signal_snapshot.dual_write_parity_ok | type) == "boolean" then .summaries.run.signal_snapshot.dual_write_parity_ok
          elif (.summaries.run.signal_snapshot.dual_write_parity | type) == "boolean" then .summaries.run.signal_snapshot.dual_write_parity
          elif (.summaries.handoff_check.signal_snapshot.dual_write_parity_ok | type) == "boolean" then .summaries.handoff_check.signal_snapshot.dual_write_parity_ok
          elif (.summaries.handoff_check.signal_snapshot.dual_write_parity | type) == "boolean" then .summaries.handoff_check.signal_snapshot.dual_write_parity
          elif (.summaries.handoff_run.signal_snapshot.dual_write_parity_ok | type) == "boolean" then .summaries.handoff_run.signal_snapshot.dual_write_parity_ok
          elif (.summaries.handoff_run.signal_snapshot.dual_write_parity | type) == "boolean" then .summaries.handoff_run.signal_snapshot.dual_write_parity
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok
          elif (.steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity | type) == "boolean" then .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity
          elif (.handoff.dual_write_parity_ok | type) == "boolean" then .handoff.dual_write_parity_ok
          elif (.handoff.dual_write_parity | type) == "boolean" then .handoff.dual_write_parity
          elif (.dual_write_parity_ok | type) == "boolean" then .dual_write_parity_ok
          elif (.dual_write_parity | type) == "boolean" then .dual_write_parity
          else empty end')"
    fi
  else
    phase7_mainnet_cutover_summary_status_json="invalid"
  fi
fi

blockchain_mainnet_activation_gate_available_json="false"
blockchain_mainnet_activation_gate_input_summary_json=""
blockchain_mainnet_activation_gate_source_summary_json=""
blockchain_mainnet_activation_gate_source_summary_kind=""
blockchain_mainnet_activation_gate_status_json="missing"
blockchain_mainnet_activation_gate_decision_json=""
blockchain_mainnet_activation_gate_go_json="null"
blockchain_mainnet_activation_gate_no_go_json="null"
blockchain_mainnet_activation_gate_reasons_json="[]"
blockchain_mainnet_activation_gate_source_paths_json="[]"
if [[ -z "$blockchain_mainnet_activation_gate_summary_json" ]]; then
  blockchain_mainnet_activation_gate_summary_json="$(find_latest_blockchain_mainnet_activation_gate_summary_json)"
fi
if [[ -n "$blockchain_mainnet_activation_gate_summary_json" ]]; then
  blockchain_mainnet_activation_gate_input_summary_json="$blockchain_mainnet_activation_gate_summary_json"
  if [[ -f "$blockchain_mainnet_activation_gate_summary_json" ]]; then
    if [[ "$(json_file_valid_01 "$blockchain_mainnet_activation_gate_summary_json")" == "1" ]]; then
      blockchain_mainnet_activation_gate_source_summary_json="$(abs_path "$blockchain_mainnet_activation_gate_summary_json")"
      blockchain_mainnet_activation_gate_source_summary_kind="$(blockchain_mainnet_activation_gate_summary_kind_from_source "$blockchain_mainnet_activation_gate_summary_json")"
      blockchain_mainnet_activation_gate_summary_payload_json="$(blockchain_mainnet_activation_gate_summary_normalize_json "$blockchain_mainnet_activation_gate_summary_json")"
      blockchain_mainnet_activation_gate_available_json="$(jq -r '.available // false' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || echo false)"
      blockchain_mainnet_activation_gate_status_json="$(jq -r '.status // "unknown"' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || echo "unknown")"
      blockchain_mainnet_activation_gate_decision_json="$(jq -r '.decision // empty' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || true)"
      blockchain_mainnet_activation_gate_go_json="$(jq -r 'if .go == null then "null" else (.go | tostring) end' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || echo "null")"
      blockchain_mainnet_activation_gate_no_go_json="$(jq -r 'if .no_go == null then "null" else (.no_go | tostring) end' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || echo "null")"
      blockchain_mainnet_activation_gate_reasons_json="$(jq -c '.reasons // []' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || echo '[]')"
      blockchain_mainnet_activation_gate_source_paths_json="$(jq -c '.source_paths // []' <<<"$blockchain_mainnet_activation_gate_summary_payload_json" 2>/dev/null || echo '[]')"
    else
      blockchain_mainnet_activation_gate_status_json="invalid"
    fi
  fi
fi

# Fallback: when no dedicated activation-gate summary is available, inherit the
# phase7 propagated mainnet_activation_gate_go signal if present.
if [[ "$blockchain_mainnet_activation_gate_status_json" == "missing" ]] \
  && [[ -z "$blockchain_mainnet_activation_gate_input_summary_json" ]] \
  && [[ "$phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json" != "null" ]]; then
  blockchain_mainnet_activation_gate_available_json="true"
  blockchain_mainnet_activation_gate_source_summary_json="$phase7_mainnet_cutover_summary_source_summary_json"
  if [[ -n "$blockchain_mainnet_activation_gate_source_summary_json" ]]; then
    blockchain_mainnet_activation_gate_input_summary_json="$blockchain_mainnet_activation_gate_source_summary_json"
    blockchain_mainnet_activation_gate_source_paths_json="$(jq -nc --arg p "$blockchain_mainnet_activation_gate_source_summary_json" '[$p]')"
  else
    blockchain_mainnet_activation_gate_source_paths_json="[]"
  fi
  blockchain_mainnet_activation_gate_source_summary_kind="phase7-mainnet-cutover-signal"
  blockchain_mainnet_activation_gate_go_json="$phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json"
  if [[ "$phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json" == "true" ]]; then
    blockchain_mainnet_activation_gate_status_json="go"
    blockchain_mainnet_activation_gate_decision_json="GO"
    blockchain_mainnet_activation_gate_no_go_json="false"
    blockchain_mainnet_activation_gate_reasons_json="[]"
  else
    blockchain_mainnet_activation_gate_status_json="no-go"
    blockchain_mainnet_activation_gate_decision_json="NO-GO"
    blockchain_mainnet_activation_gate_no_go_json="true"
    blockchain_mainnet_activation_gate_reasons_json='["derived from phase7 mainnet_activation_gate_go signal=false"]'
  fi
fi

blockchain_bootstrap_governance_graduation_gate_available_json="false"
blockchain_bootstrap_governance_graduation_gate_input_summary_json=""
blockchain_bootstrap_governance_graduation_gate_source_summary_json=""
blockchain_bootstrap_governance_graduation_gate_source_summary_kind=""
blockchain_bootstrap_governance_graduation_gate_status_json="missing"
blockchain_bootstrap_governance_graduation_gate_decision_json=""
blockchain_bootstrap_governance_graduation_gate_go_json="null"
blockchain_bootstrap_governance_graduation_gate_no_go_json="null"
blockchain_bootstrap_governance_graduation_gate_reasons_json="[]"
blockchain_bootstrap_governance_graduation_gate_source_paths_json="[]"
if [[ -z "$blockchain_bootstrap_governance_graduation_gate_summary_json" ]]; then
  blockchain_bootstrap_governance_graduation_gate_summary_json="$(find_latest_blockchain_bootstrap_governance_graduation_gate_summary_json)"
fi
if [[ -n "$blockchain_bootstrap_governance_graduation_gate_summary_json" ]]; then
  blockchain_bootstrap_governance_graduation_gate_input_summary_json="$blockchain_bootstrap_governance_graduation_gate_summary_json"
  if [[ -f "$blockchain_bootstrap_governance_graduation_gate_summary_json" ]]; then
    if [[ "$(json_file_valid_01 "$blockchain_bootstrap_governance_graduation_gate_summary_json")" == "1" ]]; then
      blockchain_bootstrap_governance_graduation_gate_source_summary_json="$(abs_path "$blockchain_bootstrap_governance_graduation_gate_summary_json")"
      blockchain_bootstrap_governance_graduation_gate_source_summary_kind="$(blockchain_bootstrap_governance_graduation_gate_summary_kind_from_source "$blockchain_bootstrap_governance_graduation_gate_summary_json")"
      blockchain_bootstrap_governance_graduation_gate_summary_payload_json="$(blockchain_bootstrap_governance_graduation_gate_summary_normalize_json "$blockchain_bootstrap_governance_graduation_gate_summary_json")"
      blockchain_bootstrap_governance_graduation_gate_available_json="$(jq -r '.available // false' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || echo false)"
      blockchain_bootstrap_governance_graduation_gate_status_json="$(jq -r '.status // "unknown"' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || echo "unknown")"
      blockchain_bootstrap_governance_graduation_gate_decision_json="$(jq -r '.decision // empty' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || true)"
      blockchain_bootstrap_governance_graduation_gate_go_json="$(jq -r 'if .go == null then "null" else (.go | tostring) end' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || echo "null")"
      blockchain_bootstrap_governance_graduation_gate_no_go_json="$(jq -r 'if .no_go == null then "null" else (.no_go | tostring) end' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || echo "null")"
      blockchain_bootstrap_governance_graduation_gate_reasons_json="$(jq -c '.reasons // []' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || echo '[]')"
      blockchain_bootstrap_governance_graduation_gate_source_paths_json="$(jq -c '.source_paths // []' <<<"$blockchain_bootstrap_governance_graduation_gate_summary_payload_json" 2>/dev/null || echo '[]')"
    else
      blockchain_bootstrap_governance_graduation_gate_status_json="invalid"
    fi
  fi
fi

# Fallback: when no dedicated bootstrap-governance gate summary is available,
# inherit the phase7 propagated bootstrap_governance_graduation_gate_go signal.
if [[ "$blockchain_bootstrap_governance_graduation_gate_status_json" == "missing" ]] \
  && [[ -z "$blockchain_bootstrap_governance_graduation_gate_input_summary_json" ]] \
  && [[ "$phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json" != "null" ]]; then
  blockchain_bootstrap_governance_graduation_gate_available_json="true"
  blockchain_bootstrap_governance_graduation_gate_source_summary_json="$phase7_mainnet_cutover_summary_source_summary_json"
  if [[ -n "$blockchain_bootstrap_governance_graduation_gate_source_summary_json" ]]; then
    blockchain_bootstrap_governance_graduation_gate_input_summary_json="$blockchain_bootstrap_governance_graduation_gate_source_summary_json"
    blockchain_bootstrap_governance_graduation_gate_source_paths_json="$(jq -nc --arg p "$blockchain_bootstrap_governance_graduation_gate_source_summary_json" '[$p]')"
  else
    blockchain_bootstrap_governance_graduation_gate_source_paths_json="[]"
  fi
  blockchain_bootstrap_governance_graduation_gate_source_summary_kind="phase7-mainnet-cutover-signal"
  blockchain_bootstrap_governance_graduation_gate_go_json="$phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json"
  if [[ "$phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json" == "true" ]]; then
    blockchain_bootstrap_governance_graduation_gate_status_json="GO"
    blockchain_bootstrap_governance_graduation_gate_decision_json="GO"
    blockchain_bootstrap_governance_graduation_gate_no_go_json="false"
    blockchain_bootstrap_governance_graduation_gate_reasons_json="[]"
  else
    blockchain_bootstrap_governance_graduation_gate_status_json="NO-GO"
    blockchain_bootstrap_governance_graduation_gate_decision_json="NO-GO"
    blockchain_bootstrap_governance_graduation_gate_no_go_json="true"
    blockchain_bootstrap_governance_graduation_gate_reasons_json='["derived from phase7 bootstrap_governance_graduation_gate_go signal=false"]'
  fi
fi

# Conflict hardening: when dedicated gate summaries are available/valid, align
# phase7 propagated gate booleans with dedicated gate decisions so operators
# never see contradictory signals in one roadmap snapshot.
if [[ "$phase7_mainnet_cutover_summary_available_json" == "true" ]]; then
  if [[ "$blockchain_mainnet_activation_gate_source_summary_kind" != "" ]] \
    && [[ "$blockchain_mainnet_activation_gate_source_summary_kind" != "phase7-mainnet-cutover-signal" ]] \
    && [[ "$blockchain_mainnet_activation_gate_go_json" != "null" ]]; then
    phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json="$blockchain_mainnet_activation_gate_go_json"
    phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source_json="dedicated-mainnet-activation-gate-summary"
  fi
  if [[ "$blockchain_bootstrap_governance_graduation_gate_source_summary_kind" != "" ]] \
    && [[ "$blockchain_bootstrap_governance_graduation_gate_source_summary_kind" != "phase7-mainnet-cutover-signal" ]] \
    && [[ "$blockchain_bootstrap_governance_graduation_gate_go_json" != "null" ]]; then
    phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json="$blockchain_bootstrap_governance_graduation_gate_go_json"
    phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source_json="dedicated-bootstrap-governance-graduation-gate-summary"
  fi
fi

blockchain_gate_summary_max_age_sec="${ROADMAP_BLOCKCHAIN_GATE_SUMMARY_MAX_AGE_SEC:-86400}"
if ! [[ "$blockchain_gate_summary_max_age_sec" =~ ^[0-9]+$ ]]; then
  blockchain_gate_summary_max_age_sec="86400"
fi

blockchain_mainnet_activation_gate_summary_generated_at_json=""
blockchain_mainnet_activation_gate_summary_age_sec_json="null"
blockchain_mainnet_activation_gate_summary_stale_json="null"
blockchain_mainnet_activation_gate_summary_max_age_sec_json="$blockchain_gate_summary_max_age_sec"
if [[ -n "$blockchain_mainnet_activation_gate_source_summary_json" ]]; then
  mapfile -t blockchain_mainnet_activation_gate_freshness_lines < <(
    blockchain_gate_summary_freshness_fields \
      "$blockchain_mainnet_activation_gate_source_summary_json" \
      "$blockchain_gate_summary_max_age_sec"
  )
  blockchain_mainnet_activation_gate_summary_generated_at_json="${blockchain_mainnet_activation_gate_freshness_lines[0]:-}"
  blockchain_mainnet_activation_gate_summary_age_sec_json="${blockchain_mainnet_activation_gate_freshness_lines[1]:-}"
  blockchain_mainnet_activation_gate_summary_stale_json="${blockchain_mainnet_activation_gate_freshness_lines[2]:-null}"
  blockchain_mainnet_activation_gate_summary_max_age_sec_json="${blockchain_mainnet_activation_gate_freshness_lines[3]:-$blockchain_gate_summary_max_age_sec}"
fi

blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json=""
blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json="null"
blockchain_bootstrap_governance_graduation_gate_summary_stale_json="null"
blockchain_bootstrap_governance_graduation_gate_summary_max_age_sec_json="$blockchain_gate_summary_max_age_sec"
if [[ -n "$blockchain_bootstrap_governance_graduation_gate_source_summary_json" ]]; then
  mapfile -t blockchain_bootstrap_governance_graduation_gate_freshness_lines < <(
    blockchain_gate_summary_freshness_fields \
      "$blockchain_bootstrap_governance_graduation_gate_source_summary_json" \
      "$blockchain_gate_summary_max_age_sec"
  )
  blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json="${blockchain_bootstrap_governance_graduation_gate_freshness_lines[0]:-}"
  blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json="${blockchain_bootstrap_governance_graduation_gate_freshness_lines[1]:-}"
  blockchain_bootstrap_governance_graduation_gate_summary_stale_json="${blockchain_bootstrap_governance_graduation_gate_freshness_lines[2]:-null}"
  blockchain_bootstrap_governance_graduation_gate_summary_max_age_sec_json="${blockchain_bootstrap_governance_graduation_gate_freshness_lines[3]:-$blockchain_gate_summary_max_age_sec}"
fi

blockchain_mainnet_activation_refresh_evidence_available_json="false"
blockchain_mainnet_activation_refresh_evidence_id_json=""
blockchain_mainnet_activation_refresh_evidence_command=""
blockchain_mainnet_activation_refresh_evidence_reason=""
if [[ "$blockchain_mainnet_activation_gate_available_json" == "true" ]] \
  && [[ "$blockchain_mainnet_activation_gate_source_summary_kind" != "phase7-mainnet-cutover-signal" ]] \
  && [[ "$blockchain_mainnet_activation_gate_go_json" == "true" ]]; then
  if [[ "$blockchain_mainnet_activation_gate_summary_stale_json" == "true" ]] \
     || [[ "$blockchain_mainnet_activation_gate_summary_stale_json" != "false" ]]; then
    blockchain_mainnet_activation_refresh_evidence_available_json="true"
    blockchain_mainnet_activation_refresh_evidence_id_json="blockchain_mainnet_activation_refresh_evidence"
    blockchain_mainnet_activation_refresh_evidence_command="./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json --reports-dir .easy-node-logs/blockchain_mainnet_activation_real_evidence_run --summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_summary.json --refresh-roadmap 1 --print-summary-json 1"
    if [[ "$blockchain_mainnet_activation_gate_summary_stale_json" == "true" ]]; then
      blockchain_mainnet_activation_refresh_evidence_reason="stale activation evidence (age=${blockchain_mainnet_activation_gate_summary_age_sec_json:-null}s, max_age=${blockchain_mainnet_activation_gate_summary_max_age_sec_json}s); operator action required: refresh real evidence before trusting the GO signal"
    else
      blockchain_mainnet_activation_refresh_evidence_reason="activation evidence freshness is unknown; operator action required: refresh real evidence before trusting the GO signal"
    fi
  fi
fi

blockchain_mainnet_activation_missing_metrics_action_available_json="false"
blockchain_mainnet_activation_missing_metrics_action_id=""
blockchain_mainnet_activation_missing_metrics_action_reason=""
blockchain_mainnet_activation_missing_metrics_action_normalize_command=""
blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command=""
blockchain_mainnet_activation_missing_metrics_action_checklist_command=""
  blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command=""
  blockchain_mainnet_activation_missing_metrics_action_template_command=""
  blockchain_mainnet_activation_missing_metrics_action_prefill_command=""
  blockchain_mainnet_activation_missing_metrics_action_operator_pack_command=""
  blockchain_mainnet_activation_missing_metrics_action_cycle_command=""
  blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command=""
blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command=""
blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json="$ROOT_DIR/.easy-node-logs/blockchain_gate_bundle_summary.json"
  blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command=".easy-node-logs/blockchain_gate_bundle_summary.json"
  blockchain_mainnet_activation_missing_metrics_action_operator_input_json_for_command=".easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json"
  blockchain_mainnet_activation_missing_metrics_action_template_output_json_for_command=".easy-node-logs/blockchain_mainnet_activation_metrics_input.template.json"
  blockchain_mainnet_activation_missing_metrics_action_prefill_output_json_for_command=".easy-node-logs/blockchain_mainnet_activation_metrics_prefill.json"
if [[ -n "${blockchain_mainnet_activation_gate_source_summary_json:-}" ]]; then
  blockchain_mainnet_activation_missing_metrics_action_metrics_summary_candidate_json="$(dirname "$blockchain_mainnet_activation_gate_source_summary_json")/blockchain_mainnet_activation_metrics_summary.json"
  if [[ "$(json_file_valid_01 "$blockchain_mainnet_activation_missing_metrics_action_metrics_summary_candidate_json")" == "1" ]]; then
    blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json="$blockchain_mainnet_activation_missing_metrics_action_metrics_summary_candidate_json"
    if [[ "$blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json" == "$ROOT_DIR/"* ]]; then
      blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command="${blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json#$ROOT_DIR/}"
    else
      blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command="$blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json"
    fi
  fi
fi
blockchain_mainnet_activation_missing_metrics_reasons_match_json="$(
  jq -r '
    if any(.[]?; ((. | tostring | ascii_downcase) | test("missing or invalid metric|missing required metrics|missing metrics|invalid metrics|required_metrics|metrics_json"))) then
      "true"
    else
      "false"
    end
  ' <<<"$blockchain_mainnet_activation_gate_reasons_json" 2>/dev/null || echo "false"
)"
if [[ "$blockchain_mainnet_activation_gate_source_summary_kind" != "" ]] \
  && [[ "$blockchain_mainnet_activation_gate_source_summary_kind" != "phase7-mainnet-cutover-signal" ]] \
  && [[ "$blockchain_mainnet_activation_gate_available_json" == "true" ]] \
  && [[ "$blockchain_mainnet_activation_gate_no_go_json" == "true" || "$blockchain_mainnet_activation_gate_decision_json" == "NO-GO" ]] \
  && [[ "$blockchain_mainnet_activation_missing_metrics_reasons_match_json" == "true" ]]; then
  blockchain_mainnet_activation_missing_metrics_action_available_json="true"
  blockchain_mainnet_activation_missing_metrics_action_id="blockchain_mainnet_activation_missing_metrics"
  blockchain_mainnet_activation_missing_metrics_action_reason="mainnet activation gate is NO-GO because required metrics evidence is missing/invalid; normalize operator metrics input and rerun gate bundle."
  blockchain_mainnet_activation_missing_metrics_action_normalize_command="./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input --input-json $blockchain_mainnet_activation_missing_metrics_action_operator_input_json_for_command --summary-json .easy-node-logs/blockchain_mainnet_activation_metrics_input_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.json --print-summary-json 1"
  blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command="./scripts/easy_node.sh blockchain-gate-bundle --blockchain-mainnet-activation-metrics-input-json $blockchain_mainnet_activation_missing_metrics_action_operator_input_json_for_command --summary-json .easy-node-logs/blockchain_gate_bundle_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json --print-summary-json 1"
  blockchain_mainnet_activation_missing_metrics_action_checklist_command="./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-checklist --metrics-summary-json $blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command --output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_checklist.json --output-md .easy-node-logs/blockchain_mainnet_activation_metrics_missing_checklist.md --print-summary-json 1"
    blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command="./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-input-template --metrics-summary-json $blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command --output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json --canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.canonical.json --print-summary-json 1"
    blockchain_mainnet_activation_missing_metrics_action_template_command="./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input-template --output-json $blockchain_mainnet_activation_missing_metrics_action_template_output_json_for_command --canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_input_template.json --print-summary-json 1"
    blockchain_mainnet_activation_missing_metrics_action_prefill_command="./scripts/easy_node.sh blockchain-mainnet-activation-metrics-prefill --metrics-summary-json $blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command --output-json $blockchain_mainnet_activation_missing_metrics_action_prefill_output_json_for_command --canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_prefill.json --print-summary-json 1"
    blockchain_mainnet_activation_missing_metrics_action_operator_pack_command="./scripts/easy_node.sh blockchain-mainnet-activation-operator-pack --metrics-summary-json $blockchain_mainnet_activation_missing_metrics_action_metrics_summary_json_for_command --reports-dir .easy-node-logs/blockchain_mainnet_activation_operator_pack --summary-json .easy-node-logs/blockchain_mainnet_activation_operator_pack_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_operator_pack_summary.json --template-output-json $blockchain_mainnet_activation_missing_metrics_action_template_output_json_for_command --template-canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_input_template.json --missing-input-template-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json --missing-input-template-canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.canonical.json --checklist-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_checklist.json --checklist-output-md .easy-node-logs/blockchain_mainnet_activation_metrics_missing_checklist.md --print-summary-json 1"
  blockchain_mainnet_activation_missing_metrics_action_cycle_command="./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle --input-json $blockchain_mainnet_activation_missing_metrics_action_operator_input_json_for_command --reports-dir .easy-node-logs/blockchain_mainnet_activation_gate_cycle --summary-json .easy-node-logs/blockchain_mainnet_activation_gate_cycle_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_gate_cycle_summary.json --refresh-roadmap 1 --print-summary-json 1"
  blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command="./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle-seeded --reports-dir .easy-node-logs/blockchain_mainnet_activation_gate_cycle_seeded --summary-json .easy-node-logs/blockchain_mainnet_activation_gate_cycle_seeded_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_gate_cycle_seeded_summary.json --refresh-roadmap 1 --print-summary-json 1"
  blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command="./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run --input-json $blockchain_mainnet_activation_missing_metrics_action_operator_input_json_for_command --reports-dir .easy-node-logs/blockchain_mainnet_activation_real_evidence_run --summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_summary.json --refresh-roadmap 1 --print-summary-json 1"
fi

# Keep missing-metrics action fail-closed and internally consistent: when the
# action is marked available, every action field must be populated.
if [[ "$blockchain_mainnet_activation_missing_metrics_action_available_json" == "true" ]]; then
  if [[ -z "$blockchain_mainnet_activation_missing_metrics_action_id" \
     || -z "$blockchain_mainnet_activation_missing_metrics_action_reason" \
     || -z "$blockchain_mainnet_activation_missing_metrics_action_normalize_command" \
     || -z "$blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command" \
     || -z "$blockchain_mainnet_activation_missing_metrics_action_checklist_command" \
       || -z "$blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command" \
       || -z "$blockchain_mainnet_activation_missing_metrics_action_template_command" \
       || -z "$blockchain_mainnet_activation_missing_metrics_action_prefill_command" \
       || -z "$blockchain_mainnet_activation_missing_metrics_action_operator_pack_command" \
       || -z "$blockchain_mainnet_activation_missing_metrics_action_cycle_command" \
       || -z "$blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command" \
     || -z "$blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command" ]]; then
    blockchain_mainnet_activation_missing_metrics_action_available_json="false"
    blockchain_mainnet_activation_missing_metrics_action_id=""
    blockchain_mainnet_activation_missing_metrics_action_reason=""
    blockchain_mainnet_activation_missing_metrics_action_normalize_command=""
    blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command=""
    blockchain_mainnet_activation_missing_metrics_action_checklist_command=""
      blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command=""
      blockchain_mainnet_activation_missing_metrics_action_template_command=""
      blockchain_mainnet_activation_missing_metrics_action_prefill_command=""
      blockchain_mainnet_activation_missing_metrics_action_operator_pack_command=""
      blockchain_mainnet_activation_missing_metrics_action_cycle_command=""
      blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command=""
    blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command=""
  fi
fi

blockchain_mainnet_activation_stale_evidence_status_json="unknown"
case "$blockchain_mainnet_activation_gate_summary_stale_json" in
  true)
    blockchain_mainnet_activation_stale_evidence_status_json="stale"
    ;;
  false)
    blockchain_mainnet_activation_stale_evidence_status_json="fresh"
    ;;
esac

blockchain_mainnet_activation_stale_evidence_action_required_json="false"
blockchain_mainnet_activation_stale_evidence_reason_json=""
blockchain_mainnet_activation_stale_evidence_refresh_command_json=""
if [[ "$blockchain_mainnet_activation_refresh_evidence_available_json" == "true" ]] \
  && [[ -n "$blockchain_mainnet_activation_refresh_evidence_id_json" ]]; then
  blockchain_mainnet_activation_stale_evidence_action_required_json="true"
  blockchain_mainnet_activation_stale_evidence_reason_json="$blockchain_mainnet_activation_refresh_evidence_reason"
  blockchain_mainnet_activation_stale_evidence_refresh_command_json="$blockchain_mainnet_activation_refresh_evidence_command"
fi

blockchain_recommended_gate_id=""
blockchain_recommended_gate_reason=""
blockchain_recommended_gate_command=""
if [[ "$blockchain_mainnet_activation_missing_metrics_action_available_json" == "true" ]] \
  && [[ -n "$blockchain_mainnet_activation_missing_metrics_action_id" ]]; then
  blockchain_recommended_gate_id="$blockchain_mainnet_activation_missing_metrics_action_id"
  blockchain_recommended_gate_reason="$blockchain_mainnet_activation_missing_metrics_action_reason"
  if [[ -n "$blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command" ]]; then
    blockchain_recommended_gate_command="$blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command"
  else
    blockchain_recommended_gate_command="$blockchain_mainnet_activation_missing_metrics_action_operator_pack_command"
  fi
elif [[ "$blockchain_mainnet_activation_stale_evidence_action_required_json" == "true" ]]; then
  blockchain_recommended_gate_id="$blockchain_mainnet_activation_refresh_evidence_id_json"
  blockchain_recommended_gate_reason="$blockchain_mainnet_activation_stale_evidence_reason_json"
  blockchain_recommended_gate_command="$blockchain_mainnet_activation_stale_evidence_refresh_command_json"
  if [[ -z "$blockchain_mainnet_activation_missing_metrics_action_id" ]]; then
    # Compatibility shim: existing blockchain actionable runners read this field
    # for recommended-only mode. Keep missing_metrics.available=false and expose
    # stale refresh action id here when stale evidence is the blocker.
    blockchain_mainnet_activation_missing_metrics_action_id="$blockchain_recommended_gate_id"
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

# Phase-level VPN RC completion is driven by resilience criteria, not by whether
# real-host signoff checks are still pending.
vpn_rc_profile_matrix_stable_effective_json="$resilience_profile_matrix_stable_json"
if [[ "$vpn_rc_profile_matrix_stable_effective_json" == "null" && "$phase1_resilience_handoff_profile_matrix_stable_json" != "null" ]]; then
  vpn_rc_profile_matrix_stable_effective_json="$phase1_resilience_handoff_profile_matrix_stable_json"
fi
vpn_rc_peer_loss_recovery_ok_effective_json="$resilience_peer_loss_recovery_ok_json"
if [[ "$vpn_rc_peer_loss_recovery_ok_effective_json" == "null" && "$phase1_resilience_handoff_peer_loss_recovery_ok_json" != "null" ]]; then
  vpn_rc_peer_loss_recovery_ok_effective_json="$phase1_resilience_handoff_peer_loss_recovery_ok_json"
fi
vpn_rc_session_churn_guard_ok_effective_json="$resilience_session_churn_guard_ok_json"
if [[ "$vpn_rc_session_churn_guard_ok_effective_json" == "null" && "$phase1_resilience_handoff_session_churn_guard_ok_json" != "null" ]]; then
  vpn_rc_session_churn_guard_ok_effective_json="$phase1_resilience_handoff_session_churn_guard_ok_json"
fi
vpn_rc_resilience_signals_complete_json="false"
if [[ "$vpn_rc_profile_matrix_stable_effective_json" != "null" \
   && "$vpn_rc_peer_loss_recovery_ok_effective_json" != "null" \
   && "$vpn_rc_session_churn_guard_ok_effective_json" != "null" ]]; then
  vpn_rc_resilience_signals_complete_json="true"
fi
vpn_rc_resilience_criteria_satisfied_json="false"
if [[ "$vpn_rc_resilience_signals_complete_json" == "true" \
   && "$vpn_rc_profile_matrix_stable_effective_json" == "true" \
   && "$vpn_rc_peer_loss_recovery_ok_effective_json" == "true" \
   && "$vpn_rc_session_churn_guard_ok_effective_json" == "true" ]]; then
  vpn_rc_resilience_criteria_satisfied_json="true"
fi
vpn_rc_done_for_phase="$vpn_rc_resilience_criteria_satisfied_json"
if [[ "$vpn_rc_done_for_phase" == "true" \
   && "$resilience_handoff_available_json" != "true" \
   && "$phase1_resilience_handoff_available_json" == "true" \
   && "$phase1_resilience_handoff_status_json" != "pass" ]]; then
  # Fail-closed when we relied on phase1 fallback signals but the phase1 handoff
  # itself is not passing.
  vpn_rc_done_for_phase="false"
fi

profile_default_gate_status_manual_raw="$(jq -r '
  if (.summary.profile_default_gate.status | type) == "string" then .summary.profile_default_gate.status
  else ""
  end
' "$manual_validation_summary_json")"
profile_default_gate_status_manual_present="0"
case "$profile_default_gate_status_manual_raw" in
  pass|warn|fail|pending|skip)
    profile_default_gate_status="$profile_default_gate_status_manual_raw"
    profile_default_gate_status_manual_present="1"
    ;;
  *)
    profile_default_gate_status="pending"
    ;;
esac
profile_default_gate_next_command="$(jq -r '
  .summary.profile_default_gate.next_command
  // .summary.profile_default_gate.command
  // .summary.profile_default_gate.next_command_sudo
  // ""
' "$manual_validation_summary_json")"
profile_default_gate_next_command_sudo="$(jq -r '
  (
    .summary.profile_default_gate.next_command_sudo
    // (
      (.summary.profile_default_gate.next_command // .summary.profile_default_gate.command // "") as $cmd
      | if ($cmd | startswith("sudo ")) then $cmd else "" end
    )
    // ""
  )
' "$manual_validation_summary_json")"
profile_default_gate_next_command_source="$(jq -r '.summary.profile_default_gate.next_command_source // ""' "$manual_validation_summary_json")"
profile_default_gate_notes="$(jq -r '.summary.profile_default_gate.notes // ""' "$manual_validation_summary_json")"
profile_default_gate_decision="$(jq -r '.summary.profile_default_gate.decision // ""' "$manual_validation_summary_json")"
profile_default_gate_recommended_profile="$(jq -r '.summary.profile_default_gate.recommended_profile // ""' "$manual_validation_summary_json")"
profile_default_gate_summary_json_manual="$(jq -r '.summary.profile_default_gate.summary_json // ""' "$manual_validation_summary_json")"
profile_default_gate_docker_hint_available_json="$(jq -r '.summary.profile_default_gate.docker_rehearsal_hint_available // false' "$manual_validation_summary_json")"
profile_default_gate_docker_hint_source="$(jq -r '.summary.profile_default_gate.docker_rehearsal_hint_source // ""' "$manual_validation_summary_json")"
profile_default_gate_campaign_check_summary_json_resolved="$(jq -r '.summary.profile_default_gate.artifacts.campaign_check_summary_json_resolved // ""' "$manual_validation_summary_json")"
profile_default_gate_docker_matrix_summary_json="$(jq -r '.summary.profile_default_gate.artifacts.docker_rehearsal_matrix_summary_json // ""' "$manual_validation_summary_json")"
profile_default_gate_docker_profile_summary_json="$(jq -r '.summary.profile_default_gate.artifacts.docker_rehearsal_profile_summary_json // ""' "$manual_validation_summary_json")"
profile_default_gate_stability_summary_json="$(
  resolve_profile_default_gate_stability_summary_path "$manual_validation_summary_json" "$default_log_dir"
)"
profile_default_gate_stability_summary_available_json="false"
profile_default_gate_stability_status_json=""
profile_default_gate_stability_rc_json="null"
profile_default_gate_stability_runs_requested_json="null"
profile_default_gate_stability_runs_completed_json="null"
profile_default_gate_stability_selection_policy_present_all_json="null"
profile_default_gate_stability_consistent_selection_policy_json="null"
profile_default_gate_stability_ok_json="null"
profile_default_gate_stability_recommended_profile_counts_json="null"
if [[ -n "$profile_default_gate_stability_summary_json" ]] \
   && [[ "$(profile_default_gate_stability_summary_usable_01 "$profile_default_gate_stability_summary_json")" == "1" ]]; then
  profile_default_gate_stability_summary_available_json="true"
  profile_default_gate_stability_status_json="$(jq -r '
    if (.status | type) == "string" then .status else "" end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc else "null" end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_runs_requested_json="$(jq -r '
    if (.runs_requested | type) == "number" then .runs_requested
    elif (.inputs.runs_requested | type) == "number" then .inputs.runs_requested
    else "null"
    end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_runs_completed_json="$(jq -r '
    if (.runs_completed | type) == "number" then .runs_completed else "null" end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_selection_policy_present_all_json="$(jq -r '
    if (.selection_policy_present_all | type) == "boolean" then (.selection_policy_present_all | tostring)
    else "null"
    end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_consistent_selection_policy_json="$(jq -r '
    if (.consistent_selection_policy | type) == "boolean" then (.consistent_selection_policy | tostring)
    else "null"
    end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_ok_json="$(jq -r '
    if (.stability_ok | type) == "boolean" then (.stability_ok | tostring)
    else "null"
    end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_recommended_profile_counts_json="$(jq -c '
    if (.recommended_profile_counts | type) == "object" then .recommended_profile_counts
    else null
    end
  ' "$profile_default_gate_stability_summary_json" 2>/dev/null || printf '%s' "null")"
fi
profile_default_gate_stability_check_summary_json="$(
  resolve_profile_default_gate_stability_check_summary_path "$manual_validation_summary_json" "$default_log_dir"
)"
profile_default_gate_stability_check_summary_available_json="false"
profile_default_gate_stability_check_decision_json=""
profile_default_gate_stability_check_status_json=""
profile_default_gate_stability_check_rc_json="null"
profile_default_gate_stability_check_modal_recommended_profile_json=""
profile_default_gate_stability_check_modal_support_rate_pct_json="null"
if [[ -n "$profile_default_gate_stability_check_summary_json" ]] \
   && [[ "$(profile_default_gate_stability_check_summary_usable_01 "$profile_default_gate_stability_check_summary_json")" == "1" ]]; then
  profile_default_gate_stability_check_summary_available_json="true"
  profile_default_gate_stability_check_decision_json="$(jq -r '
    if (.decision | type) == "string" then .decision else "" end
  ' "$profile_default_gate_stability_check_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_check_status_json="$(jq -r '
    if (.status | type) == "string" then .status else "" end
  ' "$profile_default_gate_stability_check_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_check_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc else "null" end
  ' "$profile_default_gate_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_check_modal_recommended_profile_json="$(jq -r '
    if (.observed.modal_recommended_profile | type) == "string" then .observed.modal_recommended_profile
    else ""
    end
  ' "$profile_default_gate_stability_check_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_check_modal_support_rate_pct_json="$(jq -r '
    if (.observed.modal_support_rate_pct | type) == "number" then .observed.modal_support_rate_pct
    else "null"
    end
  ' "$profile_default_gate_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
fi
profile_default_gate_stability_cycle_summary_json="$(
  resolve_profile_default_gate_stability_cycle_summary_path "$manual_validation_summary_json" "$default_log_dir"
)"
profile_default_gate_stability_cycle_summary_available_json="false"
profile_default_gate_stability_cycle_decision_json=""
profile_default_gate_stability_cycle_status_json=""
profile_default_gate_stability_cycle_rc_json="null"
profile_default_gate_stability_cycle_failure_stage_json=""
profile_default_gate_stability_cycle_failure_reason_json=""
if [[ -n "$profile_default_gate_stability_cycle_summary_json" ]] \
   && [[ "$(profile_default_gate_stability_cycle_summary_usable_01 "$profile_default_gate_stability_cycle_summary_json")" == "1" ]]; then
  profile_default_gate_stability_cycle_summary_available_json="true"
  profile_default_gate_stability_cycle_decision_json="$(jq -r '
    if (.decision | type) == "string" then .decision else "" end
  ' "$profile_default_gate_stability_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_cycle_status_json="$(jq -r '
    if (.status | type) == "string" then .status else "" end
  ' "$profile_default_gate_stability_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_cycle_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc else "null" end
  ' "$profile_default_gate_stability_cycle_summary_json" 2>/dev/null || printf '%s' "null")"
  profile_default_gate_stability_cycle_failure_stage_json="$(jq -r '
    if (.failure_stage | type) == "string" then .failure_stage else "" end
  ' "$profile_default_gate_stability_cycle_summary_json" 2>/dev/null || printf '%s' "")"
  profile_default_gate_stability_cycle_failure_reason_json="$(jq -r '
    if (.failure_reason | type) == "string" then .failure_reason else "" end
  ' "$profile_default_gate_stability_cycle_summary_json" 2>/dev/null || printf '%s' "")"
fi
if [[ -z "$profile_compare_multi_vm_stability_check_summary_json" ]]; then
  profile_compare_multi_vm_stability_check_summary_json="$(
    resolve_profile_compare_multi_vm_stability_check_summary_path "$manual_validation_summary_json" "$default_log_dir"
  )"
fi
multi_vm_stability_available_json="false"
multi_vm_stability_input_summary_json="$profile_compare_multi_vm_stability_check_summary_json"
multi_vm_stability_source_summary_json=""
multi_vm_stability_source_summary_kind=""
multi_vm_stability_status_json="missing"
multi_vm_stability_rc_json="null"
multi_vm_stability_decision_json=""
multi_vm_stability_go_json="null"
multi_vm_stability_no_go_json="null"
multi_vm_stability_recommended_profile_json=""
multi_vm_stability_support_rate_pct_json="null"
multi_vm_stability_runs_requested_json="null"
multi_vm_stability_runs_completed_json="null"
multi_vm_stability_runs_fail_json="null"
multi_vm_stability_decision_counts_json="null"
multi_vm_stability_recommended_profile_counts_json="null"
multi_vm_stability_reasons_json='[]'
multi_vm_stability_notes_json=""
multi_vm_stability_needs_attention_json="true"
multi_vm_stability_next_command="$(jq -r '
  .summary.profile_compare_multi_vm_stability.next_command
  // .summary.profile_compare_multi_vm_stability.command
  // .summary.profile_compare_multi_vm_stability_check.next_command
  // ""
' "$manual_validation_summary_json" 2>/dev/null || true)"
if [[ -z "$multi_vm_stability_next_command" ]]; then
  multi_vm_stability_next_command="./scripts/easy_node.sh profile-compare-multi-vm-stability-cycle --reports-dir .easy-node-logs --fail-on-no-go 1 --summary-json .easy-node-logs/profile_compare_multi_vm_stability_cycle_summary.json --print-summary-json 1"
fi
multi_vm_stability_next_command_reason="multi-VM stability evidence is missing; run stability cycle to refresh and publish evidence"
if [[ -n "$profile_compare_multi_vm_stability_check_summary_json" ]] \
   && [[ "$(profile_compare_multi_vm_stability_check_summary_usable_01 "$profile_compare_multi_vm_stability_check_summary_json")" == "1" ]]; then
  multi_vm_stability_available_json="true"
  multi_vm_stability_source_summary_json="$profile_compare_multi_vm_stability_check_summary_json"
  multi_vm_stability_source_summary_kind="$(profile_compare_multi_vm_stability_summary_kind_from_path "$profile_compare_multi_vm_stability_check_summary_json")"
  multi_vm_stability_status_json="$(jq -r '
    if (.status | type) == "string" then .status else "unknown" end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "unknown")"
  multi_vm_stability_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc else "null" end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_decision_json="$(jq -r '
    if (.decision | type) == "string" then .decision else "" end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_go_json="$(jq -r '
    if (.go | type) == "boolean" then (.go | tostring)
    elif (.decision | type) == "string" then
      ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
      | if $d == "GO" then "true"
        elif $d == "NOGO" then "false"
        else "null"
        end)
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_no_go_json="$(jq -r '
    if (.no_go | type) == "boolean" then (.no_go | tostring)
    elif (.decision | type) == "string" then
      ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
      | if $d == "NOGO" then "true"
        elif $d == "GO" then "false"
        else "null"
        end)
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_recommended_profile_json="$(jq -r '
    if (.observed.modal_recommended_profile | type) == "string" then .observed.modal_recommended_profile
    else ""
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_support_rate_pct_json="$(jq -r '
    if (.observed.modal_support_rate_pct | type) == "number" then .observed.modal_support_rate_pct
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_runs_requested_json="$(jq -r '
    if (.observed.runs_requested | type) == "number" then .observed.runs_requested
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_runs_completed_json="$(jq -r '
    if (.observed.runs_completed | type) == "number" then .observed.runs_completed
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_runs_fail_json="$(jq -r '
    if (.observed.runs_fail | type) == "number" then .observed.runs_fail
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_decision_counts_json="$(jq -c '
    if (.observed.decision_counts | type) == "object" then .observed.decision_counts
    else null
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_recommended_profile_counts_json="$(jq -c '
    if (.observed.recommended_profile_counts | type) == "object" then .observed.recommended_profile_counts
    else null
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_reasons_json="$(jq -c '
    if (.errors | type) == "array" then [.errors[] | strings]
    else []
    end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' '[]')"
  multi_vm_stability_notes_json="$(jq -r '
    if (.notes | type) == "string" then .notes else "" end
  ' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || printf '%s' "")"

  if [[ "$multi_vm_stability_go_json" == "true" ]] \
     && [[ "$multi_vm_stability_status_json" == "ok" || "$multi_vm_stability_status_json" == "pass" ]]; then
    multi_vm_stability_needs_attention_json="false"
    multi_vm_stability_next_command=""
    multi_vm_stability_next_command_reason=""
  else
    multi_vm_stability_needs_attention_json="true"
    first_reason="$(jq -r 'if (.errors | type) == "array" and (.errors | length) > 0 then (.errors[0] // "") else "" end' "$profile_compare_multi_vm_stability_check_summary_json" 2>/dev/null || true)"
    if [[ -n "$first_reason" ]]; then
      multi_vm_stability_next_command_reason="$first_reason"
    elif [[ -n "$multi_vm_stability_notes_json" ]]; then
      multi_vm_stability_next_command_reason="$multi_vm_stability_notes_json"
    else
      multi_vm_stability_next_command_reason="multi-VM stability evidence requires refresh; rerun stability cycle and review check summary"
    fi
  fi
fi
if [[ -z "$profile_compare_multi_vm_stability_promotion_summary_json" ]]; then
  profile_compare_multi_vm_stability_promotion_summary_json="$(
    resolve_profile_compare_multi_vm_stability_promotion_summary_path "$manual_validation_summary_json" "$default_log_dir"
  )"
fi
multi_vm_stability_promotion_available_json="false"
multi_vm_stability_promotion_input_summary_json="$profile_compare_multi_vm_stability_promotion_summary_json"
multi_vm_stability_promotion_source_summary_json=""
multi_vm_stability_promotion_status_json="missing"
multi_vm_stability_promotion_rc_json="null"
multi_vm_stability_promotion_decision_json=""
multi_vm_stability_promotion_go_json="null"
multi_vm_stability_promotion_no_go_json="null"
multi_vm_stability_promotion_reasons_json='[]'
multi_vm_stability_promotion_notes_json=""
multi_vm_stability_promotion_needs_attention_json="true"
multi_vm_stability_promotion_next_command="./scripts/easy_node.sh profile-compare-multi-vm-stability-promotion-cycle --reports-dir .easy-node-logs --fail-on-no-go 1 --summary-json .easy-node-logs/profile_compare_multi_vm_stability_promotion_cycle_summary.json --print-summary-json 1"
multi_vm_stability_promotion_next_command_reason="multi-VM stability promotion evidence is missing; run promotion cycle to produce fail-closed GO/NO-GO evidence"
if [[ -n "$profile_compare_multi_vm_stability_promotion_summary_json" ]] \
   && [[ "$(profile_compare_multi_vm_stability_promotion_summary_usable_01 "$profile_compare_multi_vm_stability_promotion_summary_json")" == "1" ]]; then
  multi_vm_stability_promotion_available_json="true"
  multi_vm_stability_promotion_source_summary_json="$profile_compare_multi_vm_stability_promotion_summary_json"
  multi_vm_stability_promotion_status_json="$(jq -r '
    if (.status | type) == "string" then .status
    elif (.promotion.status | type) == "string" then .promotion.status
    else "unknown"
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "unknown")"
  multi_vm_stability_promotion_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc
    elif (.promotion.rc | type) == "number" then .promotion.rc
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_promotion_decision_json="$(jq -r '
    if (.decision | type) == "string" then .decision
    elif (.promotion.decision | type) == "string" then .promotion.decision
    else ""
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_promotion_go_json="$(jq -r '
    if (.go | type) == "boolean" then (.go | tostring)
    elif (.decision | type) == "string" then
      ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
      | if $d == "GO" then "true"
        elif $d == "NOGO" then "false"
        else "null"
        end)
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_promotion_no_go_json="$(jq -r '
    if (.no_go | type) == "boolean" then (.no_go | tostring)
    elif (.decision | type) == "string" then
      ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
      | if $d == "NOGO" then "true"
        elif $d == "GO" then "false"
        else "null"
        end)
    else "null"
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_promotion_reasons_json="$(jq -c '
    if (.reasons | type) == "array" then
      [.reasons[] | strings]
    elif (.errors | type) == "array" then
      [.errors[] | strings]
    else
      [
        (.failure_reason // empty),
        (.next_operator_action // empty),
        (.promotion.operator_next_action // empty)
      ]
      | map(select((. | type) == "string" and (. | length > 0)))
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' '[]')"
  multi_vm_stability_promotion_notes_json="$(jq -r '
    if (.notes | type) == "string" then .notes
    elif (.next_operator_action | type) == "string" then .next_operator_action
    elif (.promotion.operator_next_action | type) == "string" then .promotion.operator_next_action
    else ""
    end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_promotion_status_norm="$(printf '%s' "${multi_vm_stability_promotion_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  multi_vm_stability_promotion_decision_norm_token="$(printf '%s' "${multi_vm_stability_promotion_decision_json:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]_-')"
  multi_vm_stability_promotion_decision_norm=""
  case "$multi_vm_stability_promotion_decision_norm_token" in
    GO) multi_vm_stability_promotion_decision_norm="GO" ;;
    NOGO) multi_vm_stability_promotion_decision_norm="NO-GO" ;;
    *) multi_vm_stability_promotion_decision_norm="" ;;
  esac
  multi_vm_stability_promotion_schema_id_json="$(jq -r '
    if (.schema.id | type) == "string" then .schema.id else "" end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_promotion_nested_status_json="$(jq -r '
    if (.promotion.status | type) == "string" then .promotion.status else "" end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_promotion_nested_status_norm="$(printf '%s' "${multi_vm_stability_promotion_nested_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  multi_vm_stability_promotion_nested_decision_json="$(jq -r '
    if (.promotion.decision | type) == "string" then .promotion.decision else "" end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  multi_vm_stability_promotion_nested_decision_norm_token="$(printf '%s' "${multi_vm_stability_promotion_nested_decision_json:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]_-')"
  multi_vm_stability_promotion_nested_decision_norm=""
  case "$multi_vm_stability_promotion_nested_decision_norm_token" in
    GO) multi_vm_stability_promotion_nested_decision_norm="GO" ;;
    NOGO) multi_vm_stability_promotion_nested_decision_norm="NO-GO" ;;
    *) multi_vm_stability_promotion_nested_decision_norm="" ;;
  esac
  multi_vm_stability_promotion_nested_rc_json="$(jq -r '
    if (.promotion.rc | type) == "number" then .promotion.rc else "null" end
  ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  multi_vm_stability_promotion_consistency_errors_json='[]'
  multi_vm_stability_promotion_consistency_ok_01="1"
  declare -a multi_vm_stability_promotion_consistency_errors=()
  if [[ "$multi_vm_stability_promotion_go_json" == "true" && "$multi_vm_stability_promotion_rc_json" != "0" ]]; then
    multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: go=true with rc!=0")
  fi
  if [[ "$multi_vm_stability_promotion_go_json" == "true" && "$multi_vm_stability_promotion_no_go_json" == "true" ]]; then
    multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: go=true and no_go=true")
  fi
  if [[ "$multi_vm_stability_promotion_go_json" == "true" && "$multi_vm_stability_promotion_decision_norm" == "NO-GO" ]]; then
    multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: go=true but decision=NO-GO")
  fi
  if [[ "$multi_vm_stability_promotion_no_go_json" == "true" && "$multi_vm_stability_promotion_decision_norm" == "GO" ]]; then
    multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: no_go=true but decision=GO")
  fi
  if [[ "$multi_vm_stability_promotion_decision_norm" == "GO" && "$multi_vm_stability_promotion_go_json" == "false" ]]; then
    multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: decision=GO but go=false")
  fi
  if [[ "$multi_vm_stability_promotion_status_norm" == "ok" || "$multi_vm_stability_promotion_status_norm" == "pass" ]]; then
    if [[ "$multi_vm_stability_promotion_go_json" != "true" ]]; then
      multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: status pass/ok without go=true")
    fi
    if [[ "$multi_vm_stability_promotion_rc_json" != "0" ]]; then
      multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: status pass/ok with rc!=0")
    fi
  fi
  if [[ "$multi_vm_stability_promotion_schema_id_json" == "profile_compare_multi_vm_stability_promotion_cycle_summary" ]]; then
    if [[ -n "$multi_vm_stability_promotion_nested_status_norm" && -n "$multi_vm_stability_promotion_status_norm" ]] \
       && [[ "$multi_vm_stability_promotion_nested_status_norm" != "$multi_vm_stability_promotion_status_norm" ]]; then
      multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: cycle top-level status disagrees with promotion.status")
    fi
    if [[ -n "$multi_vm_stability_promotion_nested_decision_norm" && -n "$multi_vm_stability_promotion_decision_norm" ]] \
       && [[ "$multi_vm_stability_promotion_nested_decision_norm" != "$multi_vm_stability_promotion_decision_norm" ]]; then
      multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: cycle top-level decision disagrees with promotion.decision")
    fi
    if [[ "$multi_vm_stability_promotion_nested_rc_json" != "null" && "$multi_vm_stability_promotion_rc_json" != "null" ]] \
       && [[ "$multi_vm_stability_promotion_nested_rc_json" != "$multi_vm_stability_promotion_rc_json" ]]; then
      multi_vm_stability_promotion_consistency_errors+=("multi-VM stability promotion summary is inconsistent: cycle top-level rc disagrees with promotion.rc")
    fi
  fi
  if ((${#multi_vm_stability_promotion_consistency_errors[@]} > 0)); then
    multi_vm_stability_promotion_consistency_ok_01="0"
    multi_vm_stability_promotion_consistency_errors_json="$(printf '%s\n' "${multi_vm_stability_promotion_consistency_errors[@]}" | jq -R . | jq -s 'map(select(length > 0))')"
    multi_vm_stability_promotion_reasons_json="$(jq -c \
      --argjson reasons "$multi_vm_stability_promotion_reasons_json" \
      --argjson consistency_errors "$multi_vm_stability_promotion_consistency_errors_json" \
      '($reasons + $consistency_errors) | map(select((type == "string") and (length > 0))) | unique' \
      <<<"{}" 2>/dev/null || printf '%s' "$multi_vm_stability_promotion_reasons_json")"
    multi_vm_stability_promotion_status_json="fail"
  fi

  if [[ "$multi_vm_stability_promotion_go_json" == "true" ]] \
     && [[ "$multi_vm_stability_promotion_status_norm" == "ok" || "$multi_vm_stability_promotion_status_norm" == "pass" ]] \
     && [[ "$multi_vm_stability_promotion_rc_json" == "0" ]] \
     && [[ "$multi_vm_stability_promotion_no_go_json" != "true" ]] \
     && [[ "$multi_vm_stability_promotion_consistency_ok_01" == "1" ]]; then
    multi_vm_stability_promotion_needs_attention_json="false"
    multi_vm_stability_promotion_next_command=""
    multi_vm_stability_promotion_next_command_reason=""
  else
    multi_vm_stability_promotion_needs_attention_json="true"
    if [[ "$multi_vm_stability_promotion_consistency_ok_01" == "0" ]]; then
      first_reason="$(jq -r 'if (. | type) == "array" and (. | length) > 0 then (.[0] // "") else "" end' <<<"$multi_vm_stability_promotion_consistency_errors_json" 2>/dev/null || true)"
    else
      first_reason="$(jq -r '
        if (.reasons | type) == "array" and (.reasons | length) > 0 then
          (.reasons[0] // "")
        elif (.errors | type) == "array" and (.errors | length) > 0 then
          (.errors[0] // "")
        elif (.failure_reason | type) == "string" then
          .failure_reason
        elif (.next_operator_action | type) == "string" then
          .next_operator_action
        elif (.promotion.operator_next_action | type) == "string" then
          .promotion.operator_next_action
        else
          ""
        end
      ' "$profile_compare_multi_vm_stability_promotion_summary_json" 2>/dev/null || true)"
    fi
    if [[ -n "$first_reason" ]]; then
      multi_vm_stability_promotion_next_command_reason="$first_reason"
    elif [[ -n "$multi_vm_stability_promotion_notes_json" ]]; then
      multi_vm_stability_promotion_next_command_reason="$multi_vm_stability_promotion_notes_json"
    else
      multi_vm_stability_promotion_next_command_reason="multi-VM stability promotion is pending or NO-GO; rerun promotion cycle after fresh cycle evidence"
    fi
  fi
fi
if [[ -z "$runtime_actuation_promotion_summary_json" ]]; then
  runtime_actuation_promotion_summary_json="$(
    resolve_runtime_actuation_promotion_summary_path "$manual_validation_summary_json" "$default_log_dir"
  )"
fi
runtime_actuation_promotion_available_json="false"
runtime_actuation_promotion_input_summary_json="$runtime_actuation_promotion_summary_json"
runtime_actuation_promotion_source_summary_json=""
runtime_actuation_promotion_status_json="missing"
runtime_actuation_promotion_rc_json="null"
runtime_actuation_promotion_decision_json=""
runtime_actuation_promotion_go_json="null"
runtime_actuation_promotion_no_go_json="null"
runtime_actuation_promotion_reasons_json='[]'
runtime_actuation_promotion_notes_json=""
runtime_actuation_promotion_needs_attention_json="true"
runtime_actuation_promotion_next_command="./scripts/easy_node.sh runtime-actuation-promotion-cycle --reports-dir .easy-node-logs --cycles 3 --fail-on-no-go 1 --summary-json .easy-node-logs/runtime_actuation_promotion_cycle_latest_summary.json --print-summary-json 1"
runtime_actuation_promotion_next_command_reason="runtime-actuation promotion evidence is missing; run promotion cycle to produce fresh fail-closed GO/NO-GO evidence"
if [[ -n "$runtime_actuation_promotion_summary_json" ]] \
   && [[ "$(runtime_actuation_promotion_summary_usable_01 "$runtime_actuation_promotion_summary_json")" == "1" ]]; then
  runtime_actuation_promotion_available_json="true"
  runtime_actuation_promotion_source_summary_json="$runtime_actuation_promotion_summary_json"
  runtime_actuation_promotion_status_json="$(jq -r '
    if (.status | type) == "string" then .status
    elif (.promotion_check.status | type) == "string" then .promotion_check.status
    else "unknown"
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "unknown")"
  runtime_actuation_promotion_rc_json="$(jq -r '
    if (.rc | type) == "number" then .rc
    elif (.promotion_check.rc | type) == "number" then .promotion_check.rc
    else "null"
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  runtime_actuation_promotion_decision_json="$(jq -r '
    if (.decision | type) == "string" then .decision
    elif (.promotion_check.decision | type) == "string" then .promotion_check.decision
    else ""
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_actuation_promotion_go_json="$(jq -r '
    if (.go | type) == "boolean" then (.go | tostring)
    elif (.decision | type) == "string" then
      ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
      | if $d == "GO" then "true"
        elif $d == "NOGO" then "false"
        else "null"
        end)
    else "null"
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  runtime_actuation_promotion_no_go_json="$(jq -r '
    if (.no_go | type) == "boolean" then (.no_go | tostring)
    elif (.decision | type) == "string" then
      ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
      | if $d == "NOGO" then "true"
        elif $d == "GO" then "false"
        else "null"
        end)
    else "null"
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  runtime_actuation_promotion_reasons_json="$(jq -c '
    if (.reasons | type) == "array" then [.reasons[] | strings]
    elif (.errors | type) == "array" then [.errors[] | strings]
    else
      ([
        (if (.failure_reason | type) == "string" then .failure_reason else empty end),
        (if (.promotion_check.next_operator_action | type) == "string" then .promotion_check.next_operator_action else empty end),
        (
          if (.promotion_check.violations | type) == "array" then
            .promotion_check.violations[]
            | if (type == "string") then .
              elif (.message | type) == "string" then .message
              else empty
              end
          else empty
          end
        ),
        (
          if (.promotion_check.errors | type) == "array" then
            .promotion_check.errors[] | strings
          else empty
          end
        )
      ] | map(select((. // "") != "")))
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' '[]')"
  runtime_actuation_promotion_notes_json="$(jq -r '
    if (.notes | type) == "string" then .notes
    elif (.promotion_check.notes | type) == "string" then .promotion_check.notes
    else ""
    end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_actuation_promotion_status_norm="$(printf '%s' "${runtime_actuation_promotion_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  runtime_actuation_promotion_decision_norm_token="$(printf '%s' "${runtime_actuation_promotion_decision_json:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]_-')"
  runtime_actuation_promotion_decision_norm=""
  case "$runtime_actuation_promotion_decision_norm_token" in
    GO) runtime_actuation_promotion_decision_norm="GO" ;;
    NOGO) runtime_actuation_promotion_decision_norm="NO-GO" ;;
    *) runtime_actuation_promotion_decision_norm="" ;;
  esac
  runtime_actuation_promotion_schema_id_json="$(jq -r '
    if (.schema.id | type) == "string" then .schema.id else "" end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_actuation_promotion_nested_status_json="$(jq -r '
    if (.promotion_check.status | type) == "string" then .promotion_check.status else "" end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_actuation_promotion_nested_status_norm="$(printf '%s' "${runtime_actuation_promotion_nested_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  runtime_actuation_promotion_nested_decision_json="$(jq -r '
    if (.promotion_check.decision | type) == "string" then .promotion_check.decision else "" end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "")"
  runtime_actuation_promotion_nested_decision_norm_token="$(printf '%s' "${runtime_actuation_promotion_nested_decision_json:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]_-')"
  runtime_actuation_promotion_nested_decision_norm=""
  case "$runtime_actuation_promotion_nested_decision_norm_token" in
    GO) runtime_actuation_promotion_nested_decision_norm="GO" ;;
    NOGO) runtime_actuation_promotion_nested_decision_norm="NO-GO" ;;
    *) runtime_actuation_promotion_nested_decision_norm="" ;;
  esac
  runtime_actuation_promotion_nested_rc_json="$(jq -r '
    if (.promotion_check.rc | type) == "number" then .promotion_check.rc else "null" end
  ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  runtime_actuation_promotion_consistency_errors_json='[]'
  runtime_actuation_promotion_consistency_ok_01="1"
  declare -a runtime_actuation_promotion_consistency_errors=()
  if [[ "$runtime_actuation_promotion_go_json" == "true" && "$runtime_actuation_promotion_rc_json" != "0" ]]; then
    runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: go=true with rc!=0")
  fi
  if [[ "$runtime_actuation_promotion_go_json" == "true" && "$runtime_actuation_promotion_no_go_json" == "true" ]]; then
    runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: go=true and no_go=true")
  fi
  if [[ "$runtime_actuation_promotion_go_json" == "true" && "$runtime_actuation_promotion_decision_norm" == "NO-GO" ]]; then
    runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: go=true but decision=NO-GO")
  fi
  if [[ "$runtime_actuation_promotion_no_go_json" == "true" && "$runtime_actuation_promotion_decision_norm" == "GO" ]]; then
    runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: no_go=true but decision=GO")
  fi
  if [[ "$runtime_actuation_promotion_decision_norm" == "GO" && "$runtime_actuation_promotion_go_json" == "false" ]]; then
    runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: decision=GO but go=false")
  fi
  if [[ "$runtime_actuation_promotion_status_norm" == "ok" || "$runtime_actuation_promotion_status_norm" == "pass" ]]; then
    if [[ "$runtime_actuation_promotion_go_json" != "true" ]]; then
      runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: status pass/ok without go=true")
    fi
    if [[ "$runtime_actuation_promotion_rc_json" != "0" ]]; then
      runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: status pass/ok with rc!=0")
    fi
  fi
  if [[ "$runtime_actuation_promotion_schema_id_json" == "runtime_actuation_promotion_cycle_summary" ]]; then
    if [[ -n "$runtime_actuation_promotion_nested_status_norm" && -n "$runtime_actuation_promotion_status_norm" ]] \
       && [[ "$runtime_actuation_promotion_nested_status_norm" != "$runtime_actuation_promotion_status_norm" ]]; then
      runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: cycle top-level status disagrees with promotion_check.status")
    fi
    if [[ -n "$runtime_actuation_promotion_nested_decision_norm" && -n "$runtime_actuation_promotion_decision_norm" ]] \
       && [[ "$runtime_actuation_promotion_nested_decision_norm" != "$runtime_actuation_promotion_decision_norm" ]]; then
      runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: cycle top-level decision disagrees with promotion_check.decision")
    fi
    if [[ "$runtime_actuation_promotion_nested_rc_json" != "null" && "$runtime_actuation_promotion_rc_json" != "null" ]] \
       && [[ "$runtime_actuation_promotion_nested_rc_json" != "$runtime_actuation_promotion_rc_json" ]]; then
      runtime_actuation_promotion_consistency_errors+=("runtime-actuation promotion summary is inconsistent: cycle top-level rc disagrees with promotion_check.rc")
    fi
  fi
  if ((${#runtime_actuation_promotion_consistency_errors[@]} > 0)); then
    runtime_actuation_promotion_consistency_ok_01="0"
    runtime_actuation_promotion_consistency_errors_json="$(printf '%s\n' "${runtime_actuation_promotion_consistency_errors[@]}" | jq -R . | jq -s 'map(select(length > 0))')"
    runtime_actuation_promotion_reasons_json="$(jq -c \
      --argjson reasons "$runtime_actuation_promotion_reasons_json" \
      --argjson consistency_errors "$runtime_actuation_promotion_consistency_errors_json" \
      '($reasons + $consistency_errors) | map(select((type == "string") and (length > 0))) | unique' \
      <<<"{}" 2>/dev/null || printf '%s' "$runtime_actuation_promotion_reasons_json")"
    runtime_actuation_promotion_status_json="fail"
  fi

  if [[ "$runtime_actuation_promotion_go_json" == "true" ]] \
     && [[ "$runtime_actuation_promotion_status_norm" == "ok" || "$runtime_actuation_promotion_status_norm" == "pass" ]] \
     && [[ "$runtime_actuation_promotion_rc_json" == "0" ]] \
     && [[ "$runtime_actuation_promotion_no_go_json" != "true" ]] \
     && [[ "$runtime_actuation_promotion_consistency_ok_01" == "1" ]]; then
    runtime_actuation_promotion_needs_attention_json="false"
    runtime_actuation_promotion_next_command=""
    runtime_actuation_promotion_next_command_reason=""
  else
    runtime_actuation_promotion_needs_attention_json="true"
    if [[ "$runtime_actuation_promotion_consistency_ok_01" == "0" ]]; then
      first_reason="$(jq -r 'if (. | type) == "array" and (. | length) > 0 then (.[0] // "") else "" end' <<<"$runtime_actuation_promotion_consistency_errors_json" 2>/dev/null || true)"
    else
    first_reason="$(jq -r '
      if (.reasons | type) == "array" and (.reasons | length) > 0 then
        (.reasons[0] // "")
      elif (.errors | type) == "array" and (.errors | length) > 0 then
        (.errors[0] // "")
      elif (.failure_reason | type) == "string" then
        .failure_reason
      elif (.promotion_check.next_operator_action | type) == "string" then
        .promotion_check.next_operator_action
      elif (.promotion_check.violations | type) == "array" and (.promotion_check.violations | length) > 0 then
        if (.promotion_check.violations[0] | type) == "string" then
          .promotion_check.violations[0]
        elif (.promotion_check.violations[0].message | type) == "string" then
          .promotion_check.violations[0].message
        else
          ""
        end
      elif (.promotion_check.errors | type) == "array" and (.promotion_check.errors | length) > 0 then
        if (.promotion_check.errors[0] | type) == "string" then
          .promotion_check.errors[0]
        else
          ""
        end
      else
        ""
      end
    ' "$runtime_actuation_promotion_summary_json" 2>/dev/null || true)"
    fi
    if [[ -n "$first_reason" ]]; then
      runtime_actuation_promotion_next_command_reason="$first_reason"
    elif [[ -n "$runtime_actuation_promotion_notes_json" ]]; then
      runtime_actuation_promotion_next_command_reason="$runtime_actuation_promotion_notes_json"
    else
      runtime_actuation_promotion_next_command_reason="runtime-actuation promotion is pending or NO-GO; refresh runtime-actuation evidence and rerun promotion cycle"
    fi
  fi
fi

profile_default_gate_evidence_pack_helper_subcommand="profile-default-gate-stability-evidence-pack"
profile_default_gate_evidence_pack_helper_available_json="false"
if [[ "$(easy_node_supports_subcommand_01 "$profile_default_gate_evidence_pack_helper_subcommand")" == "1" ]]; then
  profile_default_gate_evidence_pack_helper_available_json="true"
fi
profile_default_gate_evidence_pack_input_summary_json="$(
  resolve_profile_default_gate_evidence_pack_summary_path "$manual_validation_summary_json" "$default_log_dir"
)"
profile_default_gate_evidence_pack_source_summary_json=""
profile_default_gate_evidence_pack_available_json="false"
profile_default_gate_evidence_pack_status_json="missing"
profile_default_gate_evidence_pack_rc_json="null"
profile_default_gate_evidence_pack_decision_json=""
profile_default_gate_evidence_pack_go_json="null"
profile_default_gate_evidence_pack_no_go_json="null"
profile_default_gate_evidence_pack_reasons_json='[]'
profile_default_gate_evidence_pack_notes_json=""
profile_default_gate_evidence_pack_needs_attention_json="true"
profile_default_gate_evidence_pack_next_command=""
profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack summary is missing; publish a fresh evidence pack"
if [[ "$profile_default_gate_evidence_pack_helper_available_json" == "true" ]]; then
  profile_default_gate_evidence_pack_next_command="./scripts/easy_node.sh profile-default-gate-stability-evidence-pack --reports-dir .easy-node-logs --fail-on-no-go 1 --summary-json .easy-node-logs/profile_default_gate_evidence_pack_summary.json --print-summary-json 1"
else
  profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack helper is unavailable in this checkout; merge helper slice and rerun"
fi
if [[ -n "$profile_default_gate_evidence_pack_input_summary_json" ]] && [[ -f "$profile_default_gate_evidence_pack_input_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$profile_default_gate_evidence_pack_input_summary_json")" == "1" ]]; then
    if [[ "$(evidence_pack_summary_stale_01 "$profile_default_gate_evidence_pack_input_summary_json" "${ROADMAP_PROGRESS_PROFILE_DEFAULT_GATE_EVIDENCE_PACK_MAX_AGE_SEC:-86400}")" == "1" ]]; then
      profile_default_gate_evidence_pack_status_json="stale"
      profile_default_gate_evidence_pack_reasons_json="$(jq -nc '[ "profile-default evidence-pack summary is stale or has untrusted freshness metadata" ]')"
      profile_default_gate_evidence_pack_notes_json="fail-closed freshness policy rejected evidence-pack summary"
      profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack summary is stale; republish a fresh evidence pack"
    else
      profile_default_gate_evidence_pack_available_json="true"
      profile_default_gate_evidence_pack_source_summary_json="$profile_default_gate_evidence_pack_input_summary_json"
      profile_default_gate_evidence_pack_status_json="$(jq -r '
        if (.status | type) == "string" then .status
        elif (.evidence_pack.status | type) == "string" then .evidence_pack.status
        elif (.summary.status | type) == "string" then .summary.status
        else "unknown"
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "unknown")"
      profile_default_gate_evidence_pack_rc_json="$(jq -r '
        if (.rc | type) == "number" then .rc
        elif (.evidence_pack.rc | type) == "number" then .evidence_pack.rc
        elif (.summary.rc | type) == "number" then .summary.rc
        else "null"
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      profile_default_gate_evidence_pack_decision_json="$(jq -r '
        if (.decision | type) == "string" then .decision
        elif (.evidence_pack.decision | type) == "string" then .evidence_pack.decision
        elif (.summary.decision | type) == "string" then .summary.decision
        else ""
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "")"
      profile_default_gate_evidence_pack_go_json="$(jq -r '
        if (.go | type) == "boolean" then (.go | tostring)
        elif (.decision | type) == "string" then
          ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
           | if $d == "GO" then "true"
             elif $d == "NOGO" then "false"
             else "null"
             end)
        else "null"
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      profile_default_gate_evidence_pack_no_go_json="$(jq -r '
        if (.no_go | type) == "boolean" then (.no_go | tostring)
        elif (.decision | type) == "string" then
          ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
           | if $d == "NOGO" then "true"
             elif $d == "GO" then "false"
             else "null"
             end)
        else "null"
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      profile_default_gate_evidence_pack_reasons_json="$(jq -c '
        if (.reasons | type) == "array" then [.reasons[] | strings]
        elif (.errors | type) == "array" then [.errors[] | strings]
        else
          [
            (.failure_reason // empty),
            (.next_operator_action // empty)
          ] | map(select((type == "string") and (length > 0)))
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' '[]')"
      profile_default_gate_evidence_pack_notes_json="$(jq -r '
        if (.notes | type) == "string" then .notes
        elif (.next_operator_action | type) == "string" then .next_operator_action
        else ""
        end
      ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "")"
      profile_default_gate_evidence_pack_status_norm="$(printf '%s' "${profile_default_gate_evidence_pack_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
      if [[ "$profile_default_gate_evidence_pack_go_json" == "true" ]] \
         && [[ "$profile_default_gate_evidence_pack_status_norm" == "ok" || "$profile_default_gate_evidence_pack_status_norm" == "pass" || "$profile_default_gate_evidence_pack_status_norm" == "go" ]] \
         && [[ "$profile_default_gate_evidence_pack_rc_json" == "0" ]] \
         && [[ "$profile_default_gate_evidence_pack_no_go_json" != "true" ]]; then
        profile_default_gate_evidence_pack_needs_attention_json="false"
        profile_default_gate_evidence_pack_next_command=""
        profile_default_gate_evidence_pack_next_command_reason=""
      else
        profile_default_gate_evidence_pack_needs_attention_json="true"
        first_reason="$(jq -r '
          if (.reasons | type) == "array" and (.reasons | length) > 0 then (.reasons[0] // "")
          elif (.errors | type) == "array" and (.errors | length) > 0 then (.errors[0] // "")
          elif (.failure_reason | type) == "string" then .failure_reason
          elif (.next_operator_action | type) == "string" then .next_operator_action
          else ""
          end
        ' "$profile_default_gate_evidence_pack_input_summary_json" 2>/dev/null || true)"
        if [[ -n "$first_reason" ]]; then
          profile_default_gate_evidence_pack_next_command_reason="$first_reason"
        elif [[ -n "$profile_default_gate_evidence_pack_notes_json" ]]; then
          profile_default_gate_evidence_pack_next_command_reason="$profile_default_gate_evidence_pack_notes_json"
        else
          profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack decision is pending/NO-GO; republish and review evidence-pack output"
        fi
      fi
    fi
  else
    profile_default_gate_evidence_pack_status_json="invalid"
    profile_default_gate_evidence_pack_reasons_json="$(jq -nc '[ "profile-default evidence-pack summary is invalid JSON" ]')"
    profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack summary is invalid JSON; regenerate evidence pack"
  fi
elif [[ -n "$profile_default_gate_evidence_pack_input_summary_json" ]]; then
  profile_default_gate_evidence_pack_status_json="missing"
  profile_default_gate_evidence_pack_reasons_json="$(jq -nc --arg path "$profile_default_gate_evidence_pack_input_summary_json" '[ "profile-default evidence-pack summary path does not exist: " + $path ]')"
  profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack summary path is missing; publish evidence pack"
fi
if [[ "$profile_default_gate_evidence_pack_needs_attention_json" == "true" ]] \
   && [[ "$profile_default_gate_evidence_pack_helper_available_json" != "true" ]] \
   && [[ -z "$profile_default_gate_evidence_pack_next_command" ]]; then
  profile_default_gate_evidence_pack_next_command_reason="profile-default evidence-pack helper is unavailable in this checkout; merge helper slice and rerun"
fi

runtime_actuation_promotion_evidence_pack_helper_subcommand="runtime-actuation-promotion-evidence-pack"
runtime_actuation_promotion_evidence_pack_helper_available_json="false"
if [[ "$(easy_node_supports_subcommand_01 "$runtime_actuation_promotion_evidence_pack_helper_subcommand")" == "1" ]]; then
  runtime_actuation_promotion_evidence_pack_helper_available_json="true"
fi
runtime_actuation_promotion_evidence_pack_input_summary_json="$(
  resolve_runtime_actuation_promotion_evidence_pack_summary_path "$manual_validation_summary_json" "$default_log_dir"
)"
runtime_actuation_promotion_evidence_pack_source_summary_json=""
runtime_actuation_promotion_evidence_pack_available_json="false"
runtime_actuation_promotion_evidence_pack_status_json="missing"
runtime_actuation_promotion_evidence_pack_rc_json="null"
runtime_actuation_promotion_evidence_pack_decision_json=""
runtime_actuation_promotion_evidence_pack_go_json="null"
runtime_actuation_promotion_evidence_pack_no_go_json="null"
runtime_actuation_promotion_evidence_pack_reasons_json='[]'
runtime_actuation_promotion_evidence_pack_notes_json=""
runtime_actuation_promotion_evidence_pack_needs_attention_json="true"
runtime_actuation_promotion_evidence_pack_next_command=""
runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack summary is missing; publish a fresh evidence pack"
if [[ "$runtime_actuation_promotion_evidence_pack_helper_available_json" == "true" ]]; then
  runtime_actuation_promotion_evidence_pack_next_command="./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --reports-dir .easy-node-logs --fail-on-no-go 1 --summary-json .easy-node-logs/runtime_actuation_promotion_evidence_pack_summary.json --print-summary-json 1"
else
  runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack helper is unavailable in this checkout; merge helper slice and rerun"
fi
if [[ -n "$runtime_actuation_promotion_evidence_pack_input_summary_json" ]] && [[ -f "$runtime_actuation_promotion_evidence_pack_input_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$runtime_actuation_promotion_evidence_pack_input_summary_json")" == "1" ]]; then
    if [[ "$(evidence_pack_summary_stale_01 "$runtime_actuation_promotion_evidence_pack_input_summary_json" "${ROADMAP_PROGRESS_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_MAX_AGE_SEC:-86400}")" == "1" ]]; then
      runtime_actuation_promotion_evidence_pack_status_json="stale"
      runtime_actuation_promotion_evidence_pack_reasons_json="$(jq -nc '[ "runtime-actuation promotion evidence-pack summary is stale or has untrusted freshness metadata" ]')"
      runtime_actuation_promotion_evidence_pack_notes_json="fail-closed freshness policy rejected evidence-pack summary"
      runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack summary is stale; republish a fresh evidence pack"
    else
      runtime_actuation_promotion_evidence_pack_available_json="true"
      runtime_actuation_promotion_evidence_pack_source_summary_json="$runtime_actuation_promotion_evidence_pack_input_summary_json"
      runtime_actuation_promotion_evidence_pack_status_json="$(jq -r '
        if (.status | type) == "string" then .status
        elif (.evidence_pack.status | type) == "string" then .evidence_pack.status
        elif (.promotion.status | type) == "string" then .promotion.status
        else "unknown"
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "unknown")"
      runtime_actuation_promotion_evidence_pack_rc_json="$(jq -r '
        if (.rc | type) == "number" then .rc
        elif (.evidence_pack.rc | type) == "number" then .evidence_pack.rc
        elif (.promotion.rc | type) == "number" then .promotion.rc
        else "null"
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      runtime_actuation_promotion_evidence_pack_decision_json="$(jq -r '
        if (.decision | type) == "string" then .decision
        elif (.evidence_pack.decision | type) == "string" then .evidence_pack.decision
        elif (.promotion.decision | type) == "string" then .promotion.decision
        else ""
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "")"
      runtime_actuation_promotion_evidence_pack_go_json="$(jq -r '
        if (.go | type) == "boolean" then (.go | tostring)
        elif (.decision | type) == "string" then
          ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
           | if $d == "GO" then "true"
             elif $d == "NOGO" then "false"
             else "null"
             end)
        else "null"
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      runtime_actuation_promotion_evidence_pack_no_go_json="$(jq -r '
        if (.no_go | type) == "boolean" then (.no_go | tostring)
        elif (.decision | type) == "string" then
          ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
           | if $d == "NOGO" then "true"
             elif $d == "GO" then "false"
             else "null"
             end)
        else "null"
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      runtime_actuation_promotion_evidence_pack_reasons_json="$(jq -c '
        if (.reasons | type) == "array" then [.reasons[] | strings]
        elif (.errors | type) == "array" then [.errors[] | strings]
        else
          [
            (.failure_reason // empty),
            (.next_operator_action // empty)
          ] | map(select((type == "string") and (length > 0)))
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' '[]')"
      runtime_actuation_promotion_evidence_pack_notes_json="$(jq -r '
        if (.notes | type) == "string" then .notes
        elif (.next_operator_action | type) == "string" then .next_operator_action
        else ""
        end
      ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "")"
      runtime_actuation_promotion_evidence_pack_status_norm="$(printf '%s' "${runtime_actuation_promotion_evidence_pack_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
      if [[ "$runtime_actuation_promotion_evidence_pack_go_json" == "true" ]] \
         && [[ "$runtime_actuation_promotion_evidence_pack_status_norm" == "ok" || "$runtime_actuation_promotion_evidence_pack_status_norm" == "pass" || "$runtime_actuation_promotion_evidence_pack_status_norm" == "go" ]] \
         && [[ "$runtime_actuation_promotion_evidence_pack_rc_json" == "0" ]] \
         && [[ "$runtime_actuation_promotion_evidence_pack_no_go_json" != "true" ]]; then
        runtime_actuation_promotion_evidence_pack_needs_attention_json="false"
        runtime_actuation_promotion_evidence_pack_next_command=""
        runtime_actuation_promotion_evidence_pack_next_command_reason=""
      else
        runtime_actuation_promotion_evidence_pack_needs_attention_json="true"
        first_reason="$(jq -r '
          if (.reasons | type) == "array" and (.reasons | length) > 0 then (.reasons[0] // "")
          elif (.errors | type) == "array" and (.errors | length) > 0 then (.errors[0] // "")
          elif (.failure_reason | type) == "string" then .failure_reason
          elif (.next_operator_action | type) == "string" then .next_operator_action
          else ""
          end
        ' "$runtime_actuation_promotion_evidence_pack_input_summary_json" 2>/dev/null || true)"
        if [[ -n "$first_reason" ]]; then
          runtime_actuation_promotion_evidence_pack_next_command_reason="$first_reason"
        elif [[ -n "$runtime_actuation_promotion_evidence_pack_notes_json" ]]; then
          runtime_actuation_promotion_evidence_pack_next_command_reason="$runtime_actuation_promotion_evidence_pack_notes_json"
        else
          runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack decision is pending/NO-GO; republish and review evidence-pack output"
        fi
      fi
    fi
  else
    runtime_actuation_promotion_evidence_pack_status_json="invalid"
    runtime_actuation_promotion_evidence_pack_reasons_json="$(jq -nc '[ "runtime-actuation promotion evidence-pack summary is invalid JSON" ]')"
    runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack summary is invalid JSON; regenerate evidence pack"
  fi
elif [[ -n "$runtime_actuation_promotion_evidence_pack_input_summary_json" ]]; then
  runtime_actuation_promotion_evidence_pack_status_json="missing"
  runtime_actuation_promotion_evidence_pack_reasons_json="$(jq -nc --arg path "$runtime_actuation_promotion_evidence_pack_input_summary_json" '[ "runtime-actuation promotion evidence-pack summary path does not exist: " + $path ]')"
  runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack summary path is missing; publish evidence pack"
fi
if [[ "$runtime_actuation_promotion_evidence_pack_needs_attention_json" == "true" ]] \
   && [[ "$runtime_actuation_promotion_evidence_pack_helper_available_json" != "true" ]] \
   && [[ -z "$runtime_actuation_promotion_evidence_pack_next_command" ]]; then
  runtime_actuation_promotion_evidence_pack_next_command_reason="runtime-actuation promotion evidence-pack helper is unavailable in this checkout; merge helper slice and rerun"
fi

multi_vm_stability_promotion_evidence_pack_helper_subcommand="profile-compare-multi-vm-stability-promotion-evidence-pack"
multi_vm_stability_promotion_evidence_pack_helper_available_json="false"
if [[ "$(easy_node_supports_subcommand_01 "$multi_vm_stability_promotion_evidence_pack_helper_subcommand")" == "1" ]]; then
  multi_vm_stability_promotion_evidence_pack_helper_available_json="true"
fi
multi_vm_stability_promotion_evidence_pack_input_summary_json="$(
  resolve_profile_compare_multi_vm_stability_promotion_evidence_pack_summary_path "$manual_validation_summary_json" "$default_log_dir"
)"
multi_vm_stability_promotion_evidence_pack_source_summary_json=""
multi_vm_stability_promotion_evidence_pack_available_json="false"
multi_vm_stability_promotion_evidence_pack_status_json="missing"
multi_vm_stability_promotion_evidence_pack_rc_json="null"
multi_vm_stability_promotion_evidence_pack_decision_json=""
multi_vm_stability_promotion_evidence_pack_go_json="null"
multi_vm_stability_promotion_evidence_pack_no_go_json="null"
multi_vm_stability_promotion_evidence_pack_reasons_json='[]'
multi_vm_stability_promotion_evidence_pack_notes_json=""
multi_vm_stability_promotion_evidence_pack_needs_attention_json="true"
multi_vm_stability_promotion_evidence_pack_next_command=""
multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack summary is missing; publish a fresh evidence pack"
if [[ "$multi_vm_stability_promotion_evidence_pack_helper_available_json" == "true" ]]; then
  multi_vm_stability_promotion_evidence_pack_next_command="./scripts/easy_node.sh profile-compare-multi-vm-stability-promotion-evidence-pack --reports-dir .easy-node-logs --fail-on-no-go 1 --summary-json .easy-node-logs/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json --print-summary-json 1"
else
  multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack helper is unavailable in this checkout; merge helper slice and rerun"
fi
if [[ -n "$multi_vm_stability_promotion_evidence_pack_input_summary_json" ]] && [[ -f "$multi_vm_stability_promotion_evidence_pack_input_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$multi_vm_stability_promotion_evidence_pack_input_summary_json")" == "1" ]]; then
    if [[ "$(evidence_pack_summary_stale_01 "$multi_vm_stability_promotion_evidence_pack_input_summary_json" "${ROADMAP_PROGRESS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_MAX_AGE_SEC:-86400}")" == "1" ]]; then
      multi_vm_stability_promotion_evidence_pack_status_json="stale"
      multi_vm_stability_promotion_evidence_pack_reasons_json="$(jq -nc '[ "multi-VM stability promotion evidence-pack summary is stale or has untrusted freshness metadata" ]')"
      multi_vm_stability_promotion_evidence_pack_notes_json="fail-closed freshness policy rejected evidence-pack summary"
      multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack summary is stale; republish a fresh evidence pack"
    else
      multi_vm_stability_promotion_evidence_pack_available_json="true"
      multi_vm_stability_promotion_evidence_pack_source_summary_json="$multi_vm_stability_promotion_evidence_pack_input_summary_json"
      multi_vm_stability_promotion_evidence_pack_status_json="$(jq -r '
        if (.status | type) == "string" then .status
        elif (.evidence_pack.status | type) == "string" then .evidence_pack.status
        elif (.promotion.status | type) == "string" then .promotion.status
        else "unknown"
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "unknown")"
      multi_vm_stability_promotion_evidence_pack_rc_json="$(jq -r '
        if (.rc | type) == "number" then .rc
        elif (.evidence_pack.rc | type) == "number" then .evidence_pack.rc
        elif (.promotion.rc | type) == "number" then .promotion.rc
        else "null"
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      multi_vm_stability_promotion_evidence_pack_decision_json="$(jq -r '
        if (.decision | type) == "string" then .decision
        elif (.evidence_pack.decision | type) == "string" then .evidence_pack.decision
        elif (.promotion.decision | type) == "string" then .promotion.decision
        else ""
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "")"
      multi_vm_stability_promotion_evidence_pack_go_json="$(jq -r '
        if (.go | type) == "boolean" then (.go | tostring)
        elif (.decision | type) == "string" then
          ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
           | if $d == "GO" then "true"
             elif $d == "NOGO" then "false"
             else "null"
             end)
        else "null"
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      multi_vm_stability_promotion_evidence_pack_no_go_json="$(jq -r '
        if (.no_go | type) == "boolean" then (.no_go | tostring)
        elif (.decision | type) == "string" then
          ((.decision | ascii_upcase | gsub("[[:space:]_-]"; "")) as $d
           | if $d == "NOGO" then "true"
             elif $d == "GO" then "false"
             else "null"
             end)
        else "null"
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "null")"
      multi_vm_stability_promotion_evidence_pack_reasons_json="$(jq -c '
        if (.reasons | type) == "array" then [.reasons[] | strings]
        elif (.errors | type) == "array" then [.errors[] | strings]
        else
          [
            (.failure_reason // empty),
            (.next_operator_action // empty)
          ] | map(select((type == "string") and (length > 0)))
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' '[]')"
      multi_vm_stability_promotion_evidence_pack_notes_json="$(jq -r '
        if (.notes | type) == "string" then .notes
        elif (.next_operator_action | type) == "string" then .next_operator_action
        else ""
        end
      ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || printf '%s' "")"
      multi_vm_stability_promotion_evidence_pack_status_norm="$(printf '%s' "${multi_vm_stability_promotion_evidence_pack_status_json:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
      if [[ "$multi_vm_stability_promotion_evidence_pack_go_json" == "true" ]] \
         && [[ "$multi_vm_stability_promotion_evidence_pack_status_norm" == "ok" || "$multi_vm_stability_promotion_evidence_pack_status_norm" == "pass" || "$multi_vm_stability_promotion_evidence_pack_status_norm" == "go" ]] \
         && [[ "$multi_vm_stability_promotion_evidence_pack_rc_json" == "0" ]] \
         && [[ "$multi_vm_stability_promotion_evidence_pack_no_go_json" != "true" ]]; then
        multi_vm_stability_promotion_evidence_pack_needs_attention_json="false"
        multi_vm_stability_promotion_evidence_pack_next_command=""
        multi_vm_stability_promotion_evidence_pack_next_command_reason=""
      else
        multi_vm_stability_promotion_evidence_pack_needs_attention_json="true"
        first_reason="$(jq -r '
          if (.reasons | type) == "array" and (.reasons | length) > 0 then (.reasons[0] // "")
          elif (.errors | type) == "array" and (.errors | length) > 0 then (.errors[0] // "")
          elif (.failure_reason | type) == "string" then .failure_reason
          elif (.next_operator_action | type) == "string" then .next_operator_action
          else ""
          end
        ' "$multi_vm_stability_promotion_evidence_pack_input_summary_json" 2>/dev/null || true)"
        if [[ -n "$first_reason" ]]; then
          multi_vm_stability_promotion_evidence_pack_next_command_reason="$first_reason"
        elif [[ -n "$multi_vm_stability_promotion_evidence_pack_notes_json" ]]; then
          multi_vm_stability_promotion_evidence_pack_next_command_reason="$multi_vm_stability_promotion_evidence_pack_notes_json"
        else
          multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack decision is pending/NO-GO; republish and review evidence-pack output"
        fi
      fi
    fi
  else
    multi_vm_stability_promotion_evidence_pack_status_json="invalid"
    multi_vm_stability_promotion_evidence_pack_reasons_json="$(jq -nc '[ "multi-VM stability promotion evidence-pack summary is invalid JSON" ]')"
    multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack summary is invalid JSON; regenerate evidence pack"
  fi
elif [[ -n "$multi_vm_stability_promotion_evidence_pack_input_summary_json" ]]; then
  multi_vm_stability_promotion_evidence_pack_status_json="missing"
  multi_vm_stability_promotion_evidence_pack_reasons_json="$(jq -nc --arg path "$multi_vm_stability_promotion_evidence_pack_input_summary_json" '[ "multi-VM stability promotion evidence-pack summary path does not exist: " + $path ]')"
  multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack summary path is missing; publish evidence pack"
fi
if [[ "$multi_vm_stability_promotion_evidence_pack_needs_attention_json" == "true" ]] \
   && [[ "$multi_vm_stability_promotion_evidence_pack_helper_available_json" != "true" ]] \
   && [[ -z "$multi_vm_stability_promotion_evidence_pack_next_command" ]]; then
  multi_vm_stability_promotion_evidence_pack_next_command_reason="multi-VM stability promotion evidence-pack helper is unavailable in this checkout; merge helper slice and rerun"
fi

profile_default_gate_signoff_resolution="$(resolve_profile_default_gate_signoff_status "$profile_compare_signoff_summary_json" "$manual_validation_summary_json")"
profile_default_gate_signoff_status="${profile_default_gate_signoff_resolution%%$'\x1f'*}"
profile_default_gate_signoff_source=""
if [[ "$profile_default_gate_signoff_resolution" == *$'\x1f'* ]]; then
  profile_default_gate_signoff_source="${profile_default_gate_signoff_resolution#*$'\x1f'}"
fi
if [[ -n "$profile_default_gate_signoff_status" && "$profile_default_gate_status_manual_present" != "1" ]]; then
  profile_default_gate_status="$profile_default_gate_signoff_status"
fi
if [[ -n "$profile_default_gate_signoff_source" ]]; then
  profile_compare_signoff_summary_json="$profile_default_gate_signoff_source"
elif [[ -n "$profile_default_gate_summary_json_manual" ]]; then
  profile_compare_signoff_summary_json="$profile_default_gate_summary_json_manual"
fi
profile_default_gate_selection_policy_evidence_present_json="null"
profile_default_gate_selection_policy_evidence_valid_json="null"
profile_default_gate_selection_policy_evidence_note=""
profile_default_gate_selection_policy_evidence_resolution="$(
  profile_default_gate_selection_policy_evidence_from_signoff "$profile_compare_signoff_summary_json"
)"
if [[ "$profile_default_gate_selection_policy_evidence_resolution" == *$'\x1f'* ]]; then
  profile_default_gate_selection_policy_evidence_present_json="${profile_default_gate_selection_policy_evidence_resolution%%$'\x1f'*}"
  profile_default_gate_selection_policy_evidence_valid_json="${profile_default_gate_selection_policy_evidence_resolution#*$'\x1f'}"
fi
case "$profile_default_gate_selection_policy_evidence_present_json" in
  true|false|null) ;;
  *) profile_default_gate_selection_policy_evidence_present_json="null" ;;
esac
case "$profile_default_gate_selection_policy_evidence_valid_json" in
  true|false|null) ;;
  *) profile_default_gate_selection_policy_evidence_valid_json="null" ;;
esac
profile_default_gate_micro_relay_evidence_available_json="false"
profile_default_gate_micro_relay_quality_status_pass_json="null"
profile_default_gate_micro_relay_demotion_policy_present_json="false"
profile_default_gate_micro_relay_promotion_policy_present_json="false"
profile_default_gate_trust_tier_port_unlock_policy_present_json="false"
profile_default_gate_micro_relay_evidence_note=""
profile_default_gate_micro_relay_evidence_resolution="$(
  profile_default_gate_micro_relay_evidence_from_signoff "$profile_compare_signoff_summary_json"
)"
if [[ "$profile_default_gate_micro_relay_evidence_resolution" == *$'\x1f'* ]]; then
  profile_default_gate_micro_relay_evidence_available_json="${profile_default_gate_micro_relay_evidence_resolution%%$'\x1f'*}"
  profile_default_gate_micro_relay_evidence_resolution="${profile_default_gate_micro_relay_evidence_resolution#*$'\x1f'}"
  profile_default_gate_micro_relay_quality_status_pass_json="${profile_default_gate_micro_relay_evidence_resolution%%$'\x1f'*}"
  profile_default_gate_micro_relay_evidence_resolution="${profile_default_gate_micro_relay_evidence_resolution#*$'\x1f'}"
  profile_default_gate_micro_relay_demotion_policy_present_json="${profile_default_gate_micro_relay_evidence_resolution%%$'\x1f'*}"
  profile_default_gate_micro_relay_evidence_resolution="${profile_default_gate_micro_relay_evidence_resolution#*$'\x1f'}"
  profile_default_gate_micro_relay_promotion_policy_present_json="${profile_default_gate_micro_relay_evidence_resolution%%$'\x1f'*}"
  profile_default_gate_trust_tier_port_unlock_policy_present_json="${profile_default_gate_micro_relay_evidence_resolution#*$'\x1f'}"
fi
case "$profile_default_gate_micro_relay_evidence_available_json" in
  true|false) ;;
  *) profile_default_gate_micro_relay_evidence_available_json="false" ;;
esac
case "$profile_default_gate_micro_relay_quality_status_pass_json" in
  true|false|null) ;;
  *) profile_default_gate_micro_relay_quality_status_pass_json="null" ;;
esac
case "$profile_default_gate_micro_relay_demotion_policy_present_json" in
  true|false) ;;
  *) profile_default_gate_micro_relay_demotion_policy_present_json="false" ;;
esac
case "$profile_default_gate_micro_relay_promotion_policy_present_json" in
  true|false) ;;
  *) profile_default_gate_micro_relay_promotion_policy_present_json="false" ;;
esac
case "$profile_default_gate_trust_tier_port_unlock_policy_present_json" in
  true|false) ;;
  *) profile_default_gate_trust_tier_port_unlock_policy_present_json="false" ;;
esac
profile_default_gate_micro_relay_evidence_note="$(
  profile_default_gate_micro_relay_evidence_note_text \
    "$profile_default_gate_micro_relay_evidence_available_json" \
    "$profile_default_gate_micro_relay_quality_status_pass_json" \
    "$profile_default_gate_micro_relay_demotion_policy_present_json" \
    "$profile_default_gate_micro_relay_promotion_policy_present_json" \
    "$profile_default_gate_trust_tier_port_unlock_policy_present_json"
)"
profile_default_gate_runtime_actuation_ready_json="false"
profile_default_gate_runtime_actuation_status_json="pending"
if [[ "$profile_default_gate_micro_relay_evidence_available_json" == "true" ]] \
   && [[ "$profile_default_gate_micro_relay_quality_status_pass_json" == "true" ]] \
   && [[ "$profile_default_gate_micro_relay_demotion_policy_present_json" == "true" ]] \
   && [[ "$profile_default_gate_micro_relay_promotion_policy_present_json" == "true" ]] \
   && [[ "$profile_default_gate_trust_tier_port_unlock_policy_present_json" == "true" ]]; then
  profile_default_gate_runtime_actuation_ready_json="true"
  profile_default_gate_runtime_actuation_status_json="pass"
fi
profile_default_gate_runtime_actuation_reason="$(
  profile_default_gate_runtime_actuation_reason_text \
    "$profile_default_gate_runtime_actuation_ready_json" \
    "$profile_default_gate_micro_relay_evidence_note"
)"
profile_default_gate_next_command_host_a_effective="$(trim "${A_HOST:-}")"
profile_default_gate_next_command_host_b_effective="$(trim "${B_HOST:-}")"
if [[ -n "$profile_default_gate_next_command_host_a_effective" ]] \
   && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_host_a_effective")" != "1" ]]; then
  profile_default_gate_next_command_host_a_effective=""
fi
if [[ -n "$profile_default_gate_next_command_host_b_effective" ]] \
   && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_host_b_effective")" != "1" ]]; then
  profile_default_gate_next_command_host_b_effective=""
fi
if [[ -z "$profile_default_gate_next_command_host_a_effective" ]]; then
  profile_default_gate_next_command_host_a_extracted="$(profile_default_gate_extract_live_wrapper_host_from_cmd "$profile_default_gate_next_command" "a")"
  if [[ -n "$profile_default_gate_next_command_host_a_extracted" ]] \
     && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_host_a_extracted")" == "1" ]]; then
    profile_default_gate_next_command_host_a_effective="$profile_default_gate_next_command_host_a_extracted"
  fi
fi
if [[ -z "$profile_default_gate_next_command_host_b_effective" ]]; then
  profile_default_gate_next_command_host_b_extracted="$(profile_default_gate_extract_live_wrapper_host_from_cmd "$profile_default_gate_next_command" "b")"
  if [[ -n "$profile_default_gate_next_command_host_b_extracted" ]] \
     && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_host_b_extracted")" == "1" ]]; then
    profile_default_gate_next_command_host_b_effective="$profile_default_gate_next_command_host_b_extracted"
  fi
fi
profile_default_gate_next_command="$(
  profile_default_gate_command_localhost_run_to_live_wrapper \
    "$profile_default_gate_next_command" \
    "$profile_default_gate_next_command_host_a_effective" \
    "$profile_default_gate_next_command_host_b_effective" \
    "$profile_default_gate_next_command_source" \
    "$profile_default_gate_docker_hint_available_json"
)"
profile_default_gate_next_command_sudo_host_a_effective="$(trim "${A_HOST:-}")"
profile_default_gate_next_command_sudo_host_b_effective="$(trim "${B_HOST:-}")"
if [[ -n "$profile_default_gate_next_command_sudo_host_a_effective" ]] \
   && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_sudo_host_a_effective")" != "1" ]]; then
  profile_default_gate_next_command_sudo_host_a_effective=""
fi
if [[ -n "$profile_default_gate_next_command_sudo_host_b_effective" ]] \
   && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_sudo_host_b_effective")" != "1" ]]; then
  profile_default_gate_next_command_sudo_host_b_effective=""
fi
if [[ -z "$profile_default_gate_next_command_sudo_host_a_effective" ]]; then
  profile_default_gate_next_command_sudo_host_a_extracted="$(profile_default_gate_extract_live_wrapper_host_from_cmd "$profile_default_gate_next_command_sudo" "a")"
  if [[ -n "$profile_default_gate_next_command_sudo_host_a_extracted" ]] \
     && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_sudo_host_a_extracted")" == "1" ]]; then
    profile_default_gate_next_command_sudo_host_a_effective="$profile_default_gate_next_command_sudo_host_a_extracted"
  fi
fi
if [[ -z "$profile_default_gate_next_command_sudo_host_b_effective" ]]; then
  profile_default_gate_next_command_sudo_host_b_extracted="$(profile_default_gate_extract_live_wrapper_host_from_cmd "$profile_default_gate_next_command_sudo" "b")"
  if [[ -n "$profile_default_gate_next_command_sudo_host_b_extracted" ]] \
     && [[ "$(profile_default_gate_host_is_non_localhost_01 "$profile_default_gate_next_command_sudo_host_b_extracted")" == "1" ]]; then
    profile_default_gate_next_command_sudo_host_b_effective="$profile_default_gate_next_command_sudo_host_b_extracted"
  fi
fi
profile_default_gate_next_command_sudo="$(
  profile_default_gate_command_localhost_run_to_live_wrapper \
    "$profile_default_gate_next_command_sudo" \
    "$profile_default_gate_next_command_sudo_host_a_effective" \
    "$profile_default_gate_next_command_sudo_host_b_effective" \
    "$profile_default_gate_next_command_source" \
    "$profile_default_gate_docker_hint_available_json"
)"
profile_default_gate_next_command="$(profile_default_gate_command_with_subject_placeholder "$profile_default_gate_next_command")"
profile_default_gate_next_command_sudo="$(profile_default_gate_command_with_subject_placeholder "$profile_default_gate_next_command_sudo")"
profile_default_gate_fallback_campaign_timeout_sec="${MANUAL_VALIDATION_PROFILE_DEFAULT_GATE_CAMPAIGN_TIMEOUT_SEC:-2400}"
if [[ ! "$profile_default_gate_fallback_campaign_timeout_sec" =~ ^[0-9]+$ ]]; then
  profile_default_gate_fallback_campaign_timeout_sec="2400"
fi
if [[ "$profile_default_gate_status" != "pass" && "$profile_default_gate_status" != "skip" ]]; then
  if [[ -z "$profile_default_gate_next_command" || -z "$profile_default_gate_next_command_sudo" ]]; then
    profile_default_gate_command_summary_json_fallback="$(trim "$profile_compare_signoff_summary_json")"
    if [[ -z "$profile_default_gate_command_summary_json_fallback" ]]; then
      profile_default_gate_command_summary_json_fallback="$(trim "$profile_default_gate_summary_json_manual")"
    fi
    if [[ -z "$profile_default_gate_command_summary_json_fallback" ]]; then
      profile_default_gate_command_summary_json_fallback="$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json"
    fi
    profile_default_gate_command_reports_dir_fallback="$(dirname "$profile_default_gate_command_summary_json_fallback")"
    printf -v profile_default_gate_command_reports_dir_fallback_arg '%q' "$profile_default_gate_command_reports_dir_fallback"
    printf -v profile_default_gate_command_summary_json_fallback_arg '%q' "$profile_default_gate_command_summary_json_fallback"
    printf -v profile_default_gate_fallback_campaign_timeout_sec_arg '%q' "$profile_default_gate_fallback_campaign_timeout_sec"
    profile_default_gate_generated_next_command="$(profile_default_gate_command_with_subject_placeholder "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir $profile_default_gate_command_reports_dir_fallback_arg --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec $profile_default_gate_fallback_campaign_timeout_sec_arg --summary-json $profile_default_gate_command_summary_json_fallback_arg --print-summary-json 1")"
    profile_default_gate_generated_next_command_sudo="$(profile_default_gate_command_with_subject_placeholder "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir $profile_default_gate_command_reports_dir_fallback_arg --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec $profile_default_gate_fallback_campaign_timeout_sec_arg --summary-json $profile_default_gate_command_summary_json_fallback_arg --print-summary-json 1")"
    if [[ -z "$profile_default_gate_next_command" ]]; then
      profile_default_gate_next_command="$profile_default_gate_generated_next_command"
    fi
    if [[ -z "$profile_default_gate_next_command_sudo" ]]; then
      profile_default_gate_next_command_sudo="$profile_default_gate_generated_next_command_sudo"
    fi
    if [[ -z "$profile_default_gate_next_command_source" ]]; then
      profile_default_gate_next_command_source="default_non_sudo"
    fi
  fi
  if [[ -z "$profile_default_gate_next_command_source" ]] \
     && ([[ -n "$profile_default_gate_next_command" ]] || [[ -n "$profile_default_gate_next_command_sudo" ]]); then
    profile_default_gate_next_command_source="default_non_sudo"
  fi
fi
profile_default_gate_needs_attention_json="true"
if [[ "$profile_default_gate_status" == "pass" || "$profile_default_gate_status" == "skip" ]]; then
  profile_default_gate_needs_attention_json="false"
fi
if [[ "$profile_default_gate_needs_attention_json" == "true" ]] \
   && ([[ -n "$profile_default_gate_next_command" ]] || [[ -n "$profile_default_gate_next_command_sudo" ]]); then
  profile_default_gate_selection_policy_evidence_note="$(
    profile_default_gate_selection_policy_evidence_note_text \
      "$profile_default_gate_selection_policy_evidence_present_json" \
      "$profile_default_gate_selection_policy_evidence_valid_json"
  )"
fi
if [[ -n "$profile_default_gate_selection_policy_evidence_note" ]] \
   && [[ "$profile_default_gate_notes" != *"selection-policy evidence"* ]]; then
  if [[ -n "$profile_default_gate_notes" ]]; then
    profile_default_gate_notes="$profile_default_gate_notes; $profile_default_gate_selection_policy_evidence_note"
  else
    profile_default_gate_notes="$profile_default_gate_selection_policy_evidence_note"
  fi
fi
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
   && "$phase4_windows_full_parity_handoff_role_combination_validation_ok_json" == "true" \
   && ( "$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json" == "null" || "$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json" == "true" ) ]]; then
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
   || "$phase4_windows_full_parity_handoff_role_combination_validation_ok_json" != "true" \
   || ( "$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json" != "null" && "$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json" != "true" ) ]]; then
  phase4_actionable_reason="$phase4_actionable_reason signals=[windows_server_packaging_ok=${phase4_windows_full_parity_handoff_windows_server_packaging_ok_json},windows_role_runbooks_ok=${phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json},cross_platform_interop_ok=${phase4_windows_full_parity_handoff_cross_platform_interop_ok_json},role_combination_validation_ok=${phase4_windows_full_parity_handoff_role_combination_validation_ok_json},windows_native_bootstrap_guardrails_ok=${phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json}]"
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
integration_roadmap_next_actions_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_roadmap_next_actions_run.sh" ]]; then
  integration_roadmap_next_actions_run_script_exists_json="true"
fi
integration_easy_node_roadmap_next_actions_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_easy_node_roadmap_next_actions_run.sh" ]]; then
  integration_easy_node_roadmap_next_actions_run_script_exists_json="true"
fi
integration_roadmap_non_blockchain_actionable_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_roadmap_non_blockchain_actionable_run.sh" ]]; then
  integration_roadmap_non_blockchain_actionable_run_script_exists_json="true"
fi
integration_easy_node_roadmap_non_blockchain_actionable_run_script_exists_json="false"
if [[ -f "$ROOT_DIR/scripts/integration_easy_node_roadmap_non_blockchain_actionable_run.sh" ]]; then
  integration_easy_node_roadmap_non_blockchain_actionable_run_script_exists_json="true"
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
    --argjson integration_roadmap_next_actions_run_script_exists "$integration_roadmap_next_actions_run_script_exists_json" \
    --argjson integration_easy_node_roadmap_next_actions_run_script_exists "$integration_easy_node_roadmap_next_actions_run_script_exists_json" \
    --argjson integration_roadmap_non_blockchain_actionable_run_script_exists "$integration_roadmap_non_blockchain_actionable_run_script_exists_json" \
    --argjson integration_easy_node_roadmap_non_blockchain_actionable_run_script_exists "$integration_easy_node_roadmap_non_blockchain_actionable_run_script_exists_json" \
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
      } else empty end),
      (if $integration_roadmap_non_blockchain_actionable_run_script_exists then {
        id: "integration_roadmap_non_blockchain_actionable_run",
        label: "Roadmap non-blockchain actionable run contract",
        command: "bash ./scripts/integration_roadmap_non_blockchain_actionable_run.sh",
        reason: "validates roadmap non-blockchain actionable runner contract"
      } else empty end),
      (if $integration_easy_node_roadmap_non_blockchain_actionable_run_script_exists then {
        id: "integration_easy_node_roadmap_non_blockchain_actionable_run",
        label: "Easy-node roadmap non-blockchain actionable contract",
        command: "bash ./scripts/integration_easy_node_roadmap_non_blockchain_actionable_run.sh",
        reason: "validates easy_node roadmap non-blockchain actionable wrapper contract"
      } else empty end),
      (if $integration_roadmap_next_actions_run_script_exists then {
        id: "integration_roadmap_next_actions_run",
        label: "Roadmap next-actions run contract",
        command: "bash ./scripts/integration_roadmap_next_actions_run.sh",
        reason: "validates roadmap next-actions runner contract"
      } else empty end),
      (if $integration_easy_node_roadmap_next_actions_run_script_exists then {
        id: "integration_easy_node_roadmap_next_actions_run",
        label: "Easy-node roadmap next-actions contract",
        command: "bash ./scripts/integration_easy_node_roadmap_next_actions_run.sh",
        reason: "validates easy_node roadmap next-actions wrapper contract"
      } else empty end)
    ]'
)"
non_blockchain_recommended_gate_id="$(printf '%s\n' "$non_blockchain_actionable_no_sudo_or_github_json" | jq -r 'if length > 0 then .[0].id else "" end')"
non_blockchain_actionable_no_sudo_or_github_count="$(printf '%s\n' "$non_blockchain_actionable_no_sudo_or_github_json" | jq -r 'length')"

next_actions_json="$(jq -c --arg next_action_check_id "$next_action_check_id" --arg next_action_label "$next_action_label" --arg next_action_command "$next_action_command" --argjson profile_default_gate_needs_attention "$profile_default_gate_needs_attention_json" --arg profile_default_gate_next_command "$profile_default_gate_next_command" --argjson multi_vm_stability_needs_attention "$multi_vm_stability_needs_attention_json" --arg multi_vm_stability_next_command "$multi_vm_stability_next_command" --arg multi_vm_stability_next_command_reason "$multi_vm_stability_next_command_reason" --argjson multi_vm_stability_promotion_needs_attention "$multi_vm_stability_promotion_needs_attention_json" --arg multi_vm_stability_promotion_next_command "$multi_vm_stability_promotion_next_command" --arg multi_vm_stability_promotion_next_command_reason "$multi_vm_stability_promotion_next_command_reason" --argjson runtime_actuation_promotion_needs_attention "$runtime_actuation_promotion_needs_attention_json" --arg runtime_actuation_promotion_next_command "$runtime_actuation_promotion_next_command" --arg runtime_actuation_promotion_next_command_reason "$runtime_actuation_promotion_next_command_reason" --argjson profile_default_gate_evidence_pack_needs_attention "$profile_default_gate_evidence_pack_needs_attention_json" --arg profile_default_gate_evidence_pack_next_command "$profile_default_gate_evidence_pack_next_command" --arg profile_default_gate_evidence_pack_next_command_reason "$profile_default_gate_evidence_pack_next_command_reason" --argjson runtime_actuation_promotion_evidence_pack_needs_attention "$runtime_actuation_promotion_evidence_pack_needs_attention_json" --arg runtime_actuation_promotion_evidence_pack_next_command "$runtime_actuation_promotion_evidence_pack_next_command" --arg runtime_actuation_promotion_evidence_pack_next_command_reason "$runtime_actuation_promotion_evidence_pack_next_command_reason" --argjson multi_vm_stability_promotion_evidence_pack_needs_attention "$multi_vm_stability_promotion_evidence_pack_needs_attention_json" --arg multi_vm_stability_promotion_evidence_pack_next_command "$multi_vm_stability_promotion_evidence_pack_next_command" --arg multi_vm_stability_promotion_evidence_pack_next_command_reason "$multi_vm_stability_promotion_evidence_pack_next_command_reason" --argjson blockchain_mainnet_activation_missing_metrics_action_available "$blockchain_mainnet_activation_missing_metrics_action_available_json" --arg blockchain_mainnet_activation_missing_metrics_action_reason "$blockchain_mainnet_activation_missing_metrics_action_reason" --arg blockchain_mainnet_activation_missing_metrics_action_operator_pack_command "$blockchain_mainnet_activation_missing_metrics_action_operator_pack_command" --arg blockchain_mainnet_activation_missing_metrics_action_prefill_command "$blockchain_mainnet_activation_missing_metrics_action_prefill_command" --arg blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command "$blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command" --argjson blockchain_mainnet_activation_refresh_evidence_available "$blockchain_mainnet_activation_refresh_evidence_available_json" --arg blockchain_mainnet_activation_refresh_evidence_command "$blockchain_mainnet_activation_refresh_evidence_command" --arg blockchain_mainnet_activation_refresh_evidence_reason "$blockchain_mainnet_activation_refresh_evidence_reason" '
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
    (if ($profile_default_gate_needs_attention == true and ($profile_default_gate_next_command // "") != "") then {
      id: "profile_default_gate",
      label: "Profile default decision gate",
      command: $profile_default_gate_next_command,
      reason: "non-blocking profile default decision"
    } else empty end),
    (if ($multi_vm_stability_needs_attention == true and ($multi_vm_stability_next_command // "") != "") then {
      id: "profile_compare_multi_vm_stability",
      label: "Profile compare multi-VM stability cycle",
      command: $multi_vm_stability_next_command,
      reason: (if ($multi_vm_stability_next_command_reason // "") != "" then $multi_vm_stability_next_command_reason else "multi-VM stability evidence requires refresh; rerun stability cycle and review check summary" end)
    } else empty end),
    (if ($multi_vm_stability_promotion_needs_attention == true and ($multi_vm_stability_promotion_next_command // "") != "") then {
      id: "profile_compare_multi_vm_stability_promotion",
      label: "Profile compare multi-VM stability promotion cycle",
      command: $multi_vm_stability_promotion_next_command,
      reason: (if ($multi_vm_stability_promotion_next_command_reason // "") != "" then $multi_vm_stability_promotion_next_command_reason else "multi-VM stability promotion evidence requires refresh; rerun promotion cycle" end)
    } else empty end),
    (if ($runtime_actuation_promotion_needs_attention == true and ($runtime_actuation_promotion_next_command // "") != "") then {
      id: "runtime_actuation_promotion",
      label: "Runtime-actuation promotion cycle",
      command: $runtime_actuation_promotion_next_command,
      reason: (if ($runtime_actuation_promotion_next_command_reason // "") != "" then $runtime_actuation_promotion_next_command_reason else "runtime-actuation promotion evidence requires refresh; rerun promotion cycle" end)
    } else empty end),
    (if ($profile_default_gate_evidence_pack_needs_attention == true and ($profile_default_gate_evidence_pack_next_command // "") != "") then {
      id: "profile_default_gate_evidence_pack",
      label: "Profile default evidence-pack publish",
      command: $profile_default_gate_evidence_pack_next_command,
      reason: (if ($profile_default_gate_evidence_pack_next_command_reason // "") != "" then $profile_default_gate_evidence_pack_next_command_reason else "profile-default evidence-pack requires refresh/publish" end)
    } else empty end),
    (if ($runtime_actuation_promotion_evidence_pack_needs_attention == true and ($runtime_actuation_promotion_evidence_pack_next_command // "") != "") then {
      id: "runtime_actuation_promotion_evidence_pack",
      label: "Runtime-actuation evidence-pack publish",
      command: $runtime_actuation_promotion_evidence_pack_next_command,
      reason: (if ($runtime_actuation_promotion_evidence_pack_next_command_reason // "") != "" then $runtime_actuation_promotion_evidence_pack_next_command_reason else "runtime-actuation evidence-pack requires refresh/publish" end)
    } else empty end),
    (if ($multi_vm_stability_promotion_evidence_pack_needs_attention == true and ($multi_vm_stability_promotion_evidence_pack_next_command // "") != "") then {
      id: "profile_compare_multi_vm_stability_promotion_evidence_pack",
      label: "Multi-VM promotion evidence-pack publish",
      command: $multi_vm_stability_promotion_evidence_pack_next_command,
      reason: (if ($multi_vm_stability_promotion_evidence_pack_next_command_reason // "") != "" then $multi_vm_stability_promotion_evidence_pack_next_command_reason else "multi-VM promotion evidence-pack requires refresh/publish" end)
    } else empty end),
    (if ($blockchain_mainnet_activation_missing_metrics_action_available == true and (($blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command // "") != "" or ($blockchain_mainnet_activation_missing_metrics_action_operator_pack_command // "") != "")) then {
      id: "blockchain_mainnet_activation_missing_metrics",
      label: (if ($blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command // "") != "" then "Blockchain missing-metrics real-evidence run" else "Blockchain missing-metrics operator pack" end),
      command: (if ($blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command // "") != "" then $blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command else $blockchain_mainnet_activation_missing_metrics_action_operator_pack_command end),
      reason: (if ($blockchain_mainnet_activation_missing_metrics_action_reason // "") != "" then $blockchain_mainnet_activation_missing_metrics_action_reason else "mainnet activation metrics evidence is missing/invalid; run the real evidence flow" end)
    } else empty end),
    (if ($blockchain_mainnet_activation_refresh_evidence_available == true and ($blockchain_mainnet_activation_refresh_evidence_command // "") != "") then {
      id: "blockchain_mainnet_activation_refresh_evidence",
      label: "Blockchain mainnet activation refresh evidence",
      command: $blockchain_mainnet_activation_refresh_evidence_command,
      reason: (if ($blockchain_mainnet_activation_refresh_evidence_reason // "") != "" then $blockchain_mainnet_activation_refresh_evidence_reason else "stale activation evidence; refresh before trusting the GO signal" end)
    } else empty end),
    (if ($blockchain_mainnet_activation_missing_metrics_action_available == true and ($blockchain_mainnet_activation_missing_metrics_action_prefill_command // "") != "") then {
      id: "blockchain_mainnet_activation_missing_metrics_prefill",
      label: "Blockchain missing-metrics prefill",
      command: $blockchain_mainnet_activation_missing_metrics_action_prefill_command,
      reason: (if ($blockchain_mainnet_activation_missing_metrics_action_reason // "") != "" then $blockchain_mainnet_activation_missing_metrics_action_reason else "mainnet activation metrics evidence is missing/invalid; prefill the operator input" end)
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
elif [[ "$profile_default_gate_needs_attention_json" == "true" ]] \
  && [[ "$runtime_actuation_promotion_needs_attention_json" == "true" ]]; then
  final_status="warn"
  notes="Core roadmap gates are healthy, but optional profile-default and runtime-actuation promotion gates still need attention."
elif [[ "$profile_default_gate_needs_attention_json" == "true" ]]; then
  final_status="warn"
  notes="Core roadmap gates are healthy, but optional profile-default gate still needs attention."
elif [[ "$runtime_actuation_promotion_needs_attention_json" == "true" ]]; then
  final_status="warn"
  notes="Core roadmap gates are healthy, but optional runtime-actuation promotion gate still needs attention."
elif [[ "$profile_default_gate_evidence_pack_needs_attention_json" == "true" ]] \
  || [[ "$runtime_actuation_promotion_evidence_pack_needs_attention_json" == "true" ]] \
  || [[ "$multi_vm_stability_promotion_evidence_pack_needs_attention_json" == "true" ]]; then
  final_status="warn"
  notes="Core roadmap gates are healthy, but evidence-pack publication gates still need attention."
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
  --arg phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source "$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source_json" \
  --arg phase4_windows_full_parity_handoff_status "$phase4_windows_full_parity_handoff_status_json" \
  --argjson phase4_windows_full_parity_handoff_rc "$phase4_windows_full_parity_handoff_rc_json" \
  --argjson phase4_windows_full_parity_handoff_windows_server_packaging_ok "$phase4_windows_full_parity_handoff_windows_server_packaging_ok_json" \
  --argjson phase4_windows_full_parity_handoff_windows_role_runbooks_ok "$phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json" \
  --argjson phase4_windows_full_parity_handoff_cross_platform_interop_ok "$phase4_windows_full_parity_handoff_cross_platform_interop_ok_json" \
  --argjson phase4_windows_full_parity_handoff_role_combination_validation_ok "$phase4_windows_full_parity_handoff_role_combination_validation_ok_json" \
  --argjson phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok "$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json" \
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
  --arg phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status "$phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json" \
  --argjson phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok "$phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json" \
  --arg phase5_settlement_layer_handoff_settlement_shadow_env_status "$phase5_settlement_layer_handoff_settlement_shadow_env_status_json" \
  --argjson phase5_settlement_layer_handoff_settlement_shadow_env_ok "$phase5_settlement_layer_handoff_settlement_shadow_env_ok_json" \
  --arg phase5_settlement_layer_handoff_settlement_shadow_status_surface_status "$phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json" \
  --argjson phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok "$phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json" \
  --arg phase5_settlement_layer_handoff_settlement_dual_asset_parity_status "$phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json" \
  --argjson phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok "$phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json" \
  --arg phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json" \
  --argjson phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok "$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json" \
  --arg phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status "$phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json" \
  --argjson phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok "$phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json" \
  --arg phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status "$phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json" \
  --argjson phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok "$phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json" \
  --arg phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status "$phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json" \
  --argjson phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok "$phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json" \
  --arg phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status "$phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json" \
  --argjson phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok "$phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json" \
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
  --argjson phase6_cosmos_l1_handoff_tdpnd_comet_runtime_smoke_ok "$phase6_cosmos_l1_handoff_tdpnd_comet_runtime_smoke_ok_json" \
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
  --argjson phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok "$phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json" \
  --argjson phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok "$phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json" \
  --arg phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source "$phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source_json" \
  --arg phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source "$phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source_json" \
  --argjson phase7_mainnet_cutover_summary_tdpnd_grpc_live_smoke_ok "$phase7_mainnet_cutover_summary_tdpnd_grpc_live_smoke_ok_json" \
  --argjson phase7_mainnet_cutover_summary_module_tx_surface_ok "$phase7_mainnet_cutover_summary_module_tx_surface_ok_json" \
  --argjson phase7_mainnet_cutover_summary_tdpnd_grpc_auth_live_smoke_ok "$phase7_mainnet_cutover_summary_tdpnd_grpc_auth_live_smoke_ok_json" \
  --argjson phase7_mainnet_cutover_summary_tdpnd_comet_runtime_smoke_ok "$phase7_mainnet_cutover_summary_tdpnd_comet_runtime_smoke_ok_json" \
  --argjson phase7_mainnet_cutover_summary_cosmos_module_coverage_floor_ok "$phase7_mainnet_cutover_summary_cosmos_module_coverage_floor_ok_json" \
  --argjson phase7_mainnet_cutover_summary_cosmos_keeper_coverage_floor_ok "$phase7_mainnet_cutover_summary_cosmos_keeper_coverage_floor_ok_json" \
  --argjson phase7_mainnet_cutover_summary_cosmos_app_coverage_floor_ok "$phase7_mainnet_cutover_summary_cosmos_app_coverage_floor_ok_json" \
  --argjson phase7_mainnet_cutover_summary_dual_write_parity_ok "$phase7_mainnet_cutover_summary_dual_write_parity_ok_json" \
  --argjson blockchain_mainnet_activation_gate_available "$blockchain_mainnet_activation_gate_available_json" \
  --arg blockchain_mainnet_activation_gate_input_summary_json "$blockchain_mainnet_activation_gate_input_summary_json" \
  --arg blockchain_mainnet_activation_gate_source_summary_json "$blockchain_mainnet_activation_gate_source_summary_json" \
  --arg blockchain_mainnet_activation_gate_source_summary_kind "$blockchain_mainnet_activation_gate_source_summary_kind" \
  --arg blockchain_mainnet_activation_gate_status "$blockchain_mainnet_activation_gate_status_json" \
  --arg blockchain_mainnet_activation_gate_decision_json "$blockchain_mainnet_activation_gate_decision_json" \
  --argjson blockchain_mainnet_activation_gate_go "$blockchain_mainnet_activation_gate_go_json" \
  --argjson blockchain_mainnet_activation_gate_no_go "$blockchain_mainnet_activation_gate_no_go_json" \
  --argjson blockchain_mainnet_activation_gate_reasons "$blockchain_mainnet_activation_gate_reasons_json" \
  --argjson blockchain_mainnet_activation_gate_source_paths "$blockchain_mainnet_activation_gate_source_paths_json" \
  --arg blockchain_mainnet_activation_gate_summary_generated_at_json "$blockchain_mainnet_activation_gate_summary_generated_at_json" \
  --arg blockchain_mainnet_activation_gate_summary_age_sec_json "$blockchain_mainnet_activation_gate_summary_age_sec_json" \
  --arg blockchain_mainnet_activation_gate_summary_stale_json "$blockchain_mainnet_activation_gate_summary_stale_json" \
  --argjson blockchain_mainnet_activation_gate_summary_max_age_sec_json "$blockchain_mainnet_activation_gate_summary_max_age_sec_json" \
  --argjson blockchain_bootstrap_governance_graduation_gate_available "$blockchain_bootstrap_governance_graduation_gate_available_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_input_summary_json "$blockchain_bootstrap_governance_graduation_gate_input_summary_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_source_summary_json "$blockchain_bootstrap_governance_graduation_gate_source_summary_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_source_summary_kind "$blockchain_bootstrap_governance_graduation_gate_source_summary_kind" \
  --arg blockchain_bootstrap_governance_graduation_gate_status "$blockchain_bootstrap_governance_graduation_gate_status_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_decision_json "$blockchain_bootstrap_governance_graduation_gate_decision_json" \
  --argjson blockchain_bootstrap_governance_graduation_gate_go "$blockchain_bootstrap_governance_graduation_gate_go_json" \
  --argjson blockchain_bootstrap_governance_graduation_gate_no_go "$blockchain_bootstrap_governance_graduation_gate_no_go_json" \
  --argjson blockchain_bootstrap_governance_graduation_gate_reasons "$blockchain_bootstrap_governance_graduation_gate_reasons_json" \
  --argjson blockchain_bootstrap_governance_graduation_gate_source_paths "$blockchain_bootstrap_governance_graduation_gate_source_paths_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json "$blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json "$blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json" \
  --arg blockchain_bootstrap_governance_graduation_gate_summary_stale_json "$blockchain_bootstrap_governance_graduation_gate_summary_stale_json" \
  --argjson blockchain_bootstrap_governance_graduation_gate_summary_max_age_sec_json "$blockchain_bootstrap_governance_graduation_gate_summary_max_age_sec_json" \
  --argjson blockchain_mainnet_activation_refresh_evidence_available "$blockchain_mainnet_activation_refresh_evidence_available_json" \
  --arg blockchain_mainnet_activation_refresh_evidence_command "$blockchain_mainnet_activation_refresh_evidence_command" \
  --arg blockchain_mainnet_activation_refresh_evidence_reason "$blockchain_mainnet_activation_refresh_evidence_reason" \
  --arg blockchain_mainnet_activation_stale_evidence_status "$blockchain_mainnet_activation_stale_evidence_status_json" \
  --argjson blockchain_mainnet_activation_stale_evidence_action_required "$blockchain_mainnet_activation_stale_evidence_action_required_json" \
  --arg blockchain_mainnet_activation_stale_evidence_reason "$blockchain_mainnet_activation_stale_evidence_reason_json" \
  --arg blockchain_mainnet_activation_stale_evidence_refresh_command "$blockchain_mainnet_activation_stale_evidence_refresh_command_json" \
  --argjson blockchain_mainnet_activation_missing_metrics_action_available "$blockchain_mainnet_activation_missing_metrics_action_available_json" \
  --arg blockchain_mainnet_activation_missing_metrics_action_id "$blockchain_mainnet_activation_missing_metrics_action_id" \
  --arg blockchain_mainnet_activation_missing_metrics_action_reason "$blockchain_mainnet_activation_missing_metrics_action_reason" \
  --arg blockchain_mainnet_activation_missing_metrics_action_normalize_command "$blockchain_mainnet_activation_missing_metrics_action_normalize_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command "$blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_checklist_command "$blockchain_mainnet_activation_missing_metrics_action_checklist_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command "$blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_template_command "$blockchain_mainnet_activation_missing_metrics_action_template_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_prefill_command "$blockchain_mainnet_activation_missing_metrics_action_prefill_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_operator_pack_command "$blockchain_mainnet_activation_missing_metrics_action_operator_pack_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_cycle_command "$blockchain_mainnet_activation_missing_metrics_action_cycle_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command "$blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command" \
  --arg blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command "$blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command" \
  --arg profile_default_gate_status "$profile_default_gate_status" \
  --argjson profile_default_gate_needs_attention "$profile_default_gate_needs_attention_json" \
  --arg profile_default_gate_next_command "$profile_default_gate_next_command" \
  --arg profile_default_gate_next_command_sudo "$profile_default_gate_next_command_sudo" \
  --arg profile_default_gate_next_command_source "$profile_default_gate_next_command_source" \
  --arg profile_default_gate_notes "$profile_default_gate_notes" \
  --arg profile_default_gate_decision "$profile_default_gate_decision" \
  --arg profile_default_gate_recommended_profile "$profile_default_gate_recommended_profile" \
  --arg profile_default_gate_summary_json_manual "$profile_default_gate_summary_json_manual" \
  --argjson profile_default_gate_docker_hint_available "$profile_default_gate_docker_hint_available_json" \
  --arg profile_default_gate_docker_hint_source "$profile_default_gate_docker_hint_source" \
  --arg profile_default_gate_campaign_check_summary_json_resolved "$profile_default_gate_campaign_check_summary_json_resolved" \
  --arg profile_default_gate_docker_matrix_summary_json "$profile_default_gate_docker_matrix_summary_json" \
  --arg profile_default_gate_docker_profile_summary_json "$profile_default_gate_docker_profile_summary_json" \
  --argjson profile_default_gate_selection_policy_evidence_present "$profile_default_gate_selection_policy_evidence_present_json" \
  --argjson profile_default_gate_selection_policy_evidence_valid "$profile_default_gate_selection_policy_evidence_valid_json" \
  --arg profile_default_gate_selection_policy_evidence_note "$profile_default_gate_selection_policy_evidence_note" \
  --argjson profile_default_gate_micro_relay_evidence_available "$profile_default_gate_micro_relay_evidence_available_json" \
  --argjson profile_default_gate_micro_relay_quality_status_pass "$profile_default_gate_micro_relay_quality_status_pass_json" \
  --argjson profile_default_gate_micro_relay_demotion_policy_present "$profile_default_gate_micro_relay_demotion_policy_present_json" \
  --argjson profile_default_gate_micro_relay_promotion_policy_present "$profile_default_gate_micro_relay_promotion_policy_present_json" \
  --argjson profile_default_gate_trust_tier_port_unlock_policy_present "$profile_default_gate_trust_tier_port_unlock_policy_present_json" \
  --arg profile_default_gate_micro_relay_evidence_note "$profile_default_gate_micro_relay_evidence_note" \
  --argjson profile_default_gate_runtime_actuation_ready "$profile_default_gate_runtime_actuation_ready_json" \
  --arg profile_default_gate_runtime_actuation_status "$profile_default_gate_runtime_actuation_status_json" \
  --arg profile_default_gate_runtime_actuation_reason "$profile_default_gate_runtime_actuation_reason" \
  --arg profile_default_gate_stability_summary_json "$profile_default_gate_stability_summary_json" \
  --argjson profile_default_gate_stability_summary_available "$profile_default_gate_stability_summary_available_json" \
  --arg profile_default_gate_stability_status "$profile_default_gate_stability_status_json" \
  --argjson profile_default_gate_stability_rc "$profile_default_gate_stability_rc_json" \
  --argjson profile_default_gate_stability_runs_requested "$profile_default_gate_stability_runs_requested_json" \
  --argjson profile_default_gate_stability_runs_completed "$profile_default_gate_stability_runs_completed_json" \
  --argjson profile_default_gate_stability_selection_policy_present_all "$profile_default_gate_stability_selection_policy_present_all_json" \
  --argjson profile_default_gate_stability_consistent_selection_policy "$profile_default_gate_stability_consistent_selection_policy_json" \
  --argjson profile_default_gate_stability_ok "$profile_default_gate_stability_ok_json" \
  --argjson profile_default_gate_stability_recommended_profile_counts "$profile_default_gate_stability_recommended_profile_counts_json" \
  --arg profile_default_gate_stability_check_summary_json "$profile_default_gate_stability_check_summary_json" \
  --argjson profile_default_gate_stability_check_summary_available "$profile_default_gate_stability_check_summary_available_json" \
  --arg profile_default_gate_stability_check_decision "$profile_default_gate_stability_check_decision_json" \
  --arg profile_default_gate_stability_check_status "$profile_default_gate_stability_check_status_json" \
  --argjson profile_default_gate_stability_check_rc "$profile_default_gate_stability_check_rc_json" \
  --arg profile_default_gate_stability_check_modal_recommended_profile "$profile_default_gate_stability_check_modal_recommended_profile_json" \
  --argjson profile_default_gate_stability_check_modal_support_rate_pct "$profile_default_gate_stability_check_modal_support_rate_pct_json" \
  --arg profile_default_gate_stability_cycle_summary_json "$profile_default_gate_stability_cycle_summary_json" \
  --argjson profile_default_gate_stability_cycle_summary_available "$profile_default_gate_stability_cycle_summary_available_json" \
  --arg profile_default_gate_stability_cycle_decision "$profile_default_gate_stability_cycle_decision_json" \
  --arg profile_default_gate_stability_cycle_status "$profile_default_gate_stability_cycle_status_json" \
  --argjson profile_default_gate_stability_cycle_rc "$profile_default_gate_stability_cycle_rc_json" \
  --arg profile_default_gate_stability_cycle_failure_stage "$profile_default_gate_stability_cycle_failure_stage_json" \
  --arg profile_default_gate_stability_cycle_failure_reason "$profile_default_gate_stability_cycle_failure_reason_json" \
  --arg profile_compare_multi_vm_stability_input_summary_json "$multi_vm_stability_input_summary_json" \
  --argjson profile_compare_multi_vm_stability_available "$multi_vm_stability_available_json" \
  --arg profile_compare_multi_vm_stability_source_summary_json "$multi_vm_stability_source_summary_json" \
  --arg profile_compare_multi_vm_stability_source_summary_kind "$multi_vm_stability_source_summary_kind" \
  --arg profile_compare_multi_vm_stability_status "$multi_vm_stability_status_json" \
  --argjson profile_compare_multi_vm_stability_rc "$multi_vm_stability_rc_json" \
  --arg profile_compare_multi_vm_stability_decision "$multi_vm_stability_decision_json" \
  --argjson profile_compare_multi_vm_stability_go "$multi_vm_stability_go_json" \
  --argjson profile_compare_multi_vm_stability_no_go "$multi_vm_stability_no_go_json" \
  --arg profile_compare_multi_vm_stability_recommended_profile "$multi_vm_stability_recommended_profile_json" \
  --argjson profile_compare_multi_vm_stability_support_rate_pct "$multi_vm_stability_support_rate_pct_json" \
  --argjson profile_compare_multi_vm_stability_runs_requested "$multi_vm_stability_runs_requested_json" \
  --argjson profile_compare_multi_vm_stability_runs_completed "$multi_vm_stability_runs_completed_json" \
  --argjson profile_compare_multi_vm_stability_runs_fail "$multi_vm_stability_runs_fail_json" \
  --argjson profile_compare_multi_vm_stability_decision_counts "$multi_vm_stability_decision_counts_json" \
  --argjson profile_compare_multi_vm_stability_recommended_profile_counts "$multi_vm_stability_recommended_profile_counts_json" \
  --argjson profile_compare_multi_vm_stability_reasons "$multi_vm_stability_reasons_json" \
  --arg profile_compare_multi_vm_stability_notes "$multi_vm_stability_notes_json" \
  --argjson profile_compare_multi_vm_stability_needs_attention "$multi_vm_stability_needs_attention_json" \
  --arg profile_compare_multi_vm_stability_next_command "$multi_vm_stability_next_command" \
  --arg profile_compare_multi_vm_stability_next_command_reason "$multi_vm_stability_next_command_reason" \
  --arg profile_compare_multi_vm_stability_promotion_input_summary_json "$multi_vm_stability_promotion_input_summary_json" \
  --argjson profile_compare_multi_vm_stability_promotion_available "$multi_vm_stability_promotion_available_json" \
  --arg profile_compare_multi_vm_stability_promotion_source_summary_json "$multi_vm_stability_promotion_source_summary_json" \
  --arg profile_compare_multi_vm_stability_promotion_status "$multi_vm_stability_promotion_status_json" \
  --argjson profile_compare_multi_vm_stability_promotion_rc "$multi_vm_stability_promotion_rc_json" \
  --arg profile_compare_multi_vm_stability_promotion_decision "$multi_vm_stability_promotion_decision_json" \
  --argjson profile_compare_multi_vm_stability_promotion_go "$multi_vm_stability_promotion_go_json" \
  --argjson profile_compare_multi_vm_stability_promotion_no_go "$multi_vm_stability_promotion_no_go_json" \
  --argjson profile_compare_multi_vm_stability_promotion_reasons "$multi_vm_stability_promotion_reasons_json" \
  --arg profile_compare_multi_vm_stability_promotion_notes "$multi_vm_stability_promotion_notes_json" \
  --argjson profile_compare_multi_vm_stability_promotion_needs_attention "$multi_vm_stability_promotion_needs_attention_json" \
  --arg profile_compare_multi_vm_stability_promotion_next_command "$multi_vm_stability_promotion_next_command" \
  --arg profile_compare_multi_vm_stability_promotion_next_command_reason "$multi_vm_stability_promotion_next_command_reason" \
  --arg runtime_actuation_promotion_input_summary_json "$runtime_actuation_promotion_input_summary_json" \
  --argjson runtime_actuation_promotion_available "$runtime_actuation_promotion_available_json" \
  --arg runtime_actuation_promotion_source_summary_json "$runtime_actuation_promotion_source_summary_json" \
  --arg runtime_actuation_promotion_status "$runtime_actuation_promotion_status_json" \
  --argjson runtime_actuation_promotion_rc "$runtime_actuation_promotion_rc_json" \
  --arg runtime_actuation_promotion_decision "$runtime_actuation_promotion_decision_json" \
  --argjson runtime_actuation_promotion_go "$runtime_actuation_promotion_go_json" \
  --argjson runtime_actuation_promotion_no_go "$runtime_actuation_promotion_no_go_json" \
  --argjson runtime_actuation_promotion_reasons "$runtime_actuation_promotion_reasons_json" \
  --arg runtime_actuation_promotion_notes "$runtime_actuation_promotion_notes_json" \
  --argjson runtime_actuation_promotion_needs_attention "$runtime_actuation_promotion_needs_attention_json" \
  --arg runtime_actuation_promotion_next_command "$runtime_actuation_promotion_next_command" \
  --arg runtime_actuation_promotion_next_command_reason "$runtime_actuation_promotion_next_command_reason" \
  --argjson profile_default_gate_evidence_pack_available "$profile_default_gate_evidence_pack_available_json" \
  --arg profile_default_gate_evidence_pack_input_summary_json "$profile_default_gate_evidence_pack_input_summary_json" \
  --arg profile_default_gate_evidence_pack_source_summary_json "$profile_default_gate_evidence_pack_source_summary_json" \
  --arg profile_default_gate_evidence_pack_status "$profile_default_gate_evidence_pack_status_json" \
  --argjson profile_default_gate_evidence_pack_rc "$profile_default_gate_evidence_pack_rc_json" \
  --arg profile_default_gate_evidence_pack_decision "$profile_default_gate_evidence_pack_decision_json" \
  --argjson profile_default_gate_evidence_pack_go "$profile_default_gate_evidence_pack_go_json" \
  --argjson profile_default_gate_evidence_pack_no_go "$profile_default_gate_evidence_pack_no_go_json" \
  --argjson profile_default_gate_evidence_pack_reasons "$profile_default_gate_evidence_pack_reasons_json" \
  --arg profile_default_gate_evidence_pack_notes "$profile_default_gate_evidence_pack_notes_json" \
  --argjson profile_default_gate_evidence_pack_needs_attention "$profile_default_gate_evidence_pack_needs_attention_json" \
  --argjson profile_default_gate_evidence_pack_helper_available "$profile_default_gate_evidence_pack_helper_available_json" \
  --arg profile_default_gate_evidence_pack_next_command "$profile_default_gate_evidence_pack_next_command" \
  --arg profile_default_gate_evidence_pack_next_command_reason "$profile_default_gate_evidence_pack_next_command_reason" \
  --argjson runtime_actuation_promotion_evidence_pack_available "$runtime_actuation_promotion_evidence_pack_available_json" \
  --arg runtime_actuation_promotion_evidence_pack_input_summary_json "$runtime_actuation_promotion_evidence_pack_input_summary_json" \
  --arg runtime_actuation_promotion_evidence_pack_source_summary_json "$runtime_actuation_promotion_evidence_pack_source_summary_json" \
  --arg runtime_actuation_promotion_evidence_pack_status "$runtime_actuation_promotion_evidence_pack_status_json" \
  --argjson runtime_actuation_promotion_evidence_pack_rc "$runtime_actuation_promotion_evidence_pack_rc_json" \
  --arg runtime_actuation_promotion_evidence_pack_decision "$runtime_actuation_promotion_evidence_pack_decision_json" \
  --argjson runtime_actuation_promotion_evidence_pack_go "$runtime_actuation_promotion_evidence_pack_go_json" \
  --argjson runtime_actuation_promotion_evidence_pack_no_go "$runtime_actuation_promotion_evidence_pack_no_go_json" \
  --argjson runtime_actuation_promotion_evidence_pack_reasons "$runtime_actuation_promotion_evidence_pack_reasons_json" \
  --arg runtime_actuation_promotion_evidence_pack_notes "$runtime_actuation_promotion_evidence_pack_notes_json" \
  --argjson runtime_actuation_promotion_evidence_pack_needs_attention "$runtime_actuation_promotion_evidence_pack_needs_attention_json" \
  --argjson runtime_actuation_promotion_evidence_pack_helper_available "$runtime_actuation_promotion_evidence_pack_helper_available_json" \
  --arg runtime_actuation_promotion_evidence_pack_next_command "$runtime_actuation_promotion_evidence_pack_next_command" \
  --arg runtime_actuation_promotion_evidence_pack_next_command_reason "$runtime_actuation_promotion_evidence_pack_next_command_reason" \
  --argjson multi_vm_stability_promotion_evidence_pack_available "$multi_vm_stability_promotion_evidence_pack_available_json" \
  --arg multi_vm_stability_promotion_evidence_pack_input_summary_json "$multi_vm_stability_promotion_evidence_pack_input_summary_json" \
  --arg multi_vm_stability_promotion_evidence_pack_source_summary_json "$multi_vm_stability_promotion_evidence_pack_source_summary_json" \
  --arg multi_vm_stability_promotion_evidence_pack_status "$multi_vm_stability_promotion_evidence_pack_status_json" \
  --argjson multi_vm_stability_promotion_evidence_pack_rc "$multi_vm_stability_promotion_evidence_pack_rc_json" \
  --arg multi_vm_stability_promotion_evidence_pack_decision "$multi_vm_stability_promotion_evidence_pack_decision_json" \
  --argjson multi_vm_stability_promotion_evidence_pack_go "$multi_vm_stability_promotion_evidence_pack_go_json" \
  --argjson multi_vm_stability_promotion_evidence_pack_no_go "$multi_vm_stability_promotion_evidence_pack_no_go_json" \
  --argjson multi_vm_stability_promotion_evidence_pack_reasons "$multi_vm_stability_promotion_evidence_pack_reasons_json" \
  --arg multi_vm_stability_promotion_evidence_pack_notes "$multi_vm_stability_promotion_evidence_pack_notes_json" \
  --argjson multi_vm_stability_promotion_evidence_pack_needs_attention "$multi_vm_stability_promotion_evidence_pack_needs_attention_json" \
  --argjson multi_vm_stability_promotion_evidence_pack_helper_available "$multi_vm_stability_promotion_evidence_pack_helper_available_json" \
  --arg multi_vm_stability_promotion_evidence_pack_next_command "$multi_vm_stability_promotion_evidence_pack_next_command" \
  --arg multi_vm_stability_promotion_evidence_pack_next_command_reason "$multi_vm_stability_promotion_evidence_pack_next_command_reason" \
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
  --arg blockchain_recommended_gate_id "$blockchain_recommended_gate_id" \
  --arg blockchain_recommended_gate_reason "$blockchain_recommended_gate_reason" \
  --arg blockchain_recommended_gate_command "$blockchain_recommended_gate_command" \
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
  --arg profile_compare_signoff_summary_json "$profile_compare_signoff_summary_json" \
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
        role_combination_validation_ok: $phase4_windows_full_parity_handoff_role_combination_validation_ok,
        windows_native_bootstrap_guardrails_ok: $phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok,
        windows_native_bootstrap_guardrails_ok_source: (if $phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source == "" then null else $phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source end)
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
        settlement_adapter_signed_tx_roundtrip_status: (if $phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status == "" then null else $phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status end),
        settlement_adapter_signed_tx_roundtrip_ok: $phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok,
        settlement_shadow_env_status: (if $phase5_settlement_layer_handoff_settlement_shadow_env_status == "" then null else $phase5_settlement_layer_handoff_settlement_shadow_env_status end),
        settlement_shadow_env_ok: $phase5_settlement_layer_handoff_settlement_shadow_env_ok,
        settlement_shadow_status_surface_status: (if $phase5_settlement_layer_handoff_settlement_shadow_status_surface_status == "" then null else $phase5_settlement_layer_handoff_settlement_shadow_status_surface_status end),
        settlement_shadow_status_surface_ok: $phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok,
        settlement_dual_asset_parity_status: (if $phase5_settlement_layer_handoff_settlement_dual_asset_parity_status == "" then null else $phase5_settlement_layer_handoff_settlement_dual_asset_parity_status end),
        settlement_dual_asset_parity_ok: $phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok,
        issuer_sponsor_api_live_smoke_status: (if $phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status == "" then null else $phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status end),
        issuer_sponsor_api_live_smoke_ok: $phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok,
        issuer_sponsor_vpn_session_live_smoke_status: (if $phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status == "" then null else $phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status end),
        issuer_sponsor_vpn_session_live_smoke_ok: $phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok,
        issuer_settlement_status_live_smoke_status: (if $phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status == "" then null else $phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status end),
        issuer_settlement_status_live_smoke_ok: $phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok,
        issuer_admin_blockchain_handlers_coverage_status: (if $phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status == "" then null else $phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status end),
        issuer_admin_blockchain_handlers_coverage_ok: $phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok,
        exit_settlement_status_live_smoke_status: (if $phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status == "" then null else $phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status end),
        exit_settlement_status_live_smoke_ok: $phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok
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
      profile_default_gate: {
        status: $profile_default_gate_status,
        needs_attention: $profile_default_gate_needs_attention,
        next_command: (if $profile_default_gate_next_command == "" then null else $profile_default_gate_next_command end),
        next_command_sudo: (if $profile_default_gate_next_command_sudo == "" then null else $profile_default_gate_next_command_sudo end),
        next_command_source: (if $profile_default_gate_next_command_source == "" then null else $profile_default_gate_next_command_source end),
        notes: (if $profile_default_gate_notes == "" then null else $profile_default_gate_notes end),
        decision: (if $profile_default_gate_decision == "" then null else $profile_default_gate_decision end),
        recommended_profile: (if $profile_default_gate_recommended_profile == "" then null else $profile_default_gate_recommended_profile end),
        summary_json: (if $profile_default_gate_summary_json_manual == "" then null else $profile_default_gate_summary_json_manual end),
        docker_hint_available: $profile_default_gate_docker_hint_available,
        docker_hint_source: (if $profile_default_gate_docker_hint_source == "" then null else $profile_default_gate_docker_hint_source end),
        campaign_check_summary_json_resolved: (if $profile_default_gate_campaign_check_summary_json_resolved == "" then null else $profile_default_gate_campaign_check_summary_json_resolved end),
        docker_matrix_summary_json: (if $profile_default_gate_docker_matrix_summary_json == "" then null else $profile_default_gate_docker_matrix_summary_json end),
        docker_profile_summary_json: (if $profile_default_gate_docker_profile_summary_json == "" then null else $profile_default_gate_docker_profile_summary_json end),
        stability_summary_json: (if $profile_default_gate_stability_summary_json == "" then null else $profile_default_gate_stability_summary_json end),
        stability_summary_available: $profile_default_gate_stability_summary_available,
        stability_status: (if $profile_default_gate_stability_status == "" then null else $profile_default_gate_stability_status end),
        stability_rc: $profile_default_gate_stability_rc,
        stability_runs_requested: $profile_default_gate_stability_runs_requested,
        stability_runs_completed: $profile_default_gate_stability_runs_completed,
        stability_selection_policy_present_all: $profile_default_gate_stability_selection_policy_present_all,
        stability_consistent_selection_policy: $profile_default_gate_stability_consistent_selection_policy,
        stability_ok: $profile_default_gate_stability_ok,
        stability_recommended_profile_counts: $profile_default_gate_stability_recommended_profile_counts,
        stability_check_summary_json: (if $profile_default_gate_stability_check_summary_json == "" then null else $profile_default_gate_stability_check_summary_json end),
        stability_check_summary_available: $profile_default_gate_stability_check_summary_available,
        stability_check_decision: (if $profile_default_gate_stability_check_decision == "" then null else $profile_default_gate_stability_check_decision end),
        stability_check_status: (if $profile_default_gate_stability_check_status == "" then null else $profile_default_gate_stability_check_status end),
        stability_check_rc: $profile_default_gate_stability_check_rc,
        stability_check_modal_recommended_profile: (
          if $profile_default_gate_stability_check_modal_recommended_profile == "" then null
          else $profile_default_gate_stability_check_modal_recommended_profile
          end
        ),
        stability_check_modal_support_rate_pct: $profile_default_gate_stability_check_modal_support_rate_pct,
        cycle_summary_json: (if $profile_default_gate_stability_cycle_summary_json == "" then null else $profile_default_gate_stability_cycle_summary_json end),
        cycle_summary_available: $profile_default_gate_stability_cycle_summary_available,
        cycle_decision: (if $profile_default_gate_stability_cycle_decision == "" then null else $profile_default_gate_stability_cycle_decision end),
        cycle_status: (if $profile_default_gate_stability_cycle_status == "" then null else $profile_default_gate_stability_cycle_status end),
        cycle_rc: $profile_default_gate_stability_cycle_rc,
        cycle_failure_stage: (if $profile_default_gate_stability_cycle_failure_stage == "" then null else $profile_default_gate_stability_cycle_failure_stage end),
        cycle_failure_reason: (if $profile_default_gate_stability_cycle_failure_reason == "" then null else $profile_default_gate_stability_cycle_failure_reason end),
        selection_policy_evidence_present: $profile_default_gate_selection_policy_evidence_present,
        selection_policy_evidence_valid: $profile_default_gate_selection_policy_evidence_valid,
        selection_policy_evidence_note: (if $profile_default_gate_selection_policy_evidence_note == "" then null else $profile_default_gate_selection_policy_evidence_note end),
        micro_relay_evidence_available: $profile_default_gate_micro_relay_evidence_available,
        micro_relay_quality_status_pass: $profile_default_gate_micro_relay_quality_status_pass,
        micro_relay_demotion_policy_present: $profile_default_gate_micro_relay_demotion_policy_present,
        micro_relay_promotion_policy_present: $profile_default_gate_micro_relay_promotion_policy_present,
        trust_tier_port_unlock_policy_present: $profile_default_gate_trust_tier_port_unlock_policy_present,
        micro_relay_evidence_note: (if $profile_default_gate_micro_relay_evidence_note == "" then null else $profile_default_gate_micro_relay_evidence_note end),
        runtime_actuation_ready: $profile_default_gate_runtime_actuation_ready,
        runtime_actuation_status: $profile_default_gate_runtime_actuation_status,
        runtime_actuation_reason: $profile_default_gate_runtime_actuation_reason
      },
      multi_vm_stability: {
        available: $profile_compare_multi_vm_stability_available,
        input_summary_json: (if $profile_compare_multi_vm_stability_input_summary_json == "" then null else $profile_compare_multi_vm_stability_input_summary_json end),
        source_summary_json: (if $profile_compare_multi_vm_stability_source_summary_json == "" then null else $profile_compare_multi_vm_stability_source_summary_json end),
        source_summary_kind: (if $profile_compare_multi_vm_stability_source_summary_kind == "" then null else $profile_compare_multi_vm_stability_source_summary_kind end),
        status: (if $profile_compare_multi_vm_stability_status == "" then null else $profile_compare_multi_vm_stability_status end),
        rc: $profile_compare_multi_vm_stability_rc,
        decision: (if $profile_compare_multi_vm_stability_decision == "" then null else $profile_compare_multi_vm_stability_decision end),
        go: $profile_compare_multi_vm_stability_go,
        no_go: $profile_compare_multi_vm_stability_no_go,
        recommended_profile: (
          if $profile_compare_multi_vm_stability_recommended_profile == "" then null
          else $profile_compare_multi_vm_stability_recommended_profile
          end
        ),
        support_rate_pct: $profile_compare_multi_vm_stability_support_rate_pct,
        runs_requested: $profile_compare_multi_vm_stability_runs_requested,
        runs_completed: $profile_compare_multi_vm_stability_runs_completed,
        runs_fail: $profile_compare_multi_vm_stability_runs_fail,
        decision_counts: $profile_compare_multi_vm_stability_decision_counts,
        recommended_profile_counts: $profile_compare_multi_vm_stability_recommended_profile_counts,
        reasons: $profile_compare_multi_vm_stability_reasons,
        notes: (if $profile_compare_multi_vm_stability_notes == "" then null else $profile_compare_multi_vm_stability_notes end),
        needs_attention: $profile_compare_multi_vm_stability_needs_attention,
        next_command: (if $profile_compare_multi_vm_stability_next_command == "" then null else $profile_compare_multi_vm_stability_next_command end),
        next_command_reason: (
          if $profile_compare_multi_vm_stability_next_command_reason == "" then null
          else $profile_compare_multi_vm_stability_next_command_reason
          end
        )
      },
      multi_vm_stability_promotion: {
        available: $profile_compare_multi_vm_stability_promotion_available,
        input_summary_json: (if $profile_compare_multi_vm_stability_promotion_input_summary_json == "" then null else $profile_compare_multi_vm_stability_promotion_input_summary_json end),
        source_summary_json: (if $profile_compare_multi_vm_stability_promotion_source_summary_json == "" then null else $profile_compare_multi_vm_stability_promotion_source_summary_json end),
        status: (if $profile_compare_multi_vm_stability_promotion_status == "" then null else $profile_compare_multi_vm_stability_promotion_status end),
        rc: $profile_compare_multi_vm_stability_promotion_rc,
        decision: (if $profile_compare_multi_vm_stability_promotion_decision == "" then null else $profile_compare_multi_vm_stability_promotion_decision end),
        go: $profile_compare_multi_vm_stability_promotion_go,
        no_go: $profile_compare_multi_vm_stability_promotion_no_go,
        reasons: $profile_compare_multi_vm_stability_promotion_reasons,
        notes: (if $profile_compare_multi_vm_stability_promotion_notes == "" then null else $profile_compare_multi_vm_stability_promotion_notes end),
        needs_attention: $profile_compare_multi_vm_stability_promotion_needs_attention,
        next_command: (if $profile_compare_multi_vm_stability_promotion_next_command == "" then null else $profile_compare_multi_vm_stability_promotion_next_command end),
        next_command_reason: (
          if $profile_compare_multi_vm_stability_promotion_next_command_reason == "" then null
          else $profile_compare_multi_vm_stability_promotion_next_command_reason
          end
        )
      },
      runtime_actuation_promotion: {
        available: $runtime_actuation_promotion_available,
        input_summary_json: (if $runtime_actuation_promotion_input_summary_json == "" then null else $runtime_actuation_promotion_input_summary_json end),
        source_summary_json: (if $runtime_actuation_promotion_source_summary_json == "" then null else $runtime_actuation_promotion_source_summary_json end),
        status: (if $runtime_actuation_promotion_status == "" then null else $runtime_actuation_promotion_status end),
        rc: $runtime_actuation_promotion_rc,
        decision: (if $runtime_actuation_promotion_decision == "" then null else $runtime_actuation_promotion_decision end),
        go: $runtime_actuation_promotion_go,
        no_go: $runtime_actuation_promotion_no_go,
        reasons: $runtime_actuation_promotion_reasons,
        notes: (if $runtime_actuation_promotion_notes == "" then null else $runtime_actuation_promotion_notes end),
        needs_attention: $runtime_actuation_promotion_needs_attention,
        next_command: (if $runtime_actuation_promotion_next_command == "" then null else $runtime_actuation_promotion_next_command end),
        next_command_reason: (
          if $runtime_actuation_promotion_next_command_reason == "" then null
          else $runtime_actuation_promotion_next_command_reason
          end
        )
      },
      profile_default_gate_evidence_pack: {
        available: $profile_default_gate_evidence_pack_available,
        input_summary_json: (if $profile_default_gate_evidence_pack_input_summary_json == "" then null else $profile_default_gate_evidence_pack_input_summary_json end),
        source_summary_json: (if $profile_default_gate_evidence_pack_source_summary_json == "" then null else $profile_default_gate_evidence_pack_source_summary_json end),
        status: (if $profile_default_gate_evidence_pack_status == "" then null else $profile_default_gate_evidence_pack_status end),
        rc: $profile_default_gate_evidence_pack_rc,
        decision: (if $profile_default_gate_evidence_pack_decision == "" then null else $profile_default_gate_evidence_pack_decision end),
        go: $profile_default_gate_evidence_pack_go,
        no_go: $profile_default_gate_evidence_pack_no_go,
        reasons: $profile_default_gate_evidence_pack_reasons,
        notes: (if $profile_default_gate_evidence_pack_notes == "" then null else $profile_default_gate_evidence_pack_notes end),
        needs_attention: $profile_default_gate_evidence_pack_needs_attention,
        helper_available: $profile_default_gate_evidence_pack_helper_available,
        next_command: (if $profile_default_gate_evidence_pack_next_command == "" then null else $profile_default_gate_evidence_pack_next_command end),
        next_command_reason: (
          if $profile_default_gate_evidence_pack_next_command_reason == "" then null
          else $profile_default_gate_evidence_pack_next_command_reason
          end
        )
      },
      runtime_actuation_promotion_evidence_pack: {
        available: $runtime_actuation_promotion_evidence_pack_available,
        input_summary_json: (if $runtime_actuation_promotion_evidence_pack_input_summary_json == "" then null else $runtime_actuation_promotion_evidence_pack_input_summary_json end),
        source_summary_json: (if $runtime_actuation_promotion_evidence_pack_source_summary_json == "" then null else $runtime_actuation_promotion_evidence_pack_source_summary_json end),
        status: (if $runtime_actuation_promotion_evidence_pack_status == "" then null else $runtime_actuation_promotion_evidence_pack_status end),
        rc: $runtime_actuation_promotion_evidence_pack_rc,
        decision: (if $runtime_actuation_promotion_evidence_pack_decision == "" then null else $runtime_actuation_promotion_evidence_pack_decision end),
        go: $runtime_actuation_promotion_evidence_pack_go,
        no_go: $runtime_actuation_promotion_evidence_pack_no_go,
        reasons: $runtime_actuation_promotion_evidence_pack_reasons,
        notes: (if $runtime_actuation_promotion_evidence_pack_notes == "" then null else $runtime_actuation_promotion_evidence_pack_notes end),
        needs_attention: $runtime_actuation_promotion_evidence_pack_needs_attention,
        helper_available: $runtime_actuation_promotion_evidence_pack_helper_available,
        next_command: (if $runtime_actuation_promotion_evidence_pack_next_command == "" then null else $runtime_actuation_promotion_evidence_pack_next_command end),
        next_command_reason: (
          if $runtime_actuation_promotion_evidence_pack_next_command_reason == "" then null
          else $runtime_actuation_promotion_evidence_pack_next_command_reason
          end
        )
      },
      profile_compare_multi_vm_stability_promotion_evidence_pack: {
        available: $multi_vm_stability_promotion_evidence_pack_available,
        input_summary_json: (if $multi_vm_stability_promotion_evidence_pack_input_summary_json == "" then null else $multi_vm_stability_promotion_evidence_pack_input_summary_json end),
        source_summary_json: (if $multi_vm_stability_promotion_evidence_pack_source_summary_json == "" then null else $multi_vm_stability_promotion_evidence_pack_source_summary_json end),
        status: (if $multi_vm_stability_promotion_evidence_pack_status == "" then null else $multi_vm_stability_promotion_evidence_pack_status end),
        rc: $multi_vm_stability_promotion_evidence_pack_rc,
        decision: (if $multi_vm_stability_promotion_evidence_pack_decision == "" then null else $multi_vm_stability_promotion_evidence_pack_decision end),
        go: $multi_vm_stability_promotion_evidence_pack_go,
        no_go: $multi_vm_stability_promotion_evidence_pack_no_go,
        reasons: $multi_vm_stability_promotion_evidence_pack_reasons,
        notes: (if $multi_vm_stability_promotion_evidence_pack_notes == "" then null else $multi_vm_stability_promotion_evidence_pack_notes end),
        needs_attention: $multi_vm_stability_promotion_evidence_pack_needs_attention,
        helper_available: $multi_vm_stability_promotion_evidence_pack_helper_available,
        next_command: (if $multi_vm_stability_promotion_evidence_pack_next_command == "" then null else $multi_vm_stability_promotion_evidence_pack_next_command end),
        next_command_reason: (
          if $multi_vm_stability_promotion_evidence_pack_next_command_reason == "" then null
          else $multi_vm_stability_promotion_evidence_pack_next_command_reason
          end
        )
      },
      optional_gate_status: {
        profile_default_gate: $profile_default_gate_status,
        profile_compare_multi_vm_stability_promotion: (if $profile_compare_multi_vm_stability_promotion_status == "" then "missing" else $profile_compare_multi_vm_stability_promotion_status end),
        runtime_actuation_promotion: (if $runtime_actuation_promotion_status == "" then "missing" else $runtime_actuation_promotion_status end),
        profile_default_gate_evidence_pack: (if $profile_default_gate_evidence_pack_status == "" then "missing" else $profile_default_gate_evidence_pack_status end),
        runtime_actuation_promotion_evidence_pack: (if $runtime_actuation_promotion_evidence_pack_status == "" then "missing" else $runtime_actuation_promotion_evidence_pack_status end),
        profile_compare_multi_vm_stability_promotion_evidence_pack: (if $multi_vm_stability_promotion_evidence_pack_status == "" then "missing" else $multi_vm_stability_promotion_evidence_pack_status end),
        docker_rehearsal_gate: $docker_rehearsal_status,
        real_wg_privileged_gate: $real_wg_privileged_status
      }
    },
    blockchain_track: {
      status: $blockchain_track_status,
      policy: $blockchain_track_policy,
      recommendation: $blockchain_track_recommendation,
      recommended_gate_id: (if $blockchain_recommended_gate_id == "" then null else $blockchain_recommended_gate_id end),
      recommended_gate_reason: (if $blockchain_recommended_gate_reason == "" then null else $blockchain_recommended_gate_reason end),
      recommended_gate_command: (if $blockchain_recommended_gate_command == "" then null else $blockchain_recommended_gate_command end),
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
        tdpnd_grpc_auth_live_smoke_ok: $phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok,
        tdpnd_comet_runtime_smoke_ok: $phase6_cosmos_l1_handoff_tdpnd_comet_runtime_smoke_ok
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
        handoff_run_ok: $phase7_mainnet_cutover_summary_handoff_run_ok,
        mainnet_activation_gate_go_ok: $phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok,
        mainnet_activation_gate_go_ok_source: (if $phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source == "" then null else $phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source end),
        bootstrap_governance_graduation_gate_go_ok: $phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok,
        bootstrap_governance_graduation_gate_go_ok_source: (if $phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source == "" then null else $phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source end),
        tdpnd_grpc_live_smoke_ok: $phase7_mainnet_cutover_summary_tdpnd_grpc_live_smoke_ok,
        module_tx_surface_ok: $phase7_mainnet_cutover_summary_module_tx_surface_ok,
        tdpnd_grpc_auth_live_smoke_ok: $phase7_mainnet_cutover_summary_tdpnd_grpc_auth_live_smoke_ok,
        tdpnd_comet_runtime_smoke_ok: $phase7_mainnet_cutover_summary_tdpnd_comet_runtime_smoke_ok,
        cosmos_module_coverage_floor_ok: $phase7_mainnet_cutover_summary_cosmos_module_coverage_floor_ok,
        cosmos_keeper_coverage_floor_ok: $phase7_mainnet_cutover_summary_cosmos_keeper_coverage_floor_ok,
        cosmos_app_coverage_floor_ok: $phase7_mainnet_cutover_summary_cosmos_app_coverage_floor_ok,
        dual_write_parity_ok: $phase7_mainnet_cutover_summary_dual_write_parity_ok
      },
      mainnet_activation_gate: {
        available: $blockchain_mainnet_activation_gate_available,
        input_summary_json: (if $blockchain_mainnet_activation_gate_input_summary_json == "" then null else $blockchain_mainnet_activation_gate_input_summary_json end),
        source_summary_json: (if $blockchain_mainnet_activation_gate_source_summary_json == "" then null else $blockchain_mainnet_activation_gate_source_summary_json end),
        source_summary_kind: (if $blockchain_mainnet_activation_gate_source_summary_kind == "" then null else $blockchain_mainnet_activation_gate_source_summary_kind end),
        status: $blockchain_mainnet_activation_gate_status,
        decision: (if $blockchain_mainnet_activation_gate_decision_json == "" then null else $blockchain_mainnet_activation_gate_decision_json end),
        go: $blockchain_mainnet_activation_gate_go,
        no_go: $blockchain_mainnet_activation_gate_no_go,
        reasons: $blockchain_mainnet_activation_gate_reasons,
        source_paths: $blockchain_mainnet_activation_gate_source_paths,
        summary_generated_at: (if $blockchain_mainnet_activation_gate_summary_generated_at_json == "" then null else $blockchain_mainnet_activation_gate_summary_generated_at_json end),
        summary_age_sec: (
          if $blockchain_mainnet_activation_gate_summary_age_sec_json == ""
             or $blockchain_mainnet_activation_gate_summary_age_sec_json == "null"
          then null
          else ($blockchain_mainnet_activation_gate_summary_age_sec_json | tonumber)
          end
        ),
        summary_stale: (if $blockchain_mainnet_activation_gate_summary_stale_json == "null" then null else ($blockchain_mainnet_activation_gate_summary_stale_json == "true") end),
        summary_max_age_sec: ($blockchain_mainnet_activation_gate_summary_max_age_sec_json | tonumber)
      },
      bootstrap_governance_graduation_gate: {
        available: $blockchain_bootstrap_governance_graduation_gate_available,
        input_summary_json: (if $blockchain_bootstrap_governance_graduation_gate_input_summary_json == "" then null else $blockchain_bootstrap_governance_graduation_gate_input_summary_json end),
        source_summary_json: (if $blockchain_bootstrap_governance_graduation_gate_source_summary_json == "" then null else $blockchain_bootstrap_governance_graduation_gate_source_summary_json end),
        source_summary_kind: (if $blockchain_bootstrap_governance_graduation_gate_source_summary_kind == "" then null else $blockchain_bootstrap_governance_graduation_gate_source_summary_kind end),
        status: $blockchain_bootstrap_governance_graduation_gate_status,
        decision: (if $blockchain_bootstrap_governance_graduation_gate_decision_json == "" then null else $blockchain_bootstrap_governance_graduation_gate_decision_json end),
        go: $blockchain_bootstrap_governance_graduation_gate_go,
        no_go: $blockchain_bootstrap_governance_graduation_gate_no_go,
        reasons: $blockchain_bootstrap_governance_graduation_gate_reasons,
        source_paths: $blockchain_bootstrap_governance_graduation_gate_source_paths,
        summary_generated_at: (if $blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json == "" then null else $blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json end),
        summary_age_sec: (
          if $blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json == ""
             or $blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json == "null"
          then null
          else ($blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json | tonumber)
          end
        ),
        summary_stale: (if $blockchain_bootstrap_governance_graduation_gate_summary_stale_json == "null" then null else ($blockchain_bootstrap_governance_graduation_gate_summary_stale_json == "true") end),
        summary_max_age_sec: ($blockchain_bootstrap_governance_graduation_gate_summary_max_age_sec_json | tonumber)
      },
      mainnet_activation_missing_metrics_action: {
        available: $blockchain_mainnet_activation_missing_metrics_action_available,
        id: (if $blockchain_mainnet_activation_missing_metrics_action_id == "" then null else $blockchain_mainnet_activation_missing_metrics_action_id end),
        reason: (if $blockchain_mainnet_activation_missing_metrics_action_reason == "" then null else $blockchain_mainnet_activation_missing_metrics_action_reason end),
        normalize_command: (if $blockchain_mainnet_activation_missing_metrics_action_normalize_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_normalize_command end),
        rerun_bundle_command: (if $blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command end),
        checklist_command: (if $blockchain_mainnet_activation_missing_metrics_action_checklist_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_checklist_command end),
          missing_input_template_command: (if $blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command end),
          template_command: (if $blockchain_mainnet_activation_missing_metrics_action_template_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_template_command end),
          prefill_command: (if $blockchain_mainnet_activation_missing_metrics_action_prefill_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_prefill_command end),
          operator_pack_command: (if $blockchain_mainnet_activation_missing_metrics_action_operator_pack_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_operator_pack_command end),
          cycle_command: (if $blockchain_mainnet_activation_missing_metrics_action_cycle_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_cycle_command end),
          seeded_cycle_command: (if $blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command end),
        real_evidence_run_command: (if $blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command == "" then null else $blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command end)
      },
      mainnet_activation_refresh_evidence_action: {
        available: $blockchain_mainnet_activation_refresh_evidence_available,
        id: (if $blockchain_mainnet_activation_refresh_evidence_command == "" then null else "blockchain_mainnet_activation_refresh_evidence" end),
        reason: (if $blockchain_mainnet_activation_refresh_evidence_reason == "" then null else $blockchain_mainnet_activation_refresh_evidence_reason end),
        command: (if $blockchain_mainnet_activation_refresh_evidence_command == "" then null else $blockchain_mainnet_activation_refresh_evidence_command end)
      },
      mainnet_activation_stale_evidence: {
        status: (if $blockchain_mainnet_activation_stale_evidence_status == "" then "unknown" else $blockchain_mainnet_activation_stale_evidence_status end),
        action_required: $blockchain_mainnet_activation_stale_evidence_action_required,
        reason: (if $blockchain_mainnet_activation_stale_evidence_reason == "" then null else $blockchain_mainnet_activation_stale_evidence_reason end),
        refresh_command: (if $blockchain_mainnet_activation_stale_evidence_refresh_command == "" then null else $blockchain_mainnet_activation_stale_evidence_refresh_command end)
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
      profile_compare_signoff_summary_json: (if $profile_compare_signoff_summary_json == "" then null else $profile_compare_signoff_summary_json end),
      profile_default_gate_stability_evidence_pack_summary_json: (if $profile_default_gate_evidence_pack_source_summary_json == "" then null else $profile_default_gate_evidence_pack_source_summary_json end),
      profile_default_gate_evidence_pack_summary_json: (if $profile_default_gate_evidence_pack_source_summary_json == "" then null else $profile_default_gate_evidence_pack_source_summary_json end),
      profile_compare_multi_vm_stability_summary_json: (if $profile_compare_multi_vm_stability_source_summary_json == "" then null else $profile_compare_multi_vm_stability_source_summary_json end),
      profile_compare_multi_vm_stability_promotion_summary_json: (if $profile_compare_multi_vm_stability_promotion_source_summary_json == "" then null else $profile_compare_multi_vm_stability_promotion_source_summary_json end),
      runtime_actuation_multi_vm_evidence_pack_summary_json: (if $runtime_actuation_promotion_evidence_pack_source_summary_json == "" then null else $runtime_actuation_promotion_evidence_pack_source_summary_json end),
      profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json: (if $multi_vm_stability_promotion_evidence_pack_source_summary_json == "" then null else $multi_vm_stability_promotion_evidence_pack_source_summary_json end),
      runtime_actuation_promotion_summary_json: (if $runtime_actuation_promotion_source_summary_json == "" then null else $runtime_actuation_promotion_source_summary_json end),
      runtime_actuation_promotion_evidence_pack_summary_json: (if $runtime_actuation_promotion_evidence_pack_source_summary_json == "" then null else $runtime_actuation_promotion_evidence_pack_source_summary_json end),
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
- Phase-4 windows_native_bootstrap_guardrails_ok: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-4 windows_native_bootstrap_guardrails_ok source: $(jq -r '.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok_source // "none"' "$summary_json")
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
- Phase-5 settlement_adapter_signed_tx_roundtrip_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status // "null"' "$summary_json")
- Phase-5 settlement_adapter_signed_tx_roundtrip_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_shadow_env_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status // "null"' "$summary_json")
- Phase-5 settlement_shadow_env_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_shadow_status_surface_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status // "null"' "$summary_json")
- Phase-5 settlement_shadow_status_surface_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 settlement_dual_asset_parity_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status // "null"' "$summary_json")
- Phase-5 settlement_dual_asset_parity_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 issuer_sponsor_api_live_smoke_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status // "null"' "$summary_json")
- Phase-5 issuer_sponsor_api_live_smoke_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 issuer_sponsor_vpn_session_live_smoke_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status // "null"' "$summary_json")
- Phase-5 issuer_sponsor_vpn_session_live_smoke_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 issuer_settlement_status_live_smoke_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status // "null"' "$summary_json")
- Phase-5 issuer_settlement_status_live_smoke_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 issuer_admin_blockchain_handlers_coverage_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status // "null"' "$summary_json")
- Phase-5 issuer_admin_blockchain_handlers_coverage_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-5 exit_settlement_status_live_smoke_status: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status // "null"' "$summary_json")
- Phase-5 exit_settlement_status_live_smoke_ok: $(jq -r '.vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Resilience handoff available: $(jq -r '.vpn_track.resilience_handoff.available' "$summary_json")
- Resilience handoff source: $(jq -r '.vpn_track.resilience_handoff.source_summary_json // "none"' "$summary_json")
- profile_matrix_stable: $(jq -r '.vpn_track.resilience_handoff.profile_matrix_stable | if . == null then "null" else tostring end' "$summary_json")
- peer_loss_recovery_ok: $(jq -r '.vpn_track.resilience_handoff.peer_loss_recovery_ok | if . == null then "null" else tostring end' "$summary_json")
- session_churn_guard_ok: $(jq -r '.vpn_track.resilience_handoff.session_churn_guard_ok | if . == null then "null" else tostring end' "$summary_json")
- Checks: total=$(jq -r '.vpn_track.counts.total_checks' "$summary_json"), pass=$(jq -r '.vpn_track.counts.pass_checks' "$summary_json"), warn=$(jq -r '.vpn_track.counts.warn_checks' "$summary_json"), fail=$(jq -r '.vpn_track.counts.fail_checks' "$summary_json"), pending=$(jq -r '.vpn_track.counts.pending_checks' "$summary_json")
- Blocking checks: $(jq -r '(.vpn_track.blocking_check_ids // []) | if length == 0 then "none" else join(",") end' "$summary_json")
- Pending real-host checks: $(jq -r '(.vpn_track.pending_real_host_checks // []) | if length == 0 then "none" else map(.check_id) | join(",") end' "$summary_json")
- Optional gate status: profile=$(jq -r '.vpn_track.optional_gate_status.profile_default_gate' "$summary_json"), multi-vm-promotion=$(jq -r '.vpn_track.optional_gate_status.profile_compare_multi_vm_stability_promotion' "$summary_json"), runtime-actuation-promotion=$(jq -r '.vpn_track.optional_gate_status.runtime_actuation_promotion' "$summary_json"), profile-evidence-pack=$(jq -r '.vpn_track.optional_gate_status.profile_default_gate_evidence_pack // "missing"' "$summary_json"), runtime-evidence-pack=$(jq -r '.vpn_track.optional_gate_status.runtime_actuation_promotion_evidence_pack // "missing"' "$summary_json"), multi-vm-evidence-pack=$(jq -r '.vpn_track.optional_gate_status.profile_compare_multi_vm_stability_promotion_evidence_pack // "missing"' "$summary_json"), docker-rehearsal=$(jq -r '.vpn_track.optional_gate_status.docker_rehearsal_gate' "$summary_json"), real-wg=$(jq -r '.vpn_track.optional_gate_status.real_wg_privileged_gate' "$summary_json")
- Profile gate next command: $(jq -r '.vpn_track.profile_default_gate.next_command // "none"' "$summary_json")
- Profile gate sudo fallback: $(jq -r '.vpn_track.profile_default_gate.next_command_sudo // "none"' "$summary_json")
- Profile gate command source: $(jq -r '.vpn_track.profile_default_gate.next_command_source // "none"' "$summary_json")
- Profile gate docker hint available: $(jq -r '.vpn_track.profile_default_gate.docker_hint_available | if . == null then "null" else tostring end' "$summary_json")
- Profile gate docker hint source: $(jq -r '.vpn_track.profile_default_gate.docker_hint_source // "none"' "$summary_json")
- Profile gate campaign-check summary (resolved): $(jq -r '.vpn_track.profile_default_gate.campaign_check_summary_json_resolved // "none"' "$summary_json")
- Profile gate docker matrix summary: $(jq -r '.vpn_track.profile_default_gate.docker_matrix_summary_json // "none"' "$summary_json")
- Profile gate docker profile summary: $(jq -r '.vpn_track.profile_default_gate.docker_profile_summary_json // "none"' "$summary_json")
- Profile gate selection-policy evidence present: $(jq -r '.vpn_track.profile_default_gate.selection_policy_evidence_present | if . == null then "null" else tostring end' "$summary_json")
- Profile gate selection-policy evidence valid: $(jq -r '.vpn_track.profile_default_gate.selection_policy_evidence_valid | if . == null then "null" else tostring end' "$summary_json")
- Profile gate selection-policy evidence note: $(jq -r '.vpn_track.profile_default_gate.selection_policy_evidence_note // "none"' "$summary_json")
- Profile gate micro-relay evidence available: $(jq -r '.vpn_track.profile_default_gate.micro_relay_evidence_available | if . == null then "null" else tostring end' "$summary_json")
- Profile gate micro-relay quality status pass: $(jq -r '.vpn_track.profile_default_gate.micro_relay_quality_status_pass | if . == null then "null" else tostring end' "$summary_json")
- Profile gate micro-relay demotion policy present: $(jq -r '.vpn_track.profile_default_gate.micro_relay_demotion_policy_present | if . == null then "null" else tostring end' "$summary_json")
- Profile gate micro-relay promotion policy present: $(jq -r '.vpn_track.profile_default_gate.micro_relay_promotion_policy_present | if . == null then "null" else tostring end' "$summary_json")
- Profile gate trust-tier port-unlock policy present: $(jq -r '.vpn_track.profile_default_gate.trust_tier_port_unlock_policy_present | if . == null then "null" else tostring end' "$summary_json")
- Profile gate micro-relay evidence note: $(jq -r '.vpn_track.profile_default_gate.micro_relay_evidence_note // "none"' "$summary_json")
- Profile gate runtime-actuation ready: $(jq -r '.vpn_track.profile_default_gate.runtime_actuation_ready | if . == null then "null" else tostring end' "$summary_json")
- Profile gate runtime-actuation status: $(jq -r '.vpn_track.profile_default_gate.runtime_actuation_status // "none"' "$summary_json")
- Profile gate runtime-actuation reason: $(jq -r '.vpn_track.profile_default_gate.runtime_actuation_reason | if . == null or . == "" then "none" else . end' "$summary_json")
- Profile gate stability summary: $(jq -r '.vpn_track.profile_default_gate.stability_summary_json // "none"' "$summary_json")
- Profile gate stability available: $(jq -r '.vpn_track.profile_default_gate.stability_summary_available | if . == null then "null" else tostring end' "$summary_json")
- Profile gate stability status: $(jq -r '.vpn_track.profile_default_gate.stability_status // "none"' "$summary_json")
- Profile gate stability rc: $(jq -r '.vpn_track.profile_default_gate.stability_rc // "null"' "$summary_json")
- Profile gate stability runs: requested=$(jq -r '.vpn_track.profile_default_gate.stability_runs_requested // "null"' "$summary_json"), completed=$(jq -r '.vpn_track.profile_default_gate.stability_runs_completed // "null"' "$summary_json")
- Profile gate stability selection-policy present all: $(jq -r '.vpn_track.profile_default_gate.stability_selection_policy_present_all | if . == null then "null" else tostring end' "$summary_json")
- Profile gate stability consistent selection policy: $(jq -r '.vpn_track.profile_default_gate.stability_consistent_selection_policy | if . == null then "null" else tostring end' "$summary_json")
- Profile gate stability ok: $(jq -r '.vpn_track.profile_default_gate.stability_ok | if . == null then "null" else tostring end' "$summary_json")
- Profile gate stability recommended profile counts: $(jq -r '.vpn_track.profile_default_gate.stability_recommended_profile_counts | if . == null then "null" else tojson end' "$summary_json")
- Profile gate stability-check summary: $(jq -r '.vpn_track.profile_default_gate.stability_check_summary_json // "none"' "$summary_json")
- Profile gate stability-check available: $(jq -r '.vpn_track.profile_default_gate.stability_check_summary_available | if . == null then "null" else tostring end' "$summary_json")
- Profile gate stability-check decision/status: decision=$(jq -r '.vpn_track.profile_default_gate.stability_check_decision // "none"' "$summary_json"), status=$(jq -r '.vpn_track.profile_default_gate.stability_check_status // "none"' "$summary_json")
- Profile gate stability-check rc/modal: rc=$(jq -r '.vpn_track.profile_default_gate.stability_check_rc // "null"' "$summary_json"), modal_profile=$(jq -r '.vpn_track.profile_default_gate.stability_check_modal_recommended_profile // "none"' "$summary_json"), modal_support_rate_pct=$(jq -r '.vpn_track.profile_default_gate.stability_check_modal_support_rate_pct // "null"' "$summary_json")
- Profile gate stability-cycle summary: $(jq -r '.vpn_track.profile_default_gate.cycle_summary_json // "none"' "$summary_json")
- Profile gate stability-cycle available: $(jq -r '.vpn_track.profile_default_gate.cycle_summary_available | if . == null then "null" else tostring end' "$summary_json")
- Profile gate stability-cycle decision/status: decision=$(jq -r '.vpn_track.profile_default_gate.cycle_decision // "none"' "$summary_json"), status=$(jq -r '.vpn_track.profile_default_gate.cycle_status // "none"' "$summary_json")
- Profile gate stability-cycle rc/failure: rc=$(jq -r '.vpn_track.profile_default_gate.cycle_rc // "null"' "$summary_json"), failure_stage=$(jq -r '.vpn_track.profile_default_gate.cycle_failure_stage // "none"' "$summary_json"), failure_reason=$(jq -r '.vpn_track.profile_default_gate.cycle_failure_reason // "none"' "$summary_json")
- Multi-VM stability available: $(jq -r '.vpn_track.multi_vm_stability.available | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM stability input summary: $(jq -r '.vpn_track.multi_vm_stability.input_summary_json // "none"' "$summary_json")
- Multi-VM stability source/kind: source=$(jq -r '.vpn_track.multi_vm_stability.source_summary_json // "none"' "$summary_json"), kind=$(jq -r '.vpn_track.multi_vm_stability.source_summary_kind // "none"' "$summary_json")
- Multi-VM stability status/decision: status=$(jq -r '.vpn_track.multi_vm_stability.status // "none"' "$summary_json"), decision=$(jq -r '.vpn_track.multi_vm_stability.decision // "none"' "$summary_json")
- Multi-VM stability go/no-go: go=$(jq -r '.vpn_track.multi_vm_stability.go | if . == null then "null" else tostring end' "$summary_json"), no_go=$(jq -r '.vpn_track.multi_vm_stability.no_go | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM stability recommendation/support: profile=$(jq -r '.vpn_track.multi_vm_stability.recommended_profile // "none"' "$summary_json"), support_rate_pct=$(jq -r '.vpn_track.multi_vm_stability.support_rate_pct // "null"' "$summary_json")
- Multi-VM stability run counts: requested=$(jq -r '.vpn_track.multi_vm_stability.runs_requested // "null"' "$summary_json"), completed=$(jq -r '.vpn_track.multi_vm_stability.runs_completed // "null"' "$summary_json"), fail=$(jq -r '.vpn_track.multi_vm_stability.runs_fail // "null"' "$summary_json")
- Multi-VM stability decision counts: $(jq -r '.vpn_track.multi_vm_stability.decision_counts | if . == null then "null" else tojson end' "$summary_json")
- Multi-VM stability recommended profile counts: $(jq -r '.vpn_track.multi_vm_stability.recommended_profile_counts | if . == null then "null" else tojson end' "$summary_json")
- Multi-VM stability reasons: $(jq -r '.vpn_track.multi_vm_stability.reasons | if . == null or length == 0 then "none" else join("; ") end' "$summary_json")
- Multi-VM stability notes: $(jq -r '.vpn_track.multi_vm_stability.notes // "none"' "$summary_json")
- Multi-VM stability needs attention: $(jq -r '.vpn_track.multi_vm_stability.needs_attention | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM stability next command: $(jq -r '.vpn_track.multi_vm_stability.next_command // "none"' "$summary_json")
- Multi-VM stability next command reason: $(jq -r '.vpn_track.multi_vm_stability.next_command_reason // "none"' "$summary_json")
- Multi-VM stability promotion available: $(jq -r '.vpn_track.multi_vm_stability_promotion.available | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM stability promotion input/source: input=$(jq -r '.vpn_track.multi_vm_stability_promotion.input_summary_json // "none"' "$summary_json"), source=$(jq -r '.vpn_track.multi_vm_stability_promotion.source_summary_json // "none"' "$summary_json")
- Multi-VM stability promotion status/decision: status=$(jq -r '.vpn_track.multi_vm_stability_promotion.status // "none"' "$summary_json"), decision=$(jq -r '.vpn_track.multi_vm_stability_promotion.decision // "none"' "$summary_json")
- Multi-VM stability promotion go/no-go: go=$(jq -r '.vpn_track.multi_vm_stability_promotion.go | if . == null then "null" else tostring end' "$summary_json"), no_go=$(jq -r '.vpn_track.multi_vm_stability_promotion.no_go | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM stability promotion reasons/notes: reasons=$(jq -r '.vpn_track.multi_vm_stability_promotion.reasons | if . == null or length == 0 then "none" else join("; ") end' "$summary_json"), notes=$(jq -r '.vpn_track.multi_vm_stability_promotion.notes // "none"' "$summary_json")
- Multi-VM stability promotion needs attention: $(jq -r '.vpn_track.multi_vm_stability_promotion.needs_attention | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM stability promotion next command/reason: command=$(jq -r '.vpn_track.multi_vm_stability_promotion.next_command // "none"' "$summary_json"), reason=$(jq -r '.vpn_track.multi_vm_stability_promotion.next_command_reason // "none"' "$summary_json")
- Runtime-actuation promotion available: $(jq -r '.vpn_track.runtime_actuation_promotion.available | if . == null then "null" else tostring end' "$summary_json")
- Runtime-actuation promotion input/source: input=$(jq -r '.vpn_track.runtime_actuation_promotion.input_summary_json // "none"' "$summary_json"), source=$(jq -r '.vpn_track.runtime_actuation_promotion.source_summary_json // "none"' "$summary_json")
- Runtime-actuation promotion status/decision: status=$(jq -r '.vpn_track.runtime_actuation_promotion.status // "none"' "$summary_json"), decision=$(jq -r '.vpn_track.runtime_actuation_promotion.decision // "none"' "$summary_json")
- Runtime-actuation promotion go/no-go: go=$(jq -r '.vpn_track.runtime_actuation_promotion.go | if . == null then "null" else tostring end' "$summary_json"), no_go=$(jq -r '.vpn_track.runtime_actuation_promotion.no_go | if . == null then "null" else tostring end' "$summary_json")
- Runtime-actuation promotion reasons/notes: reasons=$(jq -r '.vpn_track.runtime_actuation_promotion.reasons | if . == null or length == 0 then "none" else join("; ") end' "$summary_json"), notes=$(jq -r '.vpn_track.runtime_actuation_promotion.notes // "none"' "$summary_json")
- Runtime-actuation promotion needs attention: $(jq -r '.vpn_track.runtime_actuation_promotion.needs_attention | if . == null then "null" else tostring end' "$summary_json")
- Runtime-actuation promotion next command/reason: command=$(jq -r '.vpn_track.runtime_actuation_promotion.next_command // "none"' "$summary_json"), reason=$(jq -r '.vpn_track.runtime_actuation_promotion.next_command_reason // "none"' "$summary_json")
- Profile-default evidence pack available: $(jq -r '.vpn_track.profile_default_gate_evidence_pack.available | if . == null then "null" else tostring end' "$summary_json")
- Profile-default evidence pack input/source: input=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.input_summary_json // "none"' "$summary_json"), source=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.source_summary_json // "none"' "$summary_json")
- Profile-default evidence pack status/decision: status=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.status // "none"' "$summary_json"), decision=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.decision // "none"' "$summary_json")
- Profile-default evidence pack helper/needs-attention: helper_available=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.helper_available | if . == null then "null" else tostring end' "$summary_json"), needs_attention=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.needs_attention | if . == null then "null" else tostring end' "$summary_json")
- Profile-default evidence pack next command/reason: command=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.next_command // "none"' "$summary_json"), reason=$(jq -r '.vpn_track.profile_default_gate_evidence_pack.next_command_reason // "none"' "$summary_json")
- Runtime-actuation evidence pack available: $(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.available | if . == null then "null" else tostring end' "$summary_json")
- Runtime-actuation evidence pack input/source: input=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.input_summary_json // "none"' "$summary_json"), source=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.source_summary_json // "none"' "$summary_json")
- Runtime-actuation evidence pack status/decision: status=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.status // "none"' "$summary_json"), decision=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.decision // "none"' "$summary_json")
- Runtime-actuation evidence pack helper/needs-attention: helper_available=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.helper_available | if . == null then "null" else tostring end' "$summary_json"), needs_attention=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.needs_attention | if . == null then "null" else tostring end' "$summary_json")
- Runtime-actuation evidence pack next command/reason: command=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.next_command // "none"' "$summary_json"), reason=$(jq -r '.vpn_track.runtime_actuation_promotion_evidence_pack.next_command_reason // "none"' "$summary_json")
- Multi-VM promotion evidence pack available: $(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.available | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM promotion evidence pack input/source: input=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.input_summary_json // "none"' "$summary_json"), source=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.source_summary_json // "none"' "$summary_json")
- Multi-VM promotion evidence pack status/decision: status=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.status // "none"' "$summary_json"), decision=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.decision // "none"' "$summary_json")
- Multi-VM promotion evidence pack helper/needs-attention: helper_available=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.helper_available | if . == null then "null" else tostring end' "$summary_json"), needs_attention=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.needs_attention | if . == null then "null" else tostring end' "$summary_json")
- Multi-VM promotion evidence pack next command/reason: command=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.next_command // "none"' "$summary_json"), reason=$(jq -r '.vpn_track.profile_compare_multi_vm_stability_promotion_evidence_pack.next_command_reason // "none"' "$summary_json")
- Primary next action: $(jq -r '.vpn_track.next_action.command // ""' "$summary_json")

## Pending Real-Host Checks

$pending_real_host_checks_md

## Blockchain Track

- Status: $(jq -r '.blockchain_track.status' "$summary_json")
- Policy: $(jq -r '.blockchain_track.policy' "$summary_json")
- Recommendation: $(jq -r '.blockchain_track.recommendation' "$summary_json")
- Blockchain recommended actionable gate id: $(jq -r '.blockchain_track.recommended_gate_id // "none"' "$summary_json")
- Blockchain recommended actionable gate reason: $(jq -r '.blockchain_track.recommended_gate_reason // "none"' "$summary_json")
- Blockchain recommended actionable gate command: $(jq -r '.blockchain_track.recommended_gate_command // "none"' "$summary_json")
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
- Phase-6 Cosmos L1 tdpnd_comet_runtime_smoke_ok: $(jq -r '.blockchain_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
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
- Phase-7 mainnet cutover mainnet_activation_gate_go_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover mainnet_activation_gate_go_ok source: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok_source // "none"' "$summary_json")
- Phase-7 mainnet cutover bootstrap_governance_graduation_gate_go_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover bootstrap_governance_graduation_gate_go_ok source: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok_source // "none"' "$summary_json")
- Phase-7 mainnet cutover tdpnd_grpc_live_smoke_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover module_tx_surface_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.module_tx_surface_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover tdpnd_grpc_auth_live_smoke_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_auth_live_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover tdpnd_comet_runtime_smoke_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_comet_runtime_smoke_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover cosmos_module_coverage_floor_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_module_coverage_floor_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover cosmos_keeper_coverage_floor_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_keeper_coverage_floor_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover cosmos_app_coverage_floor_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_app_coverage_floor_ok | if . == null then "null" else tostring end' "$summary_json")
- Phase-7 mainnet cutover dual_write_parity_ok: $(jq -r '.blockchain_track.phase7_mainnet_cutover_summary_report.dual_write_parity_ok | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation gate available: $(jq -r '.blockchain_track.mainnet_activation_gate.available' "$summary_json")
- Mainnet activation gate input: $(jq -r '.blockchain_track.mainnet_activation_gate.input_summary_json // "none"' "$summary_json")
- Mainnet activation gate source: $(jq -r '.blockchain_track.mainnet_activation_gate.source_summary_json // "none"' "$summary_json")
- Mainnet activation gate source kind: $(jq -r '.blockchain_track.mainnet_activation_gate.source_summary_kind // "none"' "$summary_json")
- Mainnet activation gate status: $(jq -r '.blockchain_track.mainnet_activation_gate.status // "missing"' "$summary_json")
- Mainnet activation gate decision: $(jq -r '.blockchain_track.mainnet_activation_gate.decision // "null"' "$summary_json")
- Mainnet activation gate go: $(jq -r '.blockchain_track.mainnet_activation_gate.go | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation gate no_go: $(jq -r '.blockchain_track.mainnet_activation_gate.no_go | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation gate reasons: $(jq -r '.blockchain_track.mainnet_activation_gate.reasons | if length == 0 then "none" else join("; ") end' "$summary_json")
- Mainnet activation gate source paths: $(jq -r '.blockchain_track.mainnet_activation_gate.source_paths | if length == 0 then "none" else join(", ") end' "$summary_json")
- Mainnet activation gate summary generated_at: $(jq -r '.blockchain_track.mainnet_activation_gate.summary_generated_at // "none"' "$summary_json")
- Mainnet activation gate summary age_sec: $(jq -r '.blockchain_track.mainnet_activation_gate.summary_age_sec // "null"' "$summary_json")
- Mainnet activation gate summary stale: $(jq -r '.blockchain_track.mainnet_activation_gate.summary_stale | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation gate summary max_age_sec: $(jq -r '.blockchain_track.mainnet_activation_gate.summary_max_age_sec // "null"' "$summary_json")
- Mainnet activation stale evidence status: $(jq -r '.blockchain_track.mainnet_activation_stale_evidence.status // "unknown"' "$summary_json")
- Mainnet activation stale evidence action required: $(jq -r '.blockchain_track.mainnet_activation_stale_evidence.action_required | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation stale evidence reason: $(jq -r '.blockchain_track.mainnet_activation_stale_evidence.reason // "none"' "$summary_json")
- Mainnet activation stale evidence refresh command: $(jq -r '.blockchain_track.mainnet_activation_stale_evidence.refresh_command // "none"' "$summary_json")
- Mainnet activation refresh evidence action available: $(jq -r '.blockchain_track.mainnet_activation_refresh_evidence_action.available | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation refresh evidence action id: $(jq -r '.blockchain_track.mainnet_activation_refresh_evidence_action.id // "none"' "$summary_json")
- Mainnet activation refresh evidence action reason: $(jq -r '.blockchain_track.mainnet_activation_refresh_evidence_action.reason // "none"' "$summary_json")
- Mainnet activation refresh evidence action command: $(jq -r '.blockchain_track.mainnet_activation_refresh_evidence_action.command // "none"' "$summary_json")
- Mainnet activation missing-metrics action available: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.available | if . == null then "null" else tostring end' "$summary_json")
- Mainnet activation missing-metrics action id: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.id // "none"' "$summary_json")
- Mainnet activation missing-metrics action reason: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.reason // "none"' "$summary_json")
- Mainnet activation missing-metrics normalize command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.normalize_command // "none"' "$summary_json")
- Mainnet activation missing-metrics rerun bundle command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command // "none"' "$summary_json")
- Mainnet activation missing-metrics checklist command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.checklist_command // "none"' "$summary_json")
- Mainnet activation missing-metrics missing-input-template command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command // "none"' "$summary_json")
- Mainnet activation missing-metrics template command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.template_command // "none"' "$summary_json")
- Mainnet activation missing-metrics prefill command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.prefill_command // "none"' "$summary_json")
- Mainnet activation missing-metrics operator-pack command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "none"' "$summary_json")
- Mainnet activation missing-metrics gate cycle command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.cycle_command // "none"' "$summary_json")
- Mainnet activation missing-metrics seeded gate cycle command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command // "none"' "$summary_json")
- Mainnet activation missing-metrics real evidence run command: $(jq -r '.blockchain_track.mainnet_activation_missing_metrics_action.real_evidence_run_command // "none"' "$summary_json")
- Bootstrap governance graduation gate available: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.available' "$summary_json")
- Bootstrap governance graduation gate input: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.input_summary_json // "none"' "$summary_json")
- Bootstrap governance graduation gate source: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.source_summary_json // "none"' "$summary_json")
- Bootstrap governance graduation gate source kind: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.source_summary_kind // "none"' "$summary_json")
- Bootstrap governance graduation gate status: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.status // "missing"' "$summary_json")
- Bootstrap governance graduation gate decision: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.decision // "null"' "$summary_json")
- Bootstrap governance graduation gate go: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.go | if . == null then "null" else tostring end' "$summary_json")
- Bootstrap governance graduation gate no_go: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.no_go | if . == null then "null" else tostring end' "$summary_json")
- Bootstrap governance graduation gate reasons: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.reasons | if length == 0 then "none" else join("; ") end' "$summary_json")
- Bootstrap governance graduation gate source paths: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.source_paths | if length == 0 then "none" else join(", ") end' "$summary_json")
- Bootstrap governance graduation gate summary generated_at: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.summary_generated_at // "none"' "$summary_json")
- Bootstrap governance graduation gate summary age_sec: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.summary_age_sec // "null"' "$summary_json")
- Bootstrap governance graduation gate summary stale: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.summary_stale | if . == null then "null" else tostring end' "$summary_json")
- Bootstrap governance graduation gate summary max_age_sec: $(jq -r '.blockchain_track.bootstrap_governance_graduation_gate.summary_max_age_sec // "null"' "$summary_json")

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
- Multi-VM stability summary source: $(jq -r '.artifacts.profile_compare_multi_vm_stability_summary_json // "none"' "$summary_json")
- Profile-default stability evidence-pack summary source: $(jq -r '.artifacts.profile_default_gate_stability_evidence_pack_summary_json // "none"' "$summary_json")
- Profile-default evidence-pack summary source: $(jq -r '.artifacts.profile_default_gate_evidence_pack_summary_json // "none"' "$summary_json")
- Runtime-actuation multi-VM evidence-pack summary source: $(jq -r '.artifacts.runtime_actuation_multi_vm_evidence_pack_summary_json // "none"' "$summary_json")
- Runtime-actuation evidence-pack summary source: $(jq -r '.artifacts.runtime_actuation_promotion_evidence_pack_summary_json // "none"' "$summary_json")
- Multi-VM promotion evidence-pack summary source: $(jq -r '.artifacts.profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json // "none"' "$summary_json")
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
echo "[roadmap-progress-report] phase4_windows_full_parity_handoff_windows_server_packaging_ok=$phase4_windows_full_parity_handoff_windows_server_packaging_ok_json windows_native_bootstrap_guardrails_ok=$phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_json windows_native_bootstrap_guardrails_ok_source=${phase4_windows_full_parity_handoff_windows_native_bootstrap_guardrails_ok_source_json:-} windows_role_runbooks_ok=$phase4_windows_full_parity_handoff_windows_role_runbooks_ok_json cross_platform_interop_ok=$phase4_windows_full_parity_handoff_cross_platform_interop_ok_json role_combination_validation_ok=$phase4_windows_full_parity_handoff_role_combination_validation_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_available=$phase5_settlement_layer_handoff_available_json source_summary_json=${phase5_settlement_layer_handoff_source_summary_json:-} source_kind=${phase5_settlement_layer_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_failsoft_ok=$phase5_settlement_layer_handoff_settlement_failsoft_ok_json settlement_acceptance_ok=$phase5_settlement_layer_handoff_settlement_acceptance_ok_json settlement_bridge_smoke_ok=$phase5_settlement_layer_handoff_settlement_bridge_smoke_ok_json settlement_state_persistence_ok=$phase5_settlement_layer_handoff_settlement_state_persistence_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status=${phase5_settlement_layer_handoff_settlement_adapter_roundtrip_status_json:-null} settlement_adapter_roundtrip_ok=$phase5_settlement_layer_handoff_settlement_adapter_roundtrip_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status=${phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status_json:-null} settlement_adapter_signed_tx_roundtrip_ok=$phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_shadow_env_status=${phase5_settlement_layer_handoff_settlement_shadow_env_status_json:-null} settlement_shadow_env_ok=$phase5_settlement_layer_handoff_settlement_shadow_env_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_shadow_status_surface_status=${phase5_settlement_layer_handoff_settlement_shadow_status_surface_status_json:-null} settlement_shadow_status_surface_ok=$phase5_settlement_layer_handoff_settlement_shadow_status_surface_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_settlement_dual_asset_parity_status=${phase5_settlement_layer_handoff_settlement_dual_asset_parity_status_json:-null} settlement_dual_asset_parity_ok=$phase5_settlement_layer_handoff_settlement_dual_asset_parity_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status=${phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status_json:-null} issuer_sponsor_api_live_smoke_ok=$phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status=${phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_status_json:-null} issuer_sponsor_vpn_session_live_smoke_ok=$phase5_settlement_layer_handoff_issuer_sponsor_vpn_session_live_smoke_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status=${phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status_json:-null} issuer_settlement_status_live_smoke_ok=$phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status=${phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status_json:-null} issuer_admin_blockchain_handlers_coverage_ok=$phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_ok_json"
echo "[roadmap-progress-report] phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status=${phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status_json:-null} exit_settlement_status_live_smoke_ok=$phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_ok_json"
echo "[roadmap-progress-report] phase6_cosmos_l1_handoff_available=$phase6_cosmos_l1_handoff_available_json source_summary_json=${phase6_cosmos_l1_handoff_source_summary_json:-} source_kind=${phase6_cosmos_l1_handoff_source_summary_kind:-}"
echo "[roadmap-progress-report] phase6_cosmos_l1_handoff_status=$phase6_cosmos_l1_handoff_status_json rc=$phase6_cosmos_l1_handoff_rc_json run_pipeline_ok=$phase6_cosmos_l1_handoff_run_pipeline_ok_json module_tx_surface_ok=$phase6_cosmos_l1_handoff_module_tx_surface_ok_json tdpnd_grpc_runtime_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_grpc_runtime_smoke_ok_json tdpnd_grpc_live_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_grpc_live_smoke_ok_json tdpnd_grpc_auth_live_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_grpc_auth_live_smoke_ok_json tdpnd_comet_runtime_smoke_ok=$phase6_cosmos_l1_handoff_tdpnd_comet_runtime_smoke_ok_json"
echo "[roadmap-progress-report] phase7_mainnet_cutover_summary_available=$phase7_mainnet_cutover_summary_available_json source_summary_json=${phase7_mainnet_cutover_summary_source_summary_json:-} source_kind=${phase7_mainnet_cutover_summary_source_summary_kind:-}"
echo "[roadmap-progress-report] phase7_mainnet_cutover_summary_status=$phase7_mainnet_cutover_summary_status_json rc=$phase7_mainnet_cutover_summary_rc_json check_ok=$phase7_mainnet_cutover_summary_check_ok_json run_ok=$phase7_mainnet_cutover_summary_run_ok_json handoff_check_ok=$phase7_mainnet_cutover_summary_handoff_check_ok_json handoff_run_ok=$phase7_mainnet_cutover_summary_handoff_run_ok_json mainnet_activation_gate_go_ok=$phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_json mainnet_activation_gate_go_ok_source=${phase7_mainnet_cutover_summary_mainnet_activation_gate_go_ok_source_json:-} bootstrap_governance_graduation_gate_go_ok=$phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_json bootstrap_governance_graduation_gate_go_ok_source=${phase7_mainnet_cutover_summary_bootstrap_governance_graduation_gate_go_ok_source_json:-} tdpnd_grpc_live_smoke_ok=$phase7_mainnet_cutover_summary_tdpnd_grpc_live_smoke_ok_json module_tx_surface_ok=$phase7_mainnet_cutover_summary_module_tx_surface_ok_json tdpnd_grpc_auth_live_smoke_ok=$phase7_mainnet_cutover_summary_tdpnd_grpc_auth_live_smoke_ok_json tdpnd_comet_runtime_smoke_ok=$phase7_mainnet_cutover_summary_tdpnd_comet_runtime_smoke_ok_json cosmos_module_coverage_floor_ok=$phase7_mainnet_cutover_summary_cosmos_module_coverage_floor_ok_json cosmos_keeper_coverage_floor_ok=$phase7_mainnet_cutover_summary_cosmos_keeper_coverage_floor_ok_json cosmos_app_coverage_floor_ok=$phase7_mainnet_cutover_summary_cosmos_app_coverage_floor_ok_json dual_write_parity_ok=$phase7_mainnet_cutover_summary_dual_write_parity_ok_json"
echo "[roadmap-progress-report] mainnet_activation_gate_available=$blockchain_mainnet_activation_gate_available_json source_summary_json=${blockchain_mainnet_activation_gate_source_summary_json:-} source_kind=${blockchain_mainnet_activation_gate_source_summary_kind:-} status=$blockchain_mainnet_activation_gate_status_json decision=${blockchain_mainnet_activation_gate_decision_json:-} go=$blockchain_mainnet_activation_gate_go_json no_go=$blockchain_mainnet_activation_gate_no_go_json summary_generated_at=${blockchain_mainnet_activation_gate_summary_generated_at_json:-} summary_age_sec=${blockchain_mainnet_activation_gate_summary_age_sec_json:-} summary_stale=${blockchain_mainnet_activation_gate_summary_stale_json:-null} summary_max_age_sec=${blockchain_mainnet_activation_gate_summary_max_age_sec_json:-}"
echo "[roadmap-progress-report] mainnet_activation_refresh_evidence_available=$blockchain_mainnet_activation_refresh_evidence_available_json action_id=${blockchain_mainnet_activation_refresh_evidence_id_json:-} reason=${blockchain_mainnet_activation_refresh_evidence_reason:-} command=${blockchain_mainnet_activation_refresh_evidence_command:-}"
echo "[roadmap-progress-report] mainnet_activation_stale_evidence_status=$blockchain_mainnet_activation_stale_evidence_status_json action_required=$blockchain_mainnet_activation_stale_evidence_action_required_json reason=${blockchain_mainnet_activation_stale_evidence_reason_json:-} refresh_command=${blockchain_mainnet_activation_stale_evidence_refresh_command_json:-}"
echo "[roadmap-progress-report] blockchain_recommended_gate_id=${blockchain_recommended_gate_id:-} reason=${blockchain_recommended_gate_reason:-} command=${blockchain_recommended_gate_command:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_available=$blockchain_mainnet_activation_missing_metrics_action_available_json action_id=${blockchain_mainnet_activation_missing_metrics_action_id:-} reason=${blockchain_mainnet_activation_missing_metrics_action_reason:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_normalize_command=${blockchain_mainnet_activation_missing_metrics_action_normalize_command:-} rerun_bundle_command=${blockchain_mainnet_activation_missing_metrics_action_rerun_bundle_command:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_checklist_command=${blockchain_mainnet_activation_missing_metrics_action_checklist_command:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command=${blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_template_command=${blockchain_mainnet_activation_missing_metrics_action_template_command:-} prefill_command=${blockchain_mainnet_activation_missing_metrics_action_prefill_command:-} operator_pack_command=${blockchain_mainnet_activation_missing_metrics_action_operator_pack_command:-} cycle_command=${blockchain_mainnet_activation_missing_metrics_action_cycle_command:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command=${blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command:-}"
echo "[roadmap-progress-report] blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command=${blockchain_mainnet_activation_missing_metrics_action_real_evidence_run_command:-}"
echo "[roadmap-progress-report] bootstrap_governance_graduation_gate_available=$blockchain_bootstrap_governance_graduation_gate_available_json source_summary_json=${blockchain_bootstrap_governance_graduation_gate_source_summary_json:-} source_kind=${blockchain_bootstrap_governance_graduation_gate_source_summary_kind:-} status=$blockchain_bootstrap_governance_graduation_gate_status_json decision=${blockchain_bootstrap_governance_graduation_gate_decision_json:-} go=$blockchain_bootstrap_governance_graduation_gate_go_json no_go=$blockchain_bootstrap_governance_graduation_gate_no_go_json summary_generated_at=${blockchain_bootstrap_governance_graduation_gate_summary_generated_at_json:-} summary_age_sec=${blockchain_bootstrap_governance_graduation_gate_summary_age_sec_json:-} summary_stale=${blockchain_bootstrap_governance_graduation_gate_summary_stale_json:-null} summary_max_age_sec=${blockchain_bootstrap_governance_graduation_gate_summary_max_age_sec_json:-}"
echo "[roadmap-progress-report] profile_default_gate_status=$profile_default_gate_status next_command=${profile_default_gate_next_command:-} next_command_sudo=${profile_default_gate_next_command_sudo:-} next_command_source=${profile_default_gate_next_command_source:-}"
echo "[roadmap-progress-report] profile_default_gate_docker_hint_available=$profile_default_gate_docker_hint_available_json docker_hint_source=${profile_default_gate_docker_hint_source:-} campaign_check_summary_resolved=${profile_default_gate_campaign_check_summary_json_resolved:-} docker_matrix_summary_json=${profile_default_gate_docker_matrix_summary_json:-} docker_profile_summary_json=${profile_default_gate_docker_profile_summary_json:-}"
echo "[roadmap-progress-report] profile_default_gate_selection_policy_evidence_present=$profile_default_gate_selection_policy_evidence_present_json selection_policy_evidence_valid=$profile_default_gate_selection_policy_evidence_valid_json selection_policy_evidence_note=${profile_default_gate_selection_policy_evidence_note:-}"
echo "[roadmap-progress-report] profile_default_gate_micro_relay_evidence_available=$profile_default_gate_micro_relay_evidence_available_json micro_relay_quality_status_pass=$profile_default_gate_micro_relay_quality_status_pass_json micro_relay_demotion_policy_present=$profile_default_gate_micro_relay_demotion_policy_present_json micro_relay_promotion_policy_present=$profile_default_gate_micro_relay_promotion_policy_present_json trust_tier_port_unlock_policy_present=$profile_default_gate_trust_tier_port_unlock_policy_present_json micro_relay_evidence_note=${profile_default_gate_micro_relay_evidence_note:-}"
echo "[roadmap-progress-report] profile_default_gate_runtime_actuation_ready=$profile_default_gate_runtime_actuation_ready_json runtime_actuation_status=${profile_default_gate_runtime_actuation_status_json:-} runtime_actuation_reason=${profile_default_gate_runtime_actuation_reason:-}"
echo "[roadmap-progress-report] profile_default_gate_stability_summary_json=${profile_default_gate_stability_summary_json:-} stability_summary_available=$profile_default_gate_stability_summary_available_json stability_status=${profile_default_gate_stability_status_json:-} stability_rc=$profile_default_gate_stability_rc_json stability_runs_requested=$profile_default_gate_stability_runs_requested_json stability_runs_completed=$profile_default_gate_stability_runs_completed_json"
echo "[roadmap-progress-report] profile_default_gate_stability_selection_policy_present_all=$profile_default_gate_stability_selection_policy_present_all_json stability_consistent_selection_policy=$profile_default_gate_stability_consistent_selection_policy_json stability_ok=$profile_default_gate_stability_ok_json stability_recommended_profile_counts=$profile_default_gate_stability_recommended_profile_counts_json"
echo "[roadmap-progress-report] profile_default_gate_stability_check_summary_json=${profile_default_gate_stability_check_summary_json:-} stability_check_summary_available=$profile_default_gate_stability_check_summary_available_json stability_check_decision=${profile_default_gate_stability_check_decision_json:-} stability_check_status=${profile_default_gate_stability_check_status_json:-} stability_check_rc=$profile_default_gate_stability_check_rc_json stability_check_modal_recommended_profile=${profile_default_gate_stability_check_modal_recommended_profile_json:-} stability_check_modal_support_rate_pct=$profile_default_gate_stability_check_modal_support_rate_pct_json"
echo "[roadmap-progress-report] profile_default_gate_stability_cycle_summary_json=${profile_default_gate_stability_cycle_summary_json:-} cycle_summary_available=$profile_default_gate_stability_cycle_summary_available_json cycle_decision=${profile_default_gate_stability_cycle_decision_json:-} cycle_status=${profile_default_gate_stability_cycle_status_json:-} cycle_rc=$profile_default_gate_stability_cycle_rc_json cycle_failure_stage=${profile_default_gate_stability_cycle_failure_stage_json:-} cycle_failure_reason=${profile_default_gate_stability_cycle_failure_reason_json:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_available=$multi_vm_stability_available_json input_summary_json=${multi_vm_stability_input_summary_json:-} source_summary_json=${multi_vm_stability_source_summary_json:-} source_kind=${multi_vm_stability_source_summary_kind:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_status=${multi_vm_stability_status_json:-} rc=$multi_vm_stability_rc_json decision=${multi_vm_stability_decision_json:-} go=$multi_vm_stability_go_json no_go=$multi_vm_stability_no_go_json recommended_profile=${multi_vm_stability_recommended_profile_json:-} support_rate_pct=$multi_vm_stability_support_rate_pct_json runs_requested=$multi_vm_stability_runs_requested_json runs_completed=$multi_vm_stability_runs_completed_json runs_fail=$multi_vm_stability_runs_fail_json needs_attention=$multi_vm_stability_needs_attention_json next_command=${multi_vm_stability_next_command:-} next_command_reason=${multi_vm_stability_next_command_reason:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_decision_counts=$multi_vm_stability_decision_counts_json recommended_profile_counts=$multi_vm_stability_recommended_profile_counts_json reasons=$multi_vm_stability_reasons_json notes=${multi_vm_stability_notes_json:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_promotion_available=$multi_vm_stability_promotion_available_json input_summary_json=${multi_vm_stability_promotion_input_summary_json:-} source_summary_json=${multi_vm_stability_promotion_source_summary_json:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_promotion_status=${multi_vm_stability_promotion_status_json:-} rc=$multi_vm_stability_promotion_rc_json decision=${multi_vm_stability_promotion_decision_json:-} go=$multi_vm_stability_promotion_go_json no_go=$multi_vm_stability_promotion_no_go_json needs_attention=$multi_vm_stability_promotion_needs_attention_json next_command=${multi_vm_stability_promotion_next_command:-} next_command_reason=${multi_vm_stability_promotion_next_command_reason:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_promotion_reasons=$multi_vm_stability_promotion_reasons_json notes=${multi_vm_stability_promotion_notes_json:-}"
echo "[roadmap-progress-report] runtime_actuation_promotion_available=$runtime_actuation_promotion_available_json input_summary_json=${runtime_actuation_promotion_input_summary_json:-} source_summary_json=${runtime_actuation_promotion_source_summary_json:-}"
echo "[roadmap-progress-report] runtime_actuation_promotion_status=${runtime_actuation_promotion_status_json:-} rc=$runtime_actuation_promotion_rc_json decision=${runtime_actuation_promotion_decision_json:-} go=$runtime_actuation_promotion_go_json no_go=$runtime_actuation_promotion_no_go_json needs_attention=$runtime_actuation_promotion_needs_attention_json next_command=${runtime_actuation_promotion_next_command:-} next_command_reason=${runtime_actuation_promotion_next_command_reason:-}"
echo "[roadmap-progress-report] runtime_actuation_promotion_reasons=$runtime_actuation_promotion_reasons_json notes=${runtime_actuation_promotion_notes_json:-}"
echo "[roadmap-progress-report] profile_default_gate_evidence_pack_available=$profile_default_gate_evidence_pack_available_json helper_available=$profile_default_gate_evidence_pack_helper_available_json input_summary_json=${profile_default_gate_evidence_pack_input_summary_json:-} source_summary_json=${profile_default_gate_evidence_pack_source_summary_json:-}"
echo "[roadmap-progress-report] profile_default_gate_evidence_pack_status=${profile_default_gate_evidence_pack_status_json:-} rc=$profile_default_gate_evidence_pack_rc_json decision=${profile_default_gate_evidence_pack_decision_json:-} go=$profile_default_gate_evidence_pack_go_json no_go=$profile_default_gate_evidence_pack_no_go_json needs_attention=$profile_default_gate_evidence_pack_needs_attention_json next_command=${profile_default_gate_evidence_pack_next_command:-} next_command_reason=${profile_default_gate_evidence_pack_next_command_reason:-}"
echo "[roadmap-progress-report] runtime_actuation_promotion_evidence_pack_available=$runtime_actuation_promotion_evidence_pack_available_json helper_available=$runtime_actuation_promotion_evidence_pack_helper_available_json input_summary_json=${runtime_actuation_promotion_evidence_pack_input_summary_json:-} source_summary_json=${runtime_actuation_promotion_evidence_pack_source_summary_json:-}"
echo "[roadmap-progress-report] runtime_actuation_promotion_evidence_pack_status=${runtime_actuation_promotion_evidence_pack_status_json:-} rc=$runtime_actuation_promotion_evidence_pack_rc_json decision=${runtime_actuation_promotion_evidence_pack_decision_json:-} go=$runtime_actuation_promotion_evidence_pack_go_json no_go=$runtime_actuation_promotion_evidence_pack_no_go_json needs_attention=$runtime_actuation_promotion_evidence_pack_needs_attention_json next_command=${runtime_actuation_promotion_evidence_pack_next_command:-} next_command_reason=${runtime_actuation_promotion_evidence_pack_next_command_reason:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_promotion_evidence_pack_available=$multi_vm_stability_promotion_evidence_pack_available_json helper_available=$multi_vm_stability_promotion_evidence_pack_helper_available_json input_summary_json=${multi_vm_stability_promotion_evidence_pack_input_summary_json:-} source_summary_json=${multi_vm_stability_promotion_evidence_pack_source_summary_json:-}"
echo "[roadmap-progress-report] profile_compare_multi_vm_stability_promotion_evidence_pack_status=${multi_vm_stability_promotion_evidence_pack_status_json:-} rc=$multi_vm_stability_promotion_evidence_pack_rc_json decision=${multi_vm_stability_promotion_evidence_pack_decision_json:-} go=$multi_vm_stability_promotion_evidence_pack_go_json no_go=$multi_vm_stability_promotion_evidence_pack_no_go_json needs_attention=$multi_vm_stability_promotion_evidence_pack_needs_attention_json next_command=${multi_vm_stability_promotion_evidence_pack_next_command:-} next_command_reason=${multi_vm_stability_promotion_evidence_pack_next_command_reason:-}"
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
