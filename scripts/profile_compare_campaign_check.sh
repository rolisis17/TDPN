#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_campaign_check.sh \
    [--campaign-summary-json PATH] \
    [--trend-summary-json PATH] \
    [--reports-dir DIR] \
    [--require-status-pass [0|1]] \
    [--require-trend-status-pass [0|1]] \
    [--require-min-runs-total N] \
    [--require-max-runs-fail N] \
    [--require-max-runs-warn N] \
    [--require-min-runs-with-summary N] \
    [--require-recommendation-support-rate-pct N] \
    [--require-recommended-profile PROFILE] \
    [--allow-recommended-profiles CSV] \
    [--disallow-experimental-default [0|1]] \
    [--require-trend-source CSV] \
    [--require-selection-policy-present [0|1]] \
    [--require-selection-policy-valid [0|1]] \
    [--require-micro-relay-quality-evidence [0|1]] \
    [--require-micro-relay-quality-status-pass [0|1]] \
    [--require-micro-relay-demotion-policy [0|1]] \
    [--require-micro-relay-promotion-policy [0|1]] \
    [--require-trust-tier-port-unlock-policy [0|1]] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Verify profile-compare campaign artifacts and emit a fail-closed
  GO/NO-GO decision for default-profile recommendation readiness.

Notes:
  - Recommended input: --campaign-summary-json from profile-compare-campaign.
  - If campaign summary is omitted, the latest
    profile_compare_campaign_summary.json under --reports-dir is used.
  - `speed-1hop` remains non-default by policy.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
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
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
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

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

file_mtime_epoch() {
  local file="$1"
  if stat -c %Y "$file" >/dev/null 2>&1; then
    stat -c %Y "$file"
    return
  fi
  if stat -f %m "$file" >/dev/null 2>&1; then
    stat -f %m "$file"
    return
  fi
  echo "0"
}

normalize_profile() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    speed|balanced|private|speed-1hop) printf '%s\n' "$profile" ;;
    2hop|2-hop|hop2|hop-2|twohop) printf '%s\n' "balanced" ;;
    3hop|3-hop|hop3|hop-3|threehop) printf '%s\n' "private" ;;
    fast) printf '%s\n' "speed" ;;
    privacy) printf '%s\n' "private" ;;
    speed1hop|onehop|1hop|1-hop|hop1|hop-1|fast-1hop|fast1hop) printf '%s\n' "speed-1hop" ;;
    *) printf '%s\n' "$profile" ;;
  esac
}

csv_contains() {
  local csv="$1"
  local needle="$2"
  local item
  IFS=',' read -r -a _items <<<"$csv"
  for item in "${_items[@]}"; do
    item="$(normalize_profile "$item")"
    if [[ -n "$item" && "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

extract_m4_policy_signals_from_summary() {
  local summary_path="$1"
  local parsed=""
  local quality_present quality_status_pass demotion_present promotion_present trust_tier_port_unlock_present

  if [[ -z "$summary_path" || ! -f "$summary_path" ]]; then
    echo "0 0 0 0 0"
    return
  fi

  parsed="$(jq -r '
    def first_non_null($values):
      reduce $values[] as $value (null; if . == null and $value != null then $value else . end);
    def boolish_true:
      if type == "boolean" then .
      elif type == "number" then . != 0
      elif type == "string" then
        ((ascii_downcase) as $text |
          ($text == "1" or
           $text == "true" or
           $text == "yes" or
           $text == "pass" or
           $text == "ok" or
           $text == "go" or
           $text == "healthy" or
           $text == "enabled"))
      else false
      end;
    def canonical_m4_evidence:
      first_non_null([
        .summary.m4_micro_relay_evidence,
        .m4_micro_relay_evidence,
        .summary.m4.micro_relay_evidence,
        .m4.micro_relay_evidence
      ]);
    def quality_candidate:
      first_non_null([
        (canonical_m4_evidence | if type == "object" then .micro_relay_quality else null end),
        .summary.micro_relay_quality_evidence,
        .summary.micro_relay_quality,
        .summary.m4.micro_relay_quality,
        .summary.m4.quality_scoring,
        .m4.micro_relay_quality_evidence,
        .m4.micro_relay_quality
      ]);
    def demotion_candidate:
      first_non_null([
        (canonical_m4_evidence | if type == "object" then .adaptive_demotion_promotion else null end),
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
        .summary.trust_tier_port_unlock_policy,
        .summary.m4.trust_tier_port_unlock_policy,
        .summary.port_unlock_policy,
        .summary.port_unlock.trust_tier_policy,
        .summary.exit_policy.trust_tier_port_unlock_policy,
        .m4.trust_tier_port_unlock_policy
      ]);
    def candidate_present($candidate):
      if $candidate == null then false
      elif ($candidate | type) == "object" then
        if ($candidate.available? != null) then (($candidate.available // false) | boolish_true)
        elif ($candidate.present? != null) then (($candidate.present // false) | boolish_true)
        elif ($candidate.status? != null) then true
        elif ($candidate.quality_status? != null) then true
        elif ($candidate.pass? != null) then true
        elif ($candidate.quality_ok? != null) then true
        elif ($candidate.status_pass? != null) then true
        elif ($candidate.healthy? != null) then true
        elif (($candidate.quality_band? | type) == "string" and (($candidate.quality_band // "") | length) > 0) then true
        elif (($candidate.quality_score? | type) == "number") then true
        elif (($candidate.quality_score_avg? | type) == "number") then true
        else false
        end
      else
        ($candidate | boolish_true)
      end;
    def adaptive_signal_present($candidate; $field):
      if $candidate == null then false
      elif ($candidate | type) == "object" then
        if ($candidate[$field]? != null) then true
        else false
        end
      else
        ($candidate | boolish_true)
      end;
    def trust_signal_present($candidate):
      if $candidate == null then false
      elif ($candidate | type) == "object" then
        if ($candidate.present? != null) then (($candidate.present // false) | boolish_true)
        elif ($candidate.evidence_hits? != null and (($candidate.evidence_hits | type) == "number")) then (($candidate.evidence_hits // 0) > 0)
        else false
        end
      else
        ($candidate | boolish_true)
      end;
    def quality_pass:
      if (candidate_present(quality_candidate) | not) then false
      elif (quality_candidate | type) == "object" then
        (((quality_candidate.status // "" | tostring | ascii_downcase) as $status |
            ($status == "pass" or $status == "ok" or $status == "go" or $status == "healthy")) or
         ((quality_candidate.quality_status // "" | tostring | ascii_downcase) as $quality_status |
            ($quality_status == "pass" or $quality_status == "ok" or $quality_status == "go" or $quality_status == "healthy")) or
         ((quality_candidate.pass // false) | boolish_true) or
         ((quality_candidate.quality_ok // false) | boolish_true) or
         ((quality_candidate.status_pass // false) | boolish_true) or
         ((quality_candidate.healthy // false) | boolish_true) or
         ((quality_candidate.quality_band // "" | tostring | ascii_downcase) as $quality_band |
            ($quality_band == "excellent" or $quality_band == "good" or $quality_band == "pass" or $quality_band == "ok" or $quality_band == "healthy")) or
         ((quality_candidate.quality_score // null) as $quality_score |
            if ($quality_score | type) == "number" then ($quality_score >= 85) else false end))
      else
        (quality_candidate | boolish_true)
      end;
    [
      candidate_present(quality_candidate),
      quality_pass,
      adaptive_signal_present(demotion_candidate; "demotion_candidate"),
      adaptive_signal_present(promotion_candidate; "promotion_candidate"),
      trust_signal_present(trust_tier_port_unlock_candidate)
    ]
    | map(if . then 1 else 0 end)
    | @tsv
  ' "$summary_path" 2>/dev/null || true)"

  if [[ -z "$parsed" ]]; then
    echo "0 0 0 0 0"
    return
  fi

  IFS=$'\t' read -r quality_present quality_status_pass demotion_present promotion_present trust_tier_port_unlock_present <<<"$parsed"
  for value in "$quality_present" "$quality_status_pass" "$demotion_present" "$promotion_present" "$trust_tier_port_unlock_present"; do
    if [[ "$value" != "0" && "$value" != "1" ]]; then
      echo "0 0 0 0 0"
      return
    fi
  done

  echo "$quality_present $quality_status_pass $demotion_present $promotion_present $trust_tier_port_unlock_present"
}

extract_m4_policy_observed_from_summary() {
  local summary_path="$1"
  local observed_json=""

  if [[ -z "$summary_path" || ! -f "$summary_path" ]]; then
    jq -nc '{
      quality: {
        present: false,
        status_pass: false,
        available: null,
        score: null,
        score_avg: null,
        band: null,
        reason: "summary_missing"
      },
      adaptive: {
        present: false,
        available: null,
        demotion_policy_present: false,
        promotion_policy_present: false,
        demotion_signal_count: null,
        promotion_signal_count: null,
        demotion_candidate: null,
        promotion_candidate: null,
        wiring_present: null,
        reason: "summary_missing"
      },
      trust_tier: {
        present: false,
        policy_present: false,
        evaluated: null,
        present_flag: null,
        evidence_hits: null,
        reason: "summary_missing"
      }
    }'
    return
  fi

  observed_json="$(jq -c '
    def bool_or_null($value):
      if $value == null then null
      elif ($value | type) == "boolean" then $value
      elif ($value | type) == "number" then ($value != 0)
      elif ($value | type) == "string" then
        (($value | ascii_downcase) as $text |
          if ($text == "1" or $text == "true" or $text == "yes" or $text == "pass" or $text == "ok" or $text == "go" or $text == "healthy" or $text == "enabled") then true
          elif ($text == "0" or $text == "false" or $text == "no" or $text == "fail" or $text == "disabled" or $text == "none" or $text == "missing") then false
          else null
          end)
      else null
      end;
    def num_or_null($value):
      if ($value | type) == "number" then $value else null end;
    def str_or_null($value):
      if ($value | type) == "string" and ($value | length) > 0 then $value else null end;
    def score_band_pass($value):
      if ($value | type) != "string" then false
      else
        (($value | ascii_downcase) as $band |
          ($band == "excellent" or $band == "good" or $band == "pass" or $band == "ok" or $band == "healthy"))
      end;
    def status_pass($value):
      if ($value | type) != "string" then false
      else
        (($value | ascii_downcase) as $status |
          ($status == "pass" or $status == "ok" or $status == "go" or $status == "healthy"))
      end;
    (.summary.m4_micro_relay_evidence // .m4_micro_relay_evidence // .summary.m4.micro_relay_evidence // .m4.micro_relay_evidence // null) as $m4
    | if ($m4 | type) != "object" then
        {
          quality: {
            present: false,
            status_pass: false,
            available: null,
            score: null,
            score_avg: null,
            band: null,
            reason: "m4_evidence_missing"
          },
          adaptive: {
            present: false,
            available: null,
            demotion_policy_present: false,
            promotion_policy_present: false,
            demotion_signal_count: null,
            promotion_signal_count: null,
            demotion_candidate: null,
            promotion_candidate: null,
            wiring_present: null,
            reason: "m4_evidence_missing"
          },
          trust_tier: {
            present: false,
            policy_present: false,
            evaluated: null,
            present_flag: null,
            evidence_hits: null,
            reason: "m4_evidence_missing"
          }
        }
      else
        ($m4.micro_relay_quality // null) as $quality
        | ($m4.adaptive_demotion_promotion // null) as $adaptive
        | ($m4.trust_tier_port_unlock_wiring // null) as $trust
        | (num_or_null($quality.quality_score) // num_or_null($quality.score)) as $quality_score
        | (num_or_null($quality.quality_score_avg) // num_or_null($quality.score_avg) // $quality_score) as $quality_score_avg
        | (str_or_null($quality.quality_band) // str_or_null($quality.band)) as $quality_band
        | (num_or_null($adaptive.demotion_signal_count_total) // num_or_null($adaptive.demotion_signal_count) // num_or_null($adaptive.demotion_signals)) as $demotion_signal_count
        | (num_or_null($adaptive.promotion_signal_count_total) // num_or_null($adaptive.promotion_signal_count) // num_or_null($adaptive.promotion_signals)) as $promotion_signal_count
        | (num_or_null($trust.evidence_hits_total) // num_or_null($trust.evidence_hits)) as $trust_evidence_hits
        | {
            quality: {
              present: (
                ($quality | type) == "object"
                and (
                  bool_or_null($quality.available) == true
                  or bool_or_null($quality.present) == true
                  or $quality_score != null
                  or $quality_score_avg != null
                  or $quality_band != null
                  or status_pass($quality.status)
                  or status_pass($quality.quality_status)
                  or bool_or_null($quality.pass) != null
                  or bool_or_null($quality.quality_ok) != null
                  or bool_or_null($quality.status_pass) != null
                  or bool_or_null($quality.healthy) != null
                )
              ),
              status_pass: (
                ($quality | type) == "object"
                and (
                  status_pass($quality.status)
                  or status_pass($quality.quality_status)
                  or bool_or_null($quality.pass) == true
                  or bool_or_null($quality.quality_ok) == true
                  or bool_or_null($quality.status_pass) == true
                  or bool_or_null($quality.healthy) == true
                  or score_band_pass($quality_band)
                  or ($quality_score != null and $quality_score >= 85)
                )
              ),
              available: (bool_or_null($quality.available) // bool_or_null($quality.present)),
              score: $quality_score,
              score_avg: $quality_score_avg,
              band: $quality_band,
              reason: str_or_null($quality.reason)
            },
            adaptive: {
              present: (
                ($adaptive | type) == "object"
                and (
                  $adaptive.demotion_candidate != null
                  or $adaptive.promotion_candidate != null
                  or $demotion_signal_count != null
                  or $promotion_signal_count != null
                )
              ),
              available: bool_or_null($adaptive.available),
              demotion_policy_present: (
                ($adaptive | type) == "object"
                and ($adaptive.demotion_candidate != null or $demotion_signal_count != null)
              ),
              promotion_policy_present: (
                ($adaptive | type) == "object"
                and ($adaptive.promotion_candidate != null or $promotion_signal_count != null)
              ),
              demotion_signal_count: $demotion_signal_count,
              promotion_signal_count: $promotion_signal_count,
              demotion_candidate: bool_or_null($adaptive.demotion_candidate),
              promotion_candidate: bool_or_null($adaptive.promotion_candidate),
              wiring_present: bool_or_null($adaptive.wiring_present),
              reason: str_or_null($adaptive.reason)
            },
            trust_tier: {
              present: (
                ($trust | type) == "object"
                and (
                  bool_or_null($trust.present) == true
                  or ($trust_evidence_hits != null and $trust_evidence_hits > 0)
                )
              ),
              policy_present: (
                ($trust | type) == "object"
                and (
                  bool_or_null($trust.present) == true
                  or ($trust_evidence_hits != null and $trust_evidence_hits > 0)
                )
              ),
              evaluated: (
                if (num_or_null($trust.evaluated_reports) != null) then (num_or_null($trust.evaluated_reports) > 0)
                else bool_or_null($trust.evaluated)
                end
              ),
              present_flag: bool_or_null($trust.present),
              evidence_hits: $trust_evidence_hits,
              reason: str_or_null($trust.reason)
            }
          }
      end
  ' "$summary_path" 2>/dev/null || true)"

  if [[ -z "$observed_json" ]]; then
    jq -nc '{
      quality: {
        present: false,
        status_pass: false,
        available: null,
        score: null,
        score_avg: null,
        band: null,
        reason: "summary_parse_error"
      },
      adaptive: {
        present: false,
        available: null,
        demotion_policy_present: false,
        promotion_policy_present: false,
        demotion_signal_count: null,
        promotion_signal_count: null,
        demotion_candidate: null,
        promotion_candidate: null,
        wiring_present: null,
        reason: "summary_parse_error"
      },
      trust_tier: {
        present: false,
        policy_present: false,
        evaluated: null,
        present_flag: null,
        evidence_hits: null,
        reason: "summary_parse_error"
      }
    }'
    return
  fi

  printf '%s\n' "$observed_json"
}

need_cmd jq
need_cmd date
need_cmd find

campaign_summary_json=""
trend_summary_json=""
reports_dir="${PROFILE_COMPARE_CAMPAIGN_CHECK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"

require_status_pass="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_STATUS_PASS:-1}"
require_trend_status_pass="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TREND_STATUS_PASS:-1}"
require_min_runs_total="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MIN_RUNS_TOTAL:-3}"
require_max_runs_fail="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MAX_RUNS_FAIL:-0}"
require_max_runs_warn="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MAX_RUNS_WARN:-0}"
require_min_runs_with_summary="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MIN_RUNS_WITH_SUMMARY:-3}"
require_recommendation_support_rate_pct="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_RECOMMENDATION_SUPPORT_RATE_PCT:-60}"
require_recommended_profile="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_RECOMMENDED_PROFILE:-}"
allow_recommended_profiles="${PROFILE_COMPARE_CAMPAIGN_CHECK_ALLOW_RECOMMENDED_PROFILES:-balanced,speed,private}"
disallow_experimental_default="${PROFILE_COMPARE_CAMPAIGN_CHECK_DISALLOW_EXPERIMENTAL_DEFAULT:-1}"
require_trend_source="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TREND_SOURCE:-policy_reliability_latency,vote_fallback,safe_default_fallback}"
require_selection_policy_present="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_SELECTION_POLICY_PRESENT:-0}"
require_selection_policy_valid="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_SELECTION_POLICY_VALID:-0}"
require_micro_relay_quality_evidence="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MICRO_RELAY_QUALITY_EVIDENCE:-0}"
require_micro_relay_quality_status_pass="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MICRO_RELAY_QUALITY_STATUS_PASS:-0}"
require_micro_relay_demotion_policy="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MICRO_RELAY_DEMOTION_POLICY:-0}"
require_micro_relay_promotion_policy="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_MICRO_RELAY_PROMOTION_POLICY:-0}"
require_trust_tier_port_unlock_policy="${PROFILE_COMPARE_CAMPAIGN_CHECK_REQUIRE_TRUST_TIER_PORT_UNLOCK_POLICY:-0}"
fail_on_no_go="${PROFILE_COMPARE_CAMPAIGN_CHECK_FAIL_ON_NO_GO:-1}"
show_json="${PROFILE_COMPARE_CAMPAIGN_CHECK_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_CAMPAIGN_CHECK_PRINT_SUMMARY_JSON:-0}"
summary_json="${PROFILE_COMPARE_CAMPAIGN_CHECK_SUMMARY_JSON:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --require-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_pass="${2:-}"
        shift 2
      else
        require_status_pass="1"
        shift
      fi
      ;;
    --require-trend-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_status_pass="${2:-}"
        shift 2
      else
        require_trend_status_pass="1"
        shift
      fi
      ;;
    --require-min-runs-total)
      require_min_runs_total="${2:-}"
      shift 2
      ;;
    --require-max-runs-fail)
      require_max_runs_fail="${2:-}"
      shift 2
      ;;
    --require-max-runs-warn)
      require_max_runs_warn="${2:-}"
      shift 2
      ;;
    --require-min-runs-with-summary)
      require_min_runs_with_summary="${2:-}"
      shift 2
      ;;
    --require-recommendation-support-rate-pct)
      require_recommendation_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-recommended-profile)
      require_recommended_profile="${2:-}"
      shift 2
      ;;
    --allow-recommended-profiles)
      allow_recommended_profiles="${2:-}"
      shift 2
      ;;
    --disallow-experimental-default)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        disallow_experimental_default="${2:-}"
        shift 2
      else
        disallow_experimental_default="1"
        shift
      fi
      ;;
    --require-trend-source)
      require_trend_source="${2:-}"
      shift 2
      ;;
    --require-selection-policy-present)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_present="${2:-}"
        shift 2
      else
        require_selection_policy_present="1"
        shift
      fi
      ;;
    --require-selection-policy-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_valid="${2:-}"
        shift 2
      else
        require_selection_policy_valid="1"
        shift
      fi
      ;;
    --require-micro-relay-quality-evidence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_quality_evidence="${2:-}"
        shift 2
      else
        require_micro_relay_quality_evidence="1"
        shift
      fi
      ;;
    --require-micro-relay-quality-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_quality_status_pass="${2:-}"
        shift 2
      else
        require_micro_relay_quality_status_pass="1"
        shift
      fi
      ;;
    --require-micro-relay-demotion-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_demotion_policy="${2:-}"
        shift 2
      else
        require_micro_relay_demotion_policy="1"
        shift
      fi
      ;;
    --require-micro-relay-promotion-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_promotion_policy="${2:-}"
        shift 2
      else
        require_micro_relay_promotion_policy="1"
        shift
      fi
      ;;
    --require-trust-tier-port-unlock-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trust_tier_port_unlock_policy="${2:-}"
        shift 2
      else
        require_trust_tier_port_unlock_policy="1"
        shift
      fi
      ;;
    --fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_no_go="${2:-}"
        shift 2
      else
        fail_on_no_go="1"
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
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
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

bool_arg_or_die "--require-status-pass" "$require_status_pass"
bool_arg_or_die "--require-trend-status-pass" "$require_trend_status_pass"
bool_arg_or_die "--disallow-experimental-default" "$disallow_experimental_default"
bool_arg_or_die "--require-selection-policy-present" "$require_selection_policy_present"
bool_arg_or_die "--require-selection-policy-valid" "$require_selection_policy_valid"
bool_arg_or_die "--require-micro-relay-quality-evidence" "$require_micro_relay_quality_evidence"
bool_arg_or_die "--require-micro-relay-quality-status-pass" "$require_micro_relay_quality_status_pass"
bool_arg_or_die "--require-micro-relay-demotion-policy" "$require_micro_relay_demotion_policy"
bool_arg_or_die "--require-micro-relay-promotion-policy" "$require_micro_relay_promotion_policy"
bool_arg_or_die "--require-trust-tier-port-unlock-policy" "$require_trust_tier_port_unlock_policy"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

for int_arg in "$require_min_runs_total" "$require_max_runs_fail" "$require_max_runs_warn" "$require_min_runs_with_summary"; do
  if ! [[ "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "run count thresholds must be non-negative integers"
    exit 2
  fi
done

if ! is_non_negative_decimal "$require_recommendation_support_rate_pct"; then
  echo "--require-recommendation-support-rate-pct must be a non-negative number"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"

if [[ -n "$campaign_summary_json" ]]; then
  campaign_summary_json="$(abs_path "$campaign_summary_json")"
fi
if [[ -n "$trend_summary_json" ]]; then
  trend_summary_json="$(abs_path "$trend_summary_json")"
fi

if [[ -z "$campaign_summary_json" ]]; then
  direct_candidate="$reports_dir/profile_compare_campaign_summary.json"
  if [[ -f "$direct_candidate" ]]; then
    campaign_summary_json="$direct_candidate"
  else
    latest_path=""
    latest_mtime="0"
    while IFS= read -r found_path; do
      found_mtime="$(file_mtime_epoch "$found_path")"
      if [[ ! "$found_mtime" =~ ^[0-9]+$ ]]; then
        continue
      fi
      if ((found_mtime > latest_mtime)); then
        latest_mtime="$found_mtime"
        latest_path="$found_path"
      fi
    done < <(find "$reports_dir" -type f -name 'profile_compare_campaign_summary.json' 2>/dev/null)
    campaign_summary_json="$latest_path"
  fi
fi

if [[ -z "$campaign_summary_json" || ! -f "$campaign_summary_json" ]]; then
  echo "profile-compare-campaign-check failed: campaign summary JSON not found"
  exit 1
fi
if ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object")' "$campaign_summary_json" >/dev/null 2>&1; then
  echo "profile-compare-campaign-check failed: invalid campaign summary JSON schema ($campaign_summary_json)"
  exit 1
fi

if [[ -z "$trend_summary_json" ]]; then
  trend_summary_json="$(jq -r '.trend.summary_json // ""' "$campaign_summary_json")"
  trend_summary_json="$(abs_path "$trend_summary_json")"
fi

trend_summary_present="0"
if [[ -n "$trend_summary_json" && -f "$trend_summary_json" ]] &&
  jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object")' "$trend_summary_json" >/dev/null 2>&1; then
  trend_summary_present="1"
fi

campaign_status="$(jq -r '.status // ""' "$campaign_summary_json")"
campaign_rc="$(jq -r '(.rc | tonumber?) // "__INVALID__"' "$campaign_summary_json")"
runs_total="$(jq -r '(.summary.runs_total | tonumber?) // "__INVALID__"' "$campaign_summary_json")"
runs_pass="$(jq -r '(.summary.runs_pass | tonumber?) // "__INVALID__"' "$campaign_summary_json")"
runs_warn="$(jq -r '(.summary.runs_warn | tonumber?) // "__INVALID__"' "$campaign_summary_json")"
runs_fail="$(jq -r '(.summary.runs_fail | tonumber?) // "__INVALID__"' "$campaign_summary_json")"
runs_with_summary="$(jq -r '(.summary.runs_with_summary | tonumber?) // "__INVALID__"' "$campaign_summary_json")"
recommended_profile="$(normalize_profile "$(jq -r '.decision.recommended_default_profile // ""' "$campaign_summary_json")")"
decision_source="$(jq -r '.decision.source // ""' "$campaign_summary_json")"
trend_status="$(jq -r '.trend.status // ""' "$campaign_summary_json")"
trend_rc="$(jq -r '(.trend.rc | tonumber?) // "__INVALID__"' "$campaign_summary_json")"

support_rate_pct="0"
trend_source_value="$decision_source"
if [[ "$trend_summary_present" == "1" ]]; then
  support_rate_pct="$(jq -r '(.decision.recommendation_support_rate_pct | tonumber?) // "__INVALID__"' "$trend_summary_json")"
  trend_source_value="$(jq -r '.decision.source // ""' "$trend_summary_json")"
  if [[ -z "$decision_source" ]]; then
    decision_source="$trend_source_value"
  fi
fi

numeric_validation_issues=()
if ! [[ "$campaign_rc" =~ ^-?[0-9]+$ ]]; then
  numeric_validation_issues+=("campaign_rc")
  campaign_rc="1"
fi
for metric_name in runs_total runs_pass runs_warn runs_fail runs_with_summary; do
  metric_value="${!metric_name}"
  if ! [[ "$metric_value" =~ ^[0-9]+$ ]]; then
    numeric_validation_issues+=("$metric_name")
    printf -v "$metric_name" '%s' "0"
  fi
done
if ! [[ "$trend_rc" =~ ^-?[0-9]+$ ]]; then
  numeric_validation_issues+=("trend_rc")
  trend_rc="1"
fi
if ! is_non_negative_decimal "$support_rate_pct"; then
  numeric_validation_issues+=("recommendation_support_rate_pct")
  support_rate_pct="0"
fi

if [[ -n "$require_recommended_profile" ]]; then
  require_recommended_profile="$(normalize_profile "$require_recommended_profile")"
fi

campaign_selection_policy_present=0
campaign_selection_policy_valid=0
campaign_selection_policy_source="$(jq -r '.summary.selection_policy_source // ""' "$campaign_summary_json" 2>/dev/null || printf '%s' "")"
campaign_selection_policy_synthetic_default=0
case "$campaign_selection_policy_source" in
  fallback-default|synthetic-default|none)
    campaign_selection_policy_synthetic_default=1
    ;;
esac
if jq -e '.summary.selection_policy | type == "object"' "$campaign_summary_json" >/dev/null 2>&1; then
  campaign_selection_policy_present=1
fi
if jq -e '
  .summary.selection_policy
  and (.summary.selection_policy.sticky_pair_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_jitter_pct | type == "number")
  and (.summary.selection_policy.exit_exploration_pct | type == "number")
  and (.summary.selection_policy.path_profile | type == "string")
' "$campaign_summary_json" >/dev/null 2>&1; then
  if ((campaign_selection_policy_synthetic_default == 0)); then
    campaign_selection_policy_valid=1
  fi
fi

campaign_micro_relay_quality_evidence_present=0
campaign_micro_relay_quality_status_pass=0
campaign_micro_relay_demotion_policy_present=0
campaign_micro_relay_promotion_policy_present=0
campaign_trust_tier_port_unlock_policy_present=0
campaign_m4_observed_json="$(extract_m4_policy_observed_from_summary "$campaign_summary_json")"
read -r campaign_micro_relay_quality_evidence_present \
  campaign_micro_relay_quality_status_pass \
  campaign_micro_relay_demotion_policy_present \
  campaign_micro_relay_promotion_policy_present \
  campaign_trust_tier_port_unlock_policy_present < <(extract_m4_policy_signals_from_summary "$campaign_summary_json")

selection_policy_selected_summaries_total="$(jq -r '[.selected_summaries[]? | select(type == "string" and length > 0)] | length' "$campaign_summary_json" 2>/dev/null || printf '0')"
if ! [[ "$selection_policy_selected_summaries_total" =~ ^[0-9]+$ ]]; then
  selection_policy_selected_summaries_total="0"
fi
selection_policy_selected_summaries_found=0
selection_policy_selected_summaries_present_count=0
selection_policy_selected_summaries_valid_count=0
m4_selected_summaries_quality_evidence_present_count=0
m4_selected_summaries_quality_status_pass_count=0
m4_selected_summaries_demotion_policy_present_count=0
m4_selected_summaries_promotion_policy_present_count=0
m4_selected_summaries_trust_tier_port_unlock_policy_present_count=0
selected_m4_observed_lines=""
while IFS= read -r selected_summary_path; do
  selected_summary_path="$(abs_path "$selected_summary_path")"
  if [[ -z "$selected_summary_path" || ! -f "$selected_summary_path" ]]; then
    continue
  fi
  selection_policy_selected_summaries_found=$((selection_policy_selected_summaries_found + 1))
  if jq -e '.summary.selection_policy | type == "object"' "$selected_summary_path" >/dev/null 2>&1; then
    selection_policy_selected_summaries_present_count=$((selection_policy_selected_summaries_present_count + 1))
  fi
  if jq -e '
    .summary.selection_policy
    and (.summary.selection_policy.sticky_pair_sec | type == "number")
    and (.summary.selection_policy.entry_rotation_sec | type == "number")
    and (.summary.selection_policy.entry_rotation_jitter_pct | type == "number")
    and (.summary.selection_policy.exit_exploration_pct | type == "number")
    and (.summary.selection_policy.path_profile | type == "string")
  ' "$selected_summary_path" >/dev/null 2>&1; then
    selection_policy_selected_summaries_valid_count=$((selection_policy_selected_summaries_valid_count + 1))
  fi
  read -r m4_selected_quality_present \
    m4_selected_quality_status_pass \
    m4_selected_demotion_present \
    m4_selected_promotion_present \
    m4_selected_trust_tier_port_unlock_present < <(extract_m4_policy_signals_from_summary "$selected_summary_path")
  m4_selected_observed_json="$(extract_m4_policy_observed_from_summary "$selected_summary_path")"
  selected_m4_observed_lines+="$m4_selected_observed_json"$'\n'
  if [[ "$m4_selected_quality_present" == "1" ]]; then
    m4_selected_summaries_quality_evidence_present_count=$((m4_selected_summaries_quality_evidence_present_count + 1))
  fi
  if [[ "$m4_selected_quality_status_pass" == "1" ]]; then
    m4_selected_summaries_quality_status_pass_count=$((m4_selected_summaries_quality_status_pass_count + 1))
  fi
  if [[ "$m4_selected_demotion_present" == "1" ]]; then
    m4_selected_summaries_demotion_policy_present_count=$((m4_selected_summaries_demotion_policy_present_count + 1))
  fi
  if [[ "$m4_selected_promotion_present" == "1" ]]; then
    m4_selected_summaries_promotion_policy_present_count=$((m4_selected_summaries_promotion_policy_present_count + 1))
  fi
  if [[ "$m4_selected_trust_tier_port_unlock_present" == "1" ]]; then
    m4_selected_summaries_trust_tier_port_unlock_policy_present_count=$((m4_selected_summaries_trust_tier_port_unlock_policy_present_count + 1))
  fi
done < <(jq -r '.selected_summaries[]? | select(type == "string" and length > 0)' "$campaign_summary_json" 2>/dev/null || true)

selected_m4_observed_aggregate_json="$(printf '%s' "$selected_m4_observed_lines" | jq -cs '
  . as $rows
  | [$rows[] | .quality.score | select(type == "number")] as $quality_scores
  | [$rows[] | .quality.score_avg | select(type == "number")] as $quality_score_avgs
  | [$rows[] | .quality.band | select(type == "string" and length > 0) | ascii_downcase] as $quality_bands
  | [$rows[] | .adaptive.demotion_signal_count | select(type == "number")] as $demotion_signals
  | [$rows[] | .adaptive.promotion_signal_count | select(type == "number")] as $promotion_signals
  | [$rows[] | .adaptive.demotion_candidate | select(type == "boolean")] as $demotion_candidates
  | [$rows[] | .adaptive.promotion_candidate | select(type == "boolean")] as $promotion_candidates
  | [$rows[] | .adaptive.wiring_present | select(type == "boolean")] as $adaptive_wiring
  | [$rows[] | .trust_tier.present_flag | select(type == "boolean")] as $trust_present_flags
  | [$rows[] | .trust_tier.evaluated | select(type == "boolean")] as $trust_evaluated_flags
  | [$rows[] | .trust_tier.evidence_hits | select(type == "number")] as $trust_evidence_hits
  | {
      summaries_count: ($rows | length),
      quality: {
        with_score: ($quality_scores | length),
        score_min: (if ($quality_scores | length) > 0 then ($quality_scores | min) else null end),
        score_max: (if ($quality_scores | length) > 0 then ($quality_scores | max) else null end),
        score_avg: (if ($quality_scores | length) > 0 then (($quality_scores | add) / ($quality_scores | length)) else null end),
        with_score_avg: ($quality_score_avgs | length),
        score_avg_min: (if ($quality_score_avgs | length) > 0 then ($quality_score_avgs | min) else null end),
        score_avg_max: (if ($quality_score_avgs | length) > 0 then ($quality_score_avgs | max) else null end),
        quality_band_counts: (
          if ($quality_bands | length) > 0 then
            ($quality_bands | sort | group_by(.) | map({band: .[0], count: length}))
          else
            []
          end
        ),
        status_pass_true_count: ([$rows[] | .quality.status_pass | select(. == true)] | length)
      },
      adaptive: {
        demotion_signal_count_total: ($demotion_signals | add // 0),
        promotion_signal_count_total: ($promotion_signals | add // 0),
        demotion_candidate_true_count: ([$demotion_candidates[] | select(. == true)] | length),
        promotion_candidate_true_count: ([$promotion_candidates[] | select(. == true)] | length),
        wiring_present_true_count: ([$adaptive_wiring[] | select(. == true)] | length)
      },
      trust_tier: {
        present_true_count: ([$trust_present_flags[] | select(. == true)] | length),
        evaluated_true_count: ([$trust_evaluated_flags[] | select(. == true)] | length),
        evidence_hits_total: ($trust_evidence_hits | add // 0)
      }
    }
')"

selection_policy_selected_summaries_missing_or_unreadable_count=$((selection_policy_selected_summaries_total - selection_policy_selected_summaries_found))
if ((selection_policy_selected_summaries_missing_or_unreadable_count < 0)); then
  selection_policy_selected_summaries_missing_or_unreadable_count=0
fi
selection_policy_selected_summaries_invalid_or_missing_policy_count=$((selection_policy_selected_summaries_total - selection_policy_selected_summaries_valid_count))
if ((selection_policy_selected_summaries_invalid_or_missing_policy_count < 0)); then
  selection_policy_selected_summaries_invalid_or_missing_policy_count=0
fi

selection_policy_evidence_present=0
if ((campaign_selection_policy_present == 1 || selection_policy_selected_summaries_present_count > 0)); then
  selection_policy_evidence_present=1
fi
selection_policy_evidence_valid=0
if ((campaign_selection_policy_valid == 1)); then
  selection_policy_evidence_valid=1
elif ((selection_policy_selected_summaries_total > 0 && selection_policy_selected_summaries_valid_count == selection_policy_selected_summaries_total)); then
  selection_policy_evidence_valid=1
fi

micro_relay_quality_evidence_present=0
if ((campaign_micro_relay_quality_evidence_present == 1)); then
  micro_relay_quality_evidence_present=1
elif ((selection_policy_selected_summaries_total > 0 \
    && selection_policy_selected_summaries_found == selection_policy_selected_summaries_total \
    && m4_selected_summaries_quality_evidence_present_count == selection_policy_selected_summaries_total)); then
  micro_relay_quality_evidence_present=1
fi

micro_relay_quality_status_pass=0
if ((campaign_micro_relay_quality_status_pass == 1)); then
  micro_relay_quality_status_pass=1
elif ((selection_policy_selected_summaries_total > 0 && m4_selected_summaries_quality_status_pass_count == selection_policy_selected_summaries_total)); then
  micro_relay_quality_status_pass=1
fi

micro_relay_demotion_policy_present=0
if ((campaign_micro_relay_demotion_policy_present == 1)); then
  micro_relay_demotion_policy_present=1
elif ((selection_policy_selected_summaries_total > 0 \
    && selection_policy_selected_summaries_found == selection_policy_selected_summaries_total \
    && m4_selected_summaries_demotion_policy_present_count == selection_policy_selected_summaries_total)); then
  micro_relay_demotion_policy_present=1
fi

micro_relay_promotion_policy_present=0
if ((campaign_micro_relay_promotion_policy_present == 1)); then
  micro_relay_promotion_policy_present=1
elif ((selection_policy_selected_summaries_total > 0 \
    && selection_policy_selected_summaries_found == selection_policy_selected_summaries_total \
    && m4_selected_summaries_promotion_policy_present_count == selection_policy_selected_summaries_total)); then
  micro_relay_promotion_policy_present=1
fi

trust_tier_port_unlock_policy_present=0
if ((campaign_trust_tier_port_unlock_policy_present == 1)); then
  trust_tier_port_unlock_policy_present=1
elif ((selection_policy_selected_summaries_total > 0 \
    && selection_policy_selected_summaries_found == selection_policy_selected_summaries_total \
    && m4_selected_summaries_trust_tier_port_unlock_policy_present_count == selection_policy_selected_summaries_total)); then
  trust_tier_port_unlock_policy_present=1
fi

declare -a errors=()
if ((${#numeric_validation_issues[@]} > 0)); then
  errors+=("campaign/trend numeric fields invalid or non-numeric: $(IFS=,; echo "${numeric_validation_issues[*]}")")
fi
declare -a m4_policy_issues=()

if [[ "$require_status_pass" == "1" ]] && [[ "$campaign_status" != "pass" ]]; then
  errors+=("campaign status must be pass (actual=${campaign_status:-unset})")
fi
if [[ "$campaign_rc" != "0" ]]; then
  errors+=("campaign rc must be 0 (actual=$campaign_rc)")
fi
if [[ "$require_trend_status_pass" == "1" ]] && [[ "$trend_status" != "pass" ]]; then
  errors+=("trend status must be pass (actual=${trend_status:-unset})")
fi
if [[ "$trend_rc" != "0" ]]; then
  errors+=("trend rc must be 0 (actual=$trend_rc)")
fi
if ((runs_total < require_min_runs_total)); then
  errors+=("runs_total below required minimum (actual=$runs_total required=$require_min_runs_total)")
fi
if ((runs_fail > require_max_runs_fail)); then
  errors+=("runs_fail exceeds allowed maximum (actual=$runs_fail max=$require_max_runs_fail)")
fi
if ((runs_warn > require_max_runs_warn)); then
  errors+=("runs_warn exceeds allowed maximum (actual=$runs_warn max=$require_max_runs_warn)")
fi
if ((runs_with_summary < require_min_runs_with_summary)); then
  errors+=("runs_with_summary below required minimum (actual=$runs_with_summary required=$require_min_runs_with_summary)")
fi
if [[ -z "$recommended_profile" ]]; then
  errors+=("recommended profile is empty")
fi
if [[ -n "$require_recommended_profile" && "$recommended_profile" != "$require_recommended_profile" ]]; then
  errors+=("recommended profile mismatch (actual=${recommended_profile:-unset} required=$require_recommended_profile)")
fi
if [[ -n "$allow_recommended_profiles" ]] && [[ -n "$recommended_profile" ]]; then
  if ! csv_contains "$allow_recommended_profiles" "$recommended_profile"; then
    errors+=("recommended profile is not in allowed set (actual=$recommended_profile allowed=$allow_recommended_profiles)")
  fi
fi
if [[ "$disallow_experimental_default" == "1" && "$recommended_profile" == "speed-1hop" ]]; then
  errors+=("recommended profile speed-1hop is experimental and cannot be a default")
fi
if awk -v observed="$support_rate_pct" -v min_required="$require_recommendation_support_rate_pct" 'BEGIN { exit !(observed < min_required) }'; then
  errors+=("recommendation support rate below threshold (actual=${support_rate_pct}% required=${require_recommendation_support_rate_pct}%)")
fi
if [[ "$trend_summary_present" != "1" ]]; then
  errors+=("trend summary JSON is missing or invalid (${trend_summary_json:-unset})")
fi
if [[ -n "$require_trend_source" ]]; then
  if [[ -z "$trend_source_value" ]]; then
    errors+=("trend source is missing")
  elif ! csv_contains "$require_trend_source" "$trend_source_value"; then
    errors+=("trend source is not allowed (actual=$trend_source_value allowed=$require_trend_source)")
  fi
fi
if [[ "$require_selection_policy_present" == "1" && "$selection_policy_evidence_present" != "1" ]]; then
  errors+=("selection policy evidence is required but not present")
fi
if [[ "$require_selection_policy_valid" == "1" && "$selection_policy_evidence_valid" != "1" ]]; then
  errors+=("selection policy evidence is required to be valid (valid_summaries=$selection_policy_selected_summaries_valid_count total_summaries=$selection_policy_selected_summaries_total)")
fi
if [[ "$require_micro_relay_quality_evidence" == "1" && "$micro_relay_quality_evidence_present" != "1" ]]; then
  errors+=("micro-relay quality evidence is required but not present")
  m4_policy_issues+=("missing_micro_relay_quality_evidence")
fi
if [[ "$require_micro_relay_quality_status_pass" == "1" && "$micro_relay_quality_status_pass" != "1" ]]; then
  errors+=("micro-relay quality status must be pass (campaign_pass=$campaign_micro_relay_quality_status_pass selected_pass_count=$m4_selected_summaries_quality_status_pass_count total_summaries=$selection_policy_selected_summaries_total)")
  m4_policy_issues+=("micro_relay_quality_status_not_pass")
fi
if [[ "$require_micro_relay_demotion_policy" == "1" && "$micro_relay_demotion_policy_present" != "1" ]]; then
  errors+=("micro-relay demotion policy evidence is required but not present")
  m4_policy_issues+=("missing_micro_relay_demotion_policy")
fi
if [[ "$require_micro_relay_promotion_policy" == "1" && "$micro_relay_promotion_policy_present" != "1" ]]; then
  errors+=("micro-relay promotion policy evidence is required but not present")
  m4_policy_issues+=("missing_micro_relay_promotion_policy")
fi
if [[ "$require_trust_tier_port_unlock_policy" == "1" && "$trust_tier_port_unlock_policy_present" != "1" ]]; then
  errors+=("trust-tier port-unlock policy evidence is required but not present")
  m4_policy_issues+=("missing_trust_tier_port_unlock_policy")
fi

decision="GO"
status="ok"
notes="campaign recommendation passes configured policy"
if ((${#errors[@]} > 0)); then
  decision="NO-GO"
  status="fail"
  notes="campaign recommendation violates one or more policy checks"
fi

rc=0
if [[ "$decision" == "NO-GO" && "$fail_on_no_go" == "1" ]]; then
  rc=1
fi

log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_compare_campaign_check_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

errors_json='[]'
if ((${#errors[@]} > 0)); then
  errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s '.')"
fi
m4_policy_issues_json='[]'
if ((${#m4_policy_issues[@]} > 0)); then
  m4_policy_issues_json="$(printf '%s\n' "${m4_policy_issues[@]}" | jq -R . | jq -s '.')"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg campaign_summary_json "$campaign_summary_json" \
  --arg trend_summary_json "$trend_summary_json" \
  --arg campaign_status "$campaign_status" \
  --argjson campaign_rc "$campaign_rc" \
  --argjson runs_total "$runs_total" \
  --argjson runs_pass "$runs_pass" \
  --argjson runs_warn "$runs_warn" \
  --argjson runs_fail "$runs_fail" \
  --argjson runs_with_summary "$runs_with_summary" \
  --arg recommended_profile "$recommended_profile" \
  --arg decision_source "$decision_source" \
  --arg trend_status "$trend_status" \
  --argjson trend_rc "$trend_rc" \
  --arg trend_source_value "$trend_source_value" \
  --argjson trend_summary_present "$trend_summary_present" \
  --argjson support_rate_pct "$support_rate_pct" \
  --argjson require_status_pass "$require_status_pass" \
  --argjson require_trend_status_pass "$require_trend_status_pass" \
  --argjson require_min_runs_total "$require_min_runs_total" \
  --argjson require_max_runs_fail "$require_max_runs_fail" \
  --argjson require_max_runs_warn "$require_max_runs_warn" \
  --argjson require_min_runs_with_summary "$require_min_runs_with_summary" \
  --argjson require_recommendation_support_rate_pct "$require_recommendation_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --argjson disallow_experimental_default "$disallow_experimental_default" \
  --arg require_trend_source "$require_trend_source" \
  --argjson require_selection_policy_present "$require_selection_policy_present" \
  --argjson require_selection_policy_valid "$require_selection_policy_valid" \
  --argjson require_micro_relay_quality_evidence "$require_micro_relay_quality_evidence" \
  --argjson require_micro_relay_quality_status_pass "$require_micro_relay_quality_status_pass" \
  --argjson require_micro_relay_demotion_policy "$require_micro_relay_demotion_policy" \
  --argjson require_micro_relay_promotion_policy "$require_micro_relay_promotion_policy" \
  --argjson require_trust_tier_port_unlock_policy "$require_trust_tier_port_unlock_policy" \
  --argjson selection_policy_evidence_present "$selection_policy_evidence_present" \
  --argjson selection_policy_evidence_valid "$selection_policy_evidence_valid" \
  --argjson campaign_selection_policy_present "$campaign_selection_policy_present" \
  --argjson campaign_selection_policy_valid "$campaign_selection_policy_valid" \
  --arg campaign_selection_policy_source "$campaign_selection_policy_source" \
  --argjson campaign_selection_policy_synthetic_default "$campaign_selection_policy_synthetic_default" \
  --argjson selection_policy_selected_summaries_total "$selection_policy_selected_summaries_total" \
  --argjson selection_policy_selected_summaries_found "$selection_policy_selected_summaries_found" \
  --argjson selection_policy_selected_summaries_present_count "$selection_policy_selected_summaries_present_count" \
  --argjson selection_policy_selected_summaries_valid_count "$selection_policy_selected_summaries_valid_count" \
  --argjson selection_policy_selected_summaries_missing_or_unreadable_count "$selection_policy_selected_summaries_missing_or_unreadable_count" \
  --argjson selection_policy_selected_summaries_invalid_or_missing_policy_count "$selection_policy_selected_summaries_invalid_or_missing_policy_count" \
  --argjson micro_relay_quality_evidence_present "$micro_relay_quality_evidence_present" \
  --argjson micro_relay_quality_status_pass "$micro_relay_quality_status_pass" \
  --argjson micro_relay_demotion_policy_present "$micro_relay_demotion_policy_present" \
  --argjson micro_relay_promotion_policy_present "$micro_relay_promotion_policy_present" \
  --argjson trust_tier_port_unlock_policy_present "$trust_tier_port_unlock_policy_present" \
  --argjson campaign_micro_relay_quality_evidence_present "$campaign_micro_relay_quality_evidence_present" \
  --argjson campaign_micro_relay_quality_status_pass "$campaign_micro_relay_quality_status_pass" \
  --argjson campaign_micro_relay_demotion_policy_present "$campaign_micro_relay_demotion_policy_present" \
  --argjson campaign_micro_relay_promotion_policy_present "$campaign_micro_relay_promotion_policy_present" \
  --argjson campaign_trust_tier_port_unlock_policy_present "$campaign_trust_tier_port_unlock_policy_present" \
  --argjson m4_selected_summaries_quality_evidence_present_count "$m4_selected_summaries_quality_evidence_present_count" \
  --argjson m4_selected_summaries_quality_status_pass_count "$m4_selected_summaries_quality_status_pass_count" \
  --argjson m4_selected_summaries_demotion_policy_present_count "$m4_selected_summaries_demotion_policy_present_count" \
  --argjson m4_selected_summaries_promotion_policy_present_count "$m4_selected_summaries_promotion_policy_present_count" \
  --argjson m4_selected_summaries_trust_tier_port_unlock_policy_present_count "$m4_selected_summaries_trust_tier_port_unlock_policy_present_count" \
  --argjson campaign_m4_observed "$campaign_m4_observed_json" \
  --argjson selected_m4_observed_aggregate "$selected_m4_observed_aggregate_json" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson rc "$rc" \
  --argjson errors "$errors_json" \
  --argjson m4_policy_issues "$m4_policy_issues_json" \
  --arg summary_json "$summary_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    decision: $decision,
    status: $status,
    rc: $rc,
    notes: $notes,
    inputs: {
      campaign_summary_json: $campaign_summary_json,
      trend_summary_json: $trend_summary_json,
      policy: {
        require_status_pass: ($require_status_pass == 1),
        require_trend_status_pass: ($require_trend_status_pass == 1),
        require_min_runs_total: $require_min_runs_total,
        require_max_runs_fail: $require_max_runs_fail,
        require_max_runs_warn: $require_max_runs_warn,
        require_min_runs_with_summary: $require_min_runs_with_summary,
        require_recommendation_support_rate_pct: $require_recommendation_support_rate_pct,
        require_recommended_profile: $require_recommended_profile,
        allow_recommended_profiles: $allow_recommended_profiles,
        disallow_experimental_default: ($disallow_experimental_default == 1),
        require_trend_source: $require_trend_source,
        require_selection_policy_present: ($require_selection_policy_present == 1),
        require_selection_policy_valid: ($require_selection_policy_valid == 1),
        require_micro_relay_quality_evidence: ($require_micro_relay_quality_evidence == 1),
        require_micro_relay_quality_status_pass: ($require_micro_relay_quality_status_pass == 1),
        require_micro_relay_demotion_policy: ($require_micro_relay_demotion_policy == 1),
        require_micro_relay_promotion_policy: ($require_micro_relay_promotion_policy == 1),
        require_trust_tier_port_unlock_policy: ($require_trust_tier_port_unlock_policy == 1),
        fail_on_no_go: ($fail_on_no_go == 1)
      }
    },
    observed: {
      campaign_status: $campaign_status,
      campaign_rc: $campaign_rc,
      runs_total: $runs_total,
      runs_pass: $runs_pass,
      runs_warn: $runs_warn,
      runs_fail: $runs_fail,
      runs_with_summary: $runs_with_summary,
      recommended_profile: $recommended_profile,
      decision_source: $decision_source,
      trend_status: $trend_status,
      trend_rc: $trend_rc,
      trend_source: $trend_source_value,
      trend_summary_present: ($trend_summary_present == 1),
      recommendation_support_rate_pct: $support_rate_pct,
      selection_policy_evidence: {
        present: ($selection_policy_evidence_present == 1),
        valid: ($selection_policy_evidence_valid == 1),
        campaign_summary_present: ($campaign_selection_policy_present == 1),
        campaign_summary_valid: ($campaign_selection_policy_valid == 1),
        campaign_summary_source: (if $campaign_selection_policy_source == "" then null else $campaign_selection_policy_source end),
        campaign_summary_synthetic_default: ($campaign_selection_policy_synthetic_default == 1),
        selected_summaries_total: $selection_policy_selected_summaries_total,
        selected_summaries_found: $selection_policy_selected_summaries_found,
        selected_summaries_with_policy_present: $selection_policy_selected_summaries_present_count,
        selected_summaries_with_policy_valid: $selection_policy_selected_summaries_valid_count,
        selected_summaries_missing_or_unreadable: $selection_policy_selected_summaries_missing_or_unreadable_count,
        selected_summaries_invalid_or_missing_policy: $selection_policy_selected_summaries_invalid_or_missing_policy_count
      },
      micro_relay_policy_evidence: {
        quality_evidence_present: ($micro_relay_quality_evidence_present == 1),
        quality_status_pass: ($micro_relay_quality_status_pass == 1),
        demotion_policy_present: ($micro_relay_demotion_policy_present == 1),
        promotion_policy_present: ($micro_relay_promotion_policy_present == 1),
        trust_tier_port_unlock_policy_present: ($trust_tier_port_unlock_policy_present == 1),
        campaign_summary_quality_evidence_present: ($campaign_micro_relay_quality_evidence_present == 1),
        campaign_summary_quality_status_pass: ($campaign_micro_relay_quality_status_pass == 1),
        campaign_summary_demotion_policy_present: ($campaign_micro_relay_demotion_policy_present == 1),
        campaign_summary_promotion_policy_present: ($campaign_micro_relay_promotion_policy_present == 1),
        campaign_summary_trust_tier_port_unlock_policy_present: ($campaign_trust_tier_port_unlock_policy_present == 1),
        selected_summaries_with_quality_evidence_present: $m4_selected_summaries_quality_evidence_present_count,
        selected_summaries_with_quality_status_pass: $m4_selected_summaries_quality_status_pass_count,
        selected_summaries_with_demotion_policy_present: $m4_selected_summaries_demotion_policy_present_count,
        selected_summaries_with_promotion_policy_present: $m4_selected_summaries_promotion_policy_present_count,
        selected_summaries_with_trust_tier_port_unlock_policy_present: $m4_selected_summaries_trust_tier_port_unlock_policy_present_count,
        campaign_summary_details: $campaign_m4_observed,
        selected_summaries_aggregate: $selected_m4_observed_aggregate
      }
    },
    decision_diagnostics: {
      m4_policy: (
        {
          required: {
            quality_evidence: ($require_micro_relay_quality_evidence == 1),
            quality_status_pass: ($require_micro_relay_quality_status_pass == 1),
            demotion_policy: ($require_micro_relay_demotion_policy == 1),
            promotion_policy: ($require_micro_relay_promotion_policy == 1),
            trust_tier_port_unlock_policy: ($require_trust_tier_port_unlock_policy == 1)
          },
          observed_details: {
            campaign_summary: $campaign_m4_observed,
            selected_summaries_aggregate: $selected_m4_observed_aggregate
          },
          unmet_requirements: $m4_policy_issues,
          gate_evaluation: {
            micro_relay_quality_evidence: {
              required: ($require_micro_relay_quality_evidence == 1),
              observed: ($micro_relay_quality_evidence_present == 1),
              observed_any: ($campaign_micro_relay_quality_evidence_present == 1 or $m4_selected_summaries_quality_evidence_present_count > 0),
              campaign_summary_observed: ($campaign_micro_relay_quality_evidence_present == 1),
              selected_summaries_total: $selection_policy_selected_summaries_total,
              selected_summaries_found: $selection_policy_selected_summaries_found,
              selected_summaries_with_signal: $m4_selected_summaries_quality_evidence_present_count,
              status: (
                if ($require_micro_relay_quality_evidence == 1) then
                  (if ($micro_relay_quality_evidence_present == 1) then "pass" else "fail" end)
                else
                  "not-required"
                end
              ),
              blocking: ($require_micro_relay_quality_evidence == 1 and $micro_relay_quality_evidence_present != 1),
              actionable_reason: (
                if ($require_micro_relay_quality_evidence == 1 and $micro_relay_quality_evidence_present != 1) then
                  "micro-relay quality evidence missing; capture m4 micro-relay quality evidence in campaign or selected summaries and rerun campaign-check"
                else
                  null
                end
              )
            },
            micro_relay_quality_status_pass: {
              required: ($require_micro_relay_quality_status_pass == 1),
              observed: ($micro_relay_quality_status_pass == 1),
              observed_any: ($campaign_micro_relay_quality_status_pass == 1 or $m4_selected_summaries_quality_status_pass_count > 0),
              campaign_summary_observed: ($campaign_micro_relay_quality_status_pass == 1),
              selected_summaries_total: $selection_policy_selected_summaries_total,
              selected_summaries_found: $selection_policy_selected_summaries_found,
              selected_summaries_with_signal: $m4_selected_summaries_quality_status_pass_count,
              status: (
                if ($require_micro_relay_quality_status_pass == 1) then
                  (if ($micro_relay_quality_status_pass == 1) then "pass" else "fail" end)
                else
                  "not-required"
                end
              ),
              blocking: ($require_micro_relay_quality_status_pass == 1 and $micro_relay_quality_status_pass != 1),
              actionable_reason: (
                if ($require_micro_relay_quality_status_pass == 1 and $micro_relay_quality_status_pass != 1) then
                  "micro-relay quality status is not pass; improve relay quality scoring evidence and rerun campaign-check"
                else
                  null
                end
              )
            },
            micro_relay_demotion_policy: {
              required: ($require_micro_relay_demotion_policy == 1),
              observed: ($micro_relay_demotion_policy_present == 1),
              observed_any: ($campaign_micro_relay_demotion_policy_present == 1 or $m4_selected_summaries_demotion_policy_present_count > 0),
              campaign_summary_observed: ($campaign_micro_relay_demotion_policy_present == 1),
              selected_summaries_total: $selection_policy_selected_summaries_total,
              selected_summaries_found: $selection_policy_selected_summaries_found,
              selected_summaries_with_signal: $m4_selected_summaries_demotion_policy_present_count,
              status: (
                if ($require_micro_relay_demotion_policy == 1) then
                  (if ($micro_relay_demotion_policy_present == 1) then "pass" else "fail" end)
                else
                  "not-required"
                end
              ),
              blocking: ($require_micro_relay_demotion_policy == 1 and $micro_relay_demotion_policy_present != 1),
              actionable_reason: (
                if ($require_micro_relay_demotion_policy == 1 and $micro_relay_demotion_policy_present != 1) then
                  "micro-relay demotion policy evidence missing; include adaptive demotion policy evidence and rerun campaign-check"
                else
                  null
                end
              )
            },
            micro_relay_promotion_policy: {
              required: ($require_micro_relay_promotion_policy == 1),
              observed: ($micro_relay_promotion_policy_present == 1),
              observed_any: ($campaign_micro_relay_promotion_policy_present == 1 or $m4_selected_summaries_promotion_policy_present_count > 0),
              campaign_summary_observed: ($campaign_micro_relay_promotion_policy_present == 1),
              selected_summaries_total: $selection_policy_selected_summaries_total,
              selected_summaries_found: $selection_policy_selected_summaries_found,
              selected_summaries_with_signal: $m4_selected_summaries_promotion_policy_present_count,
              status: (
                if ($require_micro_relay_promotion_policy == 1) then
                  (if ($micro_relay_promotion_policy_present == 1) then "pass" else "fail" end)
                else
                  "not-required"
                end
              ),
              blocking: ($require_micro_relay_promotion_policy == 1 and $micro_relay_promotion_policy_present != 1),
              actionable_reason: (
                if ($require_micro_relay_promotion_policy == 1 and $micro_relay_promotion_policy_present != 1) then
                  "micro-relay promotion policy evidence missing; include adaptive promotion policy evidence and rerun campaign-check"
                else
                  null
                end
              )
            },
            trust_tier_port_unlock_policy: {
              required: ($require_trust_tier_port_unlock_policy == 1),
              observed: ($trust_tier_port_unlock_policy_present == 1),
              observed_any: ($campaign_trust_tier_port_unlock_policy_present == 1 or $m4_selected_summaries_trust_tier_port_unlock_policy_present_count > 0),
              campaign_summary_observed: ($campaign_trust_tier_port_unlock_policy_present == 1),
              selected_summaries_total: $selection_policy_selected_summaries_total,
              selected_summaries_found: $selection_policy_selected_summaries_found,
              selected_summaries_with_signal: $m4_selected_summaries_trust_tier_port_unlock_policy_present_count,
              status: (
                if ($require_trust_tier_port_unlock_policy == 1) then
                  (if ($trust_tier_port_unlock_policy_present == 1) then "pass" else "fail" end)
                else
                  "not-required"
                end
              ),
              blocking: ($require_trust_tier_port_unlock_policy == 1 and $trust_tier_port_unlock_policy_present != 1),
              actionable_reason: (
                if ($require_trust_tier_port_unlock_policy == 1 and $trust_tier_port_unlock_policy_present != 1) then
                  "trust-tier port-unlock policy evidence missing; wire trust-tier port-unlock policy evidence and rerun campaign-check"
                else
                  null
                end
              )
            }
          }
        }
        | .gate_summary = {
            required_total: ([.gate_evaluation | to_entries[] | select(.value.required)] | length),
            required_passed: ([.gate_evaluation | to_entries[] | select(.value.required and .value.status == "pass")] | length),
            required_failed: ([.gate_evaluation | to_entries[] | select(.value.required and .value.status == "fail")] | length),
            failed_gate_ids: ([.gate_evaluation | to_entries[] | select(.value.required and .value.status == "fail") | .key])
          }
      )
    },
    errors: $errors,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[profile-compare-campaign-check] decision=$decision status=$status rc=$rc recommended_profile=${recommended_profile:-unset} support_rate_pct=${support_rate_pct}"
if ((${#errors[@]} > 0)); then
  echo "[profile-compare-campaign-check] failed with ${#errors[@]} issue(s):"
  idx=1
  for err in "${errors[@]}"; do
    echo "  $idx. $err"
    idx=$((idx + 1))
  done
fi

if [[ "$show_json" == "1" ]]; then
  echo "[profile-compare-campaign-check] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
