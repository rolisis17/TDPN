#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/three_machine_real_host_validation_pack.sh \
    [--reports-dir DIR] \
    [--max-age-sec N] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--include-missing [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Build one deterministic M3 validation pack by collecting existing
  three-machine docker-matrix/readiness and real-host validation artifacts.

Behavior:
  - Discovers known artifact patterns in --reports-dir (recursive).
  - Copies discovered artifacts into one deterministic pack directory.
  - Emits machine-readable summary + markdown report.
  - Missing required evidence groups fail closed by default.
  - Semantic usability is freshness-gated; stale artifacts fail closed.
  - With --include-missing 1, missing groups are surfaced as WARN (rc=0).
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local value
  value="$(trim "${1:-}")"
  if [[ -z "$value" ]]; then
    printf '%s' ""
  elif [[ "$value" == /* ]]; then
    printf '%s' "$value"
  elif [[ "$value" =~ ^[A-Za-z]:[\\/].* ]]; then
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$value"
    else
      local drive="${value:0:1}"
      local tail="${value:2}"
      tail="${tail//\\//}"
      printf '/mnt/%s/%s' "${drive,,}" "${tail#/}"
    fi
  else
    printf '%s' "$ROOT_DIR/$value"
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

is_non_negative_integer() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

file_mtime_epoch() {
  local path="$1"
  local raw=""
  if raw="$(stat -c %Y "$path" 2>/dev/null)"; then
    :
  elif raw="$(stat -f %m "$path" 2>/dev/null)"; then
    :
  else
    printf '%s' ""
    return
  fi
  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    printf '%s' "$raw"
  else
    printf '%s' ""
  fi
}

json_file_valid_01() {
  local path="$1"
  if [[ -f "$path" ]] && jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

json_file_semantically_usable_01() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e '
    type == "object"
    and (
      ((if (.rc == null and .summary.rc == null) then null else (.rc // .summary.rc) end) | tonumber?) as $rc
      | ($rc != null and $rc == 0)
    )
    and (
      ((if (.decision // .summary.decision) == null then "" else (.decision // .summary.decision) end)
        | ascii_upcase
        | gsub("[ _-]";"")) as $decision
      | ($decision == "" or $decision == "GO")
      and ($decision != "NOGO")
    )
    and (
      ((if (.status // .summary.status) == null then "" else (.status // .summary.status) end)
        | ascii_downcase
        | gsub("[[:space:]_-]";"")) as $status
      | ($status == "" or $status == "pass" or $status == "ok" or $status == "go")
    )
    and (
      ((if (.decision // .summary.decision) == null then "" else (.decision // .summary.decision) end)
        | ascii_upcase
        | gsub("[ _-]";"")) as $decision
      | ((if (.status // .summary.status) == null then "" else (.status // .summary.status) end)
        | ascii_downcase
        | gsub("[[:space:]_-]";"")) as $status
      | ($decision != "" or $status != "")
    )
  ' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

evaluate_artifact_freshness_json() {
  local path="$1"
  local max_age_sec="$2"
  local mtime_epoch=""
  local mtime_epoch_json="null"
  mtime_epoch="$(file_mtime_epoch "$path")"
  if [[ "$mtime_epoch" =~ ^[0-9]+$ ]]; then
    mtime_epoch_json="$mtime_epoch"
  fi

  jq -c \
    --argjson max_age_sec "$max_age_sec" \
    --argjson file_mtime_epoch "$mtime_epoch_json" \
    '
      (if (.generated_at_utc | type) == "string" then .generated_at_utc
       elif (.summary.generated_at_utc | type) == "string" then .summary.generated_at_utc
       else ""
       end) as $generated_at_utc
      | (if ($generated_at_utc | length) > 0 then (try ($generated_at_utc | fromdateiso8601) catch null) else null end) as $generated_epoch
      | if (($generated_at_utc | length) > 0 and $generated_epoch == null) then
          {
            known: false,
            fresh: false,
            source: "generated_at_utc_invalid",
            generated_at_utc: $generated_at_utc,
            age_sec: null,
            max_age_sec: $max_age_sec
          }
        elif $generated_epoch != null then
          {
            known: true,
            fresh: (($generated_epoch <= now) and ((now - $generated_epoch) <= $max_age_sec)),
            source: "generated_at_utc",
            generated_at_utc: $generated_at_utc,
            age_sec: (now - $generated_epoch),
            max_age_sec: $max_age_sec
          }
        elif $file_mtime_epoch != null then
          {
            known: true,
            fresh: (($file_mtime_epoch <= now) and ((now - $file_mtime_epoch) <= $max_age_sec)),
            source: "file_mtime_epoch",
            generated_at_utc: null,
            age_sec: (now - $file_mtime_epoch),
            max_age_sec: $max_age_sec
          }
        else
          {
            known: false,
            fresh: false,
            source: null,
            generated_at_utc: null,
            age_sec: null,
            max_age_sec: $max_age_sec
          }
        end
    ' "$path"
}

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s' "NO-GO" ;;
    *) printf '%s' "" ;;
  esac
}

json_array_from_json_lines() {
  if [[ $# -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -s '.'
}

append_unique_line() {
  local value="$1"
  local array_name="$2"
  local -n ref="$array_name"
  local existing=""
  for existing in "${ref[@]:-}"; do
    if [[ "$existing" == "$value" ]]; then
      return
    fi
  done
  ref+=("$value")
}

need_cmd jq
need_cmd find
need_cmd cp
need_cmd date
need_cmd basename
need_cmd dirname
need_cmd stat

reports_dir="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_REPORTS_DIR:-}"
summary_json="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SUMMARY_JSON:-}"
report_md="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_REPORT_MD:-}"
include_missing="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_INCLUDE_MISSING:-0}"
print_summary_json="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_PRINT_SUMMARY_JSON:-1}"
max_age_sec="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_MAX_AGE_SEC:-86400}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "--reports-dir" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "--summary-json" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --report-md)
      require_value_or_die "--report-md" "${2:-}"
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
      shift
      ;;
    --max-age-sec)
      require_value_or_die "--max-age-sec" "${2:-}"
      max_age_sec="${2:-}"
      shift 2
      ;;
    --max-age-sec=*)
      max_age_sec="${1#*=}"
      shift
      ;;
    --include-missing)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        include_missing="${2:-}"
        shift 2
      else
        include_missing="1"
        shift
      fi
      ;;
    --include-missing=*)
      include_missing="${1#*=}"
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

bool_arg_or_die "--include-missing" "$include_missing"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
max_age_sec="$(trim "$max_age_sec")"
if ! is_non_negative_integer "$max_age_sec"; then
  echo "--max-age-sec must be a non-negative integer"
  exit 2
fi

if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/three_machine_real_host_validation_pack_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/three_machine_real_host_validation_pack_report.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$report_md")"

pack_artifacts_dir="$reports_dir/three_machine_real_host_validation_pack_artifacts"
mkdir -p "$pack_artifacts_dir"

discover_latest_matching_file() {
  local base_dir="$1"
  local pattern="$2"
  local best_path=""
  local best_mtime="-1"
  local candidate=""
  local candidate_mtime=""

  while IFS= read -r -d '' candidate; do
    if [[ "$candidate" == "$pack_artifacts_dir/"* ]]; then
      continue
    fi
    if [[ "$candidate" == *"/three_machine_real_host_validation_pack_artifacts/"* ]]; then
      continue
    fi
    if [[ "$candidate" == *"/roadmap_live_evidence_archive/"* ]]; then
      continue
    fi
    if [[ "$candidate" == *"/roadmap_live_evidence_archive_"*"/"* ]]; then
      continue
    fi
    candidate_mtime="$(file_mtime_epoch "$candidate")"
    if [[ "$candidate_mtime" =~ ^[0-9]+$ ]]; then
      if (( candidate_mtime > best_mtime )); then
        best_mtime="$candidate_mtime"
        best_path="$candidate"
      elif (( candidate_mtime == best_mtime )) && [[ "$candidate" > "$best_path" ]]; then
        best_path="$candidate"
      fi
    elif [[ "$best_mtime" == "-1" && "$candidate" > "$best_path" ]]; then
      best_path="$candidate"
    fi
  done < <(find "$base_dir" -type f -name "$pattern" -print0 2>/dev/null)

  printf '%s' "$best_path"
}

copy_for_pack() {
  local source_path="$1"
  local artifact_id="$2"
  local safe_id="${artifact_id//[^a-zA-Z0-9_]/_}"
  local base_name
  base_name="$(basename "$source_path")"
  local dest_path="$pack_artifacts_dir/${safe_id}__${base_name}"
  if [[ "$source_path" != "$dest_path" ]]; then
    cp -f "$source_path" "$dest_path"
  fi
  printf '%s' "$dest_path"
}

declare -a artifact_specs=(
  "docker_matrix_summary|docker_matrix|three_machine_docker_profile_matrix_summary.json|Docker profile matrix summary"
  "docker_matrix_record_summary|docker_matrix|three_machine_docker_profile_matrix_record_summary.json|Docker profile matrix record summary"
  "docker_matrix_record_matrix|docker_matrix|three_machine_docker_profile_matrix_record_*_matrix.json|Docker profile matrix record matrix artifact"
  "docker_matrix_run_matrix|docker_matrix|three_machine_docker_profile_matrix_*_matrix.json|Docker profile matrix run matrix artifact"
  "docker_readiness_1hop|docker_readiness|three_machine_docker_readiness_1hop.json|Docker readiness 1-hop summary"
  "docker_readiness_2hop|docker_readiness|three_machine_docker_readiness_2hop.json|Docker readiness 2-hop summary"
  "docker_readiness_3hop|docker_readiness|three_machine_docker_readiness_3hop.json|Docker readiness 3-hop summary"
  "docker_readiness_summary|docker_readiness|three_machine_docker_readiness_summary.json|Docker readiness summary"
  "real_host_signoff_summary|real_host|three_machine_prod_signoff_summary.json|Real-host signoff summary"
  "real_host_signoff_latest|real_host|three_machine_prod_signoff_latest.json|Real-host signoff latest summary"
  "real_host_signoff_timestamped|real_host|three_machine_prod_signoff_*.json|Real-host signoff timestamped summary"
  "manual_validation_summary|real_host_support|manual_validation_readiness_summary.json|Manual validation readiness summary"
  "pre_real_host_summary|real_host_support|pre_real_host_readiness_summary.json|Pre real-host readiness summary"
)

declare -A path_seen=()
declare -A group_found=(
  [docker_matrix]=0
  [docker_readiness]=0
  [real_host]=0
  [real_host_support]=0
)
declare -A group_usable=(
  [docker_matrix]=0
  [docker_readiness]=0
  [real_host]=0
  [real_host_support]=0
)
declare -A group_freshness_blocked=(
  [docker_matrix]=0
  [docker_readiness]=0
  [real_host]=0
  [real_host_support]=0
)

declare -a discovered_rows=()
declare -a missing_rows=()
declare -a reasons=()
declare -a next_action_rows=()
declare -a next_action_commands=()

discovered_count=0
copied_count=0
missing_count=0

for spec in "${artifact_specs[@]}"; do
  IFS='|' read -r artifact_id artifact_group artifact_pattern artifact_label <<<"$spec"
  source_path="$(discover_latest_matching_file "$reports_dir" "$artifact_pattern")"

  if [[ -z "$source_path" ]]; then
    missing_count=$((missing_count + 1))
    missing_row="$(jq -n \
      --arg id "$artifact_id" \
      --arg group "$artifact_group" \
      --arg pattern "$artifact_pattern" \
      --arg label "$artifact_label" \
      --arg reason "missing" \
      '{
        id: $id,
        group: $group,
        pattern: $pattern,
        label: $label,
        reason: $reason
      }')"
    missing_rows+=("$missing_row")
    continue
  fi

  if [[ -n "${path_seen[$source_path]:-}" ]]; then
    continue
  fi
  path_seen["$source_path"]="1"

  group_found["$artifact_group"]=1
  discovered_count=$((discovered_count + 1))
  copied_path="$(copy_for_pack "$source_path" "$artifact_id")"
  copied_count=$((copied_count + 1))

  json_valid="$(json_file_valid_01 "$source_path")"
  schema_id=""
  status_value=""
  decision_value=""
  decision_normalized=""
  generated_at_utc=""
  semantic_usable="0"
  freshness_known="0"
  freshness_fresh="0"
  freshness_source=""
  freshness_age_sec=""
  freshness_generated_at_utc=""
  usable="0"
  if [[ "$json_valid" == "1" ]]; then
    schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$source_path" 2>/dev/null || printf '%s' "")"
    status_value="$(jq -r '
      if (.status | type) == "string" then .status
      elif (.summary.status | type) == "string" then .summary.status
      else ""
      end
    ' "$source_path" 2>/dev/null || printf '%s' "")"
    decision_value="$(jq -r '
      if (.decision | type) == "string" then .decision
      elif (.summary.decision | type) == "string" then .summary.decision
      else ""
      end
    ' "$source_path" 2>/dev/null || printf '%s' "")"
    decision_normalized="$(normalize_decision "$decision_value")"
    generated_at_utc="$(jq -r '
      if (.generated_at_utc | type) == "string" then .generated_at_utc
      elif (.summary.generated_at_utc | type) == "string" then .summary.generated_at_utc
      else ""
      end
    ' "$source_path" 2>/dev/null || printf '%s' "")"
    semantic_usable="$(json_file_semantically_usable_01 "$source_path")"
    freshness_eval_json="$(evaluate_artifact_freshness_json "$source_path" "$max_age_sec")"
    freshness_known="$(jq -r 'if .known == true then "1" else "0" end' <<<"$freshness_eval_json" 2>/dev/null || printf '%s' "0")"
    freshness_fresh="$(jq -r 'if .fresh == true then "1" else "0" end' <<<"$freshness_eval_json" 2>/dev/null || printf '%s' "0")"
    freshness_source="$(jq -r '.source // ""' <<<"$freshness_eval_json" 2>/dev/null || printf '%s' "")"
    freshness_age_sec="$(jq -r 'if (.age_sec | type) == "number" then ((.age_sec | floor) | tostring) else "" end' <<<"$freshness_eval_json" 2>/dev/null || printf '%s' "")"
    freshness_generated_at_utc="$(jq -r '.generated_at_utc // ""' <<<"$freshness_eval_json" 2>/dev/null || printf '%s' "")"
    if [[ -z "$generated_at_utc" && -n "$freshness_generated_at_utc" ]]; then
      generated_at_utc="$freshness_generated_at_utc"
    fi
    if [[ "$semantic_usable" == "1" && "$freshness_known" == "1" && "$freshness_fresh" == "1" ]]; then
      usable="1"
      group_usable["$artifact_group"]=1
    elif [[ "$semantic_usable" == "1" ]]; then
      group_freshness_blocked["$artifact_group"]=1
    fi
  fi

  row="$(jq -n \
    --arg id "$artifact_id" \
    --arg group "$artifact_group" \
    --arg pattern "$artifact_pattern" \
    --arg label "$artifact_label" \
    --arg source_path "$source_path" \
    --arg copied_path "$copied_path" \
    --arg json_valid "$json_valid" \
    --arg schema_id "$schema_id" \
    --arg status_value "$status_value" \
    --arg decision_value "$decision_value" \
    --arg decision_normalized "$decision_normalized" \
    --arg generated_at_utc "$generated_at_utc" \
    --arg semantic_usable "$semantic_usable" \
    --arg freshness_known "$freshness_known" \
    --arg freshness_fresh "$freshness_fresh" \
    --arg freshness_source "$freshness_source" \
    --arg freshness_age_sec "$freshness_age_sec" \
    --arg usable "$usable" \
    --argjson max_age_sec "$max_age_sec" \
    '
      {
        id: $id,
        group: $group,
        pattern: $pattern,
        label: $label,
        source_path: $source_path,
        copied_path: $copied_path,
        json_valid: ($json_valid == "1"),
        schema_id: (if ($schema_id | length) > 0 then $schema_id else null end),
        status: (if ($status_value | length) > 0 then $status_value else null end),
        decision: (if ($decision_value | length) > 0 then $decision_value else null end),
        decision_normalized: (if ($decision_normalized | length) > 0 then $decision_normalized else null end),
        generated_at_utc: (if ($generated_at_utc | length) > 0 then $generated_at_utc else null end),
        semantic_usable: ($semantic_usable == "1"),
        freshness: {
          known: ($freshness_known == "1"),
          fresh: ($freshness_fresh == "1"),
          source: (if ($freshness_source | length) > 0 then $freshness_source else null end),
          age_sec: (if ($freshness_age_sec | length) > 0 then ($freshness_age_sec | tonumber?) else null end),
          max_age_sec: $max_age_sec
        },
        freshness_blocked: (($semantic_usable == "1") and ((($freshness_known == "1") and ($freshness_fresh == "1")) | not)),
        usable: ($usable == "1")
      }
    ')"
  discovered_rows+=("$row")
done

ensure_group_action() {
  local group="$1"
  local id="$2"
  local label="$3"
  local command="$4"
  local reason="$5"

  local row
  row="$(jq -n \
    --arg id "$id" \
    --arg group "$group" \
    --arg label "$label" \
    --arg command "$command" \
    --arg reason "$reason" \
    '{
      id: $id,
      group: $group,
      label: $label,
      command: $command,
      reason: $reason
    }')"
  append_unique_line "$command" next_action_commands
  if [[ "${#next_action_rows[@]}" -eq 0 ]]; then
    next_action_rows+=("$row")
    return
  fi
  local existing_cmd=""
  for existing_cmd in "${next_action_rows[@]}"; do
    if jq -e --arg command "$command" '.command == $command' >/dev/null 2>&1 <<<"$existing_cmd"; then
      return
    fi
  done
  next_action_rows+=("$row")
}

if [[ "${group_usable[docker_matrix]}" != "1" ]]; then
  reasons+=("missing usable docker-matrix evidence artifacts")
  if [[ "${group_found[docker_matrix]}" == "1" && "${group_freshness_blocked[docker_matrix]}" == "1" ]]; then
    reasons+=("docker-matrix evidence artifacts are stale or freshness-unknown (max-age-sec=$max_age_sec)")
  fi
  ensure_group_action \
    "docker_matrix" \
    "capture_docker_matrix_evidence" \
    "Capture docker matrix evidence" \
    "./scripts/easy_node.sh three-machine-docker-profile-matrix-record --print-summary-json 1" \
    "M3 requires deterministic, fresh docker-matrix evidence."
fi

if [[ "${group_usable[docker_readiness]}" != "1" ]]; then
  reasons+=("missing usable docker-readiness evidence artifacts")
  if [[ "${group_found[docker_readiness]}" == "1" && "${group_freshness_blocked[docker_readiness]}" == "1" ]]; then
    reasons+=("docker-readiness evidence artifacts are stale or freshness-unknown (max-age-sec=$max_age_sec)")
  fi
  ensure_group_action \
    "docker_readiness" \
    "capture_docker_readiness_evidence" \
    "Capture docker readiness evidence" \
    "./scripts/easy_node.sh three-machine-docker-readiness-record --print-summary-json 1" \
    "M3 requires at least one readable, fresh readiness summary."
fi

if [[ "${group_usable[real_host]}" != "1" ]]; then
  reasons+=("missing usable real-host signoff evidence artifacts")
  if [[ "${group_found[real_host]}" == "1" && "${group_freshness_blocked[real_host]}" == "1" ]]; then
    reasons+=("real-host signoff evidence artifacts are stale or freshness-unknown (max-age-sec=$max_age_sec)")
  fi
  ensure_group_action \
    "real_host" \
    "capture_real_host_signoff_evidence" \
    "Capture real-host signoff evidence" \
    "sudo ./scripts/easy_node.sh three-machine-prod-signoff --pre-real-host-readiness 1 --print-summary-json 1" \
    "M3 closure still needs fresh real-host validation evidence."
fi

discovered_json="$(json_array_from_json_lines "${discovered_rows[@]:-}")"
missing_json="$(json_array_from_json_lines "${missing_rows[@]:-}")"
reasons_json="$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s '.')"
next_actions_json="$(json_array_from_json_lines "${next_action_rows[@]:-}")"

status="ok"
decision="GO"
rc=0
if (( ${#reasons[@]} > 0 )); then
  decision="NO-GO"
  if [[ "$include_missing" == "1" ]]; then
    status="warn"
    rc=0
  else
    status="fail"
    rc=1
  fi
fi

primary_next_action=""
if [[ "${#next_action_rows[@]}" -gt 0 ]]; then
  primary_next_action="$(jq -r '.[0].command // ""' <<<"$next_actions_json" 2>/dev/null || printf '%s' "")"
fi

generated_at_utc="$(timestamp_utc)"

jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  --argjson include_missing "$( [[ "$include_missing" == "1" ]] && echo true || echo false )" \
  --argjson max_age_sec "$max_age_sec" \
  --arg status "$status" \
  --arg decision "$decision" \
  --argjson rc "$rc" \
  --argjson discovered "$discovered_json" \
  --argjson missing "$missing_json" \
  --argjson reasons "$reasons_json" \
  --argjson next_actions "$next_actions_json" \
  --arg primary_next_action "$primary_next_action" \
  --argjson discovered_count "$discovered_count" \
  --argjson copied_count "$copied_count" \
  --argjson missing_count "$missing_count" \
  --argjson known_patterns_count "${#artifact_specs[@]}" \
  --argjson docker_matrix_found "$( [[ "${group_found[docker_matrix]}" == "1" ]] && echo true || echo false )" \
  --argjson docker_matrix_usable "$( [[ "${group_usable[docker_matrix]}" == "1" ]] && echo true || echo false )" \
  --argjson docker_matrix_freshness_blocked "$( [[ "${group_freshness_blocked[docker_matrix]}" == "1" ]] && echo true || echo false )" \
  --argjson docker_readiness_found "$( [[ "${group_found[docker_readiness]}" == "1" ]] && echo true || echo false )" \
  --argjson docker_readiness_usable "$( [[ "${group_usable[docker_readiness]}" == "1" ]] && echo true || echo false )" \
  --argjson docker_readiness_freshness_blocked "$( [[ "${group_freshness_blocked[docker_readiness]}" == "1" ]] && echo true || echo false )" \
  --argjson real_host_found "$( [[ "${group_found[real_host]}" == "1" ]] && echo true || echo false )" \
  --argjson real_host_usable "$( [[ "${group_usable[real_host]}" == "1" ]] && echo true || echo false )" \
  --argjson real_host_freshness_blocked "$( [[ "${group_freshness_blocked[real_host]}" == "1" ]] && echo true || echo false )" \
  '{
    version: 1,
    schema: {
      id: "three_machine_real_host_validation_pack_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    fail_closed: ($status == "fail"),
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json_path,
      report_md: $report_md_path,
      include_missing: $include_missing,
      max_age_sec: $max_age_sec
    },
    counts: {
      known_artifact_patterns: $known_patterns_count,
      discovered_artifacts: $discovered_count,
      copied_artifacts: $copied_count,
      missing_patterns: $missing_count
    },
    required_groups: {
      docker_matrix: {
        found: $docker_matrix_found,
        usable: $docker_matrix_usable,
        freshness_blocked: $docker_matrix_freshness_blocked
      },
      docker_readiness: {
        found: $docker_readiness_found,
        usable: $docker_readiness_usable,
        freshness_blocked: $docker_readiness_freshness_blocked
      },
      real_host: {
        found: $real_host_found,
        usable: $real_host_usable,
        freshness_blocked: $real_host_freshness_blocked
      }
    },
    artifacts: $discovered,
    missing_artifacts: $missing,
    reasons: $reasons,
    next_recommended_commands: $next_actions,
    next_operator_action_command: (if ($primary_next_action | length) > 0 then $primary_next_action else "" end)
  }' >"$summary_json"

cat >"$report_md" <<EOF
# Three-Machine Real-Host Validation Pack

- Generated at (UTC): $generated_at_utc
- Status: $status
- Decision: $decision
- Fail closed: $( [[ "$status" == "fail" ]] && echo true || echo false )
- Include missing as warn: $( [[ "$include_missing" == "1" ]] && echo true || echo false )
- Max artifact age (sec): $max_age_sec
- Reports dir: $reports_dir
- Summary JSON: $summary_json

## Required Evidence Groups

- docker_matrix: found=${group_found[docker_matrix]} usable=${group_usable[docker_matrix]} freshness_blocked=${group_freshness_blocked[docker_matrix]}
- docker_readiness: found=${group_found[docker_readiness]} usable=${group_usable[docker_readiness]} freshness_blocked=${group_freshness_blocked[docker_readiness]}
- real_host: found=${group_found[real_host]} usable=${group_usable[real_host]} freshness_blocked=${group_freshness_blocked[real_host]}

## Missing Artifacts
EOF

if [[ "${#missing_rows[@]}" -eq 0 ]]; then
  {
    echo
    echo "- none"
  } >>"$report_md"
else
  for row in "${missing_rows[@]}"; do
    missing_line="$(jq -r '"- \(.id) [\(.group)] pattern=\(.pattern) reason=\(.reason)"' <<<"$row" 2>/dev/null || printf '%s' "- missing artifact metadata unavailable")"
    echo "$missing_line" >>"$report_md"
  done
fi

{
  echo
  echo "## Recommended Commands"
} >>"$report_md"

if [[ "${#next_action_rows[@]}" -eq 0 ]]; then
  {
    echo
    echo "- none"
  } >>"$report_md"
else
  for row in "${next_action_rows[@]}"; do
    action_line="$(jq -r '"- \(.label): `\(.command)` (\(.reason))"' <<<"$row" 2>/dev/null || printf '%s' "- recommended command unavailable")"
    echo "$action_line" >>"$report_md"
  done
fi

{
  echo
  echo "## Collected Artifacts"
} >>"$report_md"

if [[ "${#discovered_rows[@]}" -eq 0 ]]; then
  {
    echo
    echo "- none"
  } >>"$report_md"
else
  for row in "${discovered_rows[@]}"; do
    artifact_line="$(jq -r '"- \(.id) [\(.group)] usable=\(.usable) semantic_usable=\(.semantic_usable) freshness_known=\(.freshness.known) freshness_fresh=\(.freshness.fresh) freshness_source=\(.freshness.source // "unknown") source=\(.source_path) copied=\(.copied_path)"' <<<"$row" 2>/dev/null || printf '%s' "- collected artifact metadata unavailable")"
    echo "$artifact_line" >>"$report_md"
  done
fi

echo "[three-machine-real-host-validation-pack] status=$status rc=$rc decision=$decision summary_json=$summary_json report_md=$report_md"
if [[ "$print_summary_json" == "1" ]]; then
  echo "[three-machine-real-host-validation-pack] summary_json_payload:"
  cat "$summary_json"
fi

exit "$rc"
