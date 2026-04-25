#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/gpm_gap_scan.sh \
    [--status-doc PATH] \
    [--summary-json PATH] \
    [--reports-dir DIR] \
    [--print-summary-json [0|1]]

Description:
  Scans docs/gpm-productization-status.md and emits a deterministic markdown
  summary focused on In-Progress and Missing / Next roadmap gaps.

Defaults:
  --status-doc docs/gpm-productization-status.md
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
  elif [[ "$path" == /* ]]; then
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
reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/gpm_gap_scan_summary.json"
fi
summary_json="$(abs_path "$summary_json")"

[[ -f "$status_doc" ]] || fail_closed "status doc missing: $status_doc"

declare -a ITEM_SECTIONS=()
declare -a ITEM_TEXTS=()
declare -a ITEM_NORMALIZED_TEXTS=()
declare -a ITEM_SEVERITIES=()
declare -a ITEM_RECOMMENDED_ACTIONS=()

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
    if [[ "$pending_section" == "in_progress" ]]; then
      in_progress_count=$((in_progress_count + 1))
    elif [[ "$pending_section" == "missing_next" ]]; then
      missing_next_count=$((missing_next_count + 1))
    fi
  fi
  pending_section=""
  pending_text=""
}

infer_item_severity() {
  local section="${1:-}"
  local normalized_text="${2:-}"
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
  if [[ "$normalized_text" == *"invite_key"* \
     || "$normalized_text" == *"campaign-subject"* \
     || "$normalized_text" == *"subject"* ]]; then
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
  if [[ "$section" == "missing_next" ]]; then
    printf '%s' "Close this missing/next gap with one deterministic command and summary artifact."
    return
  fi
  printf '%s' "Continue implementation and refresh summary artifacts for this in-progress item."
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
  printf '    "minor": 0\n'
  printf '  },\n'
  printf '  "generated_at_utc": "%s",\n' "$(json_escape "$generated_at_utc")"
  printf '  "status": "ok",\n'
  printf '  "inputs": {\n'
  printf '    "status_doc": "%s",\n' "$(json_escape "$status_doc")"
  printf '    "reports_dir": "%s",\n' "$(json_escape "$reports_dir")"
  printf '    "summary_json": "%s"\n' "$(json_escape "$summary_json")"
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
      printf '      "recommended_action": "%s"\n' "$(json_escape "$recommended_action")"
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
