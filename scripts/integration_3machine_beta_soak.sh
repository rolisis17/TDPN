#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
VALIDATE_SCRIPT="${THREE_MACHINE_VALIDATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_beta_validate.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_3machine_beta_soak.sh \
    [--directory-a URL] \
    [--directory-b URL] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--issuer-a-url URL] \
    [--issuer-b-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID] \
    [--anon-cred TOKEN] \
    [--rounds N] \
    [--pause-sec N] \
    [--fault-every N] \
    [--fault-command CMD] \
    [--continue-on-fail [0|1]] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--client-min-selection-lines N] \
    [--client-min-entry-operators N] \
    [--client-min-exit-operators N] \
    [--client-require-cross-operator-pair [0|1]] \
    [--exit-country CC] \
    [--exit-region REGION] \
    [--distinct-operators [0|1]] \
    [--require-issuer-quorum [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--report-file PATH]

Purpose:
  Run repeated 3-machine beta validation rounds from machine C.
  Optional fault injection can run a shell command every N rounds
  (for example: restart one server role over ssh).
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

directory_a=""
directory_b=""
issuer_url=""
issuer_a_url=""
issuer_b_url=""
entry_url=""
exit_url=""
client_subject=""
client_anon_cred=""
bootstrap_directory=""
discovery_wait_sec="${THREE_MACHINE_DISCOVERY_WAIT_SEC:-12}"
rounds="${THREE_MACHINE_SOAK_ROUNDS:-12}"
pause_sec="${THREE_MACHINE_SOAK_PAUSE_SEC:-5}"
fault_every="${THREE_MACHINE_SOAK_FAULT_EVERY:-0}"
fault_command="${THREE_MACHINE_SOAK_FAULT_COMMAND:-}"
continue_on_fail="${THREE_MACHINE_SOAK_CONTINUE_ON_FAIL:-0}"
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
client_timeout_sec="45"
client_min_selection_lines="${THREE_MACHINE_CLIENT_MIN_SELECTION_LINES:-0}"
client_min_entry_operators="${THREE_MACHINE_CLIENT_MIN_ENTRY_OPERATORS:-0}"
client_min_exit_operators="${THREE_MACHINE_CLIENT_MIN_EXIT_OPERATORS:-0}"
client_require_cross_operator_pair="${THREE_MACHINE_CLIENT_REQUIRE_CROSS_OPERATOR_PAIR:-}"
exit_country=""
exit_region=""
beta_profile="${THREE_MACHINE_BETA_PROFILE:-1}"
prod_profile="${THREE_MACHINE_PROD_PROFILE:-0}"
distinct_operators="${THREE_MACHINE_DISTINCT_OPERATORS:-}"
require_issuer_quorum="${THREE_MACHINE_REQUIRE_ISSUER_QUORUM:-}"
report_file=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-a)
      directory_a="${2:-}"
      shift 2
      ;;
    --directory-b)
      directory_b="${2:-}"
      shift 2
      ;;
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --issuer-a-url)
      issuer_a_url="${2:-}"
      shift 2
      ;;
    --issuer-b-url)
      issuer_b_url="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --entry-url)
      entry_url="${2:-}"
      shift 2
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
    --subject)
      client_subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      client_anon_cred="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --pause-sec)
      pause_sec="${2:-}"
      shift 2
      ;;
    --fault-every)
      fault_every="${2:-}"
      shift 2
      ;;
    --fault-command)
      fault_command="${2:-}"
      shift 2
      ;;
    --continue-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        continue_on_fail="${2:-}"
        shift 2
      else
        continue_on_fail="1"
        shift
      fi
      ;;
    --min-sources)
      min_sources="${2:-}"
      shift 2
      ;;
    --min-operators)
      min_operators="${2:-}"
      shift 2
      ;;
    --federation-timeout-sec)
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      client_timeout_sec="${2:-}"
      shift 2
      ;;
    --client-min-selection-lines)
      client_min_selection_lines="${2:-}"
      shift 2
      ;;
    --client-min-entry-operators)
      client_min_entry_operators="${2:-}"
      shift 2
      ;;
    --client-min-exit-operators)
      client_min_exit_operators="${2:-}"
      shift 2
      ;;
    --client-require-cross-operator-pair)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        client_require_cross_operator_pair="${2:-}"
        shift 2
      else
        client_require_cross_operator_pair="1"
        shift
      fi
      ;;
    --exit-country)
      exit_country="${2:-}"
      shift 2
      ;;
    --exit-region)
      exit_region="${2:-}"
      shift 2
      ;;
    --distinct-operators)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        distinct_operators="${2:-}"
        shift 2
      else
        distinct_operators="1"
        shift
      fi
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
        shift
      fi
      ;;
    --prod-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        prod_profile="${2:-}"
        shift 2
      else
        prod_profile="1"
        shift
      fi
      ;;
    --require-issuer-quorum)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        require_issuer_quorum="${2:-}"
        shift 2
      else
        require_issuer_quorum="1"
        shift
      fi
      ;;
    --report-file)
      report_file="${2:-}"
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

if [[ "$continue_on_fail" != "0" && "$continue_on_fail" != "1" ]]; then
  echo "--continue-on-fail must be 0 or 1"
  exit 2
fi
if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
  echo "--beta-profile must be 0 or 1"
  exit 2
fi
if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
  echo "--prod-profile must be 0 or 1"
  exit 2
fi
if [[ -n "$distinct_operators" && "$distinct_operators" != "0" && "$distinct_operators" != "1" ]]; then
  echo "--distinct-operators must be 0 or 1"
  exit 2
fi
if [[ -n "$require_issuer_quorum" && "$require_issuer_quorum" != "0" && "$require_issuer_quorum" != "1" ]]; then
  echo "--require-issuer-quorum must be 0 or 1"
  exit 2
fi
if [[ -n "$client_require_cross_operator_pair" && "$client_require_cross_operator_pair" != "0" && "$client_require_cross_operator_pair" != "1" ]]; then
  echo "--client-require-cross-operator-pair must be 0 or 1"
  exit 2
fi
if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
  echo "set only one of --subject or --anon-cred"
  exit 2
fi
if ! [[ "$rounds" =~ ^[0-9]+$ && "$pause_sec" =~ ^[0-9]+$ && "$fault_every" =~ ^[0-9]+$ && "$min_sources" =~ ^[0-9]+$ && "$min_operators" =~ ^[0-9]+$ && "$federation_timeout_sec" =~ ^[0-9]+$ && "$client_timeout_sec" =~ ^[0-9]+$ && "$discovery_wait_sec" =~ ^[0-9]+$ && "$client_min_selection_lines" =~ ^[0-9]+$ && "$client_min_entry_operators" =~ ^[0-9]+$ && "$client_min_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "numeric arguments must be integers"
  exit 2
fi
if ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ((fault_every > 0)) && [[ -z "$fault_command" ]]; then
  echo "--fault-command is required when --fault-every is greater than 0"
  exit 2
fi

if [[ "$prod_profile" == "1" ]]; then
  beta_profile="1"
fi

if [[ -z "$distinct_operators" ]]; then
  if [[ "$beta_profile" == "1" ]]; then
    distinct_operators="1"
  else
    distinct_operators="0"
  fi
fi
if [[ -z "$require_issuer_quorum" ]]; then
  if [[ "$beta_profile" == "1" ]]; then
    require_issuer_quorum="1"
  else
    require_issuer_quorum="0"
  fi
fi
if [[ -z "$client_require_cross_operator_pair" ]]; then
  if [[ "$beta_profile" == "1" && "$distinct_operators" == "1" ]]; then
    client_require_cross_operator_pair="1"
  else
    client_require_cross_operator_pair="0"
  fi
fi

if [[ "$beta_profile" == "1" ]]; then
  if ((min_sources < 2)); then
    min_sources="2"
  fi
  if ((min_operators < 2)); then
    min_operators="2"
  fi
  if ((client_min_selection_lines < 8)); then
    client_min_selection_lines="8"
  fi
  if [[ "$distinct_operators" == "1" ]]; then
    if ((client_min_entry_operators < 2)); then
      client_min_entry_operators="2"
    fi
    if ((client_min_exit_operators < 2)); then
      client_min_exit_operators="2"
    fi
  fi
fi
if ((client_min_selection_lines < 1)); then
  client_min_selection_lines="1"
fi
if ((client_min_entry_operators < 1)); then
  client_min_entry_operators="1"
fi
if ((client_min_exit_operators < 1)); then
  client_min_exit_operators="1"
fi

need_cmd bash
need_cmd date
need_cmd timeout
need_cmd tee
if [[ ! -x "$VALIDATE_SCRIPT" ]]; then
  echo "validate script not executable: $VALIDATE_SCRIPT"
  exit 2
fi

directory_a="$(trim_url "$directory_a")"
directory_b="$(trim_url "$directory_b")"
issuer_url="$(trim_url "$issuer_url")"
issuer_a_url="$(trim_url "$issuer_a_url")"
issuer_b_url="$(trim_url "$issuer_b_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"
bootstrap_directory="$(trim_url "$bootstrap_directory")"

if [[ -z "$bootstrap_directory" && ( -z "$directory_a" || -z "$directory_b" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ) ]]; then
  echo "either provide explicit directory/issuer/entry/exit URLs or set --bootstrap-directory"
  usage
  exit 2
fi

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_3machine_soak_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[3machine-soak] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[3machine-soak] report: $report_file"
echo "[3machine-soak] rounds=$rounds pause_sec=$pause_sec beta_profile=$beta_profile prod_profile=$prod_profile distinct_operators=$distinct_operators require_issuer_quorum=$require_issuer_quorum client_min_selection_lines=$client_min_selection_lines client_min_entry_operators=$client_min_entry_operators client_min_exit_operators=$client_min_exit_operators client_require_cross_operator_pair=$client_require_cross_operator_pair"

passed=0
failed=0

for round in $(seq 1 "$rounds"); do
  echo
  echo "[3machine-soak] round=$round/$rounds"

  if ((fault_every > 0)) && ((round > 1)) && (((round - 1) % fault_every == 0)); then
    echo "[3machine-soak] injecting fault (round=$round): $fault_command"
    set +e
    bash -lc "$fault_command"
    fault_rc=$?
    set -e
    if [[ "$fault_rc" -ne 0 ]]; then
      echo "[3machine-soak] fault command failed rc=$fault_rc"
      if [[ "$continue_on_fail" == "0" ]]; then
        exit 1
      fi
    fi
  fi

  cmd=(
    "$VALIDATE_SCRIPT"
    --min-sources "$min_sources"
    --min-operators "$min_operators"
    --federation-timeout-sec "$federation_timeout_sec"
    --timeout-sec "$client_timeout_sec"
    --client-min-selection-lines "$client_min_selection_lines"
    --client-min-entry-operators "$client_min_entry_operators"
    --client-min-exit-operators "$client_min_exit_operators"
    --client-require-cross-operator-pair "$client_require_cross_operator_pair"
    --distinct-operators "$distinct_operators"
    --require-issuer-quorum "$require_issuer_quorum"
    --beta-profile "$beta_profile"
    --prod-profile "$prod_profile"
  )
  if [[ -n "$directory_a" ]]; then
    cmd+=(--directory-a "$directory_a")
  fi
  if [[ -n "$directory_b" ]]; then
    cmd+=(--directory-b "$directory_b")
  fi
  if [[ -n "$bootstrap_directory" ]]; then
    cmd+=(--bootstrap-directory "$bootstrap_directory" --discovery-wait-sec "$discovery_wait_sec")
  fi
  if [[ -n "$issuer_url" ]]; then
    cmd+=(--issuer-url "$issuer_url")
  fi
  if [[ -n "$issuer_a_url" ]]; then
    cmd+=(--issuer-a-url "$issuer_a_url")
  fi
  if [[ -n "$issuer_b_url" ]]; then
    cmd+=(--issuer-b-url "$issuer_b_url")
  fi
  if [[ -n "$entry_url" ]]; then
    cmd+=(--entry-url "$entry_url")
  fi
  if [[ -n "$exit_url" ]]; then
    cmd+=(--exit-url "$exit_url")
  fi
  if [[ -n "$client_subject" ]]; then
    cmd+=(--subject "$client_subject")
  fi
  if [[ -n "$client_anon_cred" ]]; then
    cmd+=(--anon-cred "$client_anon_cred")
  fi
  if [[ -n "$exit_country" ]]; then
    cmd+=(--exit-country "$exit_country")
  fi
  if [[ -n "$exit_region" ]]; then
    cmd+=(--exit-region "$exit_region")
  fi

  set +e
  "${cmd[@]}"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    passed=$((passed + 1))
    echo "[3machine-soak] round=$round result=ok"
  else
    failed=$((failed + 1))
    echo "[3machine-soak] round=$round result=fail rc=$rc"
    if [[ "$continue_on_fail" == "0" ]]; then
      echo "[3machine-soak] stopping on first failure"
      break
    fi
  fi

  if ((round < rounds)); then
    sleep "$pause_sec"
  fi
done

echo
echo "[3machine-soak] summary passed=$passed failed=$failed total=$rounds"
if [[ -f "$report_file" ]]; then
  if rg -q "^client selection summary:" "$report_file"; then
    read -r observed min_sel avg_sel max_sel min_entry avg_entry max_entry min_exit avg_exit max_exit min_cross avg_cross max_cross < <(
      awk '
        /^client selection summary:/ {
          sel = entry = exitv = cross = 0
          for (i = 1; i <= NF; i++) {
            if ($i ~ /^selections=/) {
              split($i, a, "="); sel = a[2] + 0
            } else if ($i ~ /^entry_ops=/) {
              split($i, a, "="); entry = a[2] + 0
            } else if ($i ~ /^exit_ops=/) {
              split($i, a, "="); exitv = a[2] + 0
            } else if ($i ~ /^cross_pairs=/) {
              split($i, a, "="); cross = a[2] + 0
            }
          }
          c++
          sum_sel += sel
          sum_entry += entry
          sum_exit += exitv
          sum_cross += cross
          if (c == 1 || sel < min_sel) min_sel = sel
          if (c == 1 || sel > max_sel) max_sel = sel
          if (c == 1 || entry < min_entry) min_entry = entry
          if (c == 1 || entry > max_entry) max_entry = entry
          if (c == 1 || exitv < min_exit) min_exit = exitv
          if (c == 1 || exitv > max_exit) max_exit = exitv
          if (c == 1 || cross < min_cross) min_cross = cross
          if (c == 1 || cross > max_cross) max_cross = cross
        }
        END {
          if (c == 0) {
            print "0 0 0 0 0 0 0 0 0 0 0 0 0"
            exit
          }
          printf "%d %d %.2f %d %d %.2f %d %d %.2f %d %d %.2f %d\n",
            c, min_sel, sum_sel/c, max_sel,
            min_entry, sum_entry/c, max_entry,
            min_exit, sum_exit/c, max_exit,
            min_cross, sum_cross/c, max_cross
        }
      ' "$report_file"
    )
    echo "[3machine-soak] client diversity trend observed=$observed selections(min/avg/max)=${min_sel}/${avg_sel}/${max_sel} entry_ops(min/avg/max)=${min_entry}/${avg_entry}/${max_entry} exit_ops(min/avg/max)=${min_exit}/${avg_exit}/${max_exit} cross_pairs(min/avg/max)=${min_cross}/${avg_cross}/${max_cross}"
  else
    echo "[3machine-soak] client diversity trend unavailable (no client selection summaries found)"
  fi
fi
if ((failed > 0)); then
  exit 1
fi
echo "[3machine-soak] ok"
