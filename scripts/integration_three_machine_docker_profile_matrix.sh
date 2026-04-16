#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod grep tail mkdir cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

CAPTURE="$TMP_DIR/three_machine_docker_profile_matrix_calls.tsv"
HELP_OUT="$TMP_DIR/easy_node_help.txt"
FAKE_MATRIX="$TMP_DIR/fake_three_machine_docker_profile_matrix.sh"
FAKE_DOCKER="$TMP_BIN/docker"

cat >"$FAKE_DOCKER" <<'EOF_FAKE_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  --version)
    echo "Docker version 25.0.0, build hermetic"
    ;;
  compose)
    if [[ "${2:-}" == "version" ]]; then
      echo "Docker Compose version v2.0.0"
    fi
    ;;
  info)
    echo "Client:"
    echo " Context: default"
    ;;
  *)
    ;;
esac
EOF_FAKE_DOCKER
chmod +x "$FAKE_DOCKER"

cat >"$FAKE_MATRIX" <<'EOF_FAKE_MATRIX'
#!/usr/bin/env bash
set -euo pipefail
capture="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"
EOF_FAKE_MATRIX
chmod +x "$FAKE_MATRIX"

assert_token() {
  local line="$1"
  local token="$2"
  local message="$3"
  if [[ "$line" != *"$token"* ]]; then
    echo "$message"
    echo "line: $line"
    echo "capture:"
    cat "$CAPTURE"
    exit 1
  fi
}

echo "[three-machine-docker-profile-matrix] usage contract is advertised"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh three-machine-docker-profile-matrix [three_machine_docker_profile_matrix args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help is missing three-machine-docker-profile-matrix contract line"
  cat "$HELP_OUT"
  exit 1
fi

echo "[three-machine-docker-profile-matrix] default forwarding behavior"
: >"$CAPTURE"
PATH="$TMP_BIN:$PATH" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_SCRIPT="$FAKE_MATRIX" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh three-machine-docker-profile-matrix

default_line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$default_line" ]]; then
  echo "missing default forwarding capture line"
  cat "$CAPTURE"
  exit 1
fi
if [[ "$default_line" != "argc=0" ]]; then
  echo "expected default invocation to forward zero arguments"
  echo "line: $default_line"
  exit 1
fi

echo "[three-machine-docker-profile-matrix] key override forwarding behavior"
reports_dir="$TMP_DIR/reports dir"
summary_json="$reports_dir/summary.json"
mkdir -p "$reports_dir"
: >"$CAPTURE"

PATH="$TMP_BIN:$PATH" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_SCRIPT="$FAKE_MATRIX" \
THREE_MACHINE_DOCKER_PROFILE_MATRIX_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh three-machine-docker-profile-matrix \
  --path-profiles "speed,balanced,private" \
  --soak-rounds 5 \
  --soak-pause-sec 2 \
  --peer-failover-downtime-sec 6 \
  --peer-failover-timeout-sec 23 \
  --keep-stacks 1 \
  --summary-json "$summary_json"

override_line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$override_line" ]]; then
  echo "missing override forwarding capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$override_line" $'\t--path-profiles\tspeed,balanced,private' "missing forwarded --path-profiles override"
assert_token "$override_line" $'\t--soak-rounds\t5' "missing forwarded --soak-rounds override"
assert_token "$override_line" $'\t--soak-pause-sec\t2' "missing forwarded --soak-pause-sec override"
assert_token "$override_line" $'\t--peer-failover-downtime-sec\t6' "missing forwarded --peer-failover-downtime-sec override"
assert_token "$override_line" $'\t--peer-failover-timeout-sec\t23' "missing forwarded --peer-failover-timeout-sec override"
assert_token "$override_line" $'\t--keep-stacks\t1' "missing forwarded --keep-stacks override"
assert_token "$override_line" $'\t--summary-json\t'"$summary_json" "missing forwarded --summary-json override"

echo "[three-machine-docker-profile-matrix] dry-run command contract keeps issuer state stable across profiles"
dry_run_out="$TMP_DIR/matrix_dry_run.log"
./scripts/three_machine_docker_profile_matrix.sh \
  --profiles 1hop,2hop \
  --subject inv-integration-subject \
  --bootstrap-directory http://198.51.100.20:8081 \
  --dry-run 1 \
  --reports-dir "$TMP_DIR/matrix_reports" >"$dry_run_out"

dry_line_1hop="$(grep -F -- '--path-profile 1hop' "$dry_run_out" | head -n 1 || true)"
dry_line_2hop="$(grep -F -- '--path-profile 2hop' "$dry_run_out" | head -n 1 || true)"
if [[ -z "$dry_line_1hop" || -z "$dry_line_2hop" ]]; then
  echo "missing dry-run command lines for expected profiles"
  cat "$dry_run_out"
  exit 1
fi
assert_token "$dry_line_1hop" '--subject inv-integration-subject' "missing subject forwarding in 1hop dry-run command"
assert_token "$dry_line_1hop" '--bootstrap-directory http://198.51.100.20:8081' "missing bootstrap-directory forwarding in 1hop dry-run command"
assert_token "$dry_line_1hop" '--reset-data 1' "expected first profile dry-run command to reset data"
assert_token "$dry_line_1hop" '--distinct-operators 0' "expected 1hop dry-run command to force --distinct-operators 0"
assert_token "$dry_line_1hop" '--beta-profile 0' "expected 1hop dry-run command to force --beta-profile 0"
assert_token "$dry_line_1hop" '--prod-profile 0' "expected 1hop dry-run command to force --prod-profile 0"
assert_token "$dry_line_2hop" '--subject inv-integration-subject' "missing subject forwarding in 2hop dry-run command"
assert_token "$dry_line_2hop" '--bootstrap-directory http://198.51.100.20:8081' "missing bootstrap-directory forwarding in 2hop dry-run command"
assert_token "$dry_line_2hop" '--reset-data 0' "expected subsequent profile dry-run command to preserve data"
assert_token "$dry_line_2hop" '--distinct-operators 1' "expected 2hop dry-run command to keep --distinct-operators 1"
assert_token "$dry_line_2hop" '--beta-profile 1' "expected 2hop dry-run command to keep configured --beta-profile"
assert_token "$dry_line_2hop" '--prod-profile 0' "expected 2hop dry-run command to keep configured --prod-profile"

echo "[three-machine-docker-profile-matrix] 3hop dry-run includes lab-mode overrides by default"
dry_run_3hop_out="$TMP_DIR/matrix_dry_run_3hop.log"
./scripts/three_machine_docker_profile_matrix.sh \
  --profiles 3hop \
  --dry-run 1 \
  --reports-dir "$TMP_DIR/matrix_reports_3hop" >"$dry_run_3hop_out"

dry_line_3hop="$(grep -F -- '--path-profile 3hop' "$dry_run_3hop_out" | head -n 1 || true)"
if [[ -z "$dry_line_3hop" ]]; then
  echo "missing dry-run command line for 3hop profile"
  cat "$dry_run_3hop_out"
  exit 1
fi
assert_token "$dry_line_3hop" 'CLIENT_REQUIRE_MIDDLE_RELAY=0' "missing default 3hop CLIENT_REQUIRE_MIDDLE_RELAY override in dry-run command"
assert_token "$dry_line_3hop" 'THREE_MACHINE_DISTINCT_COUNTRIES=0' "missing default 3hop THREE_MACHINE_DISTINCT_COUNTRIES override in dry-run command"

echo "[three-machine-docker-profile-matrix] 3hop strict gate disables lab-mode overrides"
dry_run_3hop_strict_out="$TMP_DIR/matrix_dry_run_3hop_strict.log"
THREE_MACHINE_DOCKER_PROFILE_MATRIX_3HOP_STRICT=1 ./scripts/three_machine_docker_profile_matrix.sh \
  --profiles 3hop \
  --dry-run 1 \
  --reports-dir "$TMP_DIR/matrix_reports_3hop_strict" >"$dry_run_3hop_strict_out"

dry_line_3hop_strict="$(grep -F -- '--path-profile 3hop' "$dry_run_3hop_strict_out" | head -n 1 || true)"
if [[ -z "$dry_line_3hop_strict" ]]; then
  echo "missing strict-mode dry-run command line for 3hop profile"
  cat "$dry_run_3hop_strict_out"
  exit 1
fi
if [[ "$dry_line_3hop_strict" == *"CLIENT_REQUIRE_MIDDLE_RELAY=0"* ]]; then
  echo "unexpected CLIENT_REQUIRE_MIDDLE_RELAY override with THREE_MACHINE_DOCKER_PROFILE_MATRIX_3HOP_STRICT=1"
  cat "$dry_run_3hop_strict_out"
  exit 1
fi
if [[ "$dry_line_3hop_strict" == *"THREE_MACHINE_DISTINCT_COUNTRIES=0"* ]]; then
  echo "unexpected THREE_MACHINE_DISTINCT_COUNTRIES override with THREE_MACHINE_DOCKER_PROFILE_MATRIX_3HOP_STRICT=1"
  cat "$dry_run_3hop_strict_out"
  exit 1
fi

echo "[three-machine-docker-profile-matrix] explicit strict flags still force non-strict mode for 1hop"
dry_run_1hop_strict_flags_out="$TMP_DIR/matrix_dry_run_1hop_strict_flags.log"
./scripts/three_machine_docker_profile_matrix.sh \
  --profiles 1hop \
  --beta-profile 1 \
  --prod-profile 1 \
  --dry-run 1 \
  --reports-dir "$TMP_DIR/matrix_reports_1hop_strict_flags" >"$dry_run_1hop_strict_flags_out"

dry_line_1hop_strict_flags="$(grep -F -- '--path-profile 1hop' "$dry_run_1hop_strict_flags_out" | head -n 1 || true)"
if [[ -z "$dry_line_1hop_strict_flags" ]]; then
  echo "missing 1hop dry-run command line with explicit strict flags"
  cat "$dry_run_1hop_strict_flags_out"
  exit 1
fi
assert_token "$dry_line_1hop_strict_flags" '--beta-profile 0' "expected 1hop strict-flag dry-run command to force --beta-profile 0"
assert_token "$dry_line_1hop_strict_flags" '--prod-profile 0' "expected 1hop strict-flag dry-run command to force --prod-profile 0"
assert_token "$dry_line_1hop_strict_flags" '--distinct-operators 0' "expected 1hop strict-flag dry-run command to force --distinct-operators 0"

echo "three machine docker profile matrix integration check ok"
