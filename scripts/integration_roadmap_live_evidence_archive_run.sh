#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Keep this integration hermetic: ambient archive env overrides can change
# scope/policy defaults and invalidate fail-closed RC assertions.
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_ARCHIVE_ROOT
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_MISSING_SOURCE_POLICY
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_PRINT_SUMMARY_JSON
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_REPORTS_DIR
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_ROADMAP_SUMMARY_JSON
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SCOPE
unset ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SUMMARY_JSON

for cmd in bash jq mktemp mkdir rm cat grep ln; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_live_evidence_archive_run_XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

touch_json() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'JSON'
{"ok":true}
JSON
}

to_windows_path_if_supported() {
  local path="$1"
  local candidate=""
  if command -v cygpath >/dev/null 2>&1; then
    candidate="$(cygpath -w "$path" 2>/dev/null || true)"
    if [[ "$candidate" =~ ^[A-Za-z]:\\ ]]; then
      printf '%s' "$candidate"
      return
    fi
  fi
  if [[ "$path" =~ ^/mnt/([A-Za-z])/(.*)$ ]]; then
    local drive="${BASH_REMATCH[1]}"
    local tail="${BASH_REMATCH[2]}"
    printf '%s' "${drive^^}:\\${tail//\//\\}"
    return
  fi
  if [[ "$path" =~ ^/([A-Za-z])/(.*)$ ]]; then
    local drive="${BASH_REMATCH[1]}"
    local tail="${BASH_REMATCH[2]}"
    printf '%s' "${drive^^}:\\${tail//\//\\}"
    return
  fi
  printf '%s' ""
}

echo "[roadmap-live-evidence-archive-run] help contract"
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--roadmap-summary-json PATH" >/dev/null; then
  echo "help output missing --roadmap-summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--archive-root DIR" >/dev/null; then
  echo "help output missing --archive-root DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--scope auto|all|profile-default|runtime-actuation|multi-vm" >/dev/null; then
  echo "help output missing --scope auto|all|profile-default|runtime-actuation|multi-vm"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--missing-source-policy warn|fail" >/dev/null; then
  echo "help output missing --missing-source-policy warn|fail"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_archive_run.sh --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: success/all scope"
CASE1_DIR="$TMP_DIR/case_success"
REPORTS1="$CASE1_DIR/reports"
ARCHIVE_ROOT1="$CASE1_DIR/archive_root"
SUMMARY1="$CASE1_DIR/archive_summary.json"
ROADMAP1="$CASE1_DIR/roadmap_summary.json"
mkdir -p "$REPORTS1" "$ARCHIVE_ROOT1"

P1_SIGNOFF="$CASE1_DIR/artifacts/profile_compare_campaign_signoff_summary.json"
P1_STABILITY="$CASE1_DIR/artifacts/profile_default_gate_stability_summary.json"
P1_PACK="$CASE1_DIR/artifacts/profile_default_gate_evidence_pack_summary.json"
R1_PROMO="$CASE1_DIR/artifacts/runtime_actuation_promotion_summary.json"
R1_PACK="$CASE1_DIR/artifacts/runtime_actuation_promotion_evidence_pack_summary.json"
M1_STABILITY="$CASE1_DIR/artifacts/profile_compare_multi_vm_stability_summary.json"
M1_PROMO="$CASE1_DIR/artifacts/profile_compare_multi_vm_stability_promotion_summary.json"
M1_PACK="$CASE1_DIR/artifacts/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"

touch_json "$P1_SIGNOFF"
touch_json "$P1_STABILITY"
touch_json "$P1_PACK"
touch_json "$R1_PROMO"
touch_json "$R1_PACK"
touch_json "$M1_STABILITY"
touch_json "$M1_PROMO"
touch_json "$M1_PACK"

jq -n \
  --arg p_signoff "$P1_SIGNOFF" \
  --arg p_stability "$P1_STABILITY" \
  --arg p_pack "$P1_PACK" \
  --arg r_promo "$R1_PROMO" \
  --arg r_pack "$R1_PACK" \
  --arg m_stability "$M1_STABILITY" \
  --arg m_promo "$M1_PROMO" \
  --arg m_pack "$M1_PACK" \
  '{
    status: "pass",
    rc: 0,
    vpn_track: {
      profile_default_gate: {
        summary_json: $p_signoff,
        stability_summary_json: $p_stability
      },
      multi_vm_stability: {
        input_summary_json: $m_stability,
        source_summary_json: $m_stability
      }
    },
    artifacts: {
      profile_compare_signoff_summary_json: $p_signoff,
      profile_default_gate_evidence_pack_summary_json: $p_pack,
      runtime_actuation_promotion_summary_json: $r_promo,
      runtime_actuation_promotion_evidence_pack_summary_json: $r_pack,
      profile_compare_multi_vm_stability_summary_json: $m_stability,
      profile_compare_multi_vm_stability_promotion_summary_json: $m_promo,
      profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json: $m_pack
    },
    next_actions: [
      {
        id: "profile_default_gate_evidence_pack",
        command: ("./scripts/easy_node.sh profile-default-gate-evidence-pack --summary-json " + $p_pack)
      },
      {
        id: "runtime_actuation_promotion_evidence_pack",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --summary-json " + $r_pack)
      },
      {
        id: "profile_compare_multi_vm_stability_promotion_evidence_pack",
        command: ("./scripts/easy_node.sh profile-compare-multi-vm-stability-promotion-evidence-pack --summary-json " + $m_pack)
      }
    ]
  }' >"$ROADMAP1"

bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS1" \
  --roadmap-summary-json "$ROADMAP1" \
  --archive-root "$ARCHIVE_ROOT1" \
  --scope all \
  --summary-json "$SUMMARY1" \
  --print-summary-json 0

if ! jq -e --arg summary1 "$SUMMARY1" --arg reports1 "$REPORTS1" --arg archive_root1 "$ARCHIVE_ROOT1" '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .roadmap.summary_contract_state == "valid"
  and .roadmap.summary_contract_reason == "status/rc contract satisfied"
  and .scope.resolved == "all"
  and .summary.copied_total >= 7
  and .summary.missing_total == 0
  and .summary.copy_error_total == 0
  and .summary.missing_family_count == 0
  and .artifacts.summary_json == $summary1
  and .artifacts.reports_dir == $reports1
  and .artifacts.archive_root == $archive_root1
  and (.artifacts.archive_dir | startswith($archive_root1 + "/roadmap_live_evidence_archive_"))
  and (.next_action_hints | length) == 0
  and ([.family_results[] | select(.included == true) | .status] | all(. == "pass"))
' "$SUMMARY1" >/dev/null; then
  echo "case success/all scope assertions failed"
  cat "$SUMMARY1"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: partial missing sources default to warn while preserving copied artifacts"
CASE2_DIR="$TMP_DIR/case_partial_missing"
REPORTS2="$CASE2_DIR/reports"
ARCHIVE_ROOT2="$CASE2_DIR/archive_root"
SUMMARY2="$CASE2_DIR/archive_summary.json"
ROADMAP2="$CASE2_DIR/roadmap_summary.json"
mkdir -p "$REPORTS2" "$ARCHIVE_ROOT2"

P2_SIGNOFF="$CASE2_DIR/artifacts/profile_compare_campaign_signoff_summary.json"
M2_PACK="$CASE2_DIR/artifacts/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
R2_PROMO_PRESENT="$CASE2_DIR/artifacts/runtime_actuation_promotion_summary.json"
R2_PACK_MISSING="$CASE2_DIR/artifacts/runtime_actuation_promotion_evidence_pack_summary.json"

touch_json "$P2_SIGNOFF"
touch_json "$M2_PACK"
touch_json "$R2_PROMO_PRESENT"

jq -n \
  --arg p_signoff "$P2_SIGNOFF" \
  --arg r_promo "$R2_PROMO_PRESENT" \
  --arg r_pack "$R2_PACK_MISSING" \
  --arg m_pack "$M2_PACK" \
  '{
    status: "pass",
    rc: 0,
    artifacts: {
      profile_compare_signoff_summary_json: $p_signoff,
      runtime_actuation_promotion_summary_json: $r_promo,
      runtime_actuation_promotion_evidence_pack_summary_json: $r_pack,
      profile_compare_multi_vm_stability_promotion_evidence_pack_summary_json: $m_pack
    },
    next_actions: [
      {
        id: "runtime_actuation_promotion",
        label: "Runtime actuation promotion",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-cycle --summary-json " + $r_promo),
        reason: "refresh runtime evidence"
      },
      {
        id: "runtime_actuation_promotion_evidence_pack",
        label: "Runtime actuation evidence pack",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --summary-json " + $r_pack),
        reason: "publish runtime evidence pack"
      }
    ]
  }' >"$ROADMAP2"

set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS2" \
  --roadmap-summary-json "$ROADMAP2" \
  --archive-root "$ARCHIVE_ROOT2" \
  --scope all \
  --summary-json "$SUMMARY2" \
  --print-summary-json 0
case2_rc=$?
set -e
if [[ "$case2_rc" != "0" ]]; then
  echo "case partial missing (default warn policy) expected rc=0, got rc=$case2_rc"
  cat "$SUMMARY2"
  exit 1
fi

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .failure_substep == null
  and .inputs.missing_source_policy == "warn"
  and (.reason | contains("missing artifacts"))
  and .roadmap.summary_contract_state == "valid"
  and .summary.copied_total >= 3
  and .summary.missing_total >= 1
  and .summary.copy_error_total == 0
  and .summary.missing_family_count == 0
  and ((.next_action_hints | map(select(.family == "runtime-actuation")) | length) >= 1)
  and (
    [.family_results[] | select(.family == "runtime-actuation")][0].status == "warn"
  )
' "$SUMMARY2" >/dev/null; then
  echo "case partial missing (default warn policy) assertions failed"
  cat "$SUMMARY2"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: partial missing sources fail with explicit policy"
SUMMARY2_FAIL="$CASE2_DIR/archive_summary_fail_policy.json"
set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS2" \
  --roadmap-summary-json "$ROADMAP2" \
  --archive-root "$ARCHIVE_ROOT2" \
  --scope all \
  --missing-source-policy fail \
  --summary-json "$SUMMARY2_FAIL" \
  --print-summary-json 0
case2_fail_rc=$?
set -e
if [[ "$case2_fail_rc" != "1" ]]; then
  echo "case partial missing (fail policy) expected rc=1, got rc=$case2_fail_rc"
  cat "$SUMMARY2_FAIL"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "archive_copy_incomplete"
  and .inputs.missing_source_policy == "fail"
  and (.reason | contains("missing artifacts"))
  and .summary.copied_total >= 3
  and .summary.missing_total >= 1
  and .summary.copy_error_total == 0
  and .summary.missing_family_count == 0
  and (
    [.family_results[] | select(.family == "runtime-actuation")][0].status == "fail"
  )
' "$SUMMARY2_FAIL" >/dev/null; then
  echo "case partial missing (fail policy) assertions failed"
  cat "$SUMMARY2_FAIL"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: explicit scope filter"
CASE3_DIR="$TMP_DIR/case_scope_filter"
REPORTS3="$CASE3_DIR/reports"
ARCHIVE_ROOT3="$CASE3_DIR/archive_root"
SUMMARY3="$CASE3_DIR/archive_summary.json"
ROADMAP3="$CASE3_DIR/roadmap_summary.json"
mkdir -p "$REPORTS3" "$ARCHIVE_ROOT3"

P3_SIGNOFF="$CASE3_DIR/artifacts/profile_compare_campaign_signoff_summary.json"
P3_PACK="$CASE3_DIR/artifacts/profile_default_gate_evidence_pack_summary.json"
R3_PACK="$CASE3_DIR/artifacts/runtime_actuation_promotion_evidence_pack_summary.json"
touch_json "$P3_SIGNOFF"
touch_json "$P3_PACK"
touch_json "$R3_PACK"

jq -n \
  --arg p_signoff "$P3_SIGNOFF" \
  --arg p_pack "$P3_PACK" \
  --arg r_pack "$R3_PACK" \
  '{
    status: "pass",
    rc: 0,
    artifacts: {
      profile_compare_signoff_summary_json: $p_signoff,
      profile_default_gate_evidence_pack_summary_json: $p_pack,
      runtime_actuation_promotion_evidence_pack_summary_json: $r_pack
    },
    next_actions: [
      {
        id: "profile_default_gate_evidence_pack",
        command: ("./scripts/easy_node.sh profile-default-gate-evidence-pack --summary-json " + $p_pack)
      },
      {
        id: "runtime_actuation_promotion_evidence_pack",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --summary-json " + $r_pack)
      }
    ]
  }' >"$ROADMAP3"

bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS3" \
  --roadmap-summary-json "$ROADMAP3" \
  --archive-root "$ARCHIVE_ROOT3" \
  --scope profile-default \
  --summary-json "$SUMMARY3" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .roadmap.summary_contract_state == "valid"
  and .scope.resolved == "profile-default"
  and .scope.included_families == ["profile-default"]
  and (
    [.family_results[] | select(.family == "profile-default")][0].included == true
  )
  and (
    [.family_results[] | select(.family == "runtime-actuation")][0].included == false
  )
  and (
    [.family_results[] | select(.family == "multi-vm")][0].included == false
  )
' "$SUMMARY3" >/dev/null; then
  echo "case explicit scope filter assertions failed"
  cat "$SUMMARY3"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: valid roadmap with missing family paths uses default fallback artifacts"
CASE4_DIR="$TMP_DIR/case_valid_missing_paths_fallback"
REPORTS4="$CASE4_DIR/reports"
ARCHIVE_ROOT4="$CASE4_DIR/archive_root"
SUMMARY4="$CASE4_DIR/archive_summary.json"
ROADMAP4="$CASE4_DIR/roadmap_summary.json"
mkdir -p "$REPORTS4" "$ARCHIVE_ROOT4"

touch_json "$REPORTS4/runtime_actuation_promotion_cycle_latest_summary.json"
touch_json "$REPORTS4/runtime_actuation_promotion_summary.json"
touch_json "$REPORTS4/runtime_actuation_promotion_evidence_pack_summary.json"

jq -n '
  {
    status: "pass",
    rc: 0,
    artifacts: {},
    next_actions: []
  }' >"$ROADMAP4"

bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS4" \
  --roadmap-summary-json "$ROADMAP4" \
  --archive-root "$ARCHIVE_ROOT4" \
  --scope runtime-actuation \
  --summary-json "$SUMMARY4" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .roadmap.summary_contract_state == "valid"
  and .scope.resolved == "runtime-actuation"
  and .summary.copied_total >= 2
  and .summary.missing_total == 0
  and (
    [.family_results[] | select(.family == "runtime-actuation")][0].status == "pass"
  )
  and (
    ([.family_results[] | select(.family == "runtime-actuation")][0].candidates // [])
    | map(select((.source // "") == "default_fallback"))
    | length
  ) >= 1
' "$SUMMARY4" >/dev/null; then
  echo "case valid missing paths fallback assertions failed"
  cat "$SUMMARY4"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: windows-style roadmap-summary-json path normalization"
CASE5_DIR="$TMP_DIR/case_windows_path"
REPORTS5="$CASE5_DIR/reports"
ARCHIVE_ROOT5="$CASE5_DIR/archive_root"
SUMMARY5="$CASE5_DIR/archive_summary.json"
ROADMAP5="$CASE5_DIR/roadmap_summary.json"
mkdir -p "$REPORTS5" "$ARCHIVE_ROOT5"

P5_SIGNOFF="$CASE5_DIR/artifacts/profile_compare_campaign_signoff_summary.json"
touch_json "$P5_SIGNOFF"

jq -n \
  --arg p_signoff "$P5_SIGNOFF" \
  '{
    status: "pass",
    rc: 0,
    artifacts: {
      profile_compare_signoff_summary_json: $p_signoff
    }
  }' >"$ROADMAP5"

ROADMAP5_WINDOWS="$(to_windows_path_if_supported "$ROADMAP5")"
ROADMAP5_INPUT="$ROADMAP5"
if [[ -n "$ROADMAP5_WINDOWS" ]]; then
  ROADMAP5_INPUT="$ROADMAP5_WINDOWS"
  echo "[roadmap-live-evidence-archive-run] using windows-style roadmap-summary-json path: $ROADMAP5_WINDOWS"
else
  echo "[roadmap-live-evidence-archive-run] windows-style alias unavailable on this platform; using canonical path input"
fi

bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS5" \
  --roadmap-summary-json "$ROADMAP5_INPUT" \
  --archive-root "$ARCHIVE_ROOT5" \
  --scope profile-default \
  --summary-json "$SUMMARY5" \
  --print-summary-json 0

if ! jq -e --arg roadmap5 "$ROADMAP5" '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .roadmap.summary_exists == true
  and .roadmap.summary_valid == true
  and .roadmap.summary_contract_state == "valid"
  and .roadmap.summary_contract_reason == "status/rc contract satisfied"
  and .roadmap.summary_json == $roadmap5
  and .summary.copied_total >= 1
' "$SUMMARY5" >/dev/null; then
  echo "case windows path normalization assertions failed"
  cat "$SUMMARY5"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: invalid roadmap summary fails closed without fallback reuse"
CASE6_DIR="$TMP_DIR/case_invalid_roadmap_summary"
REPORTS6="$CASE6_DIR/reports"
ARCHIVE_ROOT6="$CASE6_DIR/archive_root"
SUMMARY6="$CASE6_DIR/archive_summary.json"
ROADMAP6="$CASE6_DIR/roadmap_summary_invalid.json"
mkdir -p "$REPORTS6" "$ARCHIVE_ROOT6"

# Stale-looking fallback artifacts must not be silently reused when roadmap summary is invalid.
touch_json "$REPORTS6/runtime_actuation_promotion_summary.json"
touch_json "$REPORTS6/runtime_actuation_promotion_evidence_pack_summary.json"
printf 'this is not json\n' >"$ROADMAP6"

set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS6" \
  --roadmap-summary-json "$ROADMAP6" \
  --archive-root "$ARCHIVE_ROOT6" \
  --scope runtime-actuation \
  --summary-json "$SUMMARY6" \
  --print-summary-json 0
invalid_roadmap_rc=$?
set -e
if [[ "$invalid_roadmap_rc" != "4" ]]; then
  echo "case invalid roadmap summary expected rc=4, got rc=$invalid_roadmap_rc"
  cat "$SUMMARY6"
  exit 1
fi
if ! jq -e --arg roadmap6 "$ROADMAP6" '
  .status == "fail"
  and .rc == 4
  and .failure_substep == "roadmap_summary_contract_invalid"
  and .roadmap.summary_json == $roadmap6
  and .roadmap.summary_exists == true
  and .roadmap.summary_valid == false
  and .roadmap.summary_contract_state == "invalid"
  and (.roadmap.summary_contract_reason | contains("invalid"))
  and .summary.candidate_total == 0
  and .summary.copied_total == 0
' "$SUMMARY6" >/dev/null; then
  echo "case invalid roadmap summary assertions failed"
  cat "$SUMMARY6"
  exit 1
fi

echo "[roadmap-live-evidence-archive-run] case: out-of-scope roadmap absolute path is rejected"
CASE7_DIR="$TMP_DIR/case_out_of_scope_absolute_path"
REPORTS7="$CASE7_DIR/reports"
ARCHIVE_ROOT7="$CASE7_DIR/archive_root"
SUMMARY7="$CASE7_DIR/archive_summary.json"
ROADMAP7="$CASE7_DIR/roadmap_summary.json"
mkdir -p "$REPORTS7" "$ARCHIVE_ROOT7"

R7_PROMO_ALLOWED="$REPORTS7/runtime_actuation_promotion_summary.json"
touch_json "$R7_PROMO_ALLOWED"

OUTSIDE7_DIR="$(mktemp -d)"
if [[ "$OUTSIDE7_DIR" == "$ROOT_DIR" || "$OUTSIDE7_DIR" == "$ROOT_DIR/"* ]]; then
  echo "unable to allocate out-of-scope directory (mktemp returned in-repo path): $OUTSIDE7_DIR"
  rm -rf "$OUTSIDE7_DIR"
  exit 1
fi
R7_PACK_OUT_OF_SCOPE="$OUTSIDE7_DIR/runtime_actuation_promotion_evidence_pack_summary.json"
touch_json "$R7_PACK_OUT_OF_SCOPE"

jq -n \
  --arg r_promo "$R7_PROMO_ALLOWED" \
  --arg r_pack_out_of_scope "$R7_PACK_OUT_OF_SCOPE" \
  '{
    status: "pass",
    rc: 0,
    artifacts: {
      runtime_actuation_promotion_summary_json: $r_promo
    },
    next_actions: [
      {
        id: "runtime_actuation_promotion_evidence_pack",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --summary-json " + $r_pack_out_of_scope)
      }
    ]
  }' >"$ROADMAP7"

set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS7" \
  --roadmap-summary-json "$ROADMAP7" \
  --archive-root "$ARCHIVE_ROOT7" \
  --scope runtime-actuation \
  --summary-json "$SUMMARY7" \
  --print-summary-json 0
case7_rc=$?
set -e
if [[ "$case7_rc" != "1" ]]; then
  echo "case out-of-scope absolute path expected rc=1, got rc=$case7_rc"
  cat "$SUMMARY7"
  rm -rf "$OUTSIDE7_DIR"
  exit 1
fi

if ! jq -e --arg reports7 "$REPORTS7" --arg out_of_scope "$R7_PACK_OUT_OF_SCOPE" '
  .status == "fail"
  and .rc == 1
  and ((.failure_substep == "archive_copy_incomplete") or (.failure_substep == "selected_families_no_artifacts_copied"))
  and .summary.copied_total >= 1
  and .summary.copy_error_total >= 1
  and .summary.source_path_reject_total >= 1
  and (
    [(.next_action_hints[]? | select(.family == "runtime-actuation") | (.command // "") | contains($out_of_scope))]
    | any
    | not
  )
  and (
    ([.family_results[] | select(.family == "runtime-actuation")][0].copy_errors // [])
    | map(select(.reason == "source_path_out_of_scope" and .path == $out_of_scope))
    | length
  ) == 1
  and (
    ([.family_results[] | select(.family == "runtime-actuation")][0].copied // [])
    | map(select(.path == $out_of_scope))
    | length
  ) == 0
' "$SUMMARY7" >/dev/null; then
  echo "case out-of-scope absolute path assertions failed"
  cat "$SUMMARY7"
  rm -rf "$OUTSIDE7_DIR"
  exit 1
fi
rm -rf "$OUTSIDE7_DIR"

echo "[roadmap-live-evidence-archive-run] case: in-scope symlink to out-of-scope source is rejected"
CASE8_DIR="$TMP_DIR/case_symlink_out_of_scope"
REPORTS8="$CASE8_DIR/reports"
ARCHIVE_ROOT8="$CASE8_DIR/archive_root"
SUMMARY8="$CASE8_DIR/archive_summary.json"
ROADMAP8="$CASE8_DIR/roadmap_summary.json"
mkdir -p "$REPORTS8" "$ARCHIVE_ROOT8"

OUTSIDE8_DIR="$(mktemp -d)"
if [[ "$OUTSIDE8_DIR" == "$ROOT_DIR" || "$OUTSIDE8_DIR" == "$ROOT_DIR/"* ]]; then
  echo "unable to allocate symlink out-of-scope directory (mktemp returned in-repo path): $OUTSIDE8_DIR"
  rm -rf "$OUTSIDE8_DIR"
  exit 1
fi
OUTSIDE8_SOURCE="$OUTSIDE8_DIR/runtime_actuation_promotion_summary.json"
touch_json "$OUTSIDE8_SOURCE"
REPORTS8_SYMLINK="$REPORTS8/runtime_actuation_promotion_summary.json"
ln -s "$OUTSIDE8_SOURCE" "$REPORTS8_SYMLINK"

jq -n --arg runtime_path "$REPORTS8_SYMLINK" '
  {
    status: "pass",
    rc: 0,
    artifacts: {
      runtime_actuation_promotion_summary_json: $runtime_path
    }
  }' >"$ROADMAP8"

set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS8" \
  --roadmap-summary-json "$ROADMAP8" \
  --archive-root "$ARCHIVE_ROOT8" \
  --scope runtime-actuation \
  --summary-json "$SUMMARY8" \
  --print-summary-json 0
case8_rc=$?
set -e
if [[ "$case8_rc" != "1" ]]; then
  echo "case symlink out-of-scope expected rc=1, got rc=$case8_rc"
  cat "$SUMMARY8"
  rm -rf "$OUTSIDE8_DIR"
  exit 1
fi

if ! jq -e --arg outside_source "$OUTSIDE8_SOURCE" '
  .status == "fail"
  and .rc == 1
  and ((.failure_substep == "archive_copy_incomplete") or (.failure_substep == "selected_families_no_artifacts_copied"))
  and .summary.source_path_reject_total >= 1
  and (
    ([.family_results[] | select(.family == "runtime-actuation")][0].copy_errors // [])
    | map(select(.reason == "source_path_out_of_scope" and .resolved_path == $outside_source))
    | length
  ) == 1
' "$SUMMARY8" >/dev/null; then
  echo "case symlink out-of-scope assertions failed"
  cat "$SUMMARY8"
  rm -rf "$OUTSIDE8_DIR"
  exit 1
fi
rm -rf "$OUTSIDE8_DIR"

echo "[roadmap-live-evidence-archive-run] case: out-of-scope --summary-json= path is rejected"
CASE9_DIR="$TMP_DIR/case_out_of_scope_equals_form"
REPORTS9="$CASE9_DIR/reports"
ARCHIVE_ROOT9="$CASE9_DIR/archive_root"
SUMMARY9="$CASE9_DIR/archive_summary.json"
ROADMAP9="$CASE9_DIR/roadmap_summary.json"
mkdir -p "$REPORTS9" "$ARCHIVE_ROOT9"

R9_PROMO_ALLOWED="$REPORTS9/runtime_actuation_promotion_summary.json"
touch_json "$R9_PROMO_ALLOWED"

OUTSIDE9_DIR="$(mktemp -d)"
if [[ "$OUTSIDE9_DIR" == "$ROOT_DIR" || "$OUTSIDE9_DIR" == "$ROOT_DIR/"* ]]; then
  echo "unable to allocate out-of-scope directory for equals-form case: $OUTSIDE9_DIR"
  rm -rf "$OUTSIDE9_DIR"
  exit 1
fi
R9_PACK_OUT_OF_SCOPE="$OUTSIDE9_DIR/runtime_actuation_promotion_evidence_pack_summary.json"
touch_json "$R9_PACK_OUT_OF_SCOPE"

jq -n \
  --arg r_promo "$R9_PROMO_ALLOWED" \
  --arg r_pack_out_of_scope "$R9_PACK_OUT_OF_SCOPE" \
  '{
    status: "pass",
    rc: 0,
    artifacts: {
      runtime_actuation_promotion_summary_json: $r_promo
    },
    next_actions: [
      {
        id: "runtime_actuation_promotion_evidence_pack",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --summary-json=" + $r_pack_out_of_scope)
      }
    ]
  }' >"$ROADMAP9"

set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS9" \
  --roadmap-summary-json "$ROADMAP9" \
  --archive-root "$ARCHIVE_ROOT9" \
  --scope runtime-actuation \
  --summary-json "$SUMMARY9" \
  --print-summary-json 0
case9_rc=$?
set -e
if [[ "$case9_rc" != "1" ]]; then
  echo "case out-of-scope equals-form path expected rc=1, got rc=$case9_rc"
  cat "$SUMMARY9"
  rm -rf "$OUTSIDE9_DIR"
  exit 1
fi

if ! jq -e --arg out_of_scope "$R9_PACK_OUT_OF_SCOPE" '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "archive_copy_incomplete"
  and .summary.copied_total >= 1
  and .summary.copy_error_total >= 1
  and .summary.source_path_reject_total >= 1
  and ((.next_action_hints | map(select(.family == "runtime-actuation")) | length) >= 1)
  and (
    [(.next_action_hints[]? | select(.family == "runtime-actuation") | (.command // "") | contains($out_of_scope))]
    | any
    | not
  )
  and (
    ([.family_results[] | select(.family == "runtime-actuation")][0].copy_errors // [])
    | map(select(.reason == "source_path_out_of_scope" and .path == $out_of_scope))
    | length
  ) == 1
  and (
    ([.family_results[] | select(.family == "runtime-actuation")][0].copied // [])
    | map(select(.path == $out_of_scope))
    | length
  ) == 0
' "$SUMMARY9" >/dev/null; then
  echo "case out-of-scope equals-form path assertions failed"
  cat "$SUMMARY9"
  rm -rf "$OUTSIDE9_DIR"
  exit 1
fi
rm -rf "$OUTSIDE9_DIR"

echo "[roadmap-live-evidence-archive-run] case: unsafe shell syntax in next_action hint command is dropped"
CASE10_DIR="$TMP_DIR/case_unsafe_hint_command"
REPORTS10="$CASE10_DIR/reports"
ARCHIVE_ROOT10="$CASE10_DIR/archive_root"
SUMMARY10="$CASE10_DIR/archive_summary.json"
ROADMAP10="$CASE10_DIR/roadmap_summary.json"
mkdir -p "$REPORTS10" "$ARCHIVE_ROOT10"

R10_PROMO_PRESENT="$CASE10_DIR/artifacts/runtime_actuation_promotion_summary.json"
R10_PACK_MISSING="$CASE10_DIR/artifacts/runtime_actuation_promotion_evidence_pack_summary.json"
touch_json "$R10_PROMO_PRESENT"

jq -n \
  --arg r_promo "$R10_PROMO_PRESENT" \
  --arg r_pack_missing "$R10_PACK_MISSING" \
  '{
    status: "pass",
    rc: 0,
    artifacts: {
      runtime_actuation_promotion_summary_json: $r_promo,
      runtime_actuation_promotion_evidence_pack_summary_json: $r_pack_missing
    },
    next_actions: [
      {
        id: "runtime_actuation_promotion_evidence_pack",
        label: "Runtime actuation evidence pack",
        command: ("./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --summary-json " + $r_pack_missing + " && echo unsafe"),
        reason: "publish runtime evidence pack"
      }
    ]
  }' >"$ROADMAP10"

set +e
bash ./scripts/roadmap_live_evidence_archive_run.sh \
  --reports-dir "$REPORTS10" \
  --roadmap-summary-json "$ROADMAP10" \
  --archive-root "$ARCHIVE_ROOT10" \
  --scope runtime-actuation \
  --summary-json "$SUMMARY10" \
  --print-summary-json 0
case10_rc=$?
set -e
if [[ "$case10_rc" != "0" ]]; then
  echo "case unsafe hint command expected rc=0 (warn), got rc=$case10_rc"
  cat "$SUMMARY10"
  exit 1
fi

if ! jq -e \
  --arg r_pack_missing "$R10_PACK_MISSING" \
  --arg default_cmd "./scripts/easy_node.sh runtime-actuation-promotion-cycle --reports-dir .easy-node-logs --summary-json .easy-node-logs/runtime_actuation_promotion_cycle_latest_summary.json --print-summary-json 1" '
  .status == "warn"
  and .rc == 0
  and .inputs.missing_source_policy == "warn"
  and .summary.copied_total >= 1
  and .summary.missing_total >= 1
  and .summary.copy_error_total == 0
  and ((.next_action_hints | map(select(.family == "runtime-actuation")) | length) >= 1)
  and (
    (.next_action_hints | map(select(.family == "runtime-actuation" and ((.command // "") | contains("&&")))) | length) == 0
  )
  and (
    (.next_action_hints | map(select(.family == "runtime-actuation" and ((.command // "") | contains($r_pack_missing)))) | length) == 0
  )
  and (
    (.next_action_hints | map(select(.family == "runtime-actuation" and (.command // "") == $default_cmd)) | length) >= 1
  )
  and (
    [.family_results[] | select(.family == "runtime-actuation")][0].status == "warn"
  )
' "$SUMMARY10" >/dev/null; then
  echo "case unsafe hint command assertions failed"
  cat "$SUMMARY10"
  exit 1
fi

echo "[integration_roadmap_live_evidence_archive_run] pass"
