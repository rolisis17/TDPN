#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE5_SETTLEMENT_LAYER_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/ci_phase5_pass.json"
FAIL_SUMMARY="$TMP_DIR/ci_phase5_fail.json"
RELAXED_SUMMARY="$TMP_DIR/ci_phase5_relaxed.json"
DUAL_FAIL_SUMMARY="$TMP_DIR/ci_phase5_dual_fail.json"
ADAPTER_ROUNDTRIP_FAIL_SUMMARY="$TMP_DIR/ci_phase5_adapter_roundtrip_fail.json"
ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_SUMMARY="$TMP_DIR/ci_phase5_adapter_signed_tx_roundtrip_fail.json"
SHADOW_ENV_FAIL_SUMMARY="$TMP_DIR/ci_phase5_shadow_env_fail.json"
SHADOW_STATUS_SURFACE_FAIL_SUMMARY="$TMP_DIR/ci_phase5_shadow_status_surface_fail.json"
SPONSOR_FAIL_SUMMARY="$TMP_DIR/ci_phase5_sponsor_fail.json"
SPONSOR_VPN_SESSION_FAIL_SUMMARY="$TMP_DIR/ci_phase5_sponsor_vpn_session_fail.json"
ISSUER_SETTLEMENT_STATUS_FAIL_SUMMARY="$TMP_DIR/ci_phase5_issuer_settlement_status_fail.json"
EXIT_SETTLEMENT_STATUS_FAIL_SUMMARY="$TMP_DIR/ci_phase5_exit_settlement_status_fail.json"
ADMIN_FAIL_SUMMARY="$TMP_DIR/ci_phase5_admin_fail.json"
MISSING_SUMMARY="$TMP_DIR/ci_phase5_missing.json"

PASS_OUTPUT="$TMP_DIR/pass_output.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
DUAL_FAIL_OUTPUT="$TMP_DIR/dual_fail_output.json"
DUAL_RELAXED_OUTPUT="$TMP_DIR/dual_relaxed_output.json"
ADAPTER_ROUNDTRIP_FAIL_OUTPUT="$TMP_DIR/adapter_roundtrip_fail_output.json"
ADAPTER_ROUNDTRIP_RELAXED_OUTPUT="$TMP_DIR/adapter_roundtrip_relaxed_output.json"
ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_OUTPUT="$TMP_DIR/adapter_signed_tx_roundtrip_fail_output.json"
ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_OUTPUT="$TMP_DIR/adapter_signed_tx_roundtrip_relaxed_output.json"
SHADOW_ENV_FAIL_OUTPUT="$TMP_DIR/shadow_env_fail_output.json"
SHADOW_ENV_RELAXED_OUTPUT="$TMP_DIR/shadow_env_relaxed_output.json"
SHADOW_STATUS_SURFACE_FAIL_OUTPUT="$TMP_DIR/shadow_status_surface_fail_output.json"
SHADOW_STATUS_SURFACE_RELAXED_OUTPUT="$TMP_DIR/shadow_status_surface_relaxed_output.json"
SPONSOR_FAIL_OUTPUT="$TMP_DIR/sponsor_fail_output.json"
SPONSOR_RELAXED_OUTPUT="$TMP_DIR/sponsor_relaxed_output.json"
SPONSOR_VPN_SESSION_FAIL_OUTPUT="$TMP_DIR/sponsor_vpn_session_fail_output.json"
SPONSOR_VPN_SESSION_RELAXED_OUTPUT="$TMP_DIR/sponsor_vpn_session_relaxed_output.json"
ISSUER_SETTLEMENT_STATUS_FAIL_OUTPUT="$TMP_DIR/issuer_settlement_status_fail_output.json"
ISSUER_SETTLEMENT_STATUS_RELAXED_OUTPUT="$TMP_DIR/issuer_settlement_status_relaxed_output.json"
EXIT_SETTLEMENT_STATUS_FAIL_OUTPUT="$TMP_DIR/exit_settlement_status_fail_output.json"
EXIT_SETTLEMENT_STATUS_RELAXED_OUTPUT="$TMP_DIR/exit_settlement_status_relaxed_output.json"
ADMIN_FAIL_OUTPUT="$TMP_DIR/admin_fail_output.json"
ADMIN_RELAXED_OUTPUT="$TMP_DIR/admin_relaxed_output.json"
PASS_CANONICAL="$TMP_DIR/pass_canonical_summary.json"
FAIL_CANONICAL="$TMP_DIR/fail_canonical_summary.json"
RELAXED_CANONICAL="$TMP_DIR/relaxed_canonical_summary.json"
DUAL_FAIL_CANONICAL="$TMP_DIR/dual_fail_canonical_summary.json"
DUAL_RELAXED_CANONICAL="$TMP_DIR/dual_relaxed_canonical_summary.json"
ADAPTER_ROUNDTRIP_FAIL_CANONICAL="$TMP_DIR/adapter_roundtrip_fail_canonical_summary.json"
ADAPTER_ROUNDTRIP_RELAXED_CANONICAL="$TMP_DIR/adapter_roundtrip_relaxed_canonical_summary.json"
ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_CANONICAL="$TMP_DIR/adapter_signed_tx_roundtrip_fail_canonical_summary.json"
ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_CANONICAL="$TMP_DIR/adapter_signed_tx_roundtrip_relaxed_canonical_summary.json"
SHADOW_ENV_FAIL_CANONICAL="$TMP_DIR/shadow_env_fail_canonical_summary.json"
SHADOW_ENV_RELAXED_CANONICAL="$TMP_DIR/shadow_env_relaxed_canonical_summary.json"
SHADOW_STATUS_SURFACE_FAIL_CANONICAL="$TMP_DIR/shadow_status_surface_fail_canonical_summary.json"
SHADOW_STATUS_SURFACE_RELAXED_CANONICAL="$TMP_DIR/shadow_status_surface_relaxed_canonical_summary.json"
SPONSOR_FAIL_CANONICAL="$TMP_DIR/sponsor_fail_canonical_summary.json"
SPONSOR_RELAXED_CANONICAL="$TMP_DIR/sponsor_relaxed_canonical_summary.json"
SPONSOR_VPN_SESSION_FAIL_CANONICAL="$TMP_DIR/sponsor_vpn_session_fail_canonical_summary.json"
SPONSOR_VPN_SESSION_RELAXED_CANONICAL="$TMP_DIR/sponsor_vpn_session_relaxed_canonical_summary.json"
ISSUER_SETTLEMENT_STATUS_FAIL_CANONICAL="$TMP_DIR/issuer_settlement_status_fail_canonical_summary.json"
ISSUER_SETTLEMENT_STATUS_RELAXED_CANONICAL="$TMP_DIR/issuer_settlement_status_relaxed_canonical_summary.json"
EXIT_SETTLEMENT_STATUS_FAIL_CANONICAL="$TMP_DIR/exit_settlement_status_fail_canonical_summary.json"
EXIT_SETTLEMENT_STATUS_RELAXED_CANONICAL="$TMP_DIR/exit_settlement_status_relaxed_canonical_summary.json"
ADMIN_FAIL_CANONICAL="$TMP_DIR/admin_fail_canonical_summary.json"
ADMIN_RELAXED_CANONICAL="$TMP_DIR/admin_relaxed_canonical_summary.json"
ENV_CANONICAL_OUTPUT="$TMP_DIR/env_canonical_output.json"
ENV_LEGACY_OUTPUT="$TMP_DIR/env_legacy_output.json"
LEGACY_ALIAS_OUTPUT="$TMP_DIR/legacy_alias_output.json"
MISSING_OUTPUT="$TMP_DIR/missing_output.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
RELAXED_LOG="$TMP_DIR/relaxed.log"
DUAL_FAIL_LOG="$TMP_DIR/dual_fail.log"
DUAL_RELAXED_LOG="$TMP_DIR/dual_relaxed.log"
ADAPTER_ROUNDTRIP_FAIL_LOG="$TMP_DIR/adapter_roundtrip_fail.log"
ADAPTER_ROUNDTRIP_RELAXED_LOG="$TMP_DIR/adapter_roundtrip_relaxed.log"
ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_LOG="$TMP_DIR/adapter_signed_tx_roundtrip_fail.log"
ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_LOG="$TMP_DIR/adapter_signed_tx_roundtrip_relaxed.log"
SHADOW_ENV_FAIL_LOG="$TMP_DIR/shadow_env_fail.log"
SHADOW_ENV_RELAXED_LOG="$TMP_DIR/shadow_env_relaxed.log"
SHADOW_STATUS_SURFACE_FAIL_LOG="$TMP_DIR/shadow_status_surface_fail.log"
SHADOW_STATUS_SURFACE_RELAXED_LOG="$TMP_DIR/shadow_status_surface_relaxed.log"
SPONSOR_FAIL_LOG="$TMP_DIR/sponsor_fail.log"
SPONSOR_RELAXED_LOG="$TMP_DIR/sponsor_relaxed.log"
SPONSOR_VPN_SESSION_FAIL_LOG="$TMP_DIR/sponsor_vpn_session_fail.log"
SPONSOR_VPN_SESSION_RELAXED_LOG="$TMP_DIR/sponsor_vpn_session_relaxed.log"
ISSUER_SETTLEMENT_STATUS_FAIL_LOG="$TMP_DIR/issuer_settlement_status_fail.log"
ISSUER_SETTLEMENT_STATUS_RELAXED_LOG="$TMP_DIR/issuer_settlement_status_relaxed.log"
EXIT_SETTLEMENT_STATUS_FAIL_LOG="$TMP_DIR/exit_settlement_status_fail.log"
EXIT_SETTLEMENT_STATUS_RELAXED_LOG="$TMP_DIR/exit_settlement_status_relaxed.log"
ADMIN_FAIL_LOG="$TMP_DIR/admin_fail.log"
ADMIN_RELAXED_LOG="$TMP_DIR/admin_relaxed.log"
ENV_CANONICAL_LOG="$TMP_DIR/env_canonical.log"
ENV_LEGACY_LOG="$TMP_DIR/env_legacy.log"
LEGACY_ALIAS_LOG="$TMP_DIR/legacy_alias.log"
MISSING_LOG="$TMP_DIR/missing.log"

# Isolation default: prevent any invocation path from writing canonical
# artifacts into repository-level .easy-node-logs.
DEFAULT_CANONICAL="$TMP_DIR/default_canonical_summary.json"
export PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$DEFAULT_CANONICAL"

assert_default_canonical() {
  local summary_json="$1"
  local log_file="$2"
  local label="$3"

  if [[ ! -f "$DEFAULT_CANONICAL" ]]; then
    echo "$label: missing default canonical summary: $DEFAULT_CANONICAL"
    cat "$log_file"
    exit 1
  fi
  if ! jq -e --arg expected_canonical "$DEFAULT_CANONICAL" '.artifacts.canonical_summary_json == $expected_canonical' "$summary_json" >/dev/null; then
    echo "$label: summary did not use isolated default canonical path"
    cat "$summary_json"
    cat "$log_file"
    exit 1
  fi
  if ! cmp -s "$summary_json" "$DEFAULT_CANONICAL"; then
    echo "$label: default canonical summary diverges from run summary"
    cat "$summary_json"
    cat "$DEFAULT_CANONICAL"
    cat "$log_file"
    exit 1
  fi
}

cat >"$PASS_SUMMARY" <<'EOF_PASS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_PASS

cat >"$FAIL_SUMMARY" <<'EOF_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "fail"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_FAIL

cat >"$RELAXED_SUMMARY" <<'EOF_RELAXED'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "fail"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_RELAXED

cat >"$SPONSOR_FAIL_SUMMARY" <<'EOF_SPONSOR_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "fail"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_SPONSOR_FAIL

cat >"$SPONSOR_VPN_SESSION_FAIL_SUMMARY" <<'EOF_SPONSOR_VPN_SESSION_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
    "issuer_sponsor_vpn_session_live_smoke": {
      "status": "fail"
    },
    "issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_SPONSOR_VPN_SESSION_FAIL

cat >"$ISSUER_SETTLEMENT_STATUS_FAIL_SUMMARY" <<'EOF_ISSUER_SETTLEMENT_STATUS_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "fail"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_ISSUER_SETTLEMENT_STATUS_FAIL

cat >"$EXIT_SETTLEMENT_STATUS_FAIL_SUMMARY" <<'EOF_EXIT_SETTLEMENT_STATUS_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "fail"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_EXIT_SETTLEMENT_STATUS_FAIL

cat >"$DUAL_FAIL_SUMMARY" <<'EOF_DUAL_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "fail"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_DUAL_FAIL

cat >"$ADAPTER_ROUNDTRIP_FAIL_SUMMARY" <<'EOF_ADAPTER_ROUNDTRIP_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_adapter_roundtrip": {
      "status": "fail"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_ADAPTER_ROUNDTRIP_FAIL

cat >"$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_SUMMARY" <<'EOF_ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_adapter_roundtrip": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "fail"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL

cat >"$SHADOW_ENV_FAIL_SUMMARY" <<'EOF_SHADOW_ENV_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_adapter_roundtrip": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "fail"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_SHADOW_ENV_FAIL

cat >"$SHADOW_STATUS_SURFACE_FAIL_SUMMARY" <<'EOF_SHADOW_STATUS_SURFACE_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_adapter_roundtrip": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "fail"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    }
  }
}
EOF_SHADOW_STATUS_SURFACE_FAIL

cat >"$ADMIN_FAIL_SUMMARY" <<'EOF_ADMIN_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
        "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    },
"issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "fail"
    }
  }
}
EOF_ADMIN_FAIL

echo "[phase5-settlement-layer-check] stage-derived pass path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase5_settlement_layer_check_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .inputs.usable.ci_phase5_summary_json == true
  and .policy.require_settlement_failsoft_ok == true
  and .policy.require_settlement_acceptance_ok == true
  and .policy.require_settlement_bridge_smoke_ok == true
  and .policy.require_settlement_adapter_roundtrip_ok == true
  and .policy.require_settlement_adapter_signed_tx_roundtrip_ok == true
  and .policy.require_settlement_shadow_env_ok == true
  and .policy.require_settlement_shadow_status_surface_ok == true
  and .policy.require_settlement_state_persistence_ok == true
  and .policy.require_settlement_dual_asset_parity_ok == true
  and .policy.require_issuer_sponsor_api_live_smoke_ok == true
  and .policy.require_issuer_sponsor_vpn_session_live_smoke_ok == true
  and .policy.require_issuer_settlement_status_live_smoke_ok == true
  and .policy.require_exit_settlement_status_live_smoke_ok == true
  and .signals.settlement_failsoft_ok == true
  and .signals.settlement_acceptance_ok == true
  and .signals.settlement_bridge_smoke_ok == true
  and .signals.settlement_adapter_roundtrip_ok == true
  and .signals.settlement_adapter_roundtrip_status == "pass"
  and .signals.settlement_adapter_roundtrip_resolved == true
  and .signals.settlement_adapter_signed_tx_roundtrip_ok == true
  and .signals.settlement_adapter_signed_tx_roundtrip_status == "pass"
  and .signals.settlement_adapter_signed_tx_roundtrip_resolved == true
  and .signals.settlement_shadow_env_ok == true
  and .signals.settlement_shadow_env_status == "pass"
  and .signals.settlement_shadow_env_resolved == true
  and .signals.settlement_shadow_status_surface_ok == true
  and .signals.settlement_shadow_status_surface_status == "pass"
  and .signals.settlement_shadow_status_surface_resolved == true
  and .signals.settlement_state_persistence_ok == true
  and .signals.settlement_dual_asset_parity_ok == true
  and .signals.issuer_sponsor_api_live_smoke_ok == true
  and .signals.issuer_sponsor_vpn_session_live_smoke_ok == true
  and .signals.issuer_sponsor_vpn_session_live_smoke_status == "pass"
  and .signals.issuer_sponsor_vpn_session_live_smoke_resolved == true
  and .signals.issuer_settlement_status_live_smoke_ok == true
  and .signals.issuer_settlement_status_live_smoke_status == "pass"
  and .signals.issuer_settlement_status_live_smoke_resolved == true
  and .signals.exit_settlement_status_live_smoke_ok == true
  and .signals.exit_settlement_status_live_smoke_status == "pass"
  and .signals.exit_settlement_status_live_smoke_resolved == true
  and .stages.settlement_adapter_roundtrip.status == "pass"
  and .stages.settlement_adapter_signed_tx_roundtrip.status == "pass"
  and .stages.settlement_shadow_env.status == "pass"
  and .stages.settlement_shadow_status_surface.status == "pass"
  and .stages.issuer_sponsor_vpn_session_live_smoke.status == "pass"
  and .stages.issuer_settlement_status_live_smoke.status == "pass"
  and .stages.exit_settlement_status_live_smoke.status == "pass"
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage_ok")) then
      .policy.require_issuer_admin_blockchain_handlers_coverage_ok == true
      and .signals.issuer_admin_blockchain_handlers_coverage_ok == true
      and .signals.issuer_admin_blockchain_handlers_coverage_status == "pass"
      and .stages.issuer_admin_blockchain_handlers_coverage.status == "pass"
    else true
    end
  )
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_OUTPUT" "$PASS_CANONICAL"; then
  echo "pass-path canonical summary diverges from run summary"
  cat "$PASS_OUTPUT"
  cat "$PASS_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on stage failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$FAIL_SUMMARY" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed stage failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if [[ ! -f "$FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on fail path: $FAIL_CANONICAL"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .artifacts.canonical_summary_json == $expected_canonical
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_acceptance_ok is false")))
' --arg expected_canonical "$FAIL_CANONICAL" "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_OUTPUT" "$FAIL_CANONICAL"; then
  echo "fail-path canonical summary diverges from run summary"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] canonical relaxed policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-settlement-acceptance-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if [[ ! -f "$RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on relaxed path: $RELAXED_CANONICAL"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' --arg expected_canonical "$RELAXED_CANONICAL" "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-policy summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$RELAXED_OUTPUT" "$RELAXED_CANONICAL"; then
  echo "relaxed-path canonical summary diverges from run summary"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] issuer-admin coverage fail/skip compatibility path"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ADMIN_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ADMIN_FAIL_SUMMARY" \
  --summary-json "$ADMIN_FAIL_OUTPUT" \
  --show-json 0 >"$ADMIN_FAIL_LOG" 2>&1
admin_fail_rc=$?
set -e
if [[ ! -f "$ADMIN_FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on issuer-admin fail path: $ADMIN_FAIL_CANONICAL"
  cat "$ADMIN_FAIL_LOG"
  exit 1
fi
if jq -e '.signals | has("issuer_admin_blockchain_handlers_coverage_ok")' "$ADMIN_FAIL_OUTPUT" >/dev/null; then
  if [[ "$admin_fail_rc" -ne 1 ]]; then
    echo "expected rc=1 for issuer-admin fail-closed path, got rc=$admin_fail_rc"
    cat "$ADMIN_FAIL_LOG"
    exit 1
  fi
  if ! jq -e '
    .status == "fail"
    and .rc == 1
    and .policy.require_issuer_admin_blockchain_handlers_coverage_ok == true
    and .signals.issuer_admin_blockchain_handlers_coverage_ok == false
    and .stages.issuer_admin_blockchain_handlers_coverage.status == "fail"
    and ((.decision.reasons // []) | any(test("issuer_admin_blockchain_handlers_coverage_ok is false")))
  ' "$ADMIN_FAIL_OUTPUT" >/dev/null; then
    echo "issuer-admin fail-path summary mismatch"
    cat "$ADMIN_FAIL_OUTPUT"
    cat "$ADMIN_FAIL_LOG"
    exit 1
  fi
else
  if [[ "$admin_fail_rc" -ne 0 ]]; then
    echo "expected rc=0 when issuer-admin signal is not yet surfaced, got rc=$admin_fail_rc"
    cat "$ADMIN_FAIL_LOG"
    exit 1
  fi
  if ! jq -e '
    .status == "pass"
    and .rc == 0
    and ((.signals | has("issuer_admin_blockchain_handlers_coverage_ok")) | not)
  ' "$ADMIN_FAIL_OUTPUT" >/dev/null; then
    echo "issuer-admin compatibility path summary mismatch"
    cat "$ADMIN_FAIL_OUTPUT"
    cat "$ADMIN_FAIL_LOG"
    exit 1
  fi
fi
if ! cmp -s "$ADMIN_FAIL_OUTPUT" "$ADMIN_FAIL_CANONICAL"; then
  echo "issuer-admin fail-path canonical summary diverges from run summary"
  cat "$ADMIN_FAIL_OUTPUT"
  cat "$ADMIN_FAIL_CANONICAL"
  exit 1
fi

supports_admin_requirement_flag=0
if "$SCRIPT_UNDER_TEST" --help 2>/dev/null | grep -Fq -- "--require-issuer-admin-blockchain-handlers-coverage-ok"; then
  supports_admin_requirement_flag=1
fi

if [[ "$supports_admin_requirement_flag" == "1" ]]; then
  echo "[phase5-settlement-layer-check] issuer-admin policy toggle path"
  PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ADMIN_RELAXED_CANONICAL" \
  "$SCRIPT_UNDER_TEST" \
    --ci-phase5-summary-json "$ADMIN_FAIL_SUMMARY" \
    --summary-json "$ADMIN_RELAXED_OUTPUT" \
    --require-issuer-admin-blockchain-handlers-coverage-ok 0 \
    --show-json 0 >"$ADMIN_RELAXED_LOG" 2>&1

  if ! jq -e '
    .status == "pass"
    and .rc == 0
    and .policy.require_issuer_admin_blockchain_handlers_coverage_ok == false
    and .signals.issuer_admin_blockchain_handlers_coverage_ok == false
    and .stages.issuer_admin_blockchain_handlers_coverage.status == "fail"
  ' "$ADMIN_RELAXED_OUTPUT" >/dev/null; then
    echo "issuer-admin relaxed-policy summary mismatch"
    cat "$ADMIN_RELAXED_OUTPUT"
    cat "$ADMIN_RELAXED_LOG"
    exit 1
  fi
fi

echo "[phase5-settlement-layer-check] fail-closed path on dual-asset parity failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$DUAL_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$DUAL_FAIL_SUMMARY" \
  --summary-json "$DUAL_FAIL_OUTPUT" \
  --show-json 0 >"$DUAL_FAIL_LOG" 2>&1
dual_fail_rc=$?
set -e
if [[ "$dual_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for dual-asset parity fail-closed path, got rc=$dual_fail_rc"
  cat "$DUAL_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_settlement_dual_asset_parity_ok == true
  and .signals.settlement_dual_asset_parity_ok == false
  and .stages.settlement_dual_asset_parity.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_dual_asset_parity_ok is false")))
' "$DUAL_FAIL_OUTPUT" >/dev/null; then
  echo "dual-asset fail-path summary mismatch"
  cat "$DUAL_FAIL_OUTPUT"
  cat "$DUAL_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] dual-asset policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$DUAL_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$DUAL_FAIL_SUMMARY" \
  --summary-json "$DUAL_RELAXED_OUTPUT" \
  --require-settlement-dual-asset-parity-ok 0 \
  --show-json 0 >"$DUAL_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_dual_asset_parity_ok == false
  and .signals.settlement_dual_asset_parity_ok == false
  and .stages.settlement_dual_asset_parity.status == "fail"
' "$DUAL_RELAXED_OUTPUT" >/dev/null; then
  echo "dual-asset relaxed-policy summary mismatch"
  cat "$DUAL_RELAXED_OUTPUT"
  cat "$DUAL_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on settlement adapter roundtrip failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ADAPTER_ROUNDTRIP_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ADAPTER_ROUNDTRIP_FAIL_SUMMARY" \
  --summary-json "$ADAPTER_ROUNDTRIP_FAIL_OUTPUT" \
  --show-json 0 >"$ADAPTER_ROUNDTRIP_FAIL_LOG" 2>&1
adapter_roundtrip_fail_rc=$?
set -e
if [[ "$adapter_roundtrip_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for adapter-roundtrip fail-closed path, got rc=$adapter_roundtrip_fail_rc"
  cat "$ADAPTER_ROUNDTRIP_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_settlement_adapter_roundtrip_ok == true
  and .signals.settlement_adapter_roundtrip_ok == false
  and .signals.settlement_adapter_roundtrip_status == "fail"
  and .signals.settlement_adapter_roundtrip_resolved == true
  and .stages.settlement_adapter_roundtrip.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_adapter_roundtrip_ok is false")))
' "$ADAPTER_ROUNDTRIP_FAIL_OUTPUT" >/dev/null; then
  echo "adapter-roundtrip fail-path summary mismatch"
  cat "$ADAPTER_ROUNDTRIP_FAIL_OUTPUT"
  cat "$ADAPTER_ROUNDTRIP_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] settlement adapter roundtrip policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ADAPTER_ROUNDTRIP_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ADAPTER_ROUNDTRIP_FAIL_SUMMARY" \
  --summary-json "$ADAPTER_ROUNDTRIP_RELAXED_OUTPUT" \
  --require-settlement-adapter-roundtrip-ok 0 \
  --show-json 0 >"$ADAPTER_ROUNDTRIP_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_adapter_roundtrip_ok == false
  and .signals.settlement_adapter_roundtrip_ok == false
  and .signals.settlement_adapter_roundtrip_status == "fail"
  and .signals.settlement_adapter_roundtrip_resolved == true
  and .stages.settlement_adapter_roundtrip.status == "fail"
' "$ADAPTER_ROUNDTRIP_RELAXED_OUTPUT" >/dev/null; then
  echo "adapter-roundtrip relaxed-policy summary mismatch"
  cat "$ADAPTER_ROUNDTRIP_RELAXED_OUTPUT"
  cat "$ADAPTER_ROUNDTRIP_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on settlement adapter signed-tx roundtrip failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_SUMMARY" \
  --summary-json "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_OUTPUT" \
  --show-json 0 >"$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_LOG" 2>&1
adapter_signed_tx_roundtrip_fail_rc=$?
set -e
if [[ "$adapter_signed_tx_roundtrip_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for adapter-signed-tx-roundtrip fail-closed path, got rc=$adapter_signed_tx_roundtrip_fail_rc"
  cat "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_settlement_adapter_signed_tx_roundtrip_ok == true
  and .signals.settlement_adapter_signed_tx_roundtrip_ok == false
  and .signals.settlement_adapter_signed_tx_roundtrip_status == "fail"
  and .signals.settlement_adapter_signed_tx_roundtrip_resolved == true
  and .stages.settlement_adapter_signed_tx_roundtrip.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_adapter_signed_tx_roundtrip_ok is false")))
' "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_OUTPUT" >/dev/null; then
  echo "adapter-signed-tx-roundtrip fail-path summary mismatch"
  cat "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_OUTPUT"
  cat "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] settlement adapter signed-tx roundtrip policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ADAPTER_SIGNED_TX_ROUNDTRIP_FAIL_SUMMARY" \
  --summary-json "$ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_OUTPUT" \
  --require-settlement-adapter-signed-tx-roundtrip-ok 0 \
  --show-json 0 >"$ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_adapter_signed_tx_roundtrip_ok == false
  and .signals.settlement_adapter_signed_tx_roundtrip_ok == false
  and .signals.settlement_adapter_signed_tx_roundtrip_status == "fail"
  and .signals.settlement_adapter_signed_tx_roundtrip_resolved == true
  and .stages.settlement_adapter_signed_tx_roundtrip.status == "fail"
' "$ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_OUTPUT" >/dev/null; then
  echo "adapter-signed-tx-roundtrip relaxed-policy summary mismatch"
  cat "$ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_OUTPUT"
  cat "$ADAPTER_SIGNED_TX_ROUNDTRIP_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on settlement shadow env failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SHADOW_ENV_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SHADOW_ENV_FAIL_SUMMARY" \
  --summary-json "$SHADOW_ENV_FAIL_OUTPUT" \
  --show-json 0 >"$SHADOW_ENV_FAIL_LOG" 2>&1
shadow_env_fail_rc=$?
set -e
if [[ "$shadow_env_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for shadow-env fail-closed path, got rc=$shadow_env_fail_rc"
  cat "$SHADOW_ENV_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_settlement_shadow_env_ok == true
  and .signals.settlement_shadow_env_ok == false
  and .signals.settlement_shadow_env_status == "fail"
  and .signals.settlement_shadow_env_resolved == true
  and .stages.settlement_shadow_env.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_shadow_env_ok is false")))
' "$SHADOW_ENV_FAIL_OUTPUT" >/dev/null; then
  echo "shadow-env fail-path summary mismatch"
  cat "$SHADOW_ENV_FAIL_OUTPUT"
  cat "$SHADOW_ENV_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] settlement shadow env policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SHADOW_ENV_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SHADOW_ENV_FAIL_SUMMARY" \
  --summary-json "$SHADOW_ENV_RELAXED_OUTPUT" \
  --require-settlement-shadow-env-ok 0 \
  --show-json 0 >"$SHADOW_ENV_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_shadow_env_ok == false
  and .signals.settlement_shadow_env_ok == false
  and .signals.settlement_shadow_env_status == "fail"
  and .signals.settlement_shadow_env_resolved == true
  and .stages.settlement_shadow_env.status == "fail"
' "$SHADOW_ENV_RELAXED_OUTPUT" >/dev/null; then
  echo "shadow-env relaxed-policy summary mismatch"
  cat "$SHADOW_ENV_RELAXED_OUTPUT"
  cat "$SHADOW_ENV_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on settlement shadow status surface failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SHADOW_STATUS_SURFACE_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SHADOW_STATUS_SURFACE_FAIL_SUMMARY" \
  --summary-json "$SHADOW_STATUS_SURFACE_FAIL_OUTPUT" \
  --show-json 0 >"$SHADOW_STATUS_SURFACE_FAIL_LOG" 2>&1
shadow_status_surface_fail_rc=$?
set -e
if [[ "$shadow_status_surface_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for shadow-status-surface fail-closed path, got rc=$shadow_status_surface_fail_rc"
  cat "$SHADOW_STATUS_SURFACE_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_settlement_shadow_status_surface_ok == true
  and .signals.settlement_shadow_status_surface_ok == false
  and .signals.settlement_shadow_status_surface_status == "fail"
  and .signals.settlement_shadow_status_surface_resolved == true
  and .stages.settlement_shadow_status_surface.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_shadow_status_surface_ok is false")))
' "$SHADOW_STATUS_SURFACE_FAIL_OUTPUT" >/dev/null; then
  echo "shadow-status-surface fail-path summary mismatch"
  cat "$SHADOW_STATUS_SURFACE_FAIL_OUTPUT"
  cat "$SHADOW_STATUS_SURFACE_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] settlement shadow status surface policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SHADOW_STATUS_SURFACE_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SHADOW_STATUS_SURFACE_FAIL_SUMMARY" \
  --summary-json "$SHADOW_STATUS_SURFACE_RELAXED_OUTPUT" \
  --require-settlement-shadow-status-surface-ok 0 \
  --show-json 0 >"$SHADOW_STATUS_SURFACE_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_shadow_status_surface_ok == false
  and .signals.settlement_shadow_status_surface_ok == false
  and .signals.settlement_shadow_status_surface_status == "fail"
  and .signals.settlement_shadow_status_surface_resolved == true
  and .stages.settlement_shadow_status_surface.status == "fail"
' "$SHADOW_STATUS_SURFACE_RELAXED_OUTPUT" >/dev/null; then
  echo "shadow-status-surface relaxed-policy summary mismatch"
  cat "$SHADOW_STATUS_SURFACE_RELAXED_OUTPUT"
  cat "$SHADOW_STATUS_SURFACE_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on sponsor live-smoke failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SPONSOR_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SPONSOR_FAIL_SUMMARY" \
  --summary-json "$SPONSOR_FAIL_OUTPUT" \
  --show-json 0 >"$SPONSOR_FAIL_LOG" 2>&1
sponsor_fail_rc=$?
set -e
if [[ "$sponsor_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for sponsor fail-closed path, got rc=$sponsor_fail_rc"
  cat "$SPONSOR_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_issuer_sponsor_api_live_smoke_ok == true
  and .signals.issuer_sponsor_api_live_smoke_ok == false
  and .stages.issuer_sponsor_api_live_smoke.status == "fail"
  and ((.decision.reasons // []) | any(test("issuer_sponsor_api_live_smoke_ok is false")))
' "$SPONSOR_FAIL_OUTPUT" >/dev/null; then
  echo "sponsor fail-path summary mismatch"
  cat "$SPONSOR_FAIL_OUTPUT"
  cat "$SPONSOR_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] sponsor policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SPONSOR_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SPONSOR_FAIL_SUMMARY" \
  --summary-json "$SPONSOR_RELAXED_OUTPUT" \
  --require-issuer-sponsor-api-live-smoke-ok 0 \
  --show-json 0 >"$SPONSOR_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_issuer_sponsor_api_live_smoke_ok == false
  and .signals.issuer_sponsor_api_live_smoke_ok == false
  and .stages.issuer_sponsor_api_live_smoke.status == "fail"
' "$SPONSOR_RELAXED_OUTPUT" >/dev/null; then
  echo "sponsor relaxed-policy summary mismatch"
  cat "$SPONSOR_RELAXED_OUTPUT"
  cat "$SPONSOR_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on sponsor VPN-session live-smoke failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SPONSOR_VPN_SESSION_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SPONSOR_VPN_SESSION_FAIL_SUMMARY" \
  --summary-json "$SPONSOR_VPN_SESSION_FAIL_OUTPUT" \
  --show-json 0 >"$SPONSOR_VPN_SESSION_FAIL_LOG" 2>&1
sponsor_vpn_session_fail_rc=$?
set -e
if [[ "$sponsor_vpn_session_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for sponsor VPN-session fail-closed path, got rc=$sponsor_vpn_session_fail_rc"
  cat "$SPONSOR_VPN_SESSION_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_issuer_sponsor_vpn_session_live_smoke_ok == true
  and .signals.issuer_sponsor_vpn_session_live_smoke_ok == false
  and .signals.issuer_sponsor_vpn_session_live_smoke_status == "fail"
  and .signals.issuer_sponsor_vpn_session_live_smoke_resolved == true
  and .stages.issuer_sponsor_vpn_session_live_smoke.status == "fail"
  and ((.decision.reasons // []) | any(test("issuer_sponsor_vpn_session_live_smoke_ok is false")))
' "$SPONSOR_VPN_SESSION_FAIL_OUTPUT" >/dev/null; then
  echo "sponsor VPN-session fail-path summary mismatch"
  cat "$SPONSOR_VPN_SESSION_FAIL_OUTPUT"
  cat "$SPONSOR_VPN_SESSION_FAIL_LOG"
  exit 1
fi
if ! cmp -s "$SPONSOR_VPN_SESSION_FAIL_OUTPUT" "$SPONSOR_VPN_SESSION_FAIL_CANONICAL"; then
  echo "sponsor VPN-session fail-path canonical summary diverges from run summary"
  cat "$SPONSOR_VPN_SESSION_FAIL_OUTPUT"
  cat "$SPONSOR_VPN_SESSION_FAIL_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] sponsor VPN-session policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SPONSOR_VPN_SESSION_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SPONSOR_VPN_SESSION_FAIL_SUMMARY" \
  --summary-json "$SPONSOR_VPN_SESSION_RELAXED_OUTPUT" \
  --require-issuer-sponsor-vpn-session-live-smoke-ok 0 \
  --show-json 0 >"$SPONSOR_VPN_SESSION_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_issuer_sponsor_vpn_session_live_smoke_ok == false
  and .signals.issuer_sponsor_vpn_session_live_smoke_ok == false
  and .signals.issuer_sponsor_vpn_session_live_smoke_status == "fail"
  and .signals.issuer_sponsor_vpn_session_live_smoke_resolved == true
  and .stages.issuer_sponsor_vpn_session_live_smoke.status == "fail"
' "$SPONSOR_VPN_SESSION_RELAXED_OUTPUT" >/dev/null; then
  echo "sponsor VPN-session relaxed-policy summary mismatch"
  cat "$SPONSOR_VPN_SESSION_RELAXED_OUTPUT"
  cat "$SPONSOR_VPN_SESSION_RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$SPONSOR_VPN_SESSION_RELAXED_OUTPUT" "$SPONSOR_VPN_SESSION_RELAXED_CANONICAL"; then
  echo "sponsor VPN-session relaxed-path canonical summary diverges from run summary"
  cat "$SPONSOR_VPN_SESSION_RELAXED_OUTPUT"
  cat "$SPONSOR_VPN_SESSION_RELAXED_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on issuer settlement-status live-smoke failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ISSUER_SETTLEMENT_STATUS_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ISSUER_SETTLEMENT_STATUS_FAIL_SUMMARY" \
  --summary-json "$ISSUER_SETTLEMENT_STATUS_FAIL_OUTPUT" \
  --show-json 0 >"$ISSUER_SETTLEMENT_STATUS_FAIL_LOG" 2>&1
issuer_settlement_status_fail_rc=$?
set -e
if [[ "$issuer_settlement_status_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for issuer settlement-status fail-closed path, got rc=$issuer_settlement_status_fail_rc"
  cat "$ISSUER_SETTLEMENT_STATUS_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$ISSUER_SETTLEMENT_STATUS_FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on issuer settlement-status fail path: $ISSUER_SETTLEMENT_STATUS_FAIL_CANONICAL"
  cat "$ISSUER_SETTLEMENT_STATUS_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_issuer_settlement_status_live_smoke_ok == true
  and .signals.issuer_settlement_status_live_smoke_ok == false
  and .signals.issuer_settlement_status_live_smoke_status == "fail"
  and .signals.issuer_settlement_status_live_smoke_resolved == true
  and .stages.issuer_settlement_status_live_smoke.status == "fail"
  and ((.decision.reasons // []) | any(test("issuer_settlement_status_live_smoke_ok is false")))
' "$ISSUER_SETTLEMENT_STATUS_FAIL_OUTPUT" >/dev/null; then
  echo "issuer settlement-status fail-path summary mismatch"
  cat "$ISSUER_SETTLEMENT_STATUS_FAIL_OUTPUT"
  cat "$ISSUER_SETTLEMENT_STATUS_FAIL_LOG"
  exit 1
fi
if ! cmp -s "$ISSUER_SETTLEMENT_STATUS_FAIL_OUTPUT" "$ISSUER_SETTLEMENT_STATUS_FAIL_CANONICAL"; then
  echo "issuer settlement-status fail-path canonical summary diverges from run summary"
  cat "$ISSUER_SETTLEMENT_STATUS_FAIL_OUTPUT"
  cat "$ISSUER_SETTLEMENT_STATUS_FAIL_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] issuer settlement-status policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$ISSUER_SETTLEMENT_STATUS_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$ISSUER_SETTLEMENT_STATUS_FAIL_SUMMARY" \
  --summary-json "$ISSUER_SETTLEMENT_STATUS_RELAXED_OUTPUT" \
  --require-issuer-settlement-status-live-smoke-ok 0 \
  --show-json 0 >"$ISSUER_SETTLEMENT_STATUS_RELAXED_LOG" 2>&1

if [[ ! -f "$ISSUER_SETTLEMENT_STATUS_RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on issuer settlement-status relaxed path: $ISSUER_SETTLEMENT_STATUS_RELAXED_CANONICAL"
  cat "$ISSUER_SETTLEMENT_STATUS_RELAXED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_issuer_settlement_status_live_smoke_ok == false
  and .signals.issuer_settlement_status_live_smoke_ok == false
  and .signals.issuer_settlement_status_live_smoke_status == "fail"
  and .signals.issuer_settlement_status_live_smoke_resolved == true
  and .stages.issuer_settlement_status_live_smoke.status == "fail"
' "$ISSUER_SETTLEMENT_STATUS_RELAXED_OUTPUT" >/dev/null; then
  echo "issuer settlement-status relaxed-policy summary mismatch"
  cat "$ISSUER_SETTLEMENT_STATUS_RELAXED_OUTPUT"
  cat "$ISSUER_SETTLEMENT_STATUS_RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$ISSUER_SETTLEMENT_STATUS_RELAXED_OUTPUT" "$ISSUER_SETTLEMENT_STATUS_RELAXED_CANONICAL"; then
  echo "issuer settlement-status relaxed-path canonical summary diverges from run summary"
  cat "$ISSUER_SETTLEMENT_STATUS_RELAXED_OUTPUT"
  cat "$ISSUER_SETTLEMENT_STATUS_RELAXED_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on exit settlement-status live-smoke failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$EXIT_SETTLEMENT_STATUS_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$EXIT_SETTLEMENT_STATUS_FAIL_SUMMARY" \
  --summary-json "$EXIT_SETTLEMENT_STATUS_FAIL_OUTPUT" \
  --show-json 0 >"$EXIT_SETTLEMENT_STATUS_FAIL_LOG" 2>&1
exit_settlement_status_fail_rc=$?
set -e
if [[ "$exit_settlement_status_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for exit settlement-status fail-closed path, got rc=$exit_settlement_status_fail_rc"
  cat "$EXIT_SETTLEMENT_STATUS_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$EXIT_SETTLEMENT_STATUS_FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on exit settlement-status fail path: $EXIT_SETTLEMENT_STATUS_FAIL_CANONICAL"
  cat "$EXIT_SETTLEMENT_STATUS_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_exit_settlement_status_live_smoke_ok == true
  and .signals.exit_settlement_status_live_smoke_ok == false
  and .signals.exit_settlement_status_live_smoke_status == "fail"
  and .signals.exit_settlement_status_live_smoke_resolved == true
  and .stages.exit_settlement_status_live_smoke.status == "fail"
  and ((.decision.reasons // []) | any(test("exit_settlement_status_live_smoke_ok is false")))
' "$EXIT_SETTLEMENT_STATUS_FAIL_OUTPUT" >/dev/null; then
  echo "exit settlement-status fail-path summary mismatch"
  cat "$EXIT_SETTLEMENT_STATUS_FAIL_OUTPUT"
  cat "$EXIT_SETTLEMENT_STATUS_FAIL_LOG"
  exit 1
fi
if ! cmp -s "$EXIT_SETTLEMENT_STATUS_FAIL_OUTPUT" "$EXIT_SETTLEMENT_STATUS_FAIL_CANONICAL"; then
  echo "exit settlement-status fail-path canonical summary diverges from run summary"
  cat "$EXIT_SETTLEMENT_STATUS_FAIL_OUTPUT"
  cat "$EXIT_SETTLEMENT_STATUS_FAIL_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] exit settlement-status policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$EXIT_SETTLEMENT_STATUS_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$EXIT_SETTLEMENT_STATUS_FAIL_SUMMARY" \
  --summary-json "$EXIT_SETTLEMENT_STATUS_RELAXED_OUTPUT" \
  --require-exit-settlement-status-live-smoke-ok 0 \
  --show-json 0 >"$EXIT_SETTLEMENT_STATUS_RELAXED_LOG" 2>&1

if [[ ! -f "$EXIT_SETTLEMENT_STATUS_RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on exit settlement-status relaxed path: $EXIT_SETTLEMENT_STATUS_RELAXED_CANONICAL"
  cat "$EXIT_SETTLEMENT_STATUS_RELAXED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_exit_settlement_status_live_smoke_ok == false
  and .signals.exit_settlement_status_live_smoke_ok == false
  and .signals.exit_settlement_status_live_smoke_status == "fail"
  and .signals.exit_settlement_status_live_smoke_resolved == true
  and .stages.exit_settlement_status_live_smoke.status == "fail"
' "$EXIT_SETTLEMENT_STATUS_RELAXED_OUTPUT" >/dev/null; then
  echo "exit settlement-status relaxed-policy summary mismatch"
  cat "$EXIT_SETTLEMENT_STATUS_RELAXED_OUTPUT"
  cat "$EXIT_SETTLEMENT_STATUS_RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$EXIT_SETTLEMENT_STATUS_RELAXED_OUTPUT" "$EXIT_SETTLEMENT_STATUS_RELAXED_CANONICAL"; then
  echo "exit settlement-status relaxed-path canonical summary diverges from run summary"
  cat "$EXIT_SETTLEMENT_STATUS_RELAXED_OUTPUT"
  cat "$EXIT_SETTLEMENT_STATUS_RELAXED_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] canonical env-var requirement toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK=0 \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$ENV_CANONICAL_OUTPUT" \
  --show-json 0 >"$ENV_CANONICAL_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$ENV_CANONICAL_OUTPUT" >/dev/null; then
  echo "canonical-env policy summary mismatch"
  cat "$ENV_CANONICAL_OUTPUT"
  cat "$ENV_CANONICAL_LOG"
  exit 1
fi
assert_default_canonical "$ENV_CANONICAL_OUTPUT" "$ENV_CANONICAL_LOG" "canonical-env toggle path"

echo "[phase5-settlement-layer-check] legacy env-var compatibility path"
PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK= \
PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK=0 \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$ENV_LEGACY_OUTPUT" \
  --show-json 0 >"$ENV_LEGACY_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$ENV_LEGACY_OUTPUT" >/dev/null; then
  echo "legacy-env policy summary mismatch"
  cat "$ENV_LEGACY_OUTPUT"
  cat "$ENV_LEGACY_LOG"
  exit 1
fi
assert_default_canonical "$ENV_LEGACY_OUTPUT" "$ENV_LEGACY_LOG" "legacy-env compatibility path"

echo "[phase5-settlement-layer-check] legacy alias compatibility path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$LEGACY_ALIAS_OUTPUT" \
  --require-windows-role-runbooks-ok 0 \
  --show-json 0 >"$LEGACY_ALIAS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$LEGACY_ALIAS_OUTPUT" >/dev/null; then
  echo "legacy-alias policy summary mismatch"
  cat "$LEGACY_ALIAS_OUTPUT"
  cat "$LEGACY_ALIAS_LOG"
  exit 1
fi
assert_default_canonical "$LEGACY_ALIAS_OUTPUT" "$LEGACY_ALIAS_LOG" "legacy alias compatibility path"

echo "[phase5-settlement-layer-check] dual-asset compatibility alias path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$DUAL_FAIL_SUMMARY" \
  --summary-json "$LEGACY_ALIAS_OUTPUT" \
  --require-settlement-dual-asset-ok 0 \
  --show-json 0 >"$LEGACY_ALIAS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_dual_asset_parity_ok == false
  and .signals.settlement_dual_asset_parity_ok == false
  and .stages.settlement_dual_asset_parity.status == "fail"
' "$LEGACY_ALIAS_OUTPUT" >/dev/null; then
  echo "dual-asset legacy-alias policy summary mismatch"
  cat "$LEGACY_ALIAS_OUTPUT"
  cat "$LEGACY_ALIAS_LOG"
  exit 1
fi
assert_default_canonical "$LEGACY_ALIAS_OUTPUT" "$LEGACY_ALIAS_LOG" "dual-asset alias compatibility path"

echo "[phase5-settlement-layer-check] missing-summary show-json path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$MISSING_SUMMARY" \
  --summary-json "$MISSING_OUTPUT" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing summary fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.usable.ci_phase5_summary_json == false
  and ((.decision.reasons // []) | any(test("summary file not found or invalid JSON")))
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-summary contract mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
assert_default_canonical "$MISSING_OUTPUT" "$MISSING_LOG" "missing-summary fail-close path"
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase5 settlement layer check integration ok"
