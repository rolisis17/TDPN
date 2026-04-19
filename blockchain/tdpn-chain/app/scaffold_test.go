package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestNewChainScaffold_ModuleNamesIncludeExpectedModules(t *testing.T) {
	scaffold := NewChainScaffold()
	if scaffold == nil {
		t.Fatal("expected scaffold to be non-nil")
	}

	moduleNames := scaffold.ModuleNames()
	if len(moduleNames) != 6 {
		t.Fatalf("expected 6 module names, got %d", len(moduleNames))
	}

	expected := map[string]struct{}{
		"vpnbilling":    {},
		"vpnrewards":    {},
		"vpnslashing":   {},
		"vpnsponsor":    {},
		"vpnvalidator":  {},
		"vpngovernance": {},
	}
	seen := make(map[string]struct{}, len(moduleNames))
	for _, name := range moduleNames {
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate module name returned: %q", name)
		}
		seen[name] = struct{}{}
		delete(expected, name)
	}

	if len(expected) != 0 {
		t.Fatalf("missing expected module names: %v", expected)
	}
}

func TestNewChainScaffoldWithStateDirPersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()

	scaffoldA, err := NewChainScaffoldWithStateDir(stateDir)
	if err != nil {
		t.Fatalf("NewChainScaffoldWithStateDir: %v", err)
	}

	const reservationID = "res-persist-1"
	const settlementID = "set-persist-1"
	const sessionID = "sess-persist-1"

	_, err = scaffoldA.BillingMsgServer().CreateReservation(context.Background(), BillingCreateReservationRequest{
		Record: billingtypes.CreditReservation{
			ReservationID: reservationID,
			SessionID:     sessionID,
			Amount:        100,
			AssetDenom:    "TDPNC",
		},
	})
	if err != nil {
		t.Fatalf("CreateReservation: %v", err)
	}
	_, err = scaffoldA.BillingMsgServer().FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{
		Record: billingtypes.SettlementRecord{
			SettlementID:  settlementID,
			ReservationID: reservationID,
			SessionID:     sessionID,
			BilledAmount:  75,
			AssetDenom:    "TDPNC",
		},
	})
	if err != nil {
		t.Fatalf("FinalizeSettlement: %v", err)
	}

	scaffoldB, err := NewChainScaffoldWithStateDir(stateDir)
	if err != nil {
		t.Fatalf("NewChainScaffoldWithStateDir reopen: %v", err)
	}
	for _, fileName := range []string{"vpnvalidator.json", "vpngovernance.json"} {
		if _, err := os.Stat(filepath.Join(stateDir, fileName)); err != nil {
			t.Fatalf("expected %s scaffold state file to exist: %v", fileName, err)
		}
	}
	reservationResp, err := scaffoldB.BillingQueryServer().GetReservation(context.Background(), BillingGetReservationRequest{
		ReservationID: reservationID,
	})
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if !reservationResp.Found {
		t.Fatal("expected reservation to persist across reopen")
	}

	settlementResp, err := scaffoldB.BillingQueryServer().GetSettlement(context.Background(), BillingGetSettlementRequest{
		SettlementID: settlementID,
	})
	if err != nil {
		t.Fatalf("GetSettlement: %v", err)
	}
	if !settlementResp.Found {
		t.Fatal("expected settlement to persist across reopen")
	}
}

func TestChainScaffoldConfigureStateDirRequiresPath(t *testing.T) {
	t.Parallel()

	scaffold := NewChainScaffold()
	if err := scaffold.ConfigureStateDir("   "); err == nil {
		t.Fatal("expected ConfigureStateDir to reject empty state dir")
	}
}

func TestChainScaffoldConfigureStateDirRejectsSymlinkStateFile(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	targetPath := filepath.Join(t.TempDir(), "outside-target.json")
	if err := os.WriteFile(targetPath, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("write target file: %v", err)
	}

	linkPath := filepath.Join(stateDir, "vpnvalidator.json")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}

	scaffold := NewChainScaffold()
	err := scaffold.ConfigureStateDir(stateDir)
	if err == nil {
		t.Fatal("expected ConfigureStateDir to reject symlinked scaffold state file")
	}
	if !strings.Contains(err.Error(), "resolves to a symlink") {
		t.Fatalf("expected symlink rejection error, got %v", err)
	}
}

func TestChainScaffoldConfigureStateDirDoesNotWriteThroughDanglingSymlink(t *testing.T) {
	t.Parallel()

	stateDir := t.TempDir()
	targetPath := filepath.Join(t.TempDir(), "outside", "never-created.json")
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("create target directory: %v", err)
	}

	linkPath := filepath.Join(stateDir, "vpnvalidator.json")
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}

	scaffold := NewChainScaffold()
	err := scaffold.ConfigureStateDir(stateDir)
	if err == nil {
		t.Fatal("expected ConfigureStateDir to reject dangling symlinked scaffold state file")
	}
	if !strings.Contains(err.Error(), "resolves to a symlink") {
		t.Fatalf("expected symlink rejection error, got %v", err)
	}

	if _, statErr := os.Stat(targetPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected dangling symlink target to remain absent, got stat err=%v", statErr)
	}
}
