package app

import (
	"context"
	"testing"

	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestNewChainScaffold_ModuleNamesIncludeExpectedModules(t *testing.T) {
	scaffold := NewChainScaffold()
	if scaffold == nil {
		t.Fatal("expected scaffold to be non-nil")
	}

	moduleNames := scaffold.ModuleNames()
	if len(moduleNames) != 4 {
		t.Fatalf("expected 4 module names, got %d", len(moduleNames))
	}

	expected := map[string]struct{}{
		"vpnbilling":  {},
		"vpnrewards":  {},
		"vpnslashing": {},
		"vpnsponsor":  {},
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
