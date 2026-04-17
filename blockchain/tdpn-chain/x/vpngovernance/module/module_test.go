package module

import (
	"reflect"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestAppModuleBackwardCompatibleSurface(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	m := NewAppModule(&k)

	if got := m.Name(); got != types.ModuleName {
		t.Fatalf("expected module name %q, got %q", types.ModuleName, got)
	}

	expected := []string{
		"store governance policies for validator and economic controls",
		"record policy-bound governance decisions with deterministic replay semantics",
		"expose governance read models for chain control-plane reconciliation",
	}
	if !reflect.DeepEqual(m.Responsibilities(), expected) {
		t.Fatalf("expected responsibilities to remain unchanged, got %v", m.Responsibilities())
	}
}
