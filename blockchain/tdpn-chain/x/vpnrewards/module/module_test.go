package module

import (
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

func TestAppModuleBackwardCompatibleSurface(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	m := NewAppModule(k)

	if got := m.Name(); got != types.ModuleName {
		t.Fatalf("expected module name %q, got %q", types.ModuleName, got)
	}
	if len(m.Responsibilities()) == 0 {
		t.Fatal("expected responsibilities to remain available")
	}
}
