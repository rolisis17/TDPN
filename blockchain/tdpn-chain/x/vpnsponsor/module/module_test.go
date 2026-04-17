package module

import (
	"reflect"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestAppModuleBackwardCompatibleSurface(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	m := NewAppModule(&k)

	if got := m.Name(); got != types.ModuleName {
		t.Fatalf("expected module name %q, got %q", types.ModuleName, got)
	}

	expected := []string{
		"store sponsor authorizations for app-level credit usage",
		"track delegated credits attached to user sessions",
		"expose reservation lifecycle state for sponsor APIs",
	}
	if !reflect.DeepEqual(m.Responsibilities(), expected) {
		t.Fatalf("expected responsibilities to remain unchanged, got %v", m.Responsibilities())
	}
}
