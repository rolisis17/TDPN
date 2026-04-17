package module

import (
	"reflect"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestAppModuleBackwardCompatibleSurface(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	m := NewAppModule(&k)

	if got := m.Name(); got != types.ModuleName {
		t.Fatalf("expected module name %q, got %q", types.ModuleName, got)
	}

	expected := []string{
		"store validator eligibility policy decisions",
		"record objective validator lifecycle status transitions",
		"expose deterministic validator policy read-models for governance and control planes",
	}
	if !reflect.DeepEqual(m.Responsibilities(), expected) {
		t.Fatalf("expected responsibilities to remain unchanged, got %v", m.Responsibilities())
	}
}
