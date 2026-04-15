package module

import (
	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

// AppModule describes vpngovernance responsibilities for future Cosmos SDK registration.
type AppModule struct {
	Keeper keeper.Keeper
}

func NewAppModule(k keeper.Keeper) AppModule {
	return AppModule{Keeper: k}
}

func (m AppModule) Name() string {
	return types.ModuleName
}

func (m AppModule) Responsibilities() []string {
	return []string{
		"store governance policies for validator and economic controls",
		"record policy-bound governance decisions with deterministic replay semantics",
		"expose governance read models for chain control-plane reconciliation",
	}
}
