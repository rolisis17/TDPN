package module

import (
	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

// AppModule describes vpnrewards responsibilities for future Cosmos SDK registration.
type AppModule struct {
	Keeper *keeper.Keeper
}

func NewAppModule(k *keeper.Keeper) AppModule {
	return AppModule{Keeper: k}
}

func (m AppModule) Name() string {
	return types.ModuleName
}

func (m AppModule) Responsibilities() []string {
	return []string{
		"accrue rewards from settled VPN usage",
		"track deterministic distribution records",
		"support idempotent payout reconciliation",
	}
}
