package module

import (
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

// AppModule describes vpnsponsor responsibilities for future Cosmos SDK registration.
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
		"store sponsor authorizations for app-level credit usage",
		"track delegated credits attached to user sessions",
		"expose reservation lifecycle state for sponsor APIs",
	}
}
