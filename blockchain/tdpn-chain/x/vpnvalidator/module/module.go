package module

import (
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

// AppModule describes vpnvalidator responsibilities for future Cosmos SDK registration.
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
		"store validator eligibility policy decisions",
		"record objective validator lifecycle status transitions",
		"expose deterministic validator policy read-models for governance and control planes",
	}
}
