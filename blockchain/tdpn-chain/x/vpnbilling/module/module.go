package module

import (
	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

// AppModule describes vpnbilling responsibilities for future Cosmos SDK registration.
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
		"track prepaid credits and session reservations",
		"finalize usage settlement records",
		"preserve idempotent operation references for replay safety",
	}
}
