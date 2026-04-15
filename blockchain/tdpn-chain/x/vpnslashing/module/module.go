package module

import (
	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

// AppModule describes vpnslashing responsibilities for future Cosmos SDK registration.
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
		"ingest objective slash evidence",
		"persist deterministic penalty decisions",
		"keep subjective enforcement out of automated v1 flow",
	}
}
