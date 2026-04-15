package app

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	billingkeeper "github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	billingmodule "github.com/tdpn/tdpn-chain/x/vpnbilling/module"
	rewardskeeper "github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	slashingkeeper "github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	sponsorkeeper "github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
)

// ChainScaffold keeps module placeholders together until Cosmos SDK app wiring is added.
type ChainScaffold struct {
	BillingModule  billingmodule.AppModule
	RewardsModule  rewardsmodule.AppModule
	SlashingModule slashingmodule.AppModule
	SponsorModule  sponsormodule.AppModule
}

// NewChainScaffold creates in-memory keepers and module descriptors.
func NewChainScaffold() *ChainScaffold {
	return newInMemoryChainScaffold()
}

// NewChainScaffoldWithStateDir creates module keepers backed by file stores rooted under stateDir.
func NewChainScaffoldWithStateDir(stateDir string) (*ChainScaffold, error) {
	scaffold := newInMemoryChainScaffold()
	if err := scaffold.ConfigureStateDir(stateDir); err != nil {
		return nil, err
	}
	return scaffold, nil
}

func newInMemoryChainScaffold() *ChainScaffold {
	billingKeeper := billingkeeper.NewKeeper()
	rewardsKeeper := rewardskeeper.NewKeeper()
	slashingKeeper := slashingkeeper.NewKeeper()
	sponsorKeeper := sponsorkeeper.NewKeeper()

	return &ChainScaffold{
		BillingModule:  billingmodule.NewAppModule(billingKeeper),
		RewardsModule:  rewardsmodule.NewAppModule(rewardsKeeper),
		SlashingModule: slashingmodule.NewAppModule(slashingKeeper),
		SponsorModule:  sponsormodule.NewAppModule(sponsorKeeper),
	}
}

// ConfigureStateDir replaces in-memory stores with file-backed stores rooted under stateDir.
func (s *ChainScaffold) ConfigureStateDir(stateDir string) error {
	if s == nil {
		return errors.New("chain scaffold is nil")
	}
	stateDir = strings.TrimSpace(stateDir)
	if stateDir == "" {
		return errors.New("state dir is required")
	}

	billingStore, err := billingkeeper.NewFileStore(filepath.Join(stateDir, "vpnbilling.json"))
	if err != nil {
		return fmt.Errorf("vpnbilling file store: %w", err)
	}
	rewardsStore, err := rewardskeeper.NewFileStore(filepath.Join(stateDir, "vpnrewards.json"))
	if err != nil {
		return fmt.Errorf("vpnrewards file store: %w", err)
	}
	slashingStore, err := slashingkeeper.NewFileStore(filepath.Join(stateDir, "vpnslashing.json"))
	if err != nil {
		return fmt.Errorf("vpnslashing file store: %w", err)
	}
	sponsorStore, err := sponsorkeeper.NewFileStore(filepath.Join(stateDir, "vpnsponsor.json"))
	if err != nil {
		return fmt.Errorf("vpnsponsor file store: %w", err)
	}

	s.BillingModule = billingmodule.NewAppModule(billingkeeper.NewKeeperWithStore(billingStore))
	s.RewardsModule = rewardsmodule.NewAppModule(rewardskeeper.NewKeeperWithStore(rewardsStore))
	s.SlashingModule = slashingmodule.NewAppModule(slashingkeeper.NewKeeperWithStore(slashingStore))
	s.SponsorModule = sponsormodule.NewAppModule(sponsorkeeper.NewKeeperWithStore(sponsorStore))
	return nil
}

// ModuleNames returns the module identifiers expected by future app wiring.
func (s *ChainScaffold) ModuleNames() []string {
	return []string{
		s.BillingModule.Name(),
		s.RewardsModule.Name(),
		s.SlashingModule.Name(),
		s.SponsorModule.Name(),
	}
}

// BillingMsgServer returns the phase-1 vpnbilling message server wired to scaffold state.
func (s *ChainScaffold) BillingMsgServer() BillingMsgServer {
	if s == nil {
		return billingMsgServer{msgServer: billingmodule.NewMsgServer(nil)}
	}
	return billingMsgServer{msgServer: billingmodule.NewMsgServer(&s.BillingModule.Keeper)}
}

// RewardsMsgServer returns the phase-1 vpnrewards message server wired to scaffold state.
func (s *ChainScaffold) RewardsMsgServer() RewardsMsgServer {
	if s == nil {
		return rewardsMsgServer{msgServer: rewardsmodule.NewMsgServer(nil)}
	}
	return rewardsMsgServer{msgServer: rewardsmodule.NewMsgServer(&s.RewardsModule.Keeper)}
}

// SlashingMsgServer returns the phase-1 vpnslashing message server wired to scaffold state.
func (s *ChainScaffold) SlashingMsgServer() SlashingMsgServer {
	if s == nil {
		return slashingMsgServer{msgServer: slashingmodule.NewMsgServer(nil)}
	}
	return slashingMsgServer{msgServer: slashingmodule.NewMsgServer(&s.SlashingModule.Keeper)}
}

// SponsorMsgServer returns the phase-1 vpnsponsor message server wired to scaffold state.
func (s *ChainScaffold) SponsorMsgServer() SponsorMsgServer {
	if s == nil {
		return sponsorMsgServer{msgServer: sponsormodule.NewMsgServer(nil)}
	}
	return sponsorMsgServer{msgServer: sponsormodule.NewMsgServer(&s.SponsorModule.Keeper)}
}

// BillingQueryServer returns vpnbilling query operations wired to scaffold state.
func (s *ChainScaffold) BillingQueryServer() BillingQueryServer {
	if s == nil {
		return billingQueryServer{queryServer: billingmodule.NewQueryServer(nil)}
	}
	return billingQueryServer{queryServer: billingmodule.NewQueryServer(&s.BillingModule.Keeper)}
}

// RewardsQueryServer returns vpnrewards query operations wired to scaffold state.
func (s *ChainScaffold) RewardsQueryServer() RewardsQueryServer {
	if s == nil {
		return rewardsQueryServer{queryServer: rewardsmodule.NewQueryServer(nil)}
	}
	return rewardsQueryServer{queryServer: rewardsmodule.NewQueryServer(&s.RewardsModule.Keeper)}
}

// SlashingQueryServer returns vpnslashing query operations wired to scaffold state.
func (s *ChainScaffold) SlashingQueryServer() SlashingQueryServer {
	if s == nil {
		return slashingQueryServer{queryServer: slashingmodule.NewQueryServer(nil)}
	}
	return slashingQueryServer{queryServer: slashingmodule.NewQueryServer(&s.SlashingModule.Keeper)}
}

// SponsorQueryServer returns vpnsponsor query operations wired to scaffold state.
func (s *ChainScaffold) SponsorQueryServer() SponsorQueryServer {
	if s == nil {
		return sponsorQueryServer{queryServer: sponsormodule.NewQueryServer(nil)}
	}
	return sponsorQueryServer{queryServer: sponsormodule.NewQueryServer(&s.SponsorModule.Keeper)}
}
