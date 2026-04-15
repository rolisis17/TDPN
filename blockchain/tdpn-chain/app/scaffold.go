package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	billingkeeper "github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	billingmodule "github.com/tdpn/tdpn-chain/x/vpnbilling/module"
	governancekeeper "github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	rewardskeeper "github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	slashingkeeper "github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	sponsorkeeper "github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	validatorkeeper "github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
)

const (
	moduleNameBilling    = "vpnbilling"
	moduleNameRewards    = "vpnrewards"
	moduleNameSlashing   = "vpnslashing"
	moduleNameSponsor    = "vpnsponsor"
	moduleNameValidator  = "vpnvalidator"
	moduleNameGovernance = "vpngovernance"

	stateFileBilling    = "vpnbilling.json"
	stateFileRewards    = "vpnrewards.json"
	stateFileSlashing   = "vpnslashing.json"
	stateFileSponsor    = "vpnsponsor.json"
	stateFileValidator  = "vpnvalidator.json"
	stateFileGovernance = "vpngovernance.json"
)

// ChainScaffold wires the phase-6 module set for local runtime/testnet gates.
type ChainScaffold struct {
	BillingModule    billingmodule.AppModule
	RewardsModule    rewardsmodule.AppModule
	SlashingModule   slashingmodule.AppModule
	SponsorModule    sponsormodule.AppModule
	ValidatorModule  validatormodule.AppModule
	GovernanceModule governancemodule.AppModule
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
	validatorKeeper := validatorkeeper.NewKeeper()
	governanceKeeper := governancekeeper.NewKeeper()

	return &ChainScaffold{
		BillingModule:    billingmodule.NewAppModule(billingKeeper),
		RewardsModule:    rewardsmodule.NewAppModule(rewardsKeeper),
		SlashingModule:   slashingmodule.NewAppModule(slashingKeeper),
		SponsorModule:    sponsormodule.NewAppModule(sponsorKeeper),
		ValidatorModule:  validatormodule.NewAppModule(validatorKeeper),
		GovernanceModule: governancemodule.NewAppModule(governanceKeeper),
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

	billingStore, err := billingkeeper.NewFileStore(filepath.Join(stateDir, stateFileBilling))
	if err != nil {
		return fmt.Errorf("vpnbilling file store: %w", err)
	}
	rewardsStore, err := rewardskeeper.NewFileStore(filepath.Join(stateDir, stateFileRewards))
	if err != nil {
		return fmt.Errorf("vpnrewards file store: %w", err)
	}
	slashingStore, err := slashingkeeper.NewFileStore(filepath.Join(stateDir, stateFileSlashing))
	if err != nil {
		return fmt.Errorf("vpnslashing file store: %w", err)
	}
	sponsorStore, err := sponsorkeeper.NewFileStore(filepath.Join(stateDir, stateFileSponsor))
	if err != nil {
		return fmt.Errorf("vpnsponsor file store: %w", err)
	}
	validatorStatePath := filepath.Join(stateDir, stateFileValidator)
	if err := ensureScaffoldStateFile(validatorStatePath); err != nil {
		return fmt.Errorf("vpnvalidator file store: %w", err)
	}
	governanceStatePath := filepath.Join(stateDir, stateFileGovernance)
	if err := ensureScaffoldStateFile(governanceStatePath); err != nil {
		return fmt.Errorf("vpngovernance file store: %w", err)
	}
	validatorStore, err := validatorkeeper.NewFileStore(validatorStatePath)
	if err != nil {
		return fmt.Errorf("vpnvalidator file store: %w", err)
	}
	governanceStore, err := governancekeeper.NewFileStore(governanceStatePath)
	if err != nil {
		return fmt.Errorf("vpngovernance file store: %w", err)
	}

	s.BillingModule = billingmodule.NewAppModule(billingkeeper.NewKeeperWithStore(billingStore))
	s.RewardsModule = rewardsmodule.NewAppModule(rewardskeeper.NewKeeperWithStore(rewardsStore))
	s.SlashingModule = slashingmodule.NewAppModule(slashingkeeper.NewKeeperWithStore(slashingStore))
	s.SponsorModule = sponsormodule.NewAppModule(sponsorkeeper.NewKeeperWithStore(sponsorStore))
	s.ValidatorModule = validatormodule.NewAppModule(validatorkeeper.NewKeeperWithStore(validatorStore))
	s.GovernanceModule = governancemodule.NewAppModule(governancekeeper.NewKeeperWithStore(governanceStore))
	return nil
}

// ModuleNames returns the module identifiers expected by future app wiring.
func (s *ChainScaffold) ModuleNames() []string {
	if s == nil {
		return nil
	}
	return []string{
		moduleNameOrDefault(s.BillingModule.Name(), moduleNameBilling),
		moduleNameOrDefault(s.RewardsModule.Name(), moduleNameRewards),
		moduleNameOrDefault(s.SlashingModule.Name(), moduleNameSlashing),
		moduleNameOrDefault(s.SponsorModule.Name(), moduleNameSponsor),
		moduleNameOrDefault(s.ValidatorModule.Name(), moduleNameValidator),
		moduleNameOrDefault(s.GovernanceModule.Name(), moduleNameGovernance),
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

// ValidatorMsgServer returns vpnvalidator message operations wired to scaffold state.
func (s *ChainScaffold) ValidatorMsgServer() ValidatorMsgServer {
	if s == nil {
		return validatorMsgServer{msgServer: validatormodule.NewMsgServer(nil)}
	}
	return validatorMsgServer{msgServer: validatormodule.NewMsgServer(&s.ValidatorModule.Keeper)}
}

// GovernanceMsgServer returns vpngovernance message operations wired to scaffold state.
func (s *ChainScaffold) GovernanceMsgServer() GovernanceMsgServer {
	if s == nil {
		return governanceMsgServer{msgServer: governancemodule.NewMsgServer(nil)}
	}
	return governanceMsgServer{msgServer: governancemodule.NewMsgServer(&s.GovernanceModule.Keeper)}
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

// ValidatorQueryServer returns vpnvalidator query operations wired to scaffold state.
func (s *ChainScaffold) ValidatorQueryServer() ValidatorQueryServer {
	if s == nil {
		return validatorQueryServer{queryServer: validatormodule.NewQueryServer(nil)}
	}
	return validatorQueryServer{queryServer: validatormodule.NewQueryServer(&s.ValidatorModule.Keeper)}
}

// GovernanceQueryServer returns vpngovernance query operations wired to scaffold state.
func (s *ChainScaffold) GovernanceQueryServer() GovernanceQueryServer {
	if s == nil {
		return governanceQueryServer{queryServer: governancemodule.NewQueryServer(nil)}
	}
	return governanceQueryServer{queryServer: governancemodule.NewQueryServer(&s.GovernanceModule.Keeper)}
}

func moduleNameOrDefault(value, fallback string) string {
	name := strings.TrimSpace(value)
	if name == "" {
		return fallback
	}
	return name
}

func ensureScaffoldStateFile(path string) error {
	info, err := os.Stat(path)
	if err == nil {
		if info.IsDir() {
			return fmt.Errorf("%s resolves to a directory", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, []byte("{}\n"), 0o600)
}
