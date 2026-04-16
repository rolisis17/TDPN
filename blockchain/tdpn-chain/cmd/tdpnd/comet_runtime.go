package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"
	cmtcfg "github.com/cometbft/cometbft/config"
	cmtcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	cmtnode "github.com/cometbft/cometbft/node"
	cmtp2p "github.com/cometbft/cometbft/p2p"
	cmtprivval "github.com/cometbft/cometbft/privval"
	cmtproxy "github.com/cometbft/cometbft/proxy"
	cmttypes "github.com/cometbft/cometbft/types"
)

const (
	defaultCometChainID  = "tdpn-comet-chain"
	defaultCometProxyApp = "tdpn-local"
	cometStatusQueryKey  = "status"
	cometModulesQueryKey = "modules"
	cometApplicationName = "tdpn-comet"
	cometApplicationVer  = "1"
)

type cometRuntime interface {
	Start() error
	Stop() error
	Quit() <-chan struct{}
}

type cometRuntimeConfig struct {
	homeDir   string
	moniker   string
	p2pListen string
	rpcListen string
	proxyApp  string
}

type cometRuntimeFactory func(context.Context, cometRuntimeConfig, chainScaffold) (cometRuntime, error)

type realCometRuntime struct {
	node cometRuntime
}

func (r *realCometRuntime) Start() error {
	return r.node.Start()
}

func (r *realCometRuntime) Stop() error {
	return r.node.Stop()
}

func (r *realCometRuntime) Quit() <-chan struct{} {
	return r.node.Quit()
}

func parseCometRuntimeConfig(homeDir, moniker, p2pListenAddr, rpcListenAddr, proxyApp string) (cometRuntimeConfig, bool, error) {
	cfg := cometRuntimeConfig{
		homeDir:   strings.TrimSpace(homeDir),
		moniker:   strings.TrimSpace(moniker),
		p2pListen: strings.TrimSpace(p2pListenAddr),
		rpcListen: strings.TrimSpace(rpcListenAddr),
		proxyApp:  strings.TrimSpace(proxyApp),
	}

	enabled := cfg.homeDir != "" || cfg.moniker != "" || cfg.p2pListen != "" || cfg.rpcListen != "" || cfg.proxyApp != ""
	if !enabled {
		return cometRuntimeConfig{}, false, nil
	}
	if cfg.homeDir == "" {
		return cometRuntimeConfig{}, false, errors.New("--comet-home is required when comet mode is enabled")
	}
	if cfg.moniker == "" {
		return cometRuntimeConfig{}, false, errors.New("--comet-moniker is required when comet mode is enabled")
	}
	if cfg.p2pListen == "" {
		return cometRuntimeConfig{}, false, errors.New("--comet-p2p-laddr is required when comet mode is enabled")
	}
	if cfg.rpcListen == "" {
		return cometRuntimeConfig{}, false, errors.New("--comet-rpc-laddr is required when comet mode is enabled")
	}
	if cfg.proxyApp == "" {
		cfg.proxyApp = defaultCometProxyApp
	}
	return cfg, true, nil
}

func validateCometRuntimeConfig(cfg cometRuntimeConfig) error {
	if strings.TrimSpace(cfg.homeDir) == "" {
		return errors.New("comet home is required")
	}
	if strings.TrimSpace(cfg.moniker) == "" {
		return errors.New("comet moniker is required")
	}
	if strings.TrimSpace(cfg.p2pListen) == "" {
		return errors.New("comet p2p listen address is required")
	}
	if strings.TrimSpace(cfg.rpcListen) == "" {
		return errors.New("comet rpc listen address is required")
	}
	return nil
}

func newDefaultCometRuntime(ctx context.Context, cfg cometRuntimeConfig, scaffold chainScaffold) (cometRuntime, error) {
	if err := validateCometRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if scaffold == nil {
		return nil, errors.New("chain scaffold is nil")
	}

	cmtcfg.EnsureRoot(cfg.homeDir)

	cometCfg := cmtcfg.DefaultConfig().SetRoot(cfg.homeDir)
	cometCfg.BaseConfig.Moniker = cfg.moniker
	cometCfg.BaseConfig.ProxyApp = cfg.proxyApp
	cometCfg.P2P.ListenAddress = cfg.p2pListen
	cometCfg.P2P.Seeds = ""
	cometCfg.P2P.PersistentPeers = ""
	cometCfg.P2P.PexReactor = false
	cometCfg.P2P.MaxNumInboundPeers = 0
	cometCfg.P2P.MaxNumOutboundPeers = 0
	cometCfg.P2P.AllowDuplicateIP = true
	cometCfg.RPC.ListenAddress = cfg.rpcListen

	nodeKeyPath := filepath.Join(cfg.homeDir, cmtcfg.DefaultConfigDir, cmtcfg.DefaultNodeKeyName)
	nodeKey, err := cmtp2p.LoadOrGenNodeKey(nodeKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load comet node key: %w", err)
	}

	privValKeyPath := filepath.Join(cfg.homeDir, cmtcfg.DefaultConfigDir, cmtcfg.DefaultPrivValKeyName)
	privValStatePath := filepath.Join(cfg.homeDir, cmtcfg.DefaultDataDir, cmtcfg.DefaultPrivValStateName)
	privVal := cmtprivval.LoadOrGenFilePV(privValKeyPath, privValStatePath)
	pubKey, err := privVal.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("load comet priv validator pubkey: %w", err)
	}

	genesisDoc, err := loadOrCreateCometGenesisDoc(cometCfg, cfg, pubKey, scaffold.ModuleNames())
	if err != nil {
		return nil, err
	}

	cometApp := newTDPNCometApplication(scaffold, cfg)
	clientCreator := cmtproxy.NewConnSyncLocalClientCreator(cometApp)
	genesisProvider := func() (*cmttypes.GenesisDoc, error) {
		return genesisDoc, nil
	}

	node, err := cmtnode.NewNodeWithContext(
		ctx,
		cometCfg,
		privVal,
		nodeKey,
		clientCreator,
		genesisProvider,
		cmtcfg.DefaultDBProvider,
		cmtnode.DefaultMetricsProvider(cometCfg.Instrumentation),
		log.NewNopLogger(),
	)
	if err != nil {
		return nil, fmt.Errorf("create comet node: %w", err)
	}

	return &realCometRuntime{node: node}, nil
}

func runCometMode(
	ctx context.Context,
	scaffold chainScaffold,
	cfg cometRuntimeConfig,
	newRuntime cometRuntimeFactory,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if newRuntime == nil {
		newRuntime = newDefaultCometRuntime
	}

	runtime, err := newRuntime(ctx, cfg, scaffold)
	if err != nil {
		return err
	}
	if err := runtime.Start(); err != nil {
		go func() {
			_ = runtime.Stop()
		}()
		return fmt.Errorf("start comet runtime: %w", err)
	}

	select {
	case <-ctx.Done():
		go func() {
			_ = runtime.Stop()
		}()
		select {
		case <-runtime.Quit():
			return nil
		case <-time.After(gracefulShutdownTimeout):
			return errors.New("timed out waiting for comet runtime shutdown")
		}
	case <-runtime.Quit():
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("comet runtime exited unexpectedly")
	}
}

func loadOrCreateCometGenesisDoc(
	cometCfg *cmtcfg.Config,
	cfg cometRuntimeConfig,
	pubKey cmtcrypto.PubKey,
	modules []string,
) (*cmttypes.GenesisDoc, error) {
	genesisPath := cometCfg.GenesisFile()
	if _, err := os.Stat(genesisPath); err == nil {
		doc, loadErr := cmttypes.GenesisDocFromFile(genesisPath)
		if loadErr != nil {
			return nil, fmt.Errorf("load comet genesis doc: %w", loadErr)
		}
		return doc, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat comet genesis doc: %w", err)
	}

	genesisDoc := &cmttypes.GenesisDoc{
		GenesisTime:     time.Now().UTC(),
		ChainID:         defaultCometChainID,
		InitialHeight:   1,
		ConsensusParams: cmttypes.DefaultConsensusParams(),
		Validators: []cmttypes.GenesisValidator{
			{
				Address: pubKey.Address(),
				PubKey:  pubKey,
				Power:   1,
				Name:    cfg.moniker,
			},
		},
	}
	genesisDoc.AppState = mustMarshalCometAppState(modules, cfg)
	if err := genesisDoc.ValidateAndComplete(); err != nil {
		return nil, fmt.Errorf("validate comet genesis doc: %w", err)
	}
	if err := genesisDoc.SaveAs(genesisPath); err != nil {
		return nil, fmt.Errorf("write comet genesis doc: %w", err)
	}
	return genesisDoc, nil
}

type tdpndCometApplication struct {
	abci.BaseApplication
	mu          sync.Mutex
	moniker     string
	homeDir     string
	proxyApp    string
	modules     []string
	lastHeight  int64
	lastAppHash []byte
}

func newTDPNCometApplication(scaffold chainScaffold, cfg cometRuntimeConfig) *tdpndCometApplication {
	modules := make([]string, 0)
	if scaffold != nil {
		modules = append(modules, scaffold.ModuleNames()...)
	}
	return &tdpndCometApplication{
		moniker:  cfg.moniker,
		homeDir:  cfg.homeDir,
		proxyApp: cfg.proxyApp,
		modules:  modules,
	}
}

func (a *tdpndCometApplication) Info(context.Context, *abci.RequestInfo) (*abci.ResponseInfo, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return &abci.ResponseInfo{
		Data:             cometApplicationName,
		Version:          cometApplicationVer,
		AppVersion:       1,
		LastBlockHeight:  a.lastHeight,
		LastBlockAppHash: append([]byte(nil), a.lastAppHash...),
	}, nil
}

func (a *tdpndCometApplication) Query(_ context.Context, req *abci.RequestQuery) (*abci.ResponseQuery, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := strings.TrimSpace(req.Path)
	if key == "" {
		key = cometStatusQueryKey
	}

	switch key {
	case cometStatusQueryKey:
		return a.cometStatusQuery(key)
	case cometModulesQueryKey:
		return a.cometModulesQuery(key)
	default:
		return a.cometStatusQuery(key)
	}
}

func (a *tdpndCometApplication) InitChain(_ context.Context, req *abci.RequestInitChain) (*abci.ResponseInitChain, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.lastHeight = 0
	a.lastAppHash = a.computeAppHash(0)
	return &abci.ResponseInitChain{
		ConsensusParams: req.GetConsensusParams(),
		AppHash:         append([]byte(nil), a.lastAppHash...),
	}, nil
}

func (a *tdpndCometApplication) FinalizeBlock(ctx context.Context, req *abci.RequestFinalizeBlock) (*abci.ResponseFinalizeBlock, error) {
	a.mu.Lock()
	a.lastHeight = req.Height
	a.mu.Unlock()

	return a.BaseApplication.FinalizeBlock(ctx, req)
}

func (a *tdpndCometApplication) Commit(context.Context, *abci.RequestCommit) (*abci.ResponseCommit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.lastAppHash = a.computeAppHash(a.lastHeight)
	return &abci.ResponseCommit{}, nil
}

func (a *tdpndCometApplication) cometStatusQuery(key string) (*abci.ResponseQuery, error) {
	payload := map[string]any{
		"mode":      cometApplicationName,
		"height":    a.lastHeight,
		"home":      a.homeDir,
		"moniker":   a.moniker,
		"proxy_app": a.proxyApp,
		"modules":   append([]string(nil), a.modules...),
		"app_hash":  fmt.Sprintf("%X", a.lastAppHash),
		"query_key": key,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal comet status query: %w", err)
	}
	return &abci.ResponseQuery{
		Code:   0,
		Key:    []byte(key),
		Value:  raw,
		Info:   "tdpnd comet status",
		Log:    "ok",
		Height: a.lastHeight,
	}, nil
}

func (a *tdpndCometApplication) cometModulesQuery(key string) (*abci.ResponseQuery, error) {
	payload := map[string]any{
		"modules":   append([]string(nil), a.modules...),
		"moniker":   a.moniker,
		"proxy_app": a.proxyApp,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal comet modules query: %w", err)
	}
	return &abci.ResponseQuery{
		Code:   0,
		Key:    []byte(key),
		Value:  raw,
		Info:   "tdpnd comet modules",
		Log:    "ok",
		Height: a.lastHeight,
	}, nil
}

func (a *tdpndCometApplication) computeAppHash(height int64) []byte {
	summary := fmt.Sprintf("%s|%s|%s|%d|%s", a.moniker, a.homeDir, a.proxyApp, height, strings.Join(a.modules, ","))
	sum := sha256.Sum256([]byte(summary))
	return sum[:]
}

func mustMarshalCometAppState(modules []string, cfg cometRuntimeConfig) []byte {
	payload := map[string]any{
		"mode":      cometApplicationName,
		"home":      cfg.homeDir,
		"moniker":   cfg.moniker,
		"proxy_app": cfg.proxyApp,
		"modules":   append([]string(nil), modules...),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return []byte("{}")
	}
	return raw
}
