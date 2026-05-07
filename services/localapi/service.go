package localapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	urlpkg "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"privacynode/pkg/settlement"
)

const (
	defaultAddr             = "127.0.0.1:8095"
	defaultScriptPath       = "./scripts/easy_node.sh"
	defaultCommandTimeout   = 120 * time.Second
	defaultMaxCommands      = 4
	maxAllowedCommands      = 64
	maxCommandOutputBytes   = 1 << 20
	defaultDiscoveryWaitSec = 20
	defaultReadyTimeoutSec  = 35
	defaultPathProfile      = "2hop"
	defaultVPNInterface     = "wgvpn0"
	maxRequestBodyBytes     = 1 << 20
	serverReadTimeout       = 15 * time.Second
	serverIdleTimeout       = 60 * time.Second
	serverWriteSlack        = 15 * time.Second
	hostResolveTimeout      = 2 * time.Second
	allowUnauthLoopbackEnv  = "LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK"
	allowInsecureHTTPEnv    = "LOCAL_CONTROL_API_ALLOW_INSECURE_REMOTE_HTTP"
	authTokenEnv            = "LOCAL_CONTROL_API_AUTH_TOKEN"
	maxCommandsEnv          = "LOCAL_CONTROL_API_MAX_CONCURRENT_COMMANDS"
	maxInviteKeyLen         = 512
	maxGitRemoteNameLen     = 64
	maxGitBranchNameLen     = 255
	gpmStaleLaunchStatusTTL = 10 * time.Second
	minRemoteAuthTokenLen   = 32
)

var vpnInterfaceNamePattern = regexp.MustCompile(`^wg[a-zA-Z0-9_.-]{0,13}$`)
var gitRemoteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`)
var errCommandConcurrencySaturated = errors.New("local api command concurrency limit reached")
var errLifecycleCommandRejected = errors.New("lifecycle command rejected")
var weakRemoteAuthTokens = map[string]struct{}{
	"token":         {},
	"default-token": {},
	"secret-token":  {},
	"change-me":     {},
}
var evalSymlinksPath = filepath.EvalSymlinks
var lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type Service struct {
	addr                                                  string
	scriptPath                                            string
	commandRunner                                         string
	commandTimeout                                        time.Duration
	maxConcurrentCmds                                     int
	commandSlots                                          chan struct{}
	allowUpdate                                           bool
	allowUnauthLoopback                                   bool
	allowInsecureHTTP                                     bool
	authToken                                             string
	serviceStatus                                         string
	serviceStart                                          string
	serviceStop                                           string
	serviceRestart                                        string
	gpmConnectRequireSession                              bool
	gpmAllowLegacyConnectOverride                         bool
	gpmAllowLegacyServiceMutations                        bool
	gpmAllowLegacyServiceMutationsSource                  string
	gpmAdminRoutesEnabled                                 bool
	gpmAdminRoutesSource                                  string
	gpmLegacyConnectRequireTrustedManifestBootstrap       bool
	gpmLegacyConnectRequireTrustedManifestBootstrapSource string
	gpmConnectPolicyMode                                  string
	gpmConnectPolicySource                                string
	gpmManifestTrustPolicyMode                            string
	gpmManifestTrustPolicySource                          string
	gpmManifestRequireHTTPS                               bool
	gpmManifestRequireHTTPSSource                         string
	gpmManifestRequireSignature                           bool
	gpmManifestRequireSigSource                           string
	gpmAuthVerifyPolicyMode                               string
	gpmAuthVerifyPolicySource                             string
	gpmMainDomain                                         string
	gpmManifestURL                                        string
	gpmManifestCache                                      string
	gpmManifestMaxAge                                     time.Duration
	gpmManifestRemoteRefreshIntvl                         time.Duration
	gpmManifestRemoteRefreshSrc                           string
	gpmManifestRefreshFailureMaxCacheAge                  time.Duration
	gpmManifestRefreshFailureMaxCacheAgeSrc               string
	gpmManifestHMACKey                                    string
	gpmManifestHMACKeySource                              string
	gpmManifestEd25519PublicKey                           string
	gpmManifestEd25519PublicKeySource                     string
	gpmRoleDefault                                        string
	gpmAdminWalletAllowlist                               map[string]struct{}
	gpmAdminWalletAllowlistSource                         string
	gpmApprovalToken                                      string
	gpmOperatorApprovalRequireSession                     bool
	gpmOperatorApprovalRequireSessionSource               string
	gpmAuthVerifyCommand                                  string
	gpmAuthVerifyRequireCommand                           bool
	gpmAuthVerifyRequireCmdSource                         string
	gpmAuthVerifyRequireMetadata                          bool
	gpmAuthVerifyRequireWalletExt                         bool
	gpmAuthVerifyRequireCryptoProof                       bool
	gpmAuthVerifyMetadataSource                           string
	gpmAuthVerifyWalletExtSource                          string
	gpmAuthVerifyCryptoSource                             string
	gpmAuthExpectedChainID                                string
	gpmAuthExpectedChainIDSource                          string
	gpmAuthExpectedWalletHRP                              string
	gpmAuthExpectedWalletHRPSource                        string
	gpmLegacyEnvAliasesActive                             []string
	gpmLegacyEnvAliasWarnings                             []string
	gpmAuthSignatureVerifier                              gpmAuthSignatureVerifier
	gpmStateStorePath                                     string
	gpmStateStoreLoadFailed                               bool
	gpmStateStoreLoadFailure                              string
	gpmAuditLogPath                                       string
	gpmGapScanSummaryPath                                 string
	gpmSettlement                                         settlement.Service
	gpmSettlementBackend                                  string
	gpmSettlementBackendSource                            string
	gpmSettlementChainRequired                            bool
	gpmSettlementChainRequiredSource                      string
	gpmSettlementChainBacked                              bool
	gpmSettlementAdapterConfigured                        bool
	gpmSettlementAdapterConfigError                       string
	gpmSettlementCosmosEndpointConfigured                 bool
	gpmSettlementCosmosEndpointSource                     string
	gpmSettlementCosmosSubmitMode                         string
	gpmSettlementTrustedBridgeFinality                    bool
	gpmSettlementClose                                    func()
	gpmState                                              *gpmRuntimeState
	lastConnectInterfaceMu                                sync.Mutex
	lastConnectInterface                                  string
}

type gpmSettlementWiring struct {
	service                  settlement.Service
	backend                  string
	backendSource            string
	chainRequired            bool
	chainRequiredSource      string
	chainBacked              bool
	adapterConfigured        bool
	adapterConfigError       string
	cosmosEndpointConfigured bool
	cosmosEndpointSource     string
	cosmosSubmitMode         string
	trustedBridgeFinality    bool
	close                    func()
}

type boundedOutputBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

type connectRequest struct {
	BootstrapDirectory        string `json:"bootstrap_directory"`
	InviteKey                 string `json:"invite_key"`
	SessionToken              string `json:"session_token,omitempty"`
	SessionBootstrapDirectory string `json:"session_bootstrap_directory,omitempty"`
	ReservationID             string `json:"reservation_id,omitempty"`
	ReservationSessionID      string `json:"reservation_session_id,omitempty"`
	UsageSessionID            string `json:"usage_session_id,omitempty"`
	VPNSessionID              string `json:"vpn_session_id,omitempty"`
	PathProfile               string `json:"path_profile,omitempty"`
	PolicyProfile             string `json:"policy_profile,omitempty"`
	Interface                 string `json:"interface,omitempty"`
	DiscoveryWaitSec          int    `json:"discovery_wait_sec,omitempty"`
	ReadyTimeoutSec           int    `json:"ready_timeout_sec,omitempty"`
	RunPreflight              *bool  `json:"run_preflight,omitempty"`
	ProdProfile               *bool  `json:"prod_profile,omitempty"`
	InstallRoute              *bool  `json:"install_route,omitempty"`
}

type disconnectRequest struct {
	SessionToken string `json:"session_token,omitempty"`
}

type connectDefaults struct {
	pathProfile   string
	interfaceName string
	runPreflight  bool
	prodMode      string
}

type resolvedConnectOptions struct {
	profile           string
	interfaceName     string
	discoveryWaitSec  int
	readyTimeoutSec   int
	runPreflight      bool
	prodProfile       bool
	installRoute      bool
	installRouteIsSet bool
}

type connectPolicy struct {
	minOperators       int
	operatorFloorCheck int
	operatorMin        int
	issuerQuorumCheck  int
	issuerMin          int
	betaProfile        int
	prodFlag           int
	installRoute       bool
}

type setProfileRequest struct {
	PathProfile  string `json:"path_profile"`
	SessionToken string `json:"session_token,omitempty"`
}

type updateRequest struct {
	Remote       string `json:"remote,omitempty"`
	Branch       string `json:"branch,omitempty"`
	AllowDirty   *bool  `json:"allow_dirty,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
}

func New() *Service {
	addr := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_ADDR"))
	if addr == "" {
		addr = defaultAddr
	}
	scriptPath, scriptErr := resolveControlScriptPath(strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SCRIPT")))
	if scriptErr != nil {
		log.Printf("local control api script disabled: %v", scriptErr)
	}
	commandRunner := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_RUNNER"))
	commandTimeout := defaultCommandTimeout
	if raw := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 5 {
			commandTimeout = time.Duration(v) * time.Second
		}
	}
	maxConcurrentCmds := defaultMaxCommands
	if raw := strings.TrimSpace(os.Getenv(maxCommandsEnv)); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxConcurrentCmds = v
		}
	}
	if maxConcurrentCmds > maxAllowedCommands {
		maxConcurrentCmds = maxAllowedCommands
	}
	allowUpdate := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_ALLOW_UPDATE")) == "1"
	allowUnauthLoopback := parseBoolWithDefault(os.Getenv(allowUnauthLoopbackEnv), false)
	allowInsecureHTTP := parseBoolWithDefault(os.Getenv(allowInsecureHTTPEnv), false)
	authToken := strings.TrimSpace(os.Getenv(authTokenEnv))
	serviceStatus := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND"))
	serviceStart := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_START_COMMAND"))
	serviceStop := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_STOP_COMMAND"))
	serviceRestart := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND"))
	legacyEnvAliasSeen := map[string]struct{}{}
	legacyEnvAliasesActive := make([]string, 0, 8)
	legacyEnvAliasWarnings := make([]string, 0, 8)
	noteLegacyAlias := func(primaryKey string, sourceKey string) {
		if !strings.HasPrefix(sourceKey, "TDPN_") {
			return
		}
		if _, exists := legacyEnvAliasSeen[sourceKey]; exists {
			return
		}
		legacyEnvAliasSeen[sourceKey] = struct{}{}
		legacyEnvAliasesActive = append(legacyEnvAliasesActive, sourceKey)
		legacyEnvAliasWarnings = append(
			legacyEnvAliasWarnings,
			fmt.Sprintf("%s is deprecated; migrate to %s", sourceKey, primaryKey),
		)
	}
	gpmMainDomainRaw, gpmMainDomainSource, gpmMainDomainSet := preferredEnvValueWithSource(
		"GPM_MAIN_DOMAIN",
		"TDPN_MAIN_DOMAIN",
	)
	noteLegacyAlias("GPM_MAIN_DOMAIN", gpmMainDomainSource)
	gpmMainDomain := gpmMainDomainRaw
	if !gpmMainDomainSet {
		gpmMainDomain = "https://bootstrap.globalprivatemesh.invalid"
	}
	gpmManifestURLRaw, gpmManifestURLSource, gpmManifestURLSet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_URL",
		"TDPN_BOOTSTRAP_MANIFEST_URL",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_URL", gpmManifestURLSource)
	gpmManifestURL := gpmManifestURLRaw
	if !gpmManifestURLSet {
		gpmManifestURL = ""
	}
	if gpmManifestURL == "" {
		gpmManifestURL = strings.TrimRight(gpmMainDomain, "/") + "/v1/bootstrap/manifest"
	}
	gpmManifestCacheRaw, gpmManifestCacheSource, gpmManifestCacheSet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_CACHE_PATH",
		"TDPN_BOOTSTRAP_MANIFEST_CACHE_PATH",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_CACHE_PATH", gpmManifestCacheSource)
	gpmManifestCache := gpmManifestCacheRaw
	if !gpmManifestCacheSet {
		gpmManifestCache = ".easy-node-logs/gpm_bootstrap_manifest_cache.json"
	}
	gpmManifestMaxAgeSec := 24 * 60 * 60
	if raw, source, set := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_CACHE_MAX_AGE_SEC",
		"TDPN_BOOTSTRAP_MANIFEST_CACHE_MAX_AGE_SEC",
	); set && raw != "" {
		noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_CACHE_MAX_AGE_SEC", source)
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			gpmManifestMaxAgeSec = parsed
		}
	}
	gpmManifestRemoteRefreshIntervalSec := 5 * 60
	gpmManifestRemoteRefreshSource := "default"
	if raw, source, set := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC",
		"TDPN_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC",
	); set && raw != "" {
		noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_REMOTE_REFRESH_INTERVAL_SEC", source)
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			gpmManifestRemoteRefreshIntervalSec = parsed
			gpmManifestRemoteRefreshSource = source
		}
	}
	gpmManifestRefreshFailureMaxCacheAgeSec := 0
	gpmManifestRefreshFailureMaxCacheAgeSource := "default"
	gpmManifestRefreshFailureMaxCacheAgeSet := false
	if raw, source, set := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC",
		"TDPN_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC",
	); set && raw != "" {
		gpmManifestRefreshFailureMaxCacheAgeSet = true
		noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_REFRESH_FAILURE_MAX_CACHE_AGE_SEC", source)
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			gpmManifestRefreshFailureMaxCacheAgeSec = parsed
			gpmManifestRefreshFailureMaxCacheAgeSource = source
		} else {
			gpmManifestRefreshFailureMaxCacheAgeSource = source + "-invalid-env"
		}
	}
	gpmRoleDefaultRaw, gpmRoleDefaultSource, gpmRoleDefaultSet := preferredEnvValueWithSource(
		"GPM_DEFAULT_ROLE",
		"TDPN_DEFAULT_ROLE",
	)
	noteLegacyAlias("GPM_DEFAULT_ROLE", gpmRoleDefaultSource)
	gpmRoleDefault := strings.ToLower(gpmRoleDefaultRaw)
	if !gpmRoleDefaultSet {
		gpmRoleDefault = "client"
	}
	if gpmRoleDefault != "client" {
		gpmRoleDefault = "client"
	}
	gpmAdminWalletAllowlistRaw, gpmAdminWalletAllowlistSource, gpmAdminWalletAllowlistSet := preferredEnvValueWithSource(
		"GPM_ADMIN_WALLET_ALLOWLIST",
		"TDPN_ADMIN_WALLET_ALLOWLIST",
	)
	noteLegacyAlias("GPM_ADMIN_WALLET_ALLOWLIST", gpmAdminWalletAllowlistSource)
	if !gpmAdminWalletAllowlistSet {
		gpmAdminWalletAllowlistSource = "default"
	}
	gpmAdminWalletAllowlist := normalizeGPMAdminWalletAllowlist(gpmAdminWalletAllowlistRaw)
	gpmManifestHMACKeyRaw, gpmManifestHMACKeySource, gpmManifestHMACKeySet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_HMAC_KEY",
		"TDPN_BOOTSTRAP_MANIFEST_HMAC_KEY",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_HMAC_KEY", gpmManifestHMACKeySource)
	gpmManifestHMACKey := gpmManifestHMACKeyRaw
	if !gpmManifestHMACKeySet {
		gpmManifestHMACKey = ""
	}
	gpmManifestEd25519PublicKeyRaw, gpmManifestEd25519PublicKeySource, gpmManifestEd25519PublicKeySet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_ED25519_PUBLIC_KEY",
		"TDPN_BOOTSTRAP_MANIFEST_ED25519_PUBLIC_KEY",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_ED25519_PUBLIC_KEY", gpmManifestEd25519PublicKeySource)
	gpmManifestEd25519PublicKey := gpmManifestEd25519PublicKeyRaw
	if !gpmManifestEd25519PublicKeySet {
		gpmManifestEd25519PublicKey = ""
	}
	gpmManifestRequireHTTPSRaw, gpmManifestRequireHTTPSSource, gpmManifestRequireHTTPSSet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS",
		"TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", gpmManifestRequireHTTPSSource)
	gpmManifestRequireHTTPS, gpmManifestRequireHTTPSValid := parseBool(gpmManifestRequireHTTPSRaw)
	gpmManifestRequireSignatureRaw, gpmManifestRequireSigSource, gpmManifestRequireSignatureSet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE",
		"TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", gpmManifestRequireSigSource)
	gpmManifestRequireSignature, gpmManifestRequireSignatureValid := parseBool(gpmManifestRequireSignatureRaw)
	gpmApprovalAdminToken, gpmApprovalAdminTokenSource, gpmApprovalAdminTokenSet := preferredEnvValueWithSource(
		"GPM_APPROVAL_ADMIN_TOKEN",
		"TDPN_APPROVAL_ADMIN_TOKEN",
	)
	noteLegacyAlias("GPM_APPROVAL_ADMIN_TOKEN", gpmApprovalAdminTokenSource)
	gpmOperatorApprovalToken, gpmOperatorApprovalTokenSource, gpmOperatorApprovalTokenSet := preferredEnvValueWithSource(
		"GPM_OPERATOR_APPROVAL_TOKEN",
		"TDPN_OPERATOR_APPROVAL_TOKEN",
	)
	noteLegacyAlias("GPM_OPERATOR_APPROVAL_TOKEN", gpmOperatorApprovalTokenSource)
	gpmApprovalToken := ""
	if gpmApprovalAdminTokenSet {
		gpmApprovalToken = gpmApprovalAdminToken
	} else if gpmOperatorApprovalTokenSet {
		gpmApprovalToken = gpmOperatorApprovalToken
	}
	gpmOperatorApprovalRequireSessionRaw, gpmOperatorApprovalRequireSessionSource, gpmOperatorApprovalRequireSessionSet := preferredEnvValueWithSource(
		"GPM_OPERATOR_APPROVAL_REQUIRE_SESSION",
		"TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION",
	)
	noteLegacyAlias("GPM_OPERATOR_APPROVAL_REQUIRE_SESSION", gpmOperatorApprovalRequireSessionSource)
	gpmOperatorApprovalRequireSession, gpmOperatorApprovalRequireSessionValid := parseBool(gpmOperatorApprovalRequireSessionRaw)
	gpmAuthVerifyCommandRaw, gpmAuthVerifyCommandSource, gpmAuthVerifyCommandSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_COMMAND",
		"TDPN_AUTH_VERIFY_COMMAND",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_COMMAND", gpmAuthVerifyCommandSource)
	gpmAuthVerifyCommand := gpmAuthVerifyCommandRaw
	if !gpmAuthVerifyCommandSet {
		gpmAuthVerifyCommand = ""
	}
	gpmAuthVerifyRequireCommandRaw, gpmAuthVerifyRequireCommandSource, gpmAuthVerifyRequireCommandSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_REQUIRE_COMMAND",
		"TDPN_AUTH_VERIFY_REQUIRE_COMMAND",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_REQUIRE_COMMAND", gpmAuthVerifyRequireCommandSource)
	gpmAuthVerifyRequireCommand, gpmAuthVerifyRequireCommandValid := parseBool(gpmAuthVerifyRequireCommandRaw)
	if !gpmAuthVerifyRequireCommandSet {
		gpmAuthVerifyRequireCommand = false
		gpmAuthVerifyRequireCommandSource = "default"
	}
	gpmAuthVerifyRequireMetadataRaw, gpmAuthVerifyMetadataSource, gpmAuthVerifyRequireMetadataSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_REQUIRE_METADATA",
		"TDPN_AUTH_VERIFY_REQUIRE_METADATA",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_REQUIRE_METADATA", gpmAuthVerifyMetadataSource)
	gpmAuthVerifyRequireMetadata, gpmAuthVerifyRequireMetadataValid := parseBool(gpmAuthVerifyRequireMetadataRaw)
	gpmAuthVerifyRequireWalletExtRaw, gpmAuthVerifyWalletExtSource, gpmAuthVerifyRequireWalletExtSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE",
		"TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", gpmAuthVerifyWalletExtSource)
	gpmAuthVerifyRequireWalletExt, gpmAuthVerifyRequireWalletExtValid := parseBool(gpmAuthVerifyRequireWalletExtRaw)
	gpmAuthVerifyRequireCryptoRaw, gpmAuthVerifyCryptoSource, gpmAuthVerifyRequireCryptoSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF",
		"TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF", gpmAuthVerifyCryptoSource)
	gpmAuthVerifyRequireCryptoProof, gpmAuthVerifyRequireCryptoValid := parseBool(gpmAuthVerifyRequireCryptoRaw)
	gpmAuthExpectedChainIDRaw, gpmAuthExpectedChainIDSource, gpmAuthExpectedChainIDSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_EXPECTED_CHAIN_ID",
		"TDPN_AUTH_VERIFY_EXPECTED_CHAIN_ID",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_EXPECTED_CHAIN_ID", gpmAuthExpectedChainIDSource)
	gpmAuthExpectedChainID := strings.TrimSpace(gpmAuthExpectedChainIDRaw)
	if !gpmAuthExpectedChainIDSet {
		gpmAuthExpectedChainIDSource = "default"
	}
	gpmAuthExpectedWalletHRPRaw, gpmAuthExpectedWalletHRPSource, gpmAuthExpectedWalletHRPSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_EXPECTED_WALLET_HRP",
		"TDPN_AUTH_VERIFY_EXPECTED_WALLET_HRP",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_EXPECTED_WALLET_HRP", gpmAuthExpectedWalletHRPSource)
	gpmAuthExpectedWalletHRP := strings.ToLower(strings.TrimSpace(gpmAuthExpectedWalletHRPRaw))
	if !gpmAuthExpectedWalletHRPSet {
		gpmAuthExpectedWalletHRPSource = "default"
	}
	gpmConnectPolicyRaw, gpmConnectPolicySource, gpmConnectPolicySet := preferredEnvValueWithSource(
		"GPM_PRODUCTION_MODE",
		"TDPN_PRODUCTION_MODE",
	)
	noteLegacyAlias("GPM_PRODUCTION_MODE", gpmConnectPolicySource)
	gpmConnectPolicyProduction, gpmConnectPolicyValid := parseBool(gpmConnectPolicyRaw)
	if gpmConnectPolicySet && !gpmConnectPolicyValid {
		gpmConnectPolicyProduction = true
		gpmConnectPolicySource = "production-invalid-env-fail-closed"
	}
	gpmConnectPolicyMode := "default"
	if gpmConnectPolicyProduction {
		gpmConnectPolicyMode = "production"
	}
	if !gpmConnectPolicySet {
		gpmConnectPolicySource = "default"
	}
	gpmManifestTrustPolicyMode := "default"
	if gpmConnectPolicyProduction {
		gpmManifestTrustPolicyMode = "production"
	}
	gpmManifestTrustPolicySource := "default"
	if gpmConnectPolicySet {
		gpmManifestTrustPolicySource = gpmConnectPolicySource
	}
	gpmAuthVerifyPolicyMode := "default"
	if gpmConnectPolicyProduction {
		gpmAuthVerifyPolicyMode = "production"
	}
	gpmAuthVerifyPolicySource := "default"
	if gpmConnectPolicySet {
		gpmAuthVerifyPolicySource = gpmConnectPolicySource
	}
	if gpmConnectPolicyProduction {
		const productionManifestRefreshFailureMaxCacheAgeSec = 15 * 60
		if !gpmManifestRefreshFailureMaxCacheAgeSet {
			gpmManifestRefreshFailureMaxCacheAgeSec = productionManifestRefreshFailureMaxCacheAgeSec
			gpmManifestRefreshFailureMaxCacheAgeSource = "production-default"
		} else if strings.HasSuffix(gpmManifestRefreshFailureMaxCacheAgeSource, "-invalid-env") {
			gpmManifestRefreshFailureMaxCacheAgeSec = productionManifestRefreshFailureMaxCacheAgeSec
			gpmManifestRefreshFailureMaxCacheAgeSource = "production-invalid-env-fail-closed"
		} else if gpmManifestRefreshFailureMaxCacheAgeSec <= 0 {
			gpmManifestRefreshFailureMaxCacheAgeSec = productionManifestRefreshFailureMaxCacheAgeSec
			gpmManifestRefreshFailureMaxCacheAgeSource = "production-refresh-failure-cache-fail-closed"
		}
	}
	if !gpmManifestRequireHTTPSSet {
		gpmManifestRequireHTTPSSource = "default"
		if gpmConnectPolicyProduction {
			gpmManifestRequireHTTPS = true
			gpmManifestRequireHTTPSSource = "production-default"
		}
	} else if !gpmManifestRequireHTTPSValid && gpmConnectPolicyProduction {
		gpmManifestRequireHTTPS = true
		gpmManifestRequireHTTPSSource = "production-invalid-env-fail-closed"
	} else if gpmConnectPolicyProduction && !gpmManifestRequireHTTPS {
		gpmManifestRequireHTTPS = true
		gpmManifestRequireHTTPSSource = "production-enforced"
	}
	if !gpmManifestRequireSignatureSet {
		gpmManifestRequireSigSource = "default"
		if gpmConnectPolicyProduction {
			gpmManifestRequireSignature = true
			gpmManifestRequireSigSource = "production-default"
		}
	} else if !gpmManifestRequireSignatureValid && gpmConnectPolicyProduction {
		gpmManifestRequireSignature = true
		gpmManifestRequireSigSource = "production-invalid-env-fail-closed"
	} else if gpmConnectPolicyProduction && !gpmManifestRequireSignature {
		gpmManifestRequireSignature = true
		gpmManifestRequireSigSource = "production-enforced"
	}
	if !gpmAuthVerifyRequireCommandSet && gpmConnectPolicyProduction {
		gpmAuthVerifyRequireCommand = true
		gpmAuthVerifyRequireCommandSource = "production-default"
	} else if gpmAuthVerifyRequireCommandSet && !gpmAuthVerifyRequireCommandValid && gpmConnectPolicyProduction {
		gpmAuthVerifyRequireCommand = true
		gpmAuthVerifyRequireCommandSource = "production-invalid-env-fail-closed"
	}
	if !gpmAuthVerifyRequireMetadataSet {
		gpmAuthVerifyMetadataSource = "default"
		if gpmConnectPolicyProduction {
			gpmAuthVerifyRequireMetadata = true
			gpmAuthVerifyMetadataSource = "production-default"
		}
	} else if !gpmAuthVerifyRequireMetadataValid && gpmConnectPolicyProduction {
		gpmAuthVerifyRequireMetadata = true
		gpmAuthVerifyMetadataSource = "production-invalid-env-fail-closed"
	}
	if !gpmAuthVerifyRequireWalletExtSet {
		gpmAuthVerifyWalletExtSource = "default"
		if gpmConnectPolicyProduction {
			gpmAuthVerifyRequireWalletExt = true
			gpmAuthVerifyWalletExtSource = "production-default"
		}
	} else if !gpmAuthVerifyRequireWalletExtValid && gpmConnectPolicyProduction {
		gpmAuthVerifyRequireWalletExt = true
		gpmAuthVerifyWalletExtSource = "production-invalid-env-fail-closed"
	}
	if !gpmAuthVerifyRequireCryptoSet {
		gpmAuthVerifyCryptoSource = "default"
		if gpmConnectPolicyProduction {
			gpmAuthVerifyRequireCryptoProof = true
			gpmAuthVerifyCryptoSource = "production-default"
		}
	} else if !gpmAuthVerifyRequireCryptoValid && gpmConnectPolicyProduction {
		gpmAuthVerifyRequireCryptoProof = true
		gpmAuthVerifyCryptoSource = "production-invalid-env-fail-closed"
	}
	gpmConnectRequireSessionRaw, gpmConnectRequireSessionSource, gpmConnectRequireSessionSet := preferredEnvValueWithSource(
		"GPM_CONNECT_REQUIRE_SESSION",
		"TDPN_CONNECT_REQUIRE_SESSION",
	)
	noteLegacyAlias("GPM_CONNECT_REQUIRE_SESSION", gpmConnectRequireSessionSource)
	gpmConnectRequireSession, gpmConnectRequireSessionValid := parseBool(gpmConnectRequireSessionRaw)
	if !gpmConnectRequireSessionSet && gpmConnectPolicyProduction {
		gpmConnectRequireSession = true
	} else if gpmConnectRequireSessionSet && !gpmConnectRequireSessionValid && gpmConnectPolicyProduction {
		gpmConnectRequireSession = true
	} else if gpmConnectPolicyProduction {
		gpmConnectRequireSession = true
	}
	if !gpmOperatorApprovalRequireSessionSet {
		gpmOperatorApprovalRequireSessionSource = "default"
		if gpmConnectPolicyProduction {
			gpmOperatorApprovalRequireSession = true
			gpmOperatorApprovalRequireSessionSource = "production-default"
		}
	} else if !gpmOperatorApprovalRequireSessionValid && gpmConnectPolicyProduction {
		gpmOperatorApprovalRequireSession = true
		gpmOperatorApprovalRequireSessionSource = "production-invalid-env-fail-closed"
	}
	gpmAllowLegacyConnectOverrideRaw, gpmAllowLegacyConnectOverrideSource, gpmAllowLegacyConnectOverrideSet := preferredEnvValueWithSource(
		"GPM_ALLOW_LEGACY_CONNECT_OVERRIDE",
		"TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE",
	)
	noteLegacyAlias("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", gpmAllowLegacyConnectOverrideSource)
	gpmAllowLegacyConnectOverride, gpmAllowLegacyConnectOverrideValid := parseBool(gpmAllowLegacyConnectOverrideRaw)
	if !gpmAllowLegacyConnectOverrideSet && gpmConnectPolicyProduction {
		gpmAllowLegacyConnectOverride = false
	} else if gpmAllowLegacyConnectOverrideSet && !gpmAllowLegacyConnectOverrideValid && gpmConnectPolicyProduction {
		gpmAllowLegacyConnectOverride = false
	} else if gpmConnectPolicyProduction {
		gpmAllowLegacyConnectOverride = false
	}
	gpmAllowLegacyServiceMutationsRaw, gpmAllowLegacyServiceMutationsSource, gpmAllowLegacyServiceMutationsSet := preferredEnvValueWithSource(
		"GPM_ALLOW_LEGACY_SERVICE_MUTATIONS",
		"TDPN_ALLOW_LEGACY_SERVICE_MUTATIONS",
	)
	noteLegacyAlias("GPM_ALLOW_LEGACY_SERVICE_MUTATIONS", gpmAllowLegacyServiceMutationsSource)
	gpmAllowLegacyServiceMutations, gpmAllowLegacyServiceMutationsValid := parseBool(gpmAllowLegacyServiceMutationsRaw)
	if !gpmAllowLegacyServiceMutationsSet {
		gpmAllowLegacyServiceMutationsSource = "default"
		gpmAllowLegacyServiceMutations = !gpmConnectPolicyProduction
	} else if !gpmAllowLegacyServiceMutationsValid && gpmConnectPolicyProduction {
		gpmAllowLegacyServiceMutations = false
		gpmAllowLegacyServiceMutationsSource = "production-invalid-env-fail-closed"
	}
	gpmAdminRoutesRaw, gpmAdminRoutesSource, gpmAdminRoutesSet := preferredEnvValueWithSource(
		"GPM_LOCAL_API_ADMIN_ROUTES",
		"TDPN_LOCAL_API_ADMIN_ROUTES",
	)
	noteLegacyAlias("GPM_LOCAL_API_ADMIN_ROUTES", gpmAdminRoutesSource)
	gpmAdminRoutesEnabled, gpmAdminRoutesValid := parseBool(gpmAdminRoutesRaw)
	if !gpmAdminRoutesSet {
		gpmAdminRoutesEnabled = false
		gpmAdminRoutesSource = "default"
	} else if !gpmAdminRoutesValid {
		gpmAdminRoutesEnabled = false
		gpmAdminRoutesSource = gpmAdminRoutesSource + "-invalid-env-fail-closed"
	}
	if !gpmOperatorApprovalRequireSessionSet && !gpmOperatorApprovalRequireSession && gpmAdminRoutesEnabled {
		gpmOperatorApprovalRequireSession = true
		gpmOperatorApprovalRequireSessionSource = "admin-routes-default"
	}
	gpmLegacyConnectRequireTrustedManifestBootstrapRaw, gpmLegacyConnectRequireTrustedManifestBootstrapSource, gpmLegacyConnectRequireTrustedManifestBootstrapSet := preferredEnvValueWithSource(
		"GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP",
		"TDPN_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP",
	)
	noteLegacyAlias(
		"GPM_LEGACY_CONNECT_REQUIRE_TRUSTED_MANIFEST_BOOTSTRAP",
		gpmLegacyConnectRequireTrustedManifestBootstrapSource,
	)
	gpmLegacyConnectRequireTrustedManifestBootstrap, gpmLegacyConnectRequireTrustedManifestBootstrapValid := parseBool(
		gpmLegacyConnectRequireTrustedManifestBootstrapRaw,
	)
	if !gpmLegacyConnectRequireTrustedManifestBootstrapSet {
		gpmLegacyConnectRequireTrustedManifestBootstrapSource = "default"
		if gpmConnectPolicyProduction {
			gpmLegacyConnectRequireTrustedManifestBootstrap = true
			gpmLegacyConnectRequireTrustedManifestBootstrapSource = "production-default"
		}
	} else if !gpmLegacyConnectRequireTrustedManifestBootstrapValid && gpmConnectPolicyProduction {
		gpmLegacyConnectRequireTrustedManifestBootstrap = true
		gpmLegacyConnectRequireTrustedManifestBootstrapSource = "production-invalid-env-fail-closed"
	} else if gpmConnectPolicyProduction {
		if gpmLegacyConnectRequireTrustedManifestBootstrapSet && !gpmLegacyConnectRequireTrustedManifestBootstrap {
			gpmLegacyConnectRequireTrustedManifestBootstrapSource = "production-enforced"
		}
		gpmLegacyConnectRequireTrustedManifestBootstrap = true
	}
	gpmStateStorePathRaw, gpmStateStorePathSource, gpmStateStorePathSet := preferredEnvValueWithSource(
		"GPM_STATE_STORE_PATH",
		"TDPN_STATE_STORE_PATH",
	)
	noteLegacyAlias("GPM_STATE_STORE_PATH", gpmStateStorePathSource)
	gpmStateStorePath := gpmStateStorePathRaw
	if !gpmStateStorePathSet {
		gpmStateStorePath = ".easy-node-logs/gpm_state.json"
	}
	gpmAuditLogPathRaw, gpmAuditLogPathSource, gpmAuditLogPathSet := preferredEnvValueWithSource(
		"GPM_AUDIT_LOG_PATH",
		"TDPN_AUDIT_LOG_PATH",
	)
	noteLegacyAlias("GPM_AUDIT_LOG_PATH", gpmAuditLogPathSource)
	gpmAuditLogPath := gpmAuditLogPathRaw
	if !gpmAuditLogPathSet {
		gpmAuditLogPath = ".easy-node-logs/gpm_audit.jsonl"
	}
	gpmGapScanSummaryPathRaw, gpmGapScanSummaryPathSource, gpmGapScanSummaryPathSet := preferredEnvValueWithSource(
		"GPM_GAP_SCAN_SUMMARY_JSON",
		"TDPN_GAP_SCAN_SUMMARY_JSON",
	)
	noteLegacyAlias("GPM_GAP_SCAN_SUMMARY_JSON", gpmGapScanSummaryPathSource)
	gpmGapScanSummaryPath := gpmGapScanSummaryPathRaw
	if !gpmGapScanSummaryPathSet {
		gpmGapScanSummaryPath = ".easy-node-logs/gpm_gap_scan_summary.json"
	}
	gpmSettlement := resolveGPMSettlementWiring(gpmConnectPolicyProduction, gpmConnectPolicySource, noteLegacyAlias)

	svc := &Service{
		addr:                                 addr,
		scriptPath:                           scriptPath,
		commandRunner:                        commandRunner,
		commandTimeout:                       commandTimeout,
		maxConcurrentCmds:                    maxConcurrentCmds,
		commandSlots:                         make(chan struct{}, maxConcurrentCmds),
		allowUpdate:                          allowUpdate,
		allowUnauthLoopback:                  allowUnauthLoopback,
		allowInsecureHTTP:                    allowInsecureHTTP,
		authToken:                            authToken,
		serviceStatus:                        serviceStatus,
		serviceStart:                         serviceStart,
		serviceStop:                          serviceStop,
		serviceRestart:                       serviceRestart,
		gpmConnectRequireSession:             gpmConnectRequireSession,
		gpmAllowLegacyConnectOverride:        gpmAllowLegacyConnectOverride,
		gpmAllowLegacyServiceMutations:       gpmAllowLegacyServiceMutations,
		gpmAllowLegacyServiceMutationsSource: gpmAllowLegacyServiceMutationsSource,
		gpmAdminRoutesEnabled:                gpmAdminRoutesEnabled,
		gpmAdminRoutesSource:                 gpmAdminRoutesSource,
		gpmLegacyConnectRequireTrustedManifestBootstrap:       gpmLegacyConnectRequireTrustedManifestBootstrap,
		gpmLegacyConnectRequireTrustedManifestBootstrapSource: gpmLegacyConnectRequireTrustedManifestBootstrapSource,
		gpmConnectPolicyMode:                                  gpmConnectPolicyMode,
		gpmConnectPolicySource:                                gpmConnectPolicySource,
		gpmManifestTrustPolicyMode:                            gpmManifestTrustPolicyMode,
		gpmManifestTrustPolicySource:                          gpmManifestTrustPolicySource,
		gpmManifestRequireHTTPS:                               gpmManifestRequireHTTPS,
		gpmManifestRequireHTTPSSource:                         gpmManifestRequireHTTPSSource,
		gpmManifestRequireSignature:                           gpmManifestRequireSignature,
		gpmManifestRequireSigSource:                           gpmManifestRequireSigSource,
		gpmAuthVerifyPolicyMode:                               gpmAuthVerifyPolicyMode,
		gpmAuthVerifyPolicySource:                             gpmAuthVerifyPolicySource,
		gpmMainDomain:                                         strings.TrimRight(strings.TrimSpace(gpmMainDomain), "/"),
		gpmManifestURL:                                        canonicalizeManifestSourceURLOrRaw(gpmManifestURL),
		gpmManifestCache:                                      strings.TrimSpace(gpmManifestCache),
		gpmManifestMaxAge:                                     time.Duration(gpmManifestMaxAgeSec) * time.Second,
		gpmManifestRemoteRefreshIntvl:                         time.Duration(gpmManifestRemoteRefreshIntervalSec) * time.Second,
		gpmManifestRemoteRefreshSrc:                           gpmManifestRemoteRefreshSource,
		gpmManifestRefreshFailureMaxCacheAge:                  time.Duration(gpmManifestRefreshFailureMaxCacheAgeSec) * time.Second,
		gpmManifestRefreshFailureMaxCacheAgeSrc:               gpmManifestRefreshFailureMaxCacheAgeSource,
		gpmManifestHMACKey:                                    gpmManifestHMACKey,
		gpmManifestHMACKeySource:                              strings.TrimSpace(gpmManifestHMACKeySource),
		gpmManifestEd25519PublicKey:                           gpmManifestEd25519PublicKey,
		gpmManifestEd25519PublicKeySource:                     strings.TrimSpace(gpmManifestEd25519PublicKeySource),
		gpmRoleDefault:                                        gpmRoleDefault,
		gpmAdminWalletAllowlist:                               gpmAdminWalletAllowlist,
		gpmAdminWalletAllowlistSource:                         gpmAdminWalletAllowlistSource,
		gpmApprovalToken:                                      gpmApprovalToken,
		gpmOperatorApprovalRequireSession:                     gpmOperatorApprovalRequireSession,
		gpmOperatorApprovalRequireSessionSource:               gpmOperatorApprovalRequireSessionSource,
		gpmAuthVerifyCommand:                                  strings.TrimSpace(gpmAuthVerifyCommand),
		gpmAuthVerifyRequireCommand:                           gpmAuthVerifyRequireCommand,
		gpmAuthVerifyRequireCmdSource:                         gpmAuthVerifyRequireCommandSource,
		gpmAuthVerifyRequireMetadata:                          gpmAuthVerifyRequireMetadata,
		gpmAuthVerifyRequireWalletExt:                         gpmAuthVerifyRequireWalletExt,
		gpmAuthVerifyRequireCryptoProof:                       gpmAuthVerifyRequireCryptoProof,
		gpmAuthVerifyMetadataSource:                           gpmAuthVerifyMetadataSource,
		gpmAuthVerifyWalletExtSource:                          gpmAuthVerifyWalletExtSource,
		gpmAuthVerifyCryptoSource:                             gpmAuthVerifyCryptoSource,
		gpmAuthExpectedChainID:                                gpmAuthExpectedChainID,
		gpmAuthExpectedChainIDSource:                          gpmAuthExpectedChainIDSource,
		gpmAuthExpectedWalletHRP:                              gpmAuthExpectedWalletHRP,
		gpmAuthExpectedWalletHRPSource:                        gpmAuthExpectedWalletHRPSource,
		gpmLegacyEnvAliasesActive:                             append([]string{}, legacyEnvAliasesActive...),
		gpmLegacyEnvAliasWarnings:                             append([]string{}, legacyEnvAliasWarnings...),
		gpmAuthSignatureVerifier:                              nil,
		gpmStateStorePath:                                     strings.TrimSpace(gpmStateStorePath),
		gpmAuditLogPath:                                       strings.TrimSpace(gpmAuditLogPath),
		gpmGapScanSummaryPath:                                 strings.TrimSpace(gpmGapScanSummaryPath),
		gpmSettlement:                                         gpmSettlement.service,
		gpmSettlementBackend:                                  gpmSettlement.backend,
		gpmSettlementBackendSource:                            gpmSettlement.backendSource,
		gpmSettlementChainRequired:                            gpmSettlement.chainRequired,
		gpmSettlementChainRequiredSource:                      gpmSettlement.chainRequiredSource,
		gpmSettlementChainBacked:                              gpmSettlement.chainBacked,
		gpmSettlementAdapterConfigured:                        gpmSettlement.adapterConfigured,
		gpmSettlementAdapterConfigError:                       gpmSettlement.adapterConfigError,
		gpmSettlementCosmosEndpointConfigured:                 gpmSettlement.cosmosEndpointConfigured,
		gpmSettlementCosmosEndpointSource:                     gpmSettlement.cosmosEndpointSource,
		gpmSettlementCosmosSubmitMode:                         gpmSettlement.cosmosSubmitMode,
		gpmSettlementTrustedBridgeFinality:                    gpmSettlement.trustedBridgeFinality,
		gpmSettlementClose:                                    gpmSettlement.close,
		gpmState:                                              newGPMRuntimeState(),
	}
	svc.loadGPMStateBestEffort()
	return svc
}

func resolveGPMSettlementWiring(productionMode bool, productionSource string, noteLegacyAlias func(string, string)) gpmSettlementWiring {
	chainRequiredSource := "default"
	if productionMode {
		chainRequiredSource = firstNonEmpty(strings.TrimSpace(productionSource), "GPM_PRODUCTION_MODE")
	}
	wiring := gpmSettlementWiring{
		backend:                  "memory",
		backendSource:            "default",
		chainRequired:            productionMode,
		chainRequiredSource:      chainRequiredSource,
		cosmosEndpointSource:     "default",
		cosmosSubmitMode:         settlement.CosmosSubmitModeHTTP,
		trustedBridgeFinality:    false,
		cosmosEndpointConfigured: false,
		adapterConfigured:        false,
		chainBacked:              false,
		adapterConfigError:       "",
	}

	backendRaw, backendSource, backendSet := gpmSettlementEnv("GPM_SETTLEMENT_BACKEND", "TDPN_SETTLEMENT_BACKEND", noteLegacyAlias)
	endpoint, endpointSource, endpointSet := gpmSettlementEnv("GPM_SETTLEMENT_COSMOS_ENDPOINT", "TDPN_SETTLEMENT_COSMOS_ENDPOINT", noteLegacyAlias)
	wiring.cosmosEndpointConfigured = endpointSet
	wiring.cosmosEndpointSource = endpointSource

	backend := strings.ToLower(strings.TrimSpace(backendRaw))
	switch backend {
	case "", "auto":
		if backendSet {
			wiring.backendSource = backendSource
		}
		if endpointSet {
			wiring.backend = "cosmos"
			wiring.backendSource = endpointSource
		}
	case "memory", "cosmos":
		wiring.backend = backend
		wiring.backendSource = backendSource
	default:
		wiring.backend = "invalid"
		wiring.backendSource = backendSource
		wiring.adapterConfigError = fmt.Sprintf("invalid GPM settlement backend %q (expected auto, memory, or cosmos)", backendRaw)
		wiring.service = settlement.NewMemoryService(settlement.WithBlockchainMode(wiring.chainRequired))
		return wiring
	}

	memoryOptions := []settlement.MemoryOption{
		settlement.WithBlockchainMode(wiring.chainRequired),
	}
	if wiring.backend == "cosmos" {
		adapterCfg := settlement.CosmosAdapterConfig{
			Endpoint:              endpoint,
			APIKey:                gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_API_KEY", "TDPN_SETTLEMENT_COSMOS_API_KEY", "", noteLegacyAlias),
			QueueSize:             gpmSettlementPositiveIntEnv("GPM_SETTLEMENT_COSMOS_QUEUE_SIZE", "TDPN_SETTLEMENT_COSMOS_QUEUE_SIZE", 256, noteLegacyAlias),
			MaxRetries:            gpmSettlementPositiveIntEnv("GPM_SETTLEMENT_COSMOS_MAX_RETRIES", "TDPN_SETTLEMENT_COSMOS_MAX_RETRIES", 3, noteLegacyAlias),
			BaseBackoff:           time.Duration(gpmSettlementPositiveIntEnv("GPM_SETTLEMENT_COSMOS_BASE_BACKOFF_MS", "TDPN_SETTLEMENT_COSMOS_BASE_BACKOFF_MS", 250, noteLegacyAlias)) * time.Millisecond,
			HTTPTimeout:           time.Duration(gpmSettlementPositiveIntEnv("GPM_SETTLEMENT_COSMOS_HTTP_TIMEOUT_SEC", "TDPN_SETTLEMENT_COSMOS_HTTP_TIMEOUT_SEC", 4, noteLegacyAlias)) * time.Second,
			AllowInsecureHTTP:     gpmSettlementBoolEnv("GPM_SETTLEMENT_COSMOS_ALLOW_INSECURE_HTTP", "TDPN_SETTLEMENT_COSMOS_ALLOW_INSECURE_HTTP", false, noteLegacyAlias),
			SubmitMode:            gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SUBMIT_MODE", "TDPN_SETTLEMENT_COSMOS_SUBMIT_MODE", settlement.CosmosSubmitModeHTTP, noteLegacyAlias),
			TrustedBridgeFinality: gpmSettlementBoolEnv("GPM_SETTLEMENT_COSMOS_TRUSTED_BRIDGE_FINALITY", "TDPN_SETTLEMENT_COSMOS_TRUSTED_BRIDGE_FINALITY", false, noteLegacyAlias),
			RewardProofAuthToken:  gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_REWARD_PROOF_AUTH_TOKEN", "TDPN_SETTLEMENT_COSMOS_REWARD_PROOF_AUTH_TOKEN", "", noteLegacyAlias),
			FinalityAuthToken:     gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_FINALITY_AUTH_TOKEN", "TDPN_SETTLEMENT_COSMOS_FINALITY_AUTH_TOKEN", "", noteLegacyAlias),
			RewardProofVerifierID: gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_REWARD_PROOF_VERIFIER_ID", "TDPN_SETTLEMENT_COSMOS_REWARD_PROOF_VERIFIER_ID", "", noteLegacyAlias),
			SignedTxBroadcastPath: gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SIGNED_TX_BROADCAST_PATH", "TDPN_SETTLEMENT_COSMOS_SIGNED_TX_BROADCAST_PATH", "", noteLegacyAlias),
			SignedTxChainID:       gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SIGNED_TX_CHAIN_ID", "TDPN_SETTLEMENT_COSMOS_SIGNED_TX_CHAIN_ID", "", noteLegacyAlias),
			SignedTxSigner:        gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SIGNED_TX_SIGNER", "TDPN_SETTLEMENT_COSMOS_SIGNED_TX_SIGNER", "", noteLegacyAlias),
			SignedTxSecret:        gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SIGNED_TX_SECRET", "TDPN_SETTLEMENT_COSMOS_SIGNED_TX_SECRET", "", noteLegacyAlias),
			SignedTxSecretFile:    gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SIGNED_TX_SECRET_FILE", "TDPN_SETTLEMENT_COSMOS_SIGNED_TX_SECRET_FILE", "", noteLegacyAlias),
			SignedTxKeyID:         gpmSettlementEnvValue("GPM_SETTLEMENT_COSMOS_SIGNED_TX_KEY_ID", "TDPN_SETTLEMENT_COSMOS_SIGNED_TX_KEY_ID", "", noteLegacyAlias),
		}
		wiring.cosmosSubmitMode = strings.ToLower(strings.TrimSpace(adapterCfg.SubmitMode))
		if wiring.cosmosSubmitMode == "" {
			wiring.cosmosSubmitMode = settlement.CosmosSubmitModeHTTP
		}
		wiring.trustedBridgeFinality = adapterCfg.TrustedBridgeFinality
		if strings.TrimSpace(adapterCfg.Endpoint) == "" {
			wiring.adapterConfigError = "GPM settlement Cosmos adapter endpoint is required when GPM_SETTLEMENT_BACKEND=cosmos (set GPM_SETTLEMENT_COSMOS_ENDPOINT; legacy alias TDPN_SETTLEMENT_COSMOS_ENDPOINT)"
		} else if productionMode && adapterCfg.TrustedBridgeFinality {
			wiring.adapterConfigError = "GPM production settlement cannot use trusted HTTP bridge finality; require independent chain status confirmation before enabling production settlement"
		} else if productionMode && wiring.cosmosSubmitMode == settlement.CosmosSubmitModeSignedTx {
			wiring.adapterConfigError = "GPM production settlement cannot use experimental signed-tx JSON envelope mode; configure a finalized Cosmos SDK tx adapter before enabling signed-tx in production"
		} else if adapter, err := settlement.NewCosmosAdapter(adapterCfg); err != nil {
			wiring.adapterConfigError = err.Error()
		} else {
			wiring.adapterConfigured = true
			wiring.chainBacked = true
			memoryOptions = append(memoryOptions, settlement.WithChainAdapter(adapter))
			wiring.close = adapter.Close
		}
	}

	wiring.service = settlement.NewMemoryService(memoryOptions...)
	return wiring
}

func gpmSettlementEnv(primaryKey string, legacyKey string, noteLegacyAlias func(string, string)) (string, string, bool) {
	value, source, set := preferredEnvValueWithSource(primaryKey, legacyKey)
	if noteLegacyAlias != nil {
		noteLegacyAlias(primaryKey, source)
	}
	return value, source, set
}

func gpmSettlementEnvValue(primaryKey string, legacyKey string, fallback string, noteLegacyAlias func(string, string)) string {
	value, _, set := gpmSettlementEnv(primaryKey, legacyKey, noteLegacyAlias)
	if !set {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(value)
}

func gpmSettlementPositiveIntEnv(primaryKey string, legacyKey string, fallback int, noteLegacyAlias func(string, string)) int {
	raw, _, set := gpmSettlementEnv(primaryKey, legacyKey, noteLegacyAlias)
	if !set {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func gpmSettlementBoolEnv(primaryKey string, legacyKey string, fallback bool, noteLegacyAlias func(string, string)) bool {
	raw, _, set := gpmSettlementEnv(primaryKey, legacyKey, noteLegacyAlias)
	if !set {
		return fallback
	}
	return parseBoolWithDefault(raw, fallback)
}

func (s *Service) gpmSettlementChainRequiredEffective() bool {
	if s.gpmSettlementChainRequired {
		return true
	}
	return s.isGPMProductionMode()
}

func (s *Service) isGPMProductionMode() bool {
	return strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production")
}

func (s *Service) connectRequireSessionEffective() bool {
	return s.gpmConnectRequireSession || s.isGPMProductionMode()
}

func (s *Service) legacyConnectOverrideAllowed() bool {
	return s.gpmAllowLegacyConnectOverride && !s.isGPMProductionMode()
}

func (s *Service) legacyConnectRequireTrustedManifestBootstrapEffective() bool {
	return s.gpmLegacyConnectRequireTrustedManifestBootstrap || s.isGPMProductionMode()
}

func (s *Service) rememberConnectInterface(interfaceName string) {
	interfaceName = strings.TrimSpace(interfaceName)
	if !isAllowedVPNInterfaceName(interfaceName) {
		return
	}
	s.lastConnectInterfaceMu.Lock()
	s.lastConnectInterface = interfaceName
	s.lastConnectInterfaceMu.Unlock()
}

func (s *Service) disconnectInterfaceName() string {
	s.lastConnectInterfaceMu.Lock()
	last := strings.TrimSpace(s.lastConnectInterface)
	s.lastConnectInterfaceMu.Unlock()
	if isAllowedVPNInterfaceName(last) {
		return last
	}
	defaults := loadConnectDefaultsFromEnv()
	if isAllowedVPNInterfaceName(defaults.interfaceName) {
		return defaults.interfaceName
	}
	return defaultVPNInterface
}

func (s *Service) clearRememberedConnectInterface(interfaceName string) {
	interfaceName = strings.TrimSpace(interfaceName)
	s.lastConnectInterfaceMu.Lock()
	if interfaceName == "" || s.lastConnectInterface == interfaceName {
		s.lastConnectInterface = ""
	}
	s.lastConnectInterfaceMu.Unlock()
}

func (s *Service) gpmSettlementChainRequiredSourceEffective() string {
	if source := strings.TrimSpace(s.gpmSettlementChainRequiredSource); source != "" {
		return source
	}
	if s.isGPMProductionMode() {
		return firstNonEmpty(strings.TrimSpace(s.gpmConnectPolicySource), "connect_policy_mode")
	}
	return "default"
}

func (s *Service) gpmSettlementBackendEffective() string {
	backend := strings.TrimSpace(s.gpmSettlementBackend)
	if backend == "" {
		return "memory"
	}
	return backend
}

func (s *Service) gpmSettlementBackendSourceEffective() string {
	source := strings.TrimSpace(s.gpmSettlementBackendSource)
	if source == "" {
		return "default"
	}
	return source
}

func (s *Service) gpmSettlementMode() string {
	if s.gpmSettlementChainBacked {
		return "chain_backed"
	}
	if s.gpmSettlementChainRequiredEffective() {
		return "required_unconfigured"
	}
	return "compatibility_memory"
}

func (s *Service) gpmSettlementStatusTelemetry() map[string]any {
	endpointSource := strings.TrimSpace(s.gpmSettlementCosmosEndpointSource)
	if endpointSource == "" {
		endpointSource = "default"
	}
	submitMode := strings.TrimSpace(s.gpmSettlementCosmosSubmitMode)
	if submitMode == "" {
		submitMode = settlement.CosmosSubmitModeHTTP
	}
	return map[string]any{
		"gpm_settlement_mode":                       s.gpmSettlementMode(),
		"gpm_settlement_backend":                    s.gpmSettlementBackendEffective(),
		"gpm_settlement_backend_source":             s.gpmSettlementBackendSourceEffective(),
		"gpm_settlement_chain_required":             s.gpmSettlementChainRequiredEffective(),
		"gpm_settlement_chain_required_source":      s.gpmSettlementChainRequiredSourceEffective(),
		"gpm_settlement_chain_backed":               s.gpmSettlementChainBacked,
		"gpm_settlement_adapter_configured":         s.gpmSettlementAdapterConfigured,
		"gpm_settlement_adapter_config_error":       strings.TrimSpace(s.gpmSettlementAdapterConfigError),
		"gpm_settlement_cosmos_endpoint_configured": s.gpmSettlementCosmosEndpointConfigured,
		"gpm_settlement_cosmos_endpoint_source":     endpointSource,
		"gpm_settlement_cosmos_submit_mode":         submitMode,
		"gpm_settlement_trusted_bridge_finality":    s.gpmSettlementTrustedBridgeFinality,
	}
}

func (s *Service) gpmSettlementRequiresChainBackedAdapter() bool {
	return s.gpmSettlementChainRequiredEffective() && !s.gpmSettlementChainBacked
}

func (s *Service) gpmSettlementChainRequiredError() string {
	if errMsg := strings.TrimSpace(s.gpmSettlementAdapterConfigError); errMsg != "" {
		return "chain-backed GPM settlement adapter is required in production mode, but settlement adapter configuration is not chain-backed: " + errMsg
	}
	return "chain-backed GPM settlement adapter is required in production mode; configure GPM_SETTLEMENT_COSMOS_ENDPOINT or use compatibility mode outside production"
}

func (s *Service) routes() http.Handler {
	mux := http.NewServeMux()
	s.registerPublicRoutes(mux)
	if s.gpmAdminRoutesEnabled {
		s.registerAdminRoutes(mux)
	}
	return s.withLocalAPICORS(mux)
}

func (s *Service) registerPublicRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/config", s.handleConfig)
	mux.HandleFunc("/v1/connect", s.handleConnect)
	mux.HandleFunc("/v1/disconnect", s.handleDisconnect)
	mux.HandleFunc("/v1/gpm/bootstrap/manifest", s.handleGPMBootstrapManifest)
	mux.HandleFunc("/v1/gpm/auth/challenge", s.handleGPMAuthChallenge)
	mux.HandleFunc("/v1/gpm/auth/verify", s.handleGPMAuthVerify)
	mux.HandleFunc("/v1/gpm/session", s.handleGPMSessionStatus)
	mux.HandleFunc("/v1/gpm/onboarding/client/register", s.handleGPMClientRegister)
	mux.HandleFunc("/v1/gpm/onboarding/client/status", s.handleGPMClientStatus)
	mux.HandleFunc("/v1/gpm/contribution/status", s.handleGPMContributionStatus)
	mux.HandleFunc("/v1/gpm/contribution/enable", s.handleGPMContributionEnable)
	mux.HandleFunc("/v1/gpm/contribution/disable", s.handleGPMContributionDisable)
	mux.HandleFunc("/v1/gpm/settlement/reserve-funds", s.handleGPMSettlementReserveFunds)
	mux.HandleFunc("/v1/gpm/rewards/current-week", s.handleGPMRewardsCurrentWeek)
	mux.HandleFunc("/v1/gpm/rewards/history", s.handleGPMRewardsHistory)
	mux.HandleFunc("/v1/gpm/onboarding/overview", s.handleGPMOnboardingOverview)
	mux.HandleFunc("/v1/gpm/diagnostics/public", s.handlePublicDiagnostics)
}

func (s *Service) registerAdminRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/set_profile", s.handleSetProfile)
	mux.HandleFunc("/v1/update", s.handleUpdate)
	mux.HandleFunc("/v1/service/status", s.handleServiceStatus)
	mux.HandleFunc("/v1/service/start", s.handleServiceStart)
	mux.HandleFunc("/v1/service/stop", s.handleServiceStop)
	mux.HandleFunc("/v1/service/restart", s.handleServiceRestart)
	mux.HandleFunc("/v1/get_diagnostics", s.handleDiagnostics)
	mux.HandleFunc("/v1/gpm/service/start", s.handleGPMServiceStart)
	mux.HandleFunc("/v1/gpm/service/status", s.handleGPMServiceStatus)
	mux.HandleFunc("/v1/gpm/service/stop", s.handleGPMServiceStop)
	mux.HandleFunc("/v1/gpm/service/restart", s.handleGPMServiceRestart)
	mux.HandleFunc("/v1/gpm/audit/recent", s.handleGPMAuditRecent)
	mux.HandleFunc("/v1/gpm/gaps/summary", s.handleGPMGapSummary)
	mux.HandleFunc("/v1/gpm/admin/contributions/list", s.handleGPMAdminContributionList)
	mux.HandleFunc("/v1/gpm/admin/rewards/review", s.handleGPMAdminRewardReview)
	mux.HandleFunc("/v1/gpm/admin/rewards/hold", s.handleGPMAdminRewardHold)
	mux.HandleFunc("/v1/gpm/admin/rewards/finalize", s.handleGPMAdminRewardFinalize)
	mux.HandleFunc("/v1/gpm/onboarding/server/status", s.handleGPMServerStatus)
	mux.HandleFunc("/v1/gpm/onboarding/operator/apply", s.handleGPMOperatorApply)
	mux.HandleFunc("/v1/gpm/onboarding/operator/status", s.handleGPMOperatorStatus)
	mux.HandleFunc("/v1/gpm/onboarding/operator/list", s.handleGPMOperatorList)
	mux.HandleFunc("/v1/gpm/onboarding/operator/approve", s.handleGPMOperatorApprove)
}

func (s *Service) Run(ctx context.Context) error {
	if !isLoopbackBindAddr(s.addr) {
		if !s.allowInsecureHTTP {
			return fmt.Errorf("refusing insecure non-loopback local api bind %q; set %s=1 only for trusted lab environments", s.addr, allowInsecureHTTPEnv)
		}
		if err := validateRemoteAuthToken(s.authToken); err != nil {
			return fmt.Errorf("refusing insecure non-loopback local api bind %q: %w", s.addr, err)
		}
	}

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      s.commandTimeout + serverWriteSlack,
		IdleTimeout:       serverIdleTimeout,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf(
		"local control api listening on %s script=%s runner=%s update_enabled=%t allow_unauth_loopback=%t allow_insecure_remote_http=%t max_concurrent_commands=%d",
		s.addr,
		s.scriptPath,
		s.commandRunner,
		s.allowUpdate,
		s.allowUnauthLoopback,
		s.allowInsecureHTTP,
		s.maxConcurrentCmds,
	)
	err := srv.ListenAndServe()
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "local-control-api"})
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "client-vpn-status", "--show-json", "1")
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"error":  "status command failed",
			"rc":     rc,
			"output": out,
		})
		return
	}
	var payload any
	if json.Unmarshal([]byte(out), &payload) != nil {
		payload = map[string]any{"raw": out}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"status":  payload,
		"routing": deriveRoutingPostureFromStatusPayload(payload),
	})
}

func (s *Service) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}

	commandTimeoutSec := int(s.commandTimeout / time.Second)
	if commandTimeoutSec < 0 {
		commandTimeoutSec = 0
	}
	manifestCacheMaxAgeSec := int(s.gpmManifestMaxAge / time.Second)
	if manifestCacheMaxAgeSec < 0 {
		manifestCacheMaxAgeSec = 0
	}
	manifestRemoteRefreshIntervalSec := int(s.gpmManifestRemoteRefreshIntvl / time.Second)
	if manifestRemoteRefreshIntervalSec < 0 {
		manifestRemoteRefreshIntervalSec = 0
	}
	manifestRemoteRefreshIntervalSource := strings.TrimSpace(s.gpmManifestRemoteRefreshSrc)
	if manifestRemoteRefreshIntervalSource == "" {
		manifestRemoteRefreshIntervalSource = "default"
	}
	manifestRefreshFailureMaxCacheAgeSec := int(s.gpmManifestRefreshFailureMaxCacheAge / time.Second)
	if manifestRefreshFailureMaxCacheAgeSec < 0 {
		manifestRefreshFailureMaxCacheAgeSec = 0
	}
	manifestRefreshFailureMaxCacheAgeSource := strings.TrimSpace(s.gpmManifestRefreshFailureMaxCacheAgeSrc)
	if manifestRefreshFailureMaxCacheAgeSource == "" {
		manifestRefreshFailureMaxCacheAgeSource = "default"
	}
	manifestResolvePolicyDetail := "serve trusted cache immediately; when refresh interval elapses for a still-valid cache, attempt remote refresh and fall back to trusted cache if refresh fails"
	if manifestRefreshFailureMaxCacheAgeSec > 0 {
		manifestResolvePolicyDetail = "serve trusted cache immediately; when refresh interval elapses for a still-valid cache, attempt remote refresh and fall back to trusted cache if refresh fails only while cache age stays within the configured refresh-failure fallback max age"
	}
	connectPolicyMode := strings.TrimSpace(s.gpmConnectPolicyMode)
	if connectPolicyMode == "" {
		connectPolicyMode = "default"
	}
	connectPolicySource := strings.TrimSpace(s.gpmConnectPolicySource)
	if connectPolicySource == "" {
		connectPolicySource = "default"
	}
	gpmProductionMode := strings.EqualFold(connectPolicyMode, "production")
	legacyServiceMutationsSource := strings.TrimSpace(s.gpmAllowLegacyServiceMutationsSource)
	if legacyServiceMutationsSource == "" {
		legacyServiceMutationsSource = "default"
	}
	manifestTrustPolicyMode := strings.TrimSpace(s.gpmManifestTrustPolicyMode)
	if manifestTrustPolicyMode == "" {
		manifestTrustPolicyMode = "default"
	}
	manifestTrustPolicySource := strings.TrimSpace(s.gpmManifestTrustPolicySource)
	if manifestTrustPolicySource == "" {
		manifestTrustPolicySource = "default"
	}
	authVerifyPolicyMode := strings.TrimSpace(s.gpmAuthVerifyPolicyMode)
	if authVerifyPolicyMode == "" {
		authVerifyPolicyMode = "default"
	}
	authVerifyPolicySource := strings.TrimSpace(s.gpmAuthVerifyPolicySource)
	if authVerifyPolicySource == "" {
		authVerifyPolicySource = "default"
	}
	authVerifyRequireCommandSource := strings.TrimSpace(s.gpmAuthVerifyRequireCmdSource)
	if authVerifyRequireCommandSource == "" {
		authVerifyRequireCommandSource = "default"
	}
	authVerifyRequireMetadataSource := strings.TrimSpace(s.gpmAuthVerifyMetadataSource)
	if authVerifyRequireMetadataSource == "" {
		authVerifyRequireMetadataSource = "default"
	}
	authVerifyRequireWalletExtSource := strings.TrimSpace(s.gpmAuthVerifyWalletExtSource)
	if authVerifyRequireWalletExtSource == "" {
		authVerifyRequireWalletExtSource = "default"
	}
	authVerifyRequireCryptoSource := strings.TrimSpace(s.gpmAuthVerifyCryptoSource)
	if authVerifyRequireCryptoSource == "" {
		authVerifyRequireCryptoSource = "default"
	}
	authExpectedChainIDSource := strings.TrimSpace(s.gpmAuthExpectedChainIDSource)
	if authExpectedChainIDSource == "" {
		authExpectedChainIDSource = "default"
	}
	authExpectedWalletHRPSource := strings.TrimSpace(s.gpmAuthExpectedWalletHRPSource)
	if authExpectedWalletHRPSource == "" {
		authExpectedWalletHRPSource = "default"
	}
	operatorApprovalRequireSessionSource := strings.TrimSpace(s.gpmOperatorApprovalRequireSessionSource)
	if operatorApprovalRequireSessionSource == "" {
		operatorApprovalRequireSessionSource = "default"
	}
	adminWalletAllowlistSource := strings.TrimSpace(s.gpmAdminWalletAllowlistSource)
	if adminWalletAllowlistSource == "" {
		adminWalletAllowlistSource = "default"
	}
	adminRoutesSource := strings.TrimSpace(s.gpmAdminRoutesSource)
	if adminRoutesSource == "" {
		adminRoutesSource = "default"
	}
	daemonSurfaceMode := "public_app"
	if s.gpmAdminRoutesEnabled {
		daemonSurfaceMode = "admin_console"
	}
	manifestRequireHTTPSSource := strings.TrimSpace(s.gpmManifestRequireHTTPSSource)
	if manifestRequireHTTPSSource == "" {
		manifestRequireHTTPSSource = "default"
	}
	manifestRequireSigSource := strings.TrimSpace(s.gpmManifestRequireSigSource)
	if manifestRequireSigSource == "" {
		manifestRequireSigSource = "default"
	}
	legacyConnectRequireTrustedManifestBootstrapSource := strings.TrimSpace(s.gpmLegacyConnectRequireTrustedManifestBootstrapSource)
	if legacyConnectRequireTrustedManifestBootstrapSource == "" {
		legacyConnectRequireTrustedManifestBootstrapSource = "default"
	}
	manifestSignatureMode, manifestSignatureKeySource := s.manifestSignatureVerifierTelemetry()
	legacyEnvAliasesActive := append([]string{}, s.gpmLegacyEnvAliasesActive...)
	legacyEnvAliasWarnings := append([]string{}, s.gpmLegacyEnvAliasWarnings...)
	legacyEnvAliasWarning := ""
	if len(legacyEnvAliasWarnings) > 0 {
		legacyEnvAliasWarning = strings.Join(legacyEnvAliasWarnings, "; ")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"config": map[string]any{
			"connect_require_session":                                             s.connectRequireSessionEffective(),
			"allow_legacy_connect_override":                                       s.legacyConnectOverrideAllowed(),
			"allow_legacy_service_mutations":                                      s.legacyServiceMutationsAllowed(),
			"allow_legacy_service_mutations_policy_source":                        legacyServiceMutationsSource,
			"gpm_legacy_connect_require_trusted_manifest_bootstrap":               s.legacyConnectRequireTrustedManifestBootstrapEffective(),
			"gpm_legacy_connect_require_trusted_manifest_bootstrap_policy_source": legacyConnectRequireTrustedManifestBootstrapSource,
			"gpm_production_mode":                                                 gpmProductionMode,
			"gpm_production_mode_source":                                          connectPolicySource,
			"connect_policy_mode":                                                 connectPolicyMode,
			"connect_policy_source":                                               connectPolicySource,
			"gpm_daemon_surface_mode":                                             daemonSurfaceMode,
			"gpm_admin_routes_enabled":                                            s.gpmAdminRoutesEnabled,
			"gpm_admin_routes_policy_source":                                      adminRoutesSource,
			"gpm_admin_wallet_allowlist_configured":                               len(s.gpmAdminWalletAllowlist) > 0,
			"gpm_admin_wallet_allowlist_count":                                    len(s.gpmAdminWalletAllowlist),
			"gpm_admin_wallet_allowlist_source":                                   adminWalletAllowlistSource,
			"gpm_operator_approval_require_session":                               s.gpmOperatorApprovalRequireSession,
			"gpm_operator_approval_require_session_policy_source":                 operatorApprovalRequireSessionSource,
			"gpm_manifest_trust_policy_mode":                                      manifestTrustPolicyMode,
			"gpm_manifest_trust_policy_source":                                    manifestTrustPolicySource,
			"gpm_manifest_require_https":                                          s.gpmManifestRequireHTTPS,
			"gpm_manifest_require_https_policy_source":                            manifestRequireHTTPSSource,
			"gpm_manifest_require_signature":                                      s.gpmManifestRequireSignature,
			"gpm_manifest_require_signature_policy_source":                        manifestRequireSigSource,
			"gpm_manifest_signature_mode":                                         manifestSignatureMode,
			"gpm_manifest_signature_key_source":                                   manifestSignatureKeySource,
			"gpm_manifest_hmac_key_configured":                                    strings.TrimSpace(s.gpmManifestHMACKey) != "",
			"gpm_manifest_ed25519_public_key_configured":                          strings.TrimSpace(s.gpmManifestEd25519PublicKey) != "",
			"gpm_auth_verify_policy_mode":                                         authVerifyPolicyMode,
			"gpm_auth_verify_policy_source":                                       authVerifyPolicySource,
			"gpm_auth_verify_require_command":                                     s.gpmAuthVerifyRequireCommand,
			"gpm_auth_verify_require_command_policy_source":                       authVerifyRequireCommandSource,
			"gpm_auth_verify_require_metadata":                                    s.gpmAuthVerifyRequireMetadata,
			"gpm_auth_verify_require_metadata_policy_source":                      authVerifyRequireMetadataSource,
			"gpm_auth_verify_require_wallet_extension":                            s.gpmAuthVerifyRequireWalletExt,
			"gpm_auth_verify_require_wallet_extension_source":                     s.gpmAuthVerifyRequireWalletExt,
			"gpm_auth_verify_require_wallet_extension_policy_source":              authVerifyRequireWalletExtSource,
			"gpm_auth_verify_require_crypto_proof":                                s.gpmAuthVerifyRequireCryptoProof,
			"gpm_auth_verify_require_crypto_proof_policy_source":                  authVerifyRequireCryptoSource,
			"gpm_auth_verify_command_configured":                                  strings.TrimSpace(s.gpmAuthVerifyCommand) != "",
			"gpm_auth_expected_chain_id":                                          strings.TrimSpace(s.gpmAuthExpectedChainID),
			"gpm_auth_expected_chain_id_source":                                   authExpectedChainIDSource,
			"gpm_auth_expected_wallet_hrp":                                        strings.TrimSpace(s.gpmAuthExpectedWalletHRP),
			"gpm_auth_expected_wallet_hrp_source":                                 authExpectedWalletHRPSource,
			"gpm_settlement_mode":                                                 s.gpmSettlementMode(),
			"gpm_settlement_backend":                                              s.gpmSettlementBackendEffective(),
			"gpm_settlement_backend_source":                                       s.gpmSettlementBackendSourceEffective(),
			"gpm_settlement_chain_required":                                       s.gpmSettlementChainRequiredEffective(),
			"gpm_settlement_chain_required_source":                                s.gpmSettlementChainRequiredSourceEffective(),
			"gpm_settlement_chain_backed":                                         s.gpmSettlementChainBacked,
			"gpm_settlement_adapter_configured":                                   s.gpmSettlementAdapterConfigured,
			"gpm_settlement_adapter_config_error":                                 strings.TrimSpace(s.gpmSettlementAdapterConfigError),
			"gpm_settlement_cosmos_endpoint_configured":                           s.gpmSettlementCosmosEndpointConfigured,
			"gpm_settlement_cosmos_endpoint_source":                               firstNonEmpty(s.gpmSettlementCosmosEndpointSource, "default"),
			"gpm_settlement_cosmos_submit_mode":                                   firstNonEmpty(s.gpmSettlementCosmosSubmitMode, settlement.CosmosSubmitModeHTTP),
			"gpm_main_domain":                                                     strings.TrimSpace(s.gpmMainDomain),
			"gpm_manifest_url":                                                    strings.TrimSpace(s.gpmManifestURL),
			"gpm_manifest_cache_path":                                             strings.TrimSpace(s.gpmManifestCache),
			"gpm_manifest_cache_max_age_sec":                                      manifestCacheMaxAgeSec,
			"gpm_manifest_remote_refresh_interval_sec":                            manifestRemoteRefreshIntervalSec,
			"gpm_manifest_remote_refresh_interval_source":                         manifestRemoteRefreshIntervalSource,
			"gpm_manifest_refresh_failure_max_cache_age_sec":                      manifestRefreshFailureMaxCacheAgeSec,
			"gpm_manifest_refresh_failure_max_cache_age_source":                   manifestRefreshFailureMaxCacheAgeSource,
			"gpm_manifest_resolve_policy":                                         "cache_first_bounded_remote_refresh",
			"gpm_manifest_resolve_policy_detail":                                  manifestResolvePolicyDetail,
			"gpm_legacy_env_aliases_active":                                       legacyEnvAliasesActive,
			"gpm_legacy_env_aliases_active_count":                                 len(legacyEnvAliasesActive),
			"gpm_legacy_env_alias_warnings":                                       legacyEnvAliasWarnings,
			"gpm_legacy_env_aliases_warning":                                      legacyEnvAliasWarning,
			"command_timeout_sec":                                                 commandTimeoutSec,
			"allow_update":                                                        s.allowUpdate,
			"allow_remote":                                                        !isLoopbackBindAddr(s.addr),
		},
	})
}

type gpmProductionConnectEntitlement struct {
	WalletAddress                string
	ReservationID                string
	ReservationSessionID         string
	SessionExpiresAt             time.Time
	ReservationStatus            settlement.OperationStatus
	ReservationStatusSource      string
	ReservationFinalizationState string
}

func (s *Service) gpmProductionConnectEntitlementGate(ctx context.Context, sessionPresent bool, session gpmSession, reservationID string, reservationSessionID string, requireChainBacked bool) (gpmProductionConnectEntitlement, int, map[string]any) {
	out := gpmProductionConnectEntitlement{}
	settlementStatus := s.gpmSettlementStatusTelemetry()
	if !sessionPresent {
		return out, http.StatusUnauthorized, map[string]any{
			"ok":                              false,
			"error":                           "production connect requires a registered wallet session_token",
			"connect_allowed":                 false,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	walletAddress := normalizeWalletAddress(session.WalletAddress)
	out.WalletAddress = walletAddress
	out.SessionExpiresAt = session.ExpiresAt.UTC()
	if !session.WalletBindingVerified || walletAddress == "" {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           "wallet-bound session is required before production VPN connect",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if lockReason := s.gpmProductionEntitlementEvidenceLock(session); lockReason != "" {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           lockReason,
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"entitlement_evidence_source":     strings.TrimSpace(session.EntitlementEvidenceSource),
			"entitlement_evidence_trusted":    false,
			"public_app_admin_controls":       false,
		}
	}
	if !gpmEffectiveStakeSatisfied(session) {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           "stake is required before production VPN connect",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if !gpmEffectivePrepaidSatisfied(session) {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           "prepaid balance is required before production VPN connect",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if (requireChainBacked || s.gpmSettlementChainRequiredEffective()) && !s.gpmSettlementChainBacked {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           s.gpmSettlementChainRequiredError(),
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           "production connect requires a confirmed settlement reservation_id from /v1/gpm/settlement/reserve-funds",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if len(reservationID) > 256 || strings.IndexFunc(reservationID, unicode.IsControl) >= 0 {
		return out, http.StatusBadRequest, map[string]any{
			"ok":                              false,
			"error":                           "reservation_id is invalid",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	reservationSessionID = strings.TrimSpace(reservationSessionID)
	if reservationSessionID == "" {
		return out, http.StatusBadRequest, map[string]any{
			"ok":                              false,
			"error":                           "reservation_session_id is required before production VPN connect",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if len(reservationSessionID) > 256 || strings.IndexFunc(reservationSessionID, unicode.IsControl) >= 0 {
		return out, http.StatusBadRequest, map[string]any{
			"ok":                              false,
			"error":                           "reservation_session_id is invalid",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	querier, ok := s.gpmSettlementService().(settlement.ChainFundReservationStatusQuerier)
	if !ok || querier == nil {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "production connect requires a settlement service that can verify fund reservation chain status",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	materialQuerier, ok := s.gpmSettlementService().(settlement.FundReservationQuerier)
	if !ok || materialQuerier == nil {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "production connect requires a settlement service that can verify fund reservation ownership",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	reservation, reservationFound, reservationErr := materialQuerier.FundReservation(ctx, reservationID)
	if reservationErr != nil {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           fmt.Sprintf("fund reservation ownership query failed: %v", reservationErr),
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"reservation_finalization_state":  "unknown_chain_status",
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if !reservationFound {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "fund reservation ownership is unknown",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"reservation_finalization_state":  "unknown_chain_status",
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if strings.TrimSpace(reservation.ReservationID) != "" && strings.TrimSpace(reservation.ReservationID) != reservationID {
		return out, http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           "fund reservation id mismatch",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if normalizeWalletAddress(reservation.SubjectID) != walletAddress {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           "fund reservation is not bound to the signed-in wallet",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if strings.TrimSpace(reservation.SessionID) != reservationSessionID {
		return out, http.StatusForbidden, map[string]any{
			"ok":                              false,
			"error":                           "fund reservation session_id does not match reservation_session_id",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if reservation.AmountMicros <= 0 {
		return out, http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           "fund reservation amount is invalid",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if reservation.AmountMicros != gpmPublicVPNReservationMicros {
		return out, http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           fmt.Sprintf("fund reservation amount must equal public VPN reservation amount %d", gpmPublicVPNReservationMicros),
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"expected_amount_micros":          gpmPublicVPNReservationMicros,
			"reservation_amount_micros":       reservation.AmountMicros,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	currency := strings.TrimSpace(reservation.Currency)
	if currency == "" {
		currency = gpmPublicVPNReservationCurrency
	}
	if !strings.EqualFold(currency, gpmPublicVPNReservationCurrency) {
		return out, http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           fmt.Sprintf("fund reservation currency must be %s", gpmPublicVPNReservationCurrency),
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"settlement_status":               settlementStatus,
			"expected_currency":               gpmPublicVPNReservationCurrency,
			"reservation_currency":            reservation.Currency,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if out.SessionExpiresAt.IsZero() || !out.SessionExpiresAt.After(time.Now().UTC()) {
		return out, http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           "wallet session has expired before production VPN connect",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"reservation_session_id":          reservationSessionID,
			"session_expires_at_utc":          out.SessionExpiresAt.Format(time.RFC3339),
			"settlement_status":               settlementStatus,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	status, found, err := querier.FundReservationStatus(ctx, reservationID)
	if err != nil {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           fmt.Sprintf("fund reservation chain status query failed: %v", err),
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"settlement_status":               settlementStatus,
			"reservation_status_source":       "chain_status_query",
			"reservation_finalization_state":  "unknown_chain_status",
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if !found {
		return out, http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "fund reservation chain status is unknown",
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"settlement_status":               settlementStatus,
			"reservation_status_source":       "chain_status_query",
			"reservation_finalization_state":  "unknown_chain_status",
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	status, allowed, state, errMsg, httpStatus := gpmFundReservationFinalityDecision(status)
	if !allowed {
		if httpStatus == 0 {
			httpStatus = http.StatusServiceUnavailable
		}
		return out, httpStatus, map[string]any{
			"ok":                              false,
			"error":                           errMsg,
			"connect_allowed":                 false,
			"wallet_address":                  walletAddress,
			"reservation_id":                  reservationID,
			"settlement_status":               settlementStatus,
			"reservation_chain_status":        string(status),
			"reservation_status_source":       "chain_status_query",
			"reservation_finalization_state":  state,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	out.ReservationID = reservationID
	out.ReservationSessionID = reservationSessionID
	out.ReservationStatus = status
	out.ReservationStatusSource = "chain_status_query"
	out.ReservationFinalizationState = state
	s.appendGPMAudit("connect_entitlement_verified", map[string]any{
		"wallet_address":                 walletAddress,
		"reservation_id":                 reservationID,
		"reservation_session_id":         reservationSessionID,
		"reservation_chain_status":       string(status),
		"reservation_status_source":      out.ReservationStatusSource,
		"reservation_finalization_state": state,
		"settlement_surface":             "public_app",
		"connect_allowed":                true,
		"public_app_admin_controls":      false,
	})
	return out, 0, nil
}

func gpmProductionConnectCommandEnv(entitlement gpmProductionConnectEntitlement) []string {
	if strings.TrimSpace(entitlement.ReservationID) == "" {
		return nil
	}
	return []string{
		"GPM_SETTLEMENT_RESERVATION_ID=" + strings.TrimSpace(entitlement.ReservationID),
		"GPM_SETTLEMENT_RESERVATION_SESSION_ID=" + strings.TrimSpace(entitlement.ReservationSessionID),
		"GPM_SETTLEMENT_WALLET_ADDRESS=" + strings.TrimSpace(entitlement.WalletAddress),
		"GPM_SETTLEMENT_RESERVATION_EXPIRES_AT_UNIX=" + strconv.FormatInt(entitlement.SessionExpiresAt.UTC().Unix(), 10),
	}
}

func (s *Service) claimGPMProductionConnectReservation(entitlement gpmProductionConnectEntitlement) (int, map[string]any) {
	if strings.TrimSpace(entitlement.ReservationID) == "" {
		return 0, nil
	}
	if s.gpmStateStoreLoadFailed {
		reason := strings.TrimSpace(s.gpmStateStoreLoadFailure)
		if reason == "" {
			reason = "state store load failed"
		}
		return http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "production connect disabled because persisted reservation state could not be loaded",
			"state_store_error":               reason,
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if s.gpmState == nil {
		s.gpmState = newGPMRuntimeState()
	}
	if statusCode, payload := s.reconcileStaleGPMProductionConnectLaunch(entitlement); payload != nil {
		return statusCode, payload
	}
	claim, ok, reason := s.gpmState.claimReservationForConnect(
		entitlement.ReservationID,
		entitlement.ReservationSessionID,
		entitlement.WalletAddress,
		time.Now().UTC(),
	)
	if !ok {
		if reason == "" {
			reason = "reservation_id is already claimed for production VPN connect"
		}
		return http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           reason,
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"reservation_claim_status":        claim.Status,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	s.appendGPMAudit("connect_reservation_claimed", map[string]any{
		"wallet_address":         entitlement.WalletAddress,
		"reservation_id":         entitlement.ReservationID,
		"reservation_session_id": entitlement.ReservationSessionID,
		"claim_status":           claim.Status,
		"settlement_surface":     "public_app",
	})
	if err := s.persistGPMState("connect_reservation_claimed"); err != nil {
		_ = s.gpmState.releasePendingReservationClaim(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress)
		s.appendGPMAudit("connect_reservation_claim_persist_failed", map[string]any{
			"wallet_address":         entitlement.WalletAddress,
			"reservation_id":         entitlement.ReservationID,
			"reservation_session_id": entitlement.ReservationSessionID,
			"error":                  err.Error(),
			"settlement_surface":     "public_app",
		})
		return http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "failed to persist production reservation claim before connect launch",
			"state_store_error":               err.Error(),
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	return 0, nil
}

func (s *Service) releasePendingGPMProductionConnectReservation(entitlement gpmProductionConnectEntitlement, reason string) bool {
	if s.gpmState == nil || strings.TrimSpace(entitlement.ReservationID) == "" {
		return false
	}
	if !s.gpmState.releasePendingReservationClaim(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress) {
		return false
	}
	s.appendGPMAudit("connect_reservation_claim_released", map[string]any{
		"wallet_address":         entitlement.WalletAddress,
		"reservation_id":         entitlement.ReservationID,
		"reservation_session_id": entitlement.ReservationSessionID,
		"reason":                 reason,
		"settlement_surface":     "public_app",
	})
	s.persistGPMStateBestEffort("connect_reservation_claim_released")
	return true
}

func (s *Service) teardownConnectInterfaceBestEffort(interfaceName string) (string, int, error) {
	teardownTimeout := s.commandTimeout
	if teardownTimeout <= 0 {
		teardownTimeout = defaultCommandTimeout
	}
	teardownCtx, teardownCancel := context.WithTimeout(context.Background(), teardownTimeout)
	defer teardownCancel()
	return s.runEasyNode(teardownCtx, "client-vpn-down", "--force-iface-cleanup", "1", "--iface", interfaceName)
}

func (s *Service) reconcileStaleGPMProductionConnectLaunch(entitlement gpmProductionConnectEntitlement) (int, map[string]any) {
	if s.gpmState == nil || strings.TrimSpace(entitlement.ReservationID) == "" {
		return 0, nil
	}
	now := time.Now().UTC()
	claim, stale := s.gpmState.staleLaunchingReservationClaim(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, now)
	if !stale {
		return 0, nil
	}

	running, known, statusOut, statusErr := s.gpmProductionConnectRuntimeRunning()
	if statusErr != nil || !known {
		errMsg := "stale production reservation launch could not be reconciled from local VPN status"
		if statusErr != nil {
			errMsg = fmt.Sprintf("%s: %v", errMsg, statusErr)
		}
		s.appendGPMAudit("connect_reservation_stale_launch_reconcile_failed", map[string]any{
			"wallet_address":         entitlement.WalletAddress,
			"reservation_id":         entitlement.ReservationID,
			"reservation_session_id": entitlement.ReservationSessionID,
			"claim_status":           claim.Status,
			"status_output":          statusOut,
			"error":                  errMsg,
			"settlement_surface":     "public_app",
		})
		return http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           errMsg,
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"reservation_claim_status":        claim.Status,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}

	if running {
		if !s.gpmState.markReservationConnectLaunched(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, now) {
			return http.StatusConflict, map[string]any{
				"ok":                              false,
				"error":                           "failed to mark stale production reservation launch as launched",
				"connect_allowed":                 false,
				"wallet_address":                  entitlement.WalletAddress,
				"reservation_id":                  entitlement.ReservationID,
				"reservation_session_id":          entitlement.ReservationSessionID,
				"settlement_reservation_required": true,
				"public_app_admin_controls":       false,
			}
		}
		if err := s.persistGPMState("connect_reservation_stale_launch_marked_launched"); err != nil {
			return http.StatusServiceUnavailable, map[string]any{
				"ok":                              false,
				"error":                           "failed to persist reconciled launched production reservation",
				"state_store_error":               err.Error(),
				"connect_allowed":                 false,
				"wallet_address":                  entitlement.WalletAddress,
				"reservation_id":                  entitlement.ReservationID,
				"reservation_session_id":          entitlement.ReservationSessionID,
				"reservation_claim_status":        "launched",
				"settlement_reservation_required": true,
				"public_app_admin_controls":       false,
			}
		}
		s.appendGPMAudit("connect_reservation_stale_launch_marked_launched", map[string]any{
			"wallet_address":         entitlement.WalletAddress,
			"reservation_id":         entitlement.ReservationID,
			"reservation_session_id": entitlement.ReservationSessionID,
			"claim_status":           "launched",
			"status_output":          statusOut,
			"settlement_surface":     "public_app",
		})
		return http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           "stale production reservation launch is already running and has been marked launched",
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"reservation_claim_status":        "launched",
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}

	s.appendGPMAudit("connect_reservation_stale_launch_retained", map[string]any{
		"wallet_address":         entitlement.WalletAddress,
		"reservation_id":         entitlement.ReservationID,
		"reservation_session_id": entitlement.ReservationSessionID,
		"claim_status":           claim.Status,
		"status_output":          statusOut,
		"settlement_surface":     "public_app",
	})
	return http.StatusConflict, map[string]any{
		"ok":                              false,
		"error":                           "stale production reservation launch is not currently proven running; reservation claim retained for session-bound or admin-bound cleanup",
		"connect_allowed":                 false,
		"wallet_address":                  entitlement.WalletAddress,
		"reservation_id":                  entitlement.ReservationID,
		"reservation_session_id":          entitlement.ReservationSessionID,
		"reservation_claim_status":        claim.Status,
		"reservation_claim_retained":      true,
		"settlement_reservation_required": true,
		"public_app_admin_controls":       false,
	}
}

func (s *Service) gpmProductionConnectRuntimeRunning() (bool, bool, string, error) {
	timeout := gpmStaleLaunchStatusTTL
	if s.commandTimeout > 0 && s.commandTimeout < timeout {
		timeout = s.commandTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, _, err := s.runEasyNode(ctx, "client-vpn-status", "--show-json", "1")
	if err != nil {
		return false, false, out, err
	}
	var payload any
	if json.Unmarshal([]byte(out), &payload) != nil {
		return false, false, out, nil
	}
	running, known := gpmStatusPayloadIndicatesVPNRunning(payload)
	return running, known, out, nil
}

func (s *Service) markGPMProductionConnectReservationLaunchStarted(entitlement gpmProductionConnectEntitlement) (int, map[string]any) {
	if s.gpmState == nil || strings.TrimSpace(entitlement.ReservationID) == "" {
		return 0, nil
	}
	if !s.gpmState.markReservationConnectLaunchStarted(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, time.Now().UTC()) {
		return http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           "failed to mark production reservation launch started",
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	if err := s.persistGPMState("connect_reservation_launch_started"); err != nil {
		return http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"error":                           "failed to persist production reservation launch-start before VPN launch",
			"state_store_error":               err.Error(),
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	s.appendGPMAudit("connect_reservation_launch_started", map[string]any{
		"wallet_address":         entitlement.WalletAddress,
		"reservation_id":         entitlement.ReservationID,
		"reservation_session_id": entitlement.ReservationSessionID,
		"claim_status":           "launching",
		"settlement_surface":     "public_app",
	})
	return 0, nil
}

func (s *Service) markGPMProductionConnectReservationLaunched(entitlement gpmProductionConnectEntitlement) (int, map[string]any) {
	if s.gpmState == nil || strings.TrimSpace(entitlement.ReservationID) == "" {
		return 0, nil
	}
	ok := s.gpmState.markReservationConnectLaunched(entitlement.ReservationID, entitlement.ReservationSessionID, entitlement.WalletAddress, time.Now().UTC())
	if !ok {
		return http.StatusConflict, map[string]any{
			"ok":                              false,
			"error":                           "failed to mark production reservation launched",
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	s.appendGPMAudit("connect_reservation_launched", map[string]any{
		"wallet_address":         entitlement.WalletAddress,
		"reservation_id":         entitlement.ReservationID,
		"reservation_session_id": entitlement.ReservationSessionID,
		"claim_status":           "launched",
		"settlement_surface":     "public_app",
	})
	if err := s.persistGPMState("connect_reservation_launched"); err != nil {
		return http.StatusServiceUnavailable, map[string]any{
			"ok":                              false,
			"stage":                           "connect_state_persist",
			"error":                           "failed to persist production reservation launched state after VPN launch",
			"state_store_error":               err.Error(),
			"connect_allowed":                 false,
			"wallet_address":                  entitlement.WalletAddress,
			"reservation_id":                  entitlement.ReservationID,
			"reservation_session_id":          entitlement.ReservationSessionID,
			"reservation_claim_status":        "launched",
			"settlement_reservation_required": true,
			"public_app_admin_controls":       false,
		}
	}
	return 0, nil
}

func (s *Service) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in connectRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	in.BootstrapDirectory = strings.TrimSpace(in.BootstrapDirectory)
	in.InviteKey = strings.TrimSpace(in.InviteKey)
	in.SessionToken = strings.TrimSpace(in.SessionToken)
	in.SessionBootstrapDirectory = strings.TrimSpace(in.SessionBootstrapDirectory)
	in.ReservationID = strings.TrimSpace(in.ReservationID)
	in.ReservationSessionID = strings.TrimSpace(in.ReservationSessionID)
	in.UsageSessionID = strings.TrimSpace(in.UsageSessionID)
	in.VPNSessionID = strings.TrimSpace(in.VPNSessionID)
	manualOverridesProvided := in.BootstrapDirectory != "" || in.InviteKey != ""
	manualBootstrapDirectoryOverrideUsed := in.BootstrapDirectory != ""
	manualInviteKeyOverrideUsed := in.InviteKey != ""
	connectRequireSession := s.connectRequireSessionEffective()
	allowLegacyConnectOverride := s.legacyConnectOverrideAllowed()
	requireTrustedManifestBootstrap := s.legacyConnectRequireTrustedManifestBootstrapEffective()
	if in.SessionBootstrapDirectory != "" && in.SessionToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "session_bootstrap_directory requires session_token",
		})
		return
	}
	if in.SessionBootstrapDirectory != "" && manualOverridesProvided {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "session_bootstrap_directory cannot be combined with bootstrap_directory or invite_key; use the registered session secrets instead",
		})
		return
	}
	if manualOverridesProvided && (connectRequireSession || !allowLegacyConnectOverride) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "manual bootstrap_directory/invite_key overrides are disabled; connect requires a registered session_token",
		})
		return
	}
	if connectRequireSession {
		if in.SessionToken == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "connect requires a registered session_token when session-required mode is enabled",
			})
			return
		}
	}
	if in.PolicyProfile != "" && strings.TrimSpace(in.PathProfile) == "" {
		in.PathProfile = strings.TrimSpace(in.PolicyProfile)
	}
	sessionPathProfile := ""
	sessionBootstrapDirectories := []string{}
	var resolvedSession gpmSession
	sessionPresent := false
	var sessionResolveErr error
	if in.SessionToken != "" {
		resolvedBootstrapDirectories, sessionInvite, resolvedSessionPathProfile, resolveErr := s.resolveConnectSecretsFromSession(r.Context(), in.SessionToken)
		if resolveErr == nil {
			if session, ok, err := s.gpmSessionFromToken(in.SessionToken); err == nil && ok {
				resolvedSession = session
				sessionPresent = true
			}
			if in.SessionBootstrapDirectory != "" {
				selectedBootstrapDirectory, err := canonicalizeBootstrapDirectoryURL(in.SessionBootstrapDirectory)
				if err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]any{
						"ok":    false,
						"error": err.Error(),
					})
					return
				}
				in.SessionBootstrapDirectory = selectedBootstrapDirectory
				selectedTrusted := false
				for _, trustedBootstrapDirectory := range resolvedBootstrapDirectories {
					if trustedBootstrapDirectory == selectedBootstrapDirectory {
						selectedTrusted = true
						break
					}
				}
				if !selectedTrusted {
					writeJSON(w, http.StatusForbidden, map[string]any{
						"ok":    false,
						"error": fmt.Sprintf("session_bootstrap_directory %q is not in the session's trusted bootstrap directories; use one of the registered session bootstrap_directories or re-register the client profile", selectedBootstrapDirectory),
					})
					return
				}
				sessionBootstrapDirectories = append(sessionBootstrapDirectories, selectedBootstrapDirectory)
			}
			if in.BootstrapDirectory == "" {
				if len(sessionBootstrapDirectories) == 0 {
					sessionBootstrapDirectories = append(sessionBootstrapDirectories, resolvedBootstrapDirectories...)
				}
			}
			if in.InviteKey == "" {
				in.InviteKey = sessionInvite
			}
			sessionPathProfile = normalizeOptionalPathProfile(resolvedSessionPathProfile)
		} else {
			sessionResolveErr = resolveErr
		}
	}
	if in.SessionToken != "" && sessionResolveErr != nil {
		statusCode := http.StatusBadRequest
		errMsg := "failed to resolve session_token for connect"
		switch {
		case errors.Is(sessionResolveErr, errConnectSessionTokenInvalidOrExpired):
			statusCode = http.StatusUnauthorized
			errMsg = "invalid or expired session_token"
		case errors.Is(sessionResolveErr, errConnectSessionWalletPolicyInvalid):
			statusCode = http.StatusForbidden
			errMsg = "session no longer satisfies wallet auth policy; sign in again"
		case errors.Is(sessionResolveErr, errConnectSessionWalletBindingRequired):
			statusCode = http.StatusForbidden
			errMsg = "wallet-bound session is required for connect; sign in again with a verified wallet proof"
		case errors.Is(sessionResolveErr, errConnectSessionNotRegistered):
			statusCode = http.StatusForbidden
			errMsg = "session_token is valid but not registered for connect; register the client profile first"
		case errors.Is(sessionResolveErr, errConnectSessionBootstrapRevoked):
			statusCode = http.StatusForbidden
			errMsg = "session_token is valid but no registered bootstrap_directory remains trusted by the current manifest; re-register the client profile"
		case errors.Is(sessionResolveErr, errConnectSessionBootstrapTrustError):
			statusCode = http.StatusBadGateway
			errMsg = "failed to revalidate session bootstrap directories against the trusted manifest"
		case errors.Is(sessionResolveErr, errConnectSessionTokenEmpty):
			errMsg = "session_token is required for connect"
		}
		writeJSON(w, statusCode, map[string]any{
			"ok":    false,
			"error": errMsg,
		})
		return
	}
	bootstrapDirectories := []string{}
	if in.BootstrapDirectory != "" {
		bootstrapDirectories = append(bootstrapDirectories, in.BootstrapDirectory)
	} else {
		bootstrapDirectories = append(bootstrapDirectories, sessionBootstrapDirectories...)
	}
	bootstrapDirectories = normalizeBootstrapDirectories(bootstrapDirectories)
	if manualBootstrapDirectoryOverrideUsed && len(bootstrapDirectories) > 0 {
		in.BootstrapDirectory = bootstrapDirectories[0]
	}
	if len(bootstrapDirectories) == 0 || in.InviteKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "connect requires either bootstrap_directory+invite_key or a registered session_token",
		})
		return
	}
	if sessionPathProfile != "" {
		requestedPathProfileRaw := strings.TrimSpace(in.PathProfile)
		requestedPathProfile := normalizeOptionalPathProfile(in.PathProfile)
		if requestedPathProfileRaw != "" && requestedPathProfile != sessionPathProfile {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("path_profile %q conflicts with registered session path_profile %q; omit path_profile or use the registered profile", requestedPathProfileRaw, sessionPathProfile),
			})
			return
		}
		in.PathProfile = sessionPathProfile
	}
	for _, bootstrapDirectory := range bootstrapDirectories {
		if err := validateBootstrapDirectoryURL(bootstrapDirectory); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": err.Error(),
			})
			return
		}
	}
	if requireTrustedManifestBootstrap && manualBootstrapDirectoryOverrideUsed {
		manifest, _, _, err := s.resolveBootstrapManifest(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("manual bootstrap_directory override requires trusted manifest binding, but trusted manifest resolution failed: %v", err),
			})
			return
		}
		trustedBootstrapSet := make(map[string]struct{}, len(manifest.BootstrapDirectories))
		for _, trustedBootstrapDirectory := range normalizeBootstrapDirectories(manifest.BootstrapDirectories) {
			trustedBootstrapSet[trustedBootstrapDirectory] = struct{}{}
		}
		if _, ok := trustedBootstrapSet[in.BootstrapDirectory]; !ok {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": fmt.Sprintf("manual bootstrap_directory %q is not present in trusted manifest bootstrap_directories", in.BootstrapDirectory),
			})
			return
		}
	}
	if requireTrustedManifestBootstrap && manualInviteKeyOverrideUsed && in.SessionToken != "" {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "manual invite_key override cannot be combined with session_token when trusted manifest binding policy is enabled; use the registered session invite_key",
		})
		return
	}
	if err := validateInviteKey(in.InviteKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	defaults := loadConnectDefaultsFromEnv()
	options := resolveConnectOptions(in, defaults)
	productionMode := s.isGPMProductionMode()
	if !sessionPresent && gpmPathProfileUsesMicroRelay(options.profile) {
		lockReason := "micro-relay path profile requires an authenticated Tier 2 or Tier 3 session with stake and prepaid balance"
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":                       false,
			"error":                    lockReason,
			"path_profile":             options.profile,
			"can_use_micro_relays":     false,
			"contribution_lock_reason": lockReason,
		})
		return
	}
	if sessionPresent {
		if lockReason := gpmMicroRelayUseLock(resolvedSession, options.profile); lockReason != "" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":                       false,
				"error":                    lockReason,
				"path_profile":             options.profile,
				"can_use_micro_relays":     false,
				"contribution_lock_reason": lockReason,
			})
			return
		}
	}
	if options.prodProfile && options.profile == "1hop" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "production profile connect requires a strict 2hop or 3hop profile",
		})
		return
	}
	if !isAllowedVPNInterfaceName(options.interfaceName) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "interface must start with wg, use only [a-zA-Z0-9_.-], and be <= 15 characters",
		})
		return
	}
	if productionMode {
		if options.profile == "1hop" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "production connect requires a strict 2hop or 3hop profile",
			})
			return
		}
		options.prodProfile = true
	}
	if options.prodProfile {
		if !options.installRouteIsSet {
			options.installRoute = true
		}
		if !options.installRoute {
			errorMessage := "production profile connect requires install_route=true so full-tunnel host traffic is routed through GPM; omit install_route to use the production profile default or disable prod_profile for diagnostics"
			if productionMode {
				errorMessage = "production connect requires install_route=true so full-tunnel host traffic is routed through GPM; omit install_route to use the production default or enable an explicit diagnostic no-route override outside the public connect API"
			}
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": errorMessage,
			})
			return
		}
	}
	productionConnectRequired := productionMode || options.prodProfile
	var productionEntitlement gpmProductionConnectEntitlement
	if productionConnectRequired {
		reservationSessionID := strings.TrimSpace(firstNonEmpty(in.ReservationSessionID, in.UsageSessionID, in.VPNSessionID))
		entitlement, statusCode, payload := s.gpmProductionConnectEntitlementGate(r.Context(), sessionPresent, resolvedSession, in.ReservationID, reservationSessionID, true)
		if payload != nil {
			writeJSON(w, statusCode, payload)
			return
		}
		productionEntitlement = entitlement
	}
	policy := deriveConnectPolicy(options)

	inviteKeyPath := ""
	var cleanupInviteKey func()
	defer func() {
		if cleanupInviteKey != nil {
			cleanupInviteKey()
		}
	}()

	lastFailureStage := ""
	lastFailureBootstrapDirectory := ""
	lastFailureRC := 0
	lastFailureOutput := ""
	connectEnv := gpmProductionConnectCommandEnv(productionEntitlement)
	connectSubject := in.InviteKey
	if productionConnectRequired {
		connectSubject = strings.TrimSpace(productionEntitlement.WalletAddress)
	}
	productionReservationClaimActive := false
	if productionConnectRequired {
		if statusCode, payload := s.claimGPMProductionConnectReservation(productionEntitlement); payload != nil {
			writeJSON(w, statusCode, payload)
			return
		}
		productionReservationClaimActive = true
		defer func() {
			if productionReservationClaimActive {
				s.releasePendingGPMProductionConnectReservation(productionEntitlement, "connect command did not launch")
			}
		}()
	}

	for _, bootstrapDirectory := range bootstrapDirectories {
		if options.runPreflight {
			preflightArgs := []string{
				"client-vpn-preflight",
				"--bootstrap-directory", bootstrapDirectory,
				"--discovery-wait-sec", strconv.Itoa(options.discoveryWaitSec),
				"--path-profile", options.profile,
				"--prod-profile", strconv.Itoa(policy.prodFlag),
				"--interface", options.interfaceName,
				"--operator-floor-check", strconv.Itoa(policy.operatorFloorCheck),
				"--operator-min-operators", strconv.Itoa(policy.operatorMin),
				"--issuer-quorum-check", strconv.Itoa(policy.issuerQuorumCheck),
				"--issuer-min-operators", strconv.Itoa(policy.issuerMin),
			}
			preflightOut, preflightRC, preflightErr := s.runEasyNodeWithEnv(r.Context(), connectEnv, preflightArgs...)
			if preflightErr != nil {
				if errors.Is(preflightErr, errCommandConcurrencySaturated) {
					writeJSON(w, http.StatusTooManyRequests, map[string]any{
						"ok":     false,
						"stage":  "preflight",
						"error":  s.commandConcurrencyError(),
						"rc":     preflightRC,
						"output": preflightOut,
					})
					return
				}
				lastFailureStage = "preflight"
				lastFailureBootstrapDirectory = bootstrapDirectory
				lastFailureRC = preflightRC
				lastFailureOutput = preflightOut
				continue
			}
		}

		if inviteKeyPath == "" {
			path, cleanup, stageErr := writeSecretTempFile("tdpn-localapi-invite-", connectSubject)
			if stageErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{
					"ok":    false,
					"stage": "connect",
					"error": "failed to stage invite key",
				})
				return
			}
			inviteKeyPath = path
			cleanupInviteKey = cleanup
		}

		if productionConnectRequired && productionReservationClaimActive {
			if statusCode, payload := s.markGPMProductionConnectReservationLaunchStarted(productionEntitlement); payload != nil {
				writeJSON(w, statusCode, payload)
				return
			}
		}

		upArgs := []string{
			"client-vpn-up",
			"--bootstrap-directory", bootstrapDirectory,
			"--discovery-wait-sec", strconv.Itoa(options.discoveryWaitSec),
			"--subject-file", inviteKeyPath,
			"--min-sources", "1",
			"--min-operators", strconv.Itoa(policy.minOperators),
			"--path-profile", options.profile,
			"--session-reuse", "1",
			"--allow-session-churn", "0",
			"--operator-floor-check", strconv.Itoa(policy.operatorFloorCheck),
			"--operator-min-operators", strconv.Itoa(policy.operatorMin),
			"--issuer-quorum-check", strconv.Itoa(policy.issuerQuorumCheck),
			"--issuer-min-operators", strconv.Itoa(policy.issuerMin),
			"--beta-profile", strconv.Itoa(policy.betaProfile),
			"--prod-profile", strconv.Itoa(policy.prodFlag),
			"--interface", options.interfaceName,
			"--ready-timeout-sec", strconv.Itoa(options.readyTimeoutSec),
			"--install-route", boolTo01(policy.installRoute),
			"--force-restart", "1",
			"--foreground", "0",
		}
		upOut, upRC, upErr := s.runEasyNodeWithEnv(r.Context(), connectEnv, upArgs...)
		if upErr != nil {
			if errors.Is(upErr, errCommandConcurrencySaturated) {
				writeJSON(w, http.StatusTooManyRequests, map[string]any{
					"ok":     false,
					"stage":  "connect",
					"error":  s.commandConcurrencyError(),
					"rc":     upRC,
					"output": upOut,
				})
				return
			}
			lastFailureStage = "connect"
			lastFailureBootstrapDirectory = bootstrapDirectory
			lastFailureRC = upRC
			lastFailureOutput = upOut
			if productionConnectRequired && productionReservationClaimActive {
				productionReservationClaimActive = false
				s.appendGPMAudit("connect_reservation_launch_ambiguous_retained", map[string]any{
					"wallet_address":         productionEntitlement.WalletAddress,
					"reservation_id":         productionEntitlement.ReservationID,
					"reservation_session_id": productionEntitlement.ReservationSessionID,
					"bootstrap_directory":    bootstrapDirectory,
					"rc":                     upRC,
					"error":                  upErr.Error(),
					"settlement_surface":     "public_app",
				})
				writeJSON(w, http.StatusBadGateway, map[string]any{
					"ok":                              false,
					"stage":                           "connect",
					"error":                           "production VPN launch returned an error after reservation launch started; reservation claim retained for reconciliation",
					"command_error":                   upErr.Error(),
					"rc":                              upRC,
					"output":                          upOut,
					"bootstrap_directory":             bootstrapDirectory,
					"connect_allowed":                 false,
					"wallet_address":                  productionEntitlement.WalletAddress,
					"reservation_id":                  productionEntitlement.ReservationID,
					"reservation_session_id":          productionEntitlement.ReservationSessionID,
					"reservation_claim_status":        "launching",
					"reservation_claim_retained":      true,
					"settlement_reservation_required": true,
					"public_app_admin_controls":       false,
				})
				return
			}
			continue
		}
		statusOut, _, statusErr := s.runEasyNode(r.Context(), "client-vpn-status", "--show-json", "1")
		if errors.Is(statusErr, errCommandConcurrencySaturated) && !productionConnectRequired {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"stage": "status",
				"error": s.commandConcurrencyError(),
			})
			return
		}
		var statusPayload any
		if json.Unmarshal([]byte(statusOut), &statusPayload) != nil {
			statusPayload = map[string]any{"raw": statusOut}
		}
		routingPayload := deriveRoutingPostureFromStatusPayload(statusPayload)
		if productionConnectRequired {
			readinessPayload, readinessOK, readinessError := gpmProductionConnectReadinessFromStatusPayload(statusPayload, options.interfaceName)
			if statusErr != nil {
				readinessOK = false
				readinessError = fmt.Sprintf("production VPN status command failed after launch: %v", statusErr)
			}
			if !readinessOK {
				teardownOut, teardownRC, teardownErr := s.teardownConnectInterfaceBestEffort(options.interfaceName)
				claimReleased := false
				claimRetained := productionReservationClaimActive
				if productionReservationClaimActive && statusErr == nil && teardownErr == nil && gpmProductionConnectReadinessProvesStopped(readinessPayload) {
					claimReleased = s.releasePendingGPMProductionConnectReservation(productionEntitlement, "post-launch readiness check proved tunnel stopped")
					productionReservationClaimActive = false
					claimRetained = false
				}
				if productionReservationClaimActive && !claimReleased {
					productionReservationClaimActive = false
					s.appendGPMAudit("connect_reservation_readiness_ambiguous_retained", map[string]any{
						"wallet_address":         productionEntitlement.WalletAddress,
						"reservation_id":         productionEntitlement.ReservationID,
						"reservation_session_id": productionEntitlement.ReservationSessionID,
						"readiness_error":        readinessError,
						"settlement_surface":     "public_app",
					})
				}
				claimStatus := "launching"
				if claimReleased {
					claimStatus = "released"
				}
				statusCode := http.StatusBadGateway
				if errors.Is(statusErr, errCommandConcurrencySaturated) {
					statusCode = http.StatusTooManyRequests
				}
				payload := map[string]any{
					"ok":                              false,
					"stage":                           "status",
					"error":                           "production VPN readiness check failed after launch",
					"readiness_error":                 readinessError,
					"readiness":                       readinessPayload,
					"status":                          statusPayload,
					"routing":                         routingPayload,
					"output":                          upOut,
					"status_output":                   statusOut,
					"bootstrap_directory":             bootstrapDirectory,
					"connect_allowed":                 false,
					"wallet_address":                  productionEntitlement.WalletAddress,
					"reservation_id":                  productionEntitlement.ReservationID,
					"reservation_session_id":          productionEntitlement.ReservationSessionID,
					"reservation_claim_status":        claimStatus,
					"reservation_claim_released":      claimReleased,
					"reservation_claim_retained":      claimRetained,
					"settlement_reservation_required": true,
					"public_app_admin_controls":       false,
					"teardown_attempted":              true,
					"teardown_rc":                     teardownRC,
					"teardown_output":                 teardownOut,
				}
				if statusErr != nil {
					payload["status_error"] = statusErr.Error()
				}
				if teardownErr != nil {
					payload["teardown_error"] = teardownErr.Error()
				}
				writeJSON(w, statusCode, payload)
				return
			}
			if productionReservationClaimActive {
				if statusCode, payload := s.markGPMProductionConnectReservationLaunched(productionEntitlement); payload != nil {
					teardownOut, teardownRC, teardownErr := s.teardownConnectInterfaceBestEffort(options.interfaceName)
					payload["teardown_attempted"] = true
					payload["teardown_rc"] = teardownRC
					payload["teardown_output"] = teardownOut
					if teardownErr != nil {
						payload["teardown_error"] = teardownErr.Error()
					}
					writeJSON(w, statusCode, payload)
					return
				}
				productionReservationClaimActive = false
			}
		}
		s.rememberConnectInterface(options.interfaceName)

		payload := map[string]any{
			"ok":                  true,
			"stage":               "connect",
			"output":              upOut,
			"status":              statusPayload,
			"routing":             routingPayload,
			"profile":             options.profile,
			"bootstrap_directory": bootstrapDirectory,
		}
		if productionConnectRequired {
			payload["connect_allowed"] = true
			payload["wallet_address"] = productionEntitlement.WalletAddress
			payload["reservation_id"] = productionEntitlement.ReservationID
			payload["reservation_session_id"] = productionEntitlement.ReservationSessionID
			payload["reservation_chain_status"] = string(productionEntitlement.ReservationStatus)
			payload["reservation_status_source"] = productionEntitlement.ReservationStatusSource
			payload["reservation_finalization_state"] = productionEntitlement.ReservationFinalizationState
			payload["reservation_claim_status"] = "launched"
			payload["settlement_reservation_required"] = true
			payload["public_app_admin_controls"] = false
		}
		writeJSON(w, http.StatusOK, payload)
		return
	}

	if lastFailureStage == "preflight" {
		writeJSON(w, http.StatusConflict, map[string]any{
			"ok":                  false,
			"stage":               "preflight",
			"rc":                  lastFailureRC,
			"output":              lastFailureOutput,
			"bootstrap_directory": lastFailureBootstrapDirectory,
		})
		return
	}
	writeJSON(w, http.StatusBadGateway, map[string]any{
		"ok":                  false,
		"stage":               "connect",
		"rc":                  lastFailureRC,
		"output":              lastFailureOutput,
		"bootstrap_directory": lastFailureBootstrapDirectory,
	})
}

func (s *Service) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in disconnectRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	if s.isGPMProductionMode() || strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production") {
		sessionToken := gpmSessionTokenFromRequest(r, in.SessionToken)
		if sessionToken == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "session_token is required for production disconnect"})
			return
		}
		session, ok, policyErr := s.gpmSessionFromTokenWithWalletPolicy(sessionToken)
		if policyErr != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"ok":    false,
				"error": "session no longer satisfies wallet auth policy; sign in again: " + policyErr.Error(),
			})
			return
		}
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "invalid or expired session_token"})
			return
		}
		walletAddress := normalizeWalletAddress(session.WalletAddress)
		if !session.WalletBindingVerified || walletAddress == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wallet-bound session is required for production disconnect"})
			return
		}
		if s.gpmState != nil {
			allowed, hasLaunched := s.gpmState.launchedReservationClaimWalletAllowed(walletAddress)
			if hasLaunched && !allowed {
				writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "session wallet does not match the active production reservation claim"})
				return
			}
		}
	}
	interfaceName := s.disconnectInterfaceName()
	// Public disconnect intentionally avoids force-deleting interfaces. Users can
	// still run the explicit support command when they need privileged cleanup.
	out, rc, err := s.runEasyNode(r.Context(), "client-vpn-down", "--force-iface-cleanup", "0")
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
			"error":  "disconnect command failed",
		})
		return
	}
	s.clearRememberedConnectInterface(interfaceName)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stage": "disconnect", "output": out})
}

func (s *Service) handleSetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in setProfileRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	if _, ok := s.gpmAdminSessionFromTokenForResponse(w, in.SessionToken); !ok {
		return
	}
	profile := normalizeOptionalPathProfile(in.PathProfile)
	if profile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "path_profile is required (1hop|2hop|3hop)",
		})
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "config-v1-set-profile", "--path-profile", profile)
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path_profile": profile, "output": out})
}

func (s *Service) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "runtime-doctor", "--show-json", "1")
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
		})
		return
	}
	var payload any
	if json.Unmarshal([]byte(out), &payload) != nil {
		payload = map[string]any{"raw": out}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "diagnostics": payload})
}

func (s *Service) handlePublicDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "runtime-doctor", "--show-json", "1")
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":    false,
			"rc":    rc,
			"error": "public diagnostics collection failed",
		})
		return
	}
	var payload map[string]any
	if json.Unmarshal([]byte(out), &payload) != nil {
		payload = map[string]any{"status": "unknown"}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "diagnostics": publicDiagnosticsPayload(payload)})
}

func publicDiagnosticsPayload(payload map[string]any) map[string]any {
	view := map[string]any{}
	for _, key := range []string{"status", "generated_at_utc"} {
		if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
			view[key] = value
		}
	}
	if summary, ok := payload["summary"].(map[string]any); ok {
		summaryView := map[string]any{}
		for _, key := range []string{"findings_total", "warnings_total", "failures_total"} {
			if value, ok := summary[key]; ok {
				summaryView[key] = value
			}
		}
		if len(summaryView) > 0 {
			view["summary"] = summaryView
		}
	}
	if findings, ok := payload["findings"].([]any); ok {
		findingsView := make([]any, 0, min(len(findings), 100))
		for _, finding := range findings {
			findingMap, ok := finding.(map[string]any)
			if !ok {
				continue
			}
			findingView := map[string]any{}
			for _, key := range []string{"severity", "code", "message", "remediation"} {
				if value, ok := findingMap[key].(string); ok && strings.TrimSpace(value) != "" {
					findingView[key] = value
				}
			}
			if len(findingView) > 0 {
				findingsView = append(findingsView, findingView)
			}
			if len(findingsView) >= 100 {
				break
			}
		}
		if len(findingsView) > 0 {
			view["findings"] = findingsView
		}
		if len(findings) > 100 {
			view["findings_truncated"] = true
		}
	}
	return view
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	if !s.allowUpdate {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "update endpoint disabled (set LOCAL_CONTROL_API_ALLOW_UPDATE=1 to enable)",
		})
		return
	}
	var in updateRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	if _, ok := s.gpmAdminSessionFromTokenForResponse(w, in.SessionToken); !ok {
		return
	}
	args := []string{"self-update", "--show-status", "1"}
	if remote := strings.TrimSpace(in.Remote); remote != "" {
		if !isSafeGitRemoteName(remote) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "invalid remote name (allowed: letters, digits, ., _, -, /; cannot start with '-')",
			})
			return
		}
		args = append(args, "--remote", remote)
	}
	if branch := strings.TrimSpace(in.Branch); branch != "" {
		if !isSafeGitBranchName(branch) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok":    false,
				"error": "invalid branch name",
			})
			return
		}
		args = append(args, "--branch", branch)
	}
	if in.AllowDirty != nil {
		args = append(args, "--allow-dirty", boolTo01(*in.AllowDirty))
	}
	out, rc, err := s.runEasyNode(r.Context(), args...)
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

func (s *Service) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireCommandReadAuth(w, r) {
		return
	}
	s.handleServiceStatusExecution(w, r)
}

func (s *Service) handleServiceStatusExecution(w http.ResponseWriter, r *http.Request) {
	statusConfigured := strings.TrimSpace(s.serviceStatus) != ""
	startConfigured := strings.TrimSpace(s.serviceStart) != ""
	stopConfigured := strings.TrimSpace(s.serviceStop) != ""
	restartConfigured := strings.TrimSpace(s.serviceRestart) != ""

	lifecycle := map[string]any{
		"supported": true,
		"commands": map[string]any{
			"status_configured":  statusConfigured,
			"start_configured":   startConfigured,
			"stop_configured":    stopConfigured,
			"restart_configured": restartConfigured,
		},
	}

	if statusConfigured {
		out, rc, err := s.runLifecycleCommand(r.Context(), s.serviceStatus)
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":    false,
				"error": s.commandConcurrencyError(),
			})
			return
		}
		lifecycle["status"] = map[string]any{
			"ok":     err == nil,
			"rc":     rc,
			"output": out,
		}
		if err != nil {
			lifecycle["status_error"] = "service status command failed"
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": lifecycle,
	})
}

func (s *Service) handleServiceStart(w http.ResponseWriter, r *http.Request) {
	s.handleServiceMutation(w, r, "start", s.serviceStart, "LOCAL_CONTROL_API_SERVICE_START_COMMAND")
}

func (s *Service) handleServiceStop(w http.ResponseWriter, r *http.Request) {
	s.handleServiceMutation(w, r, "stop", s.serviceStop, "LOCAL_CONTROL_API_SERVICE_STOP_COMMAND")
}

func (s *Service) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	s.handleServiceMutation(w, r, "restart", s.serviceRestart, "LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND")
}

func (s *Service) handleServiceMutation(w http.ResponseWriter, r *http.Request, action, command, envVar string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	if !s.legacyServiceMutationsAllowed() {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":      false,
			"error":   fmt.Sprintf("legacy service lifecycle endpoint is disabled in GPM production mode; use /v1/gpm/service/%s with an approved wallet-bound operator/admin session", action),
			"action":  action,
			"hint":    fmt.Sprintf("use /v1/gpm/service/%s with session_token, or set GPM_ALLOW_LEGACY_SERVICE_MUTATIONS=1 only as a break-glass support override", action),
			"release": "gpm-production",
		})
		return
	}
	if strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production") {
		if !s.requireGPMServiceMutationAuth(w, r) {
			return
		}
	}
	legacyHint := fmt.Sprintf("prefer /v1/gpm/service/%s with session_token for approved operator/admin sessions", action)
	s.handleLifecycleMutationExecution(w, r, action, command, envVar, map[string]any{"note": legacyHint})
}

func (s *Service) legacyServiceMutationsAllowed() bool {
	if s == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(s.gpmConnectPolicyMode), "production") {
		return s.gpmAllowLegacyServiceMutations
	}
	return true
}

func (s *Service) handleGPMServiceStart(w http.ResponseWriter, r *http.Request) {
	s.handleGPMServiceMutation(w, r, "start", s.serviceStart, "LOCAL_CONTROL_API_SERVICE_START_COMMAND")
}

func (s *Service) handleGPMServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireGPMServiceMutationAuth(w, r) {
		return
	}
	s.handleServiceStatusExecution(w, r)
}

func (s *Service) handleGPMServiceStop(w http.ResponseWriter, r *http.Request) {
	s.handleGPMServiceMutation(w, r, "stop", s.serviceStop, "LOCAL_CONTROL_API_SERVICE_STOP_COMMAND")
}

func (s *Service) handleGPMServiceRestart(w http.ResponseWriter, r *http.Request) {
	s.handleGPMServiceMutation(w, r, "restart", s.serviceRestart, "LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND")
}

func (s *Service) handleGPMServiceMutation(w http.ResponseWriter, r *http.Request, action, command, envVar string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireGPMServiceMutationAuth(w, r) {
		return
	}
	s.handleLifecycleMutationExecution(w, r, action, command, envVar, nil)
}

func (s *Service) handleLifecycleMutationExecution(w http.ResponseWriter, r *http.Request, action, command, envVar string, responseExtras map[string]any) {
	command = strings.TrimSpace(command)
	if command == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("service %s not configured (set %s)", action, envVar),
		})
		return
	}

	out, rc, err := s.runLifecycleCommand(r.Context(), command)
	if err != nil {
		if errors.Is(err, errCommandConcurrencySaturated) {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"ok":     false,
				"action": action,
				"error":  s.commandConcurrencyError(),
			})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"action": action,
			"error":  fmt.Sprintf("service %s command failed", action),
			"rc":     rc,
			"output": out,
		})
		return
	}
	payload := map[string]any{
		"ok":     true,
		"action": action,
		"rc":     rc,
		"output": out,
	}
	if responseExtras != nil {
		if note, ok := responseExtras["note"]; ok {
			payload["note"] = note
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Service) runEasyNode(ctx context.Context, args ...string) (string, int, error) {
	return s.runEasyNodeWithEnv(ctx, nil, args...)
}

func (s *Service) runEasyNodeWithEnv(ctx context.Context, env []string, args ...string) (string, int, error) {
	scriptPath := strings.TrimSpace(s.scriptPath)
	if scriptPath == "" {
		return "", 127, errors.New("control script path unavailable (set LOCAL_CONTROL_API_SCRIPT to a trusted absolute file path)")
	}

	release, err := s.acquireCommandSlot()
	if err != nil {
		return "", 0, err
	}
	defer release()

	cmdCtx, cancel := context.WithTimeout(ctx, s.commandTimeout)
	defer cancel()

	cmdName, cmdArgs := buildEasyNodeCommandWithPlatform(scriptPath, args, runtime.GOOS, s.commandRunner)
	cmd := exec.CommandContext(cmdCtx, cmdName, cmdArgs...)
	if len(env) > 0 {
		mergedEnv := append([]string{}, os.Environ()...)
		mergedEnv = append(mergedEnv, env...)
		cmd.Env = mergedEnv
	}
	outputBuffer := newBoundedOutputBuffer(maxCommandOutputBytes)
	cmd.Stdout = outputBuffer
	cmd.Stderr = outputBuffer
	err = cmd.Run()
	output := outputBuffer.String()
	if err == nil {
		return output, 0, nil
	}
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return output, 124, fmt.Errorf("command timeout")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, exitErr.ExitCode(), err
	}
	return output, 127, err
}

func (s *Service) runLifecycleCommand(ctx context.Context, rawCommand string) (string, int, error) {
	release, err := s.acquireCommandSlot()
	if err != nil {
		return "", 0, err
	}
	defer release()

	cmdCtx, cancel := context.WithTimeout(ctx, s.commandTimeout)
	defer cancel()

	cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform(rawCommand, runtime.GOOS)
	if err != nil {
		return "", 127, err
	}
	cmd := exec.CommandContext(cmdCtx, cmdName, cmdArgs...)
	outputBuffer := newBoundedOutputBuffer(maxCommandOutputBytes)
	cmd.Stdout = outputBuffer
	cmd.Stderr = outputBuffer
	err = cmd.Run()
	output := outputBuffer.String()
	if err == nil {
		return output, 0, nil
	}
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return output, 124, fmt.Errorf("command timeout")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, exitErr.ExitCode(), err
	}
	return output, 127, err
}

func (s *Service) acquireCommandSlot() (func(), error) {
	if s == nil || s.commandSlots == nil {
		return func() {}, nil
	}
	select {
	case s.commandSlots <- struct{}{}:
		return func() {
			<-s.commandSlots
		}, nil
	default:
		return nil, errCommandConcurrencySaturated
	}
}

func newBoundedOutputBuffer(limit int) *boundedOutputBuffer {
	return &boundedOutputBuffer{limit: limit}
}

func (b *boundedOutputBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b == nil || b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) <= remaining {
		_, _ = b.buf.Write(p)
		return len(p), nil
	}
	_, _ = b.buf.Write(p[:remaining])
	b.truncated = true
	return len(p), nil
}

func (b *boundedOutputBuffer) String() string {
	if b == nil {
		return ""
	}
	output := strings.TrimSpace(b.buf.String())
	if !b.truncated {
		return output
	}
	suffix := fmt.Sprintf("[output truncated to %d bytes]", b.limit)
	if output == "" {
		return suffix
	}
	return output + "\n" + suffix
}

func (s *Service) commandConcurrencyError() string {
	limit := s.maxConcurrentCmds
	if limit <= 0 {
		limit = defaultMaxCommands
	}
	return fmt.Sprintf("command concurrency limit reached (%d); retry later or raise %s", limit, maxCommandsEnv)
}

func resolveControlScriptPath(rawScriptPath string) (string, error) {
	return resolveControlScriptPathWithLookup(rawScriptPath, os.Executable, os.Stat)
}

func resolveControlScriptPathWithLookup(
	rawScriptPath string,
	executablePath func() (string, error),
	statPath func(string) (os.FileInfo, error),
) (string, error) {
	if executablePath == nil {
		executablePath = os.Executable
	}
	if statPath == nil {
		statPath = os.Stat
	}

	scriptPath := strings.TrimSpace(rawScriptPath)
	if scriptPath == "" {
		scriptPath = defaultScriptPath
	}
	execDir := ""

	if !filepath.IsAbs(scriptPath) {
		execPath, err := executablePath()
		if err != nil {
			return "", fmt.Errorf("resolve script path from executable: %w", err)
		}
		execDir = filepath.Clean(strings.TrimSpace(filepath.Dir(execPath)))
		if execDir == "" || execDir == "." {
			return "", errors.New("resolve script path from executable: invalid executable directory")
		}
		candidate := filepath.Clean(filepath.Join(execDir, scriptPath))
		if !pathWithinBase(execDir, candidate) {
			return "", fmt.Errorf("script path escapes executable directory: %q", scriptPath)
		}
		scriptPath = candidate
	}

	scriptPath = filepath.Clean(scriptPath)
	if !filepath.IsAbs(scriptPath) {
		return "", fmt.Errorf("script path is not absolute: %q", scriptPath)
	}
	info, err := statPath(scriptPath)
	if err != nil {
		return "", fmt.Errorf("script path unavailable: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("script path is a directory: %q", scriptPath)
	}
	resolvedPath := scriptPath
	if evalSymlinksPath != nil {
		resolved, err := evalSymlinksPath(scriptPath)
		if err != nil {
			return "", fmt.Errorf("resolve script symlinks: %w", err)
		}
		resolvedPath = filepath.Clean(strings.TrimSpace(resolved))
	}
	if !filepath.IsAbs(resolvedPath) {
		absPath, err := filepath.Abs(resolvedPath)
		if err != nil {
			return "", fmt.Errorf("resolve absolute script path: %w", err)
		}
		resolvedPath = filepath.Clean(absPath)
	}
	if execDir != "" && !pathWithinBase(execDir, resolvedPath) {
		return "", fmt.Errorf("script path resolves outside executable directory: %q", resolvedPath)
	}
	if resolvedPath != scriptPath {
		resolvedInfo, err := statPath(resolvedPath)
		if err != nil {
			return "", fmt.Errorf("resolved script path unavailable: %w", err)
		}
		if resolvedInfo.IsDir() {
			return "", fmt.Errorf("resolved script path is a directory: %q", resolvedPath)
		}
	}
	return resolvedPath, nil
}

func pathWithinBase(baseDir, targetPath string) bool {
	base := filepath.Clean(strings.TrimSpace(baseDir))
	target := filepath.Clean(strings.TrimSpace(targetPath))
	if base == "" || target == "" {
		return false
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	rel = strings.TrimSpace(rel)
	if rel == "." || rel == "" {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func buildEasyNodeCommandWithPlatform(scriptPath string, args []string, goos string, commandRunner string) (string, []string) {
	return buildEasyNodeCommandWithPlatformWithLookup(
		scriptPath,
		args,
		goos,
		commandRunner,
		os.Getenv,
		func(path string) bool {
			info, err := os.Stat(path)
			return err == nil && !info.IsDir()
		},
	)
}

func buildEasyNodeCommandWithPlatformWithLookup(
	scriptPath string,
	args []string,
	goos string,
	commandRunner string,
	getenv func(string) string,
	fileExists func(string) bool,
) (string, []string) {
	runner := strings.TrimSpace(commandRunner)
	if runner != "" {
		cmdArgs := append([]string{scriptPath}, args...)
		return runner, cmdArgs
	}
	if strings.EqualFold(strings.TrimSpace(goos), "windows") {
		ext := strings.ToLower(strings.TrimSpace(filepath.Ext(scriptPath)))
		if ext == ".ps1" {
			cmdArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, args...)
			return "powershell", cmdArgs
		}
		cmdArgs := append([]string{scriptPath}, args...)
		return resolveWindowsBashRunner(getenv, fileExists), cmdArgs
	}
	return scriptPath, args
}

func resolveWindowsBashRunner(getenv func(string) string, fileExists func(string) bool) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	if fileExists == nil {
		fileExists = func(path string) bool {
			info, err := os.Stat(path)
			return err == nil && !info.IsDir()
		}
	}

	override := strings.TrimSpace(getenv("LOCAL_CONTROL_API_GIT_BASH_PATH"))
	if override != "" {
		return override
	}

	preferGitBash := parseBoolWithDefault(getenv("LOCAL_CONTROL_API_PREFER_GIT_BASH"), true)
	if preferGitBash {
		candidates := []string{
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
			`C:\Program Files (x86)\Git\bin\bash.exe`,
			`C:\Program Files (x86)\Git\usr\bin\bash.exe`,
		}
		for _, candidate := range candidates {
			if fileExists(candidate) {
				return candidate
			}
		}
	}

	return "bash"
}

func buildLifecycleCommandWithPlatform(rawCommand string, goos string) (string, []string, error) {
	command := strings.TrimSpace(rawCommand)
	if command == "" {
		return "", nil, fmt.Errorf("%w: command is empty", errLifecycleCommandRejected)
	}
	_ = goos

	parts, err := splitLifecycleCommandLine(command)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", errLifecycleCommandRejected, err)
	}
	if hasDisallowedLifecycleControlOperator(parts) {
		return "", nil, fmt.Errorf("%w: shell control operators are not allowed; invoke an explicit shell binary if required", errLifecycleCommandRejected)
	}
	return parts[0], parts[1:], nil
}

func splitLifecycleCommandLine(command string) ([]string, error) {
	var (
		parts         []string
		current       strings.Builder
		inSingleQuote bool
		inDoubleQuote bool
	)

	flushCurrent := func() {
		if current.Len() == 0 {
			return
		}
		parts = append(parts, current.String())
		current.Reset()
	}

	for i := 0; i < len(command); i++ {
		ch := command[i]
		switch ch {
		case '\'':
			if inDoubleQuote {
				current.WriteByte(ch)
				continue
			}
			inSingleQuote = !inSingleQuote
		case '"':
			if inSingleQuote {
				current.WriteByte(ch)
				continue
			}
			inDoubleQuote = !inDoubleQuote
		case '\\':
			if inSingleQuote {
				current.WriteByte(ch)
				continue
			}
			if i+1 >= len(command) {
				current.WriteByte(ch)
				continue
			}
			next := command[i+1]
			if (!inDoubleQuote && (next == ' ' || next == '\t' || next == '"' || next == '\'' || next == '\\')) ||
				(inDoubleQuote && (next == '"' || next == '\\')) {
				current.WriteByte(next)
				i++
				continue
			}
			current.WriteByte(ch)
		case ' ', '\t':
			if inSingleQuote || inDoubleQuote {
				current.WriteByte(ch)
				continue
			}
			flushCurrent()
		default:
			current.WriteByte(ch)
		}
	}
	if inSingleQuote || inDoubleQuote {
		return nil, errors.New("unterminated quote")
	}
	flushCurrent()
	if len(parts) == 0 {
		return nil, errors.New("command is empty")
	}
	return parts, nil
}

func hasDisallowedLifecycleControlOperator(parts []string) bool {
	for _, part := range parts {
		switch part {
		case "|", "||", "&", "&&", ";", "<", ">", "<<", ">>":
			return true
		}
	}
	return false
}

func decodeJSONBody(r *http.Request, out any) error {
	body, err := readBodyWithLimit(r, maxRequestBodyBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return io.EOF
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func decodeOptionalJSONBody(r *http.Request, out any) error {
	body, err := readBodyWithLimit(r, maxRequestBodyBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func readBodyWithLimit(r *http.Request, maxBytes int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, io.EOF
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxBytes)
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"ok":false,"error":"json marshal failed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func normalizePathProfile(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "2", "2hop", "speed", "fast", "balanced":
		return "2hop"
	case "1", "1hop", "speed-1hop":
		return "1hop"
	case "3", "3hop", "private", "privacy":
		return "3hop"
	default:
		return ""
	}
}

func normalizeOptionalPathProfile(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return normalizePathProfile(raw)
}

func loadConnectDefaultsFromEnv() connectDefaults {
	defaults := connectDefaults{
		pathProfile:   defaultPathProfile,
		interfaceName: defaultVPNInterface,
		runPreflight:  true,
		prodMode:      "0",
	}
	if profile := normalizeOptionalPathProfile(os.Getenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE")); profile != "" {
		defaults.pathProfile = profile
	} else if profile := normalizeOptionalPathProfile(os.Getenv("CLIENT_PATH_PROFILE")); profile != "" {
		defaults.pathProfile = profile
	}
	if iface := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_CONNECT_INTERFACE")); iface != "" {
		defaults.interfaceName = iface
	} else if iface := strings.TrimSpace(os.Getenv("CLIENT_WG_INTERFACE")); iface != "" {
		defaults.interfaceName = iface
	}
	defaults.runPreflight = parseBoolWithDefault(
		firstNonEmpty(
			os.Getenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT"),
			os.Getenv("SIMPLE_CLIENT_RUN_PREFLIGHT"),
		),
		true,
	)
	defaults.prodMode = normalizeProdModeWithDefault(
		firstNonEmpty(
			os.Getenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT"),
			os.Getenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT"),
		),
		"0",
	)
	return defaults
}

func resolveConnectOptions(in connectRequest, defaults connectDefaults) resolvedConnectOptions {
	profile := normalizeOptionalPathProfile(in.PathProfile)
	if profile == "" {
		profile = defaults.pathProfile
	}
	interfaceName := strings.TrimSpace(in.Interface)
	if interfaceName == "" {
		interfaceName = defaults.interfaceName
	}
	discoveryWaitSec := in.DiscoveryWaitSec
	if discoveryWaitSec <= 0 {
		discoveryWaitSec = defaultDiscoveryWaitSec
	}
	readyTimeoutSec := in.ReadyTimeoutSec
	if readyTimeoutSec <= 0 {
		readyTimeoutSec = defaultReadyTimeoutSec
	}
	runPreflight := defaults.runPreflight
	if in.RunPreflight != nil {
		runPreflight = *in.RunPreflight
	}
	prodProfile := defaultProdProfileForMode(defaults.prodMode, profile)
	if in.ProdProfile != nil {
		prodProfile = *in.ProdProfile
	}
	installRoute := false
	installRouteIsSet := in.InstallRoute != nil
	if installRouteIsSet {
		installRoute = *in.InstallRoute
	}
	return resolvedConnectOptions{
		profile:           profile,
		interfaceName:     interfaceName,
		discoveryWaitSec:  discoveryWaitSec,
		readyTimeoutSec:   readyTimeoutSec,
		runPreflight:      runPreflight,
		prodProfile:       prodProfile,
		installRoute:      installRoute,
		installRouteIsSet: installRouteIsSet,
	}
}

func deriveConnectPolicy(options resolvedConnectOptions) connectPolicy {
	policy := connectPolicy{
		minOperators:       2,
		operatorFloorCheck: 1,
		operatorMin:        2,
		issuerQuorumCheck:  1,
		issuerMin:          2,
		betaProfile:        1,
		prodFlag:           0,
		installRoute:       options.installRoute,
	}
	if options.profile == "1hop" {
		policy.minOperators = 1
		policy.operatorFloorCheck = 0
		policy.operatorMin = 1
		policy.issuerQuorumCheck = 0
		policy.issuerMin = 1
		policy.betaProfile = 0
		policy.prodFlag = 0
		if !allowOneHopInstallRouteOverride() {
			policy.installRoute = false
		} else if !options.installRouteIsSet {
			policy.installRoute = false
		}
		return policy
	}
	if options.prodProfile {
		policy.prodFlag = 1
	}
	return policy
}

func allowOneHopInstallRouteOverride() bool {
	return parseBoolWithDefault(
		firstNonEmpty(
			os.Getenv("GPM_ALLOW_1HOP_INSTALL_ROUTE"),
			os.Getenv("TDPN_ALLOW_1HOP_INSTALL_ROUTE"),
			os.Getenv("LOCAL_CONTROL_API_ALLOW_1HOP_INSTALL_ROUTE"),
		),
		false,
	)
}

func defaultProdProfileForMode(mode string, profile string) bool {
	switch mode {
	case "1":
		return true
	case "auto":
		return profile != "1hop"
	default:
		return false
	}
}

func normalizeProdModeWithDefault(raw string, fallback string) string {
	mode := normalizeProdMode(raw)
	if mode != "" {
		return mode
	}
	return fallback
}

func normalizeProdMode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "auto":
		return "auto"
	case "1", "true", "yes", "y", "on":
		return "1"
	case "0", "false", "no", "n", "off":
		return "0"
	default:
		return ""
	}
}

func parseBoolWithDefault(raw string, fallback bool) bool {
	value, ok := parseBool(raw)
	if ok {
		return value
	}
	return fallback
}

func parseBool(raw string) (bool, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "1", "true", "yes", "y", "on":
		return true, true
	case "0", "false", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func preferredEnvValueWithSource(primaryKey string, legacyKey string) (string, string, bool) {
	primary := strings.TrimSpace(os.Getenv(primaryKey))
	if primary != "" {
		return primary, primaryKey, true
	}
	legacy := strings.TrimSpace(os.Getenv(legacyKey))
	if legacy != "" {
		log.Printf("local control api config deprecation: %s is deprecated; migrate to %s", legacyKey, primaryKey)
		return legacy, legacyKey, true
	}
	return "", "default", false
}

func preferredEnvValue(primaryKey string, legacyKey string, fallback string) string {
	if value, _, ok := preferredEnvValueWithSource(primaryKey, legacyKey); ok {
		return value
	}
	return strings.TrimSpace(fallback)
}

func boolTo01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func gpmStatusPayloadIndicatesVPNRunning(statusPayload any) (bool, bool) {
	aliasValues := map[string][]any{}
	collectRoutingAliasValues(statusPayload, nil, aliasValues)
	return findRoutingBool(
		aliasValues,
		"connected",
		"vpn_connected",
		"client_connected",
		"client_vpn_connected",
		"tunnel_connected",
		"wireguard_connected",
		"wireguard_interface_up",
		"interface_up",
		"running",
		"vpn_running",
		"client_vpn_running",
		"tunnel_running",
		"wg_running",
		"session_active",
		"vpn_session_active",
	)
}

func gpmProductionConnectReadinessFromStatusPayload(statusPayload any, expectedInterface string) (map[string]any, bool, string) {
	expectedInterface = strings.TrimSpace(expectedInterface)
	aliasValues := map[string][]any{}
	collectRoutingAliasValues(statusPayload, nil, aliasValues)

	running, runningKnown := findRoutingBool(
		aliasValues,
		"running",
		"vpn_running",
		"client_vpn_running",
		"tunnel_running",
		"wg_running",
	)
	interfaceName, interfaceKnown := findRoutingString(
		aliasValues,
		"interface",
		"iface",
		"interface_name",
		"vpn_interface",
		"client_vpn_interface",
		"wg_interface",
		"wireguard_interface",
		"device",
		"device_name",
	)
	interfaceState, interfaceStateKnown := findRoutingString(
		aliasValues,
		"interface_state",
		"vpn_interface_state",
		"client_vpn_interface_state",
		"wg_interface_state",
		"wireguard_interface_state",
		"link_state",
	)
	interfaceUp, interfaceUpKnown := findRoutingBool(
		aliasValues,
		"interface_up",
		"wireguard_interface_up",
		"wg_interface_up",
		"client_vpn_interface_up",
	)
	interfaceMatches := interfaceKnown && expectedInterface != "" && strings.EqualFold(strings.TrimSpace(interfaceName), expectedInterface)
	interfaceStatePresent := false
	if interfaceStateKnown {
		interfaceStatePresent = gpmProductionInterfaceStatePresent(interfaceState)
	}
	interfacePresent := interfaceMatches && ((interfaceStateKnown && interfaceStatePresent) || (interfaceUpKnown && interfaceUp))

	routeModeRaw, routeModeKnown := findRoutingString(
		aliasValues,
		"route_mode",
		"routing_mode",
		"path_mode",
		"connection_mode",
		"selected_route",
		"active_path",
		"routing_state",
		"routing_status",
		"transport_mode",
		"routing_path_mode",
		"routing_mode_state",
		"mode",
	)
	routeMode := canonicalProductionRouteMode(routeModeRaw)
	if routeMode == "" {
		routeMode, routeModeKnown = inferProductionRouteMode(aliasValues)
	} else {
		routeModeKnown = true
	}
	routeModeSafe := routeMode == "full-tunnel"
	if routeMode == "" {
		routeMode = "unknown"
	}

	readiness := map[string]any{
		"running":                 running,
		"running_known":           runningKnown,
		"interface":               strings.TrimSpace(interfaceName),
		"expected_interface":      expectedInterface,
		"interface_matches":       interfaceMatches,
		"interface_present":       interfacePresent,
		"interface_known":         interfaceKnown,
		"interface_state":         strings.TrimSpace(interfaceState),
		"interface_state_known":   interfaceStateKnown,
		"interface_state_present": interfaceStatePresent,
		"interface_up":            interfaceUp,
		"interface_up_known":      interfaceUpKnown,
		"route_mode":              routeMode,
		"route_mode_known":        routeModeKnown,
		"route_mode_safe":         routeModeSafe,
	}
	switch {
	case !runningKnown:
		return readiness, false, "production VPN status did not report running=true"
	case !running:
		return readiness, false, "production VPN status reported running=false"
	case !interfaceKnown:
		return readiness, false, "production VPN status did not report the WireGuard interface"
	case !interfacePresent:
		return readiness, false, "production VPN status did not report the expected WireGuard interface as present"
	case !routeModeKnown:
		return readiness, false, "production VPN status did not report a route_mode"
	case !routeModeSafe:
		return readiness, false, fmt.Sprintf("production VPN status reported unsafe route_mode=%q", routeMode)
	default:
		return readiness, true, ""
	}
}

func gpmProductionConnectReadinessProvesStopped(readiness map[string]any) bool {
	if readiness == nil {
		return false
	}
	if runningKnown, _ := readiness["running_known"].(bool); runningKnown {
		running, _ := readiness["running"].(bool)
		if !running {
			return true
		}
	}
	if interfaceStateKnown, _ := readiness["interface_state_known"].(bool); interfaceStateKnown {
		interfaceStatePresent, _ := readiness["interface_state_present"].(bool)
		if !interfaceStatePresent {
			return true
		}
	}
	if interfaceUpKnown, _ := readiness["interface_up_known"].(bool); interfaceUpKnown {
		interfaceUp, _ := readiness["interface_up"].(bool)
		if !interfaceUp {
			return true
		}
	}
	return false
}

func gpmProductionInterfaceStatePresent(raw string) bool {
	tokens := splitRoutingModeTokens(raw)
	if len(tokens) == 0 {
		return false
	}
	joined := strings.Join(tokens, "")
	if strings.Contains(joined, "missing") || strings.Contains(joined, "absent") || strings.Contains(joined, "notfound") || containsRoutingToken(tokens, "down") || containsRoutingToken(tokens, "deleted") {
		return false
	}
	return strings.Contains(joined, "present") ||
		strings.Contains(joined, "ready") ||
		containsRoutingToken(tokens, "up") ||
		containsRoutingToken(tokens, "running") ||
		containsRoutingToken(tokens, "active")
}

func inferProductionRouteMode(aliasValues map[string][]any) (string, bool) {
	installRoute, installRouteKnown := findRoutingBool(aliasValues, "install_route", "route_installed", "default_route_installed")
	allowedIPs, allowedIPsKnown := findRoutingString(aliasValues, "allowed_ips", "allowedips", "client_allowed_ips")
	if !installRouteKnown || !allowedIPsKnown {
		return "", false
	}
	fullTunnel := gpmAllowedIPsUseFullTunnel(allowedIPs)
	switch {
	case installRoute && fullTunnel:
		return "full-tunnel", true
	case installRoute:
		return "split-route", true
	case fullTunnel:
		return "no-route", true
	default:
		return "manual-route", true
	}
}

func gpmAllowedIPsUseFullTunnel(raw string) bool {
	hasIPv4Default := false
	hasIPv6Default := false
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		switch token {
		case "0.0.0.0/0":
			hasIPv4Default = true
		case "::/0":
			hasIPv6Default = true
		}
	}
	return hasIPv4Default && hasIPv6Default
}

func canonicalProductionRouteMode(raw string) string {
	tokens := splitRoutingModeTokens(raw)
	if len(tokens) == 0 {
		return ""
	}
	joined := strings.Join(tokens, "")
	hasRoute := containsRoutingToken(tokens, "route")
	switch {
	case strings.Contains(joined, "noroute") || (containsRoutingToken(tokens, "no") && hasRoute):
		return "no-route"
	case strings.Contains(joined, "fulltunnel") || (containsRoutingToken(tokens, "full") && containsRoutingToken(tokens, "tunnel")) || strings.Contains(joined, "defaultroute"):
		return "full-tunnel"
	case strings.Contains(joined, "splitroute") || (containsRoutingToken(tokens, "split") && hasRoute):
		return "split-route"
	case strings.Contains(joined, "manualroute") || (containsRoutingToken(tokens, "manual") && hasRoute):
		return "manual-route"
	default:
		return ""
	}
}

func deriveRoutingPostureFromStatusPayload(statusPayload any) map[string]any {
	aliasValues := map[string][]any{}
	collectRoutingAliasValues(statusPayload, nil, aliasValues)

	modeAliases := []string{
		"routing_mode",
		"path_mode",
		"route_mode",
		"connection_mode",
		"selected_route",
		"active_path",
		"routing_state",
		"routing_status",
		"transport_mode",
		"routing_path_mode",
		"routing_mode_state",
		"mode",
	}
	relayFallbackAliases := []string{
		"relay_fallback_active",
		"relay_fallback",
		"fallback_relay_active",
		"using_relay_fallback",
		"relay_fallback_enabled",
		"routing_relay_fallback_active",
		"routing_relay_fallback",
		"routing_relay_fallback_state",
		"routing_relay_fallback_status",
	}
	directPreferredAliases := []string{
		"direct_preferred",
		"prefer_direct",
		"direct_path_preferred",
		"prefer_direct_path",
		"routing_direct_preferred",
		"routing_prefer_direct",
		"routing_direct_path_preferred",
	}
	detailAliases := []string{
		"routing_detail",
		"route_detail",
		"routing_reason",
		"route_reason",
		"fallback_reason",
		"detail",
		"reason",
		"status_detail",
	}

	mode := ""
	if modeHint, ok := findRoutingString(aliasValues, modeAliases...); ok {
		mode = canonicalRoutingMode(modeHint)
	}
	relayFallbackActive, relayFallbackFound := findRoutingBool(aliasValues, relayFallbackAliases...)
	directPreferred, _ := findRoutingBool(aliasValues, directPreferredAliases...)

	detail := ""
	if detailHint, ok := findRoutingString(aliasValues, detailAliases...); ok {
		if mode == "" {
			if inferred := canonicalRoutingMode(detailHint); inferred != "" {
				mode = inferred
			} else {
				detail = detailHint
			}
		} else {
			detail = detailHint
		}
	}

	if mode == "" {
		switch {
		case relayFallbackActive:
			mode = "relay_fallback"
		case directPreferred:
			mode = "direct"
		}
	}

	if mode == "relay" && relayFallbackFound && relayFallbackActive {
		mode = "relay_fallback"
	}

	switch mode {
	case "direct":
		directPreferred = true
	case "relay_fallback":
		relayFallbackActive = true
		if !directPreferred {
			directPreferred = true
		}
	case "relay":
		// Preserve direct_preferred hint as-is when explicit relay mode is reported.
	default:
		mode = "unknown"
	}

	routing := map[string]any{
		"mode":                  mode,
		"relay_fallback_active": relayFallbackActive,
		"direct_preferred":      directPreferred,
		"source":                "status_payload",
	}
	if detail != "" {
		routing["detail"] = detail
	}
	return routing
}

func collectRoutingAliasValues(node any, path []string, aliasValues map[string][]any) {
	switch typed := node.(type) {
	case map[string]any:
		for rawKey, value := range typed {
			normalizedKey := normalizeRoutingAliasKey(rawKey)
			nextPath := path
			if normalizedKey != "" {
				aliasValues[normalizedKey] = append(aliasValues[normalizedKey], value)
				nextPath = append(append([]string{}, path...), normalizedKey)
				normalizedPath := strings.Join(nextPath, "")
				if normalizedPath != "" {
					aliasValues[normalizedPath] = append(aliasValues[normalizedPath], value)
				}
			}
			collectRoutingAliasValues(value, nextPath, aliasValues)
		}
	case []any:
		for _, value := range typed {
			collectRoutingAliasValues(value, path, aliasValues)
		}
	}
}

func normalizeRoutingAliasKey(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(raw))
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func findRoutingString(aliasValues map[string][]any, aliases ...string) (string, bool) {
	for _, alias := range aliases {
		values, ok := aliasValues[normalizeRoutingAliasKey(alias)]
		if !ok {
			continue
		}
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				continue
			}
			text = strings.TrimSpace(text)
			if text != "" {
				return text, true
			}
		}
	}
	return "", false
}

func findRoutingBool(aliasValues map[string][]any, aliases ...string) (bool, bool) {
	for _, alias := range aliases {
		values, ok := aliasValues[normalizeRoutingAliasKey(alias)]
		if !ok {
			continue
		}
		for _, value := range values {
			parsed, ok := parseRoutingBoolValue(value)
			if ok {
				return parsed, true
			}
		}
	}
	return false, false
}

func parseRoutingBoolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "y", "on", "enabled", "active":
			return true, true
		case "0", "false", "no", "n", "off", "disabled", "inactive":
			return false, true
		}
	case float64:
		if typed == 1 {
			return true, true
		}
		if typed == 0 {
			return false, true
		}
	case int:
		if typed == 1 {
			return true, true
		}
		if typed == 0 {
			return false, true
		}
	case int64:
		if typed == 1 {
			return true, true
		}
		if typed == 0 {
			return false, true
		}
	case json.Number:
		if v, err := typed.Int64(); err == nil {
			if v == 1 {
				return true, true
			}
			if v == 0 {
				return false, true
			}
		}
	}
	return false, false
}

func canonicalRoutingMode(raw string) string {
	tokens := splitRoutingModeTokens(raw)
	if len(tokens) == 0 {
		return ""
	}
	joined := strings.Join(tokens, "")
	hasRelay := containsRoutingToken(tokens, "relay")
	hasFallback := containsRoutingToken(tokens, "fallback") || containsRoutingToken(tokens, "failover")
	if strings.Contains(joined, "relayfallback") || strings.Contains(joined, "fallbackrelay") || (hasRelay && hasFallback) {
		return "relay_fallback"
	}
	if containsRoutingToken(tokens, "direct") || containsRoutingToken(tokens, "mesh") || containsRoutingToken(tokens, "peer") || containsRoutingToken(tokens, "p2p") {
		return "direct"
	}
	if hasRelay || containsRoutingToken(tokens, "proxy") {
		return "relay"
	}
	return ""
}

func splitRoutingModeTokens(raw string) []string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			tokens = append(tokens, field)
		}
	}
	return tokens
}

func containsRoutingToken(tokens []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, token := range tokens {
		if token == target {
			return true
		}
	}
	return false
}

func validateBootstrapDirectoryURL(raw string) error {
	_, err := canonicalizeBootstrapDirectoryURL(raw)
	return err
}

func canonicalizeBootstrapDirectoryURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("bootstrap_directory is required")
	}
	parsed, err := urlpkg.Parse(value)
	if err != nil || !parsed.IsAbs() {
		return "", errors.New("bootstrap_directory must be an absolute URL with http or https scheme")
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	switch scheme {
	case "http", "https":
	default:
		return "", errors.New("bootstrap_directory scheme must be http or https")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", errors.New("bootstrap_directory host is required")
	}
	if parsed.User != nil {
		return "", errors.New("bootstrap_directory userinfo is not allowed")
	}
	if parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(value, "#") {
		return "", errors.New("bootstrap_directory query/fragment are not allowed")
	}
	if scheme == "http" && !hostResolvesToLoopback(host) {
		return "", errors.New("bootstrap_directory must use https for non-loopback hosts")
	}
	return canonicalizeParsedHTTPURL(parsed, true), nil
}

func validateInviteKey(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return errors.New("invite_key is required")
	}
	if len(value) > maxInviteKeyLen {
		return fmt.Errorf("invite_key must be <= %d chars", maxInviteKeyLen)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("invite_key contains invalid control characters")
	}
	return nil
}

func isSafeGitRemoteName(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxGitRemoteNameLen {
		return false
	}
	if strings.HasPrefix(value, "-") {
		return false
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	return gitRemoteNamePattern.MatchString(value)
}

func isSafeGitBranchName(raw string) bool {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxGitBranchNameLen {
		return false
	}
	if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, ".") {
		return false
	}
	if strings.HasSuffix(value, "/") || strings.HasSuffix(value, ".") || strings.HasSuffix(value, ".lock") {
		return false
	}
	if strings.Contains(value, "..") || strings.Contains(value, "//") || strings.Contains(value, "@{") {
		return false
	}
	if strings.ContainsAny(value, " ~^:?*[]\\") {
		return false
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	return true
}

func writeSecretTempFile(prefix string, secret string) (string, func(), error) {
	if strings.TrimSpace(secret) == "" {
		return "", nil, errors.New("secret is empty")
	}
	f, err := os.CreateTemp("", prefix)
	if err != nil {
		return "", nil, err
	}
	path := f.Name()
	cleanup := func() {
		_ = os.Remove(path)
	}
	if runtime.GOOS != "windows" {
		_ = f.Chmod(0o600)
	}
	if _, err := f.WriteString(secret); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func (s *Service) requireMutationAuth(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(s.authToken)
	authRequired := expected != "" || !isLoopbackBindAddr(s.addr) || !s.allowUnauthLoopback
	if !authRequired {
		if !isAllowedUnauthLoopbackOrigin(s.addr, r.Header.Get("Origin")) {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "cross-origin mutation blocked in unauthenticated loopback mode"})
			return false
		}
		return true
	}
	if !s.validateConfiguredAuthToken(w, expected) {
		return false
	}
	provided := parseBearerToken(r.Header.Get("Authorization"))
	if !constantTimeTokenEqual(expected, provided) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return false
	}
	return true
}

func (s *Service) requireCommandReadAuth(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(s.authToken)
	authRequired := expected != "" || !isLoopbackBindAddr(s.addr) || !s.allowUnauthLoopback
	if !authRequired {
		if !isAllowedUnauthLoopbackOrigin(s.addr, r.Header.Get("Origin")) {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "cross-origin command read blocked in unauthenticated loopback mode"})
			return false
		}
		return true
	}
	if !s.validateConfiguredAuthToken(w, expected) {
		return false
	}
	provided := parseBearerToken(r.Header.Get("Authorization"))
	if !constantTimeTokenEqual(expected, provided) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return false
	}
	return true
}

func (s *Service) validateConfiguredAuthToken(w http.ResponseWriter, expected string) bool {
	if expected == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "local api auth token not configured (set LOCAL_CONTROL_API_AUTH_TOKEN or LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1 for developer loopback mode)",
		})
		return false
	}
	if !isLoopbackBindAddr(s.addr) {
		if err := validateRemoteAuthToken(expected); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"error": "local api auth token is too weak for non-loopback bind: " + err.Error(),
			})
			return false
		}
	}
	return true
}

func (s *Service) withLocalAPICORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" {
			if !s.localAPICORSOriginAllowed(origin) {
				if r.Method == http.MethodOptions {
					writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "CORS origin is not allowed"})
					return
				}
			} else {
				headers := w.Header()
				headers.Add("Vary", "Origin")
				headers.Set("Access-Control-Allow-Origin", origin)
				headers.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				headers.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-GPM-Session-Token")
				headers.Set("Access-Control-Max-Age", "600")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) localAPICORSOriginAllowed(origin string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" || s == nil || !isLoopbackBindAddr(s.addr) {
		return false
	}
	if strings.TrimSpace(s.authToken) == "" {
		return isAllowedUnauthLoopbackOrigin(s.addr, origin)
	}
	parsed, err := urlpkg.Parse(origin)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	return isLiteralLoopbackOrLocalhostHost(parsed.Hostname())
}

func parseBearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Fields(raw)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func validateRemoteAuthToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("%s must be set for non-loopback binds", authTokenEnv)
	}
	normalized := strings.ToLower(token)
	if _, weak := weakRemoteAuthTokens[normalized]; weak {
		return fmt.Errorf("%s must not use a known weak/default bearer token for non-loopback binds", authTokenEnv)
	}
	if len(token) < minRemoteAuthTokenLen {
		return fmt.Errorf("%s must be at least %d characters for non-loopback binds", authTokenEnv, minRemoteAuthTokenLen)
	}
	if strings.ContainsFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return fmt.Errorf("%s must not contain whitespace/control characters", authTokenEnv)
	}
	return nil
}

func gpmSessionTokenFromRequest(r *http.Request, explicit string) string {
	token := strings.TrimSpace(explicit)
	if token != "" || r == nil {
		return token
	}
	if token = strings.TrimSpace(r.Header.Get("X-GPM-Session-Token")); token != "" {
		return token
	}
	return strings.TrimSpace(parseBearerToken(r.Header.Get("Authorization")))
}

func constantTimeTokenEqual(expected, provided string) bool {
	if expected == "" || provided == "" {
		return false
	}
	expectedBytes := []byte(expected)
	providedBytes := []byte(provided)
	if len(expectedBytes) != len(providedBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(expectedBytes, providedBytes) == 1
}

func isAllowedUnauthLoopbackOrigin(bindAddr, rawOrigin string) bool {
	rawOrigin = strings.TrimSpace(rawOrigin)
	if rawOrigin == "" {
		return false
	}
	parsed, err := urlpkg.Parse(rawOrigin)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return false
	}
	if !isLiteralLoopbackOrLocalhostHost(host) {
		return false
	}
	expectedPort := bindAddrPort(bindAddr)
	if expectedPort == "" {
		return false
	}
	originPort := strings.TrimSpace(parsed.Port())
	if originPort == "" {
		if parsed.Scheme == "https" {
			originPort = "443"
		} else {
			originPort = "80"
		}
	}
	return originPort == expectedPort
}

func isAllowedVPNInterfaceName(raw string) bool {
	name := strings.TrimSpace(raw)
	if name == "" || len(name) > 15 {
		return false
	}
	return vpnInterfaceNamePattern.MatchString(name)
}

func isLoopbackBindAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}
	host := bindAddrHost(addr)
	if host == "" {
		return false
	}
	return isLiteralLoopbackOrLocalhostHost(host)
}

func isLiteralLoopbackOrLocalhostHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hostResolvesToLoopback(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}

	ctx, cancel := context.WithTimeout(context.Background(), hostResolveTimeout)
	defer cancel()

	addrs, err := lookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if addr.IP == nil || !addr.IP.IsLoopback() {
			return false
		}
	}
	return true
}

func bindAddrHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(addr)
}

func bindAddrPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimSpace(strings.TrimPrefix(addr, ":"))
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(port)
}
