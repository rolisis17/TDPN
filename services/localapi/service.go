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
	"time"
	"unicode"
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
	maxCommandsEnv          = "LOCAL_CONTROL_API_MAX_CONCURRENT_COMMANDS"
	maxInviteKeyLen         = 512
	maxGitRemoteNameLen     = 64
	maxGitBranchNameLen     = 255
)

var vpnInterfaceNamePattern = regexp.MustCompile(`^wg[a-zA-Z0-9_.-]{0,13}$`)
var gitRemoteNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$`)
var errCommandConcurrencySaturated = errors.New("local api command concurrency limit reached")
var errLifecycleCommandRejected = errors.New("lifecycle command rejected")
var evalSymlinksPath = filepath.EvalSymlinks
var lookupIPAddr = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

type Service struct {
	addr                          string
	scriptPath                    string
	commandRunner                 string
	commandTimeout                time.Duration
	maxConcurrentCmds             int
	commandSlots                  chan struct{}
	allowUpdate                   bool
	allowUnauthLoopback           bool
	allowInsecureHTTP             bool
	authToken                     string
	serviceStatus                 string
	serviceStart                  string
	serviceStop                   string
	serviceRestart                string
	gpmConnectRequireSession      bool
	gpmAllowLegacyConnectOverride bool
	gpmConnectPolicyMode          string
	gpmConnectPolicySource        string
	gpmManifestTrustPolicyMode    string
	gpmManifestTrustPolicySource  string
	gpmManifestRequireHTTPS       bool
	gpmManifestRequireHTTPSSource string
	gpmManifestRequireSignature   bool
	gpmManifestRequireSigSource   string
	gpmAuthVerifyPolicyMode       string
	gpmAuthVerifyPolicySource     string
	gpmMainDomain                 string
	gpmManifestURL                string
	gpmManifestCache              string
	gpmManifestMaxAge             time.Duration
	gpmManifestRemoteRefreshIntvl time.Duration
	gpmManifestRemoteRefreshSrc   string
	gpmManifestHMACKey            string
	gpmRoleDefault                string
	gpmApprovalToken              string
	gpmOperatorApprovalRequireSession       bool
	gpmOperatorApprovalRequireSessionSource string
	gpmAuthVerifyCommand          string
	gpmAuthVerifyRequireCommand   bool
	gpmAuthVerifyRequireCmdSource string
	gpmAuthVerifyRequireMetadata  bool
	gpmAuthVerifyRequireWalletExt bool
	gpmAuthVerifyMetadataSource   string
	gpmAuthVerifyWalletExtSource  string
	gpmLegacyEnvAliasesActive     []string
	gpmLegacyEnvAliasWarnings     []string
	gpmAuthSignatureVerifier      gpmAuthSignatureVerifier
	gpmStateStorePath             string
	gpmAuditLogPath               string
	gpmState                      *gpmRuntimeState
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
	PathProfile               string `json:"path_profile,omitempty"`
	PolicyProfile             string `json:"policy_profile,omitempty"`
	Interface                 string `json:"interface,omitempty"`
	DiscoveryWaitSec          int    `json:"discovery_wait_sec,omitempty"`
	ReadyTimeoutSec           int    `json:"ready_timeout_sec,omitempty"`
	RunPreflight              *bool  `json:"run_preflight,omitempty"`
	ProdProfile               *bool  `json:"prod_profile,omitempty"`
	InstallRoute              *bool  `json:"install_route,omitempty"`
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
	PathProfile string `json:"path_profile"`
}

type updateRequest struct {
	Remote     string `json:"remote,omitempty"`
	Branch     string `json:"branch,omitempty"`
	AllowDirty *bool  `json:"allow_dirty,omitempty"`
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
	authToken := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_AUTH_TOKEN"))
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
	gpmRoleDefaultRaw, gpmRoleDefaultSource, gpmRoleDefaultSet := preferredEnvValueWithSource(
		"GPM_DEFAULT_ROLE",
		"TDPN_DEFAULT_ROLE",
	)
	noteLegacyAlias("GPM_DEFAULT_ROLE", gpmRoleDefaultSource)
	gpmRoleDefault := strings.ToLower(gpmRoleDefaultRaw)
	if !gpmRoleDefaultSet {
		gpmRoleDefault = "client"
	}
	if gpmRoleDefault != "operator" && gpmRoleDefault != "admin" {
		gpmRoleDefault = "client"
	}
	gpmManifestHMACKeyRaw, gpmManifestHMACKeySource, gpmManifestHMACKeySet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_HMAC_KEY",
		"TDPN_BOOTSTRAP_MANIFEST_HMAC_KEY",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_HMAC_KEY", gpmManifestHMACKeySource)
	gpmManifestHMACKey := gpmManifestHMACKeyRaw
	if !gpmManifestHMACKeySet {
		gpmManifestHMACKey = ""
	}
	gpmManifestRequireHTTPSRaw, gpmManifestRequireHTTPSSource, gpmManifestRequireHTTPSSet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS",
		"TDPN_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS", gpmManifestRequireHTTPSSource)
	gpmManifestRequireHTTPS := parseBoolWithDefault(gpmManifestRequireHTTPSRaw, false)
	gpmManifestRequireSignatureRaw, gpmManifestRequireSigSource, gpmManifestRequireSignatureSet := preferredEnvValueWithSource(
		"GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE",
		"TDPN_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE",
	)
	noteLegacyAlias("GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE", gpmManifestRequireSigSource)
	gpmManifestRequireSignature := parseBoolWithDefault(gpmManifestRequireSignatureRaw, false)
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
	gpmOperatorApprovalRequireSession := parseBoolWithDefault(gpmOperatorApprovalRequireSessionRaw, false)
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
	gpmAuthVerifyRequireCommand := parseBoolWithDefault(gpmAuthVerifyRequireCommandRaw, false)
	if !gpmAuthVerifyRequireCommandSet {
		gpmAuthVerifyRequireCommand = false
		gpmAuthVerifyRequireCommandSource = "default"
	}
	gpmAuthVerifyRequireMetadataRaw, gpmAuthVerifyMetadataSource, gpmAuthVerifyRequireMetadataSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_REQUIRE_METADATA",
		"TDPN_AUTH_VERIFY_REQUIRE_METADATA",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_REQUIRE_METADATA", gpmAuthVerifyMetadataSource)
	gpmAuthVerifyRequireMetadata := parseBoolWithDefault(gpmAuthVerifyRequireMetadataRaw, false)
	gpmAuthVerifyRequireWalletExtRaw, gpmAuthVerifyWalletExtSource, gpmAuthVerifyRequireWalletExtSet := preferredEnvValueWithSource(
		"GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE",
		"TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE",
	)
	noteLegacyAlias("GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE", gpmAuthVerifyWalletExtSource)
	gpmAuthVerifyRequireWalletExt := parseBoolWithDefault(gpmAuthVerifyRequireWalletExtRaw, false)
	gpmConnectPolicyRaw, gpmConnectPolicySource, gpmConnectPolicySet := preferredEnvValueWithSource(
		"GPM_PRODUCTION_MODE",
		"TDPN_PRODUCTION_MODE",
	)
	noteLegacyAlias("GPM_PRODUCTION_MODE", gpmConnectPolicySource)
	gpmConnectPolicyProduction := parseBoolWithDefault(gpmConnectPolicyRaw, false)
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
	if !gpmManifestRequireHTTPSSet {
		gpmManifestRequireHTTPSSource = "default"
		if gpmConnectPolicyProduction {
			gpmManifestRequireHTTPS = true
			gpmManifestRequireHTTPSSource = "production-default"
		}
	}
	if !gpmManifestRequireSignatureSet {
		gpmManifestRequireSigSource = "default"
		if gpmConnectPolicyProduction {
			gpmManifestRequireSignature = true
			gpmManifestRequireSigSource = "production-default"
		}
	}
	if !gpmAuthVerifyRequireCommandSet && gpmConnectPolicyProduction {
		gpmAuthVerifyRequireCommand = true
		gpmAuthVerifyRequireCommandSource = "production-default"
	}
	if !gpmAuthVerifyRequireMetadataSet {
		gpmAuthVerifyMetadataSource = "default"
		if gpmConnectPolicyProduction {
			gpmAuthVerifyRequireMetadata = true
			gpmAuthVerifyMetadataSource = "production-default"
		}
	}
	if !gpmAuthVerifyRequireWalletExtSet {
		gpmAuthVerifyWalletExtSource = "default"
		if gpmConnectPolicyProduction {
			gpmAuthVerifyRequireWalletExt = true
			gpmAuthVerifyWalletExtSource = "production-default"
		}
	}
	gpmConnectRequireSessionRaw, gpmConnectRequireSessionSource, gpmConnectRequireSessionSet := preferredEnvValueWithSource(
		"GPM_CONNECT_REQUIRE_SESSION",
		"TDPN_CONNECT_REQUIRE_SESSION",
	)
	noteLegacyAlias("GPM_CONNECT_REQUIRE_SESSION", gpmConnectRequireSessionSource)
	gpmConnectRequireSession := parseBoolWithDefault(gpmConnectRequireSessionRaw, false)
	if !gpmConnectRequireSessionSet && gpmConnectPolicyProduction {
		gpmConnectRequireSession = true
	}
	if !gpmOperatorApprovalRequireSessionSet {
		gpmOperatorApprovalRequireSessionSource = "default"
		if gpmConnectPolicyProduction {
			gpmOperatorApprovalRequireSession = true
			gpmOperatorApprovalRequireSessionSource = "production-default"
		}
	}
	gpmAllowLegacyConnectOverrideRaw, gpmAllowLegacyConnectOverrideSource, gpmAllowLegacyConnectOverrideSet := preferredEnvValueWithSource(
		"GPM_ALLOW_LEGACY_CONNECT_OVERRIDE",
		"TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE",
	)
	noteLegacyAlias("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE", gpmAllowLegacyConnectOverrideSource)
	gpmAllowLegacyConnectOverride := parseBoolWithDefault(gpmAllowLegacyConnectOverrideRaw, false)
	if !gpmAllowLegacyConnectOverrideSet && gpmConnectPolicyProduction {
		gpmAllowLegacyConnectOverride = false
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

	svc := &Service{
		addr:                          addr,
		scriptPath:                    scriptPath,
		commandRunner:                 commandRunner,
		commandTimeout:                commandTimeout,
		maxConcurrentCmds:             maxConcurrentCmds,
		commandSlots:                  make(chan struct{}, maxConcurrentCmds),
		allowUpdate:                   allowUpdate,
		allowUnauthLoopback:           allowUnauthLoopback,
		allowInsecureHTTP:             allowInsecureHTTP,
		authToken:                     authToken,
		serviceStatus:                 serviceStatus,
		serviceStart:                  serviceStart,
		serviceStop:                   serviceStop,
		serviceRestart:                serviceRestart,
		gpmConnectRequireSession:      gpmConnectRequireSession,
		gpmAllowLegacyConnectOverride: gpmAllowLegacyConnectOverride,
		gpmConnectPolicyMode:          gpmConnectPolicyMode,
		gpmConnectPolicySource:        gpmConnectPolicySource,
		gpmManifestTrustPolicyMode:    gpmManifestTrustPolicyMode,
		gpmManifestTrustPolicySource:  gpmManifestTrustPolicySource,
		gpmManifestRequireHTTPS:       gpmManifestRequireHTTPS,
		gpmManifestRequireHTTPSSource: gpmManifestRequireHTTPSSource,
		gpmManifestRequireSignature:   gpmManifestRequireSignature,
		gpmManifestRequireSigSource:   gpmManifestRequireSigSource,
		gpmAuthVerifyPolicyMode:       gpmAuthVerifyPolicyMode,
		gpmAuthVerifyPolicySource:     gpmAuthVerifyPolicySource,
		gpmMainDomain:                 strings.TrimRight(strings.TrimSpace(gpmMainDomain), "/"),
		gpmManifestURL:                strings.TrimSpace(gpmManifestURL),
		gpmManifestCache:              strings.TrimSpace(gpmManifestCache),
		gpmManifestMaxAge:             time.Duration(gpmManifestMaxAgeSec) * time.Second,
		gpmManifestRemoteRefreshIntvl: time.Duration(gpmManifestRemoteRefreshIntervalSec) * time.Second,
		gpmManifestRemoteRefreshSrc:   gpmManifestRemoteRefreshSource,
		gpmManifestHMACKey:            gpmManifestHMACKey,
		gpmRoleDefault:                gpmRoleDefault,
		gpmApprovalToken:              gpmApprovalToken,
		gpmOperatorApprovalRequireSession:       gpmOperatorApprovalRequireSession,
		gpmOperatorApprovalRequireSessionSource: gpmOperatorApprovalRequireSessionSource,
		gpmAuthVerifyCommand:          strings.TrimSpace(gpmAuthVerifyCommand),
		gpmAuthVerifyRequireCommand:   gpmAuthVerifyRequireCommand,
		gpmAuthVerifyRequireCmdSource: gpmAuthVerifyRequireCommandSource,
		gpmAuthVerifyRequireMetadata:  gpmAuthVerifyRequireMetadata,
		gpmAuthVerifyRequireWalletExt: gpmAuthVerifyRequireWalletExt,
		gpmAuthVerifyMetadataSource:   gpmAuthVerifyMetadataSource,
		gpmAuthVerifyWalletExtSource:  gpmAuthVerifyWalletExtSource,
		gpmLegacyEnvAliasesActive:     append([]string{}, legacyEnvAliasesActive...),
		gpmLegacyEnvAliasWarnings:     append([]string{}, legacyEnvAliasWarnings...),
		gpmAuthSignatureVerifier:      defaultGPMAuthSignatureVerifier,
		gpmStateStorePath:             strings.TrimSpace(gpmStateStorePath),
		gpmAuditLogPath:               strings.TrimSpace(gpmAuditLogPath),
		gpmState:                      newGPMRuntimeState(),
	}
	svc.loadGPMStateBestEffort()
	return svc
}

func (s *Service) Run(ctx context.Context) error {
	if !isLoopbackBindAddr(s.addr) && !s.allowInsecureHTTP {
		return fmt.Errorf("refusing insecure non-loopback local api bind %q; set %s=1 only for trusted lab environments", s.addr, allowInsecureHTTPEnv)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/config", s.handleConfig)
	mux.HandleFunc("/v1/connect", s.handleConnect)
	mux.HandleFunc("/v1/disconnect", s.handleDisconnect)
	mux.HandleFunc("/v1/set_profile", s.handleSetProfile)
	mux.HandleFunc("/v1/get_diagnostics", s.handleDiagnostics)
	mux.HandleFunc("/v1/update", s.handleUpdate)
	mux.HandleFunc("/v1/service/status", s.handleServiceStatus)
	mux.HandleFunc("/v1/service/start", s.handleServiceStart)
	mux.HandleFunc("/v1/service/stop", s.handleServiceStop)
	mux.HandleFunc("/v1/service/restart", s.handleServiceRestart)
	mux.HandleFunc("/v1/gpm/service/start", s.handleGPMServiceStart)
	mux.HandleFunc("/v1/gpm/service/stop", s.handleGPMServiceStop)
	mux.HandleFunc("/v1/gpm/service/restart", s.handleGPMServiceRestart)
	mux.HandleFunc("/v1/gpm/bootstrap/manifest", s.handleGPMBootstrapManifest)
	mux.HandleFunc("/v1/gpm/auth/challenge", s.handleGPMAuthChallenge)
	mux.HandleFunc("/v1/gpm/auth/verify", s.handleGPMAuthVerify)
	mux.HandleFunc("/v1/gpm/session", s.handleGPMSessionStatus)
	mux.HandleFunc("/v1/gpm/audit/recent", s.handleGPMAuditRecent)
	mux.HandleFunc("/v1/gpm/onboarding/client/register", s.handleGPMClientRegister)
	mux.HandleFunc("/v1/gpm/onboarding/client/status", s.handleGPMClientStatus)
	mux.HandleFunc("/v1/gpm/onboarding/server/status", s.handleGPMServerStatus)
	mux.HandleFunc("/v1/gpm/onboarding/overview", s.handleGPMOnboardingOverview)
	mux.HandleFunc("/v1/gpm/onboarding/operator/apply", s.handleGPMOperatorApply)
	mux.HandleFunc("/v1/gpm/onboarding/operator/status", s.handleGPMOperatorStatus)
	mux.HandleFunc("/v1/gpm/onboarding/operator/list", s.handleGPMOperatorList)
	mux.HandleFunc("/v1/gpm/onboarding/operator/approve", s.handleGPMOperatorApprove)

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": payload})
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
	connectPolicyMode := strings.TrimSpace(s.gpmConnectPolicyMode)
	if connectPolicyMode == "" {
		connectPolicyMode = "default"
	}
	connectPolicySource := strings.TrimSpace(s.gpmConnectPolicySource)
	if connectPolicySource == "" {
		connectPolicySource = "default"
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
	operatorApprovalRequireSessionSource := strings.TrimSpace(s.gpmOperatorApprovalRequireSessionSource)
	if operatorApprovalRequireSessionSource == "" {
		operatorApprovalRequireSessionSource = "default"
	}
	manifestRequireHTTPSSource := strings.TrimSpace(s.gpmManifestRequireHTTPSSource)
	if manifestRequireHTTPSSource == "" {
		manifestRequireHTTPSSource = "default"
	}
	manifestRequireSigSource := strings.TrimSpace(s.gpmManifestRequireSigSource)
	if manifestRequireSigSource == "" {
		manifestRequireSigSource = "default"
	}
	legacyEnvAliasesActive := append([]string{}, s.gpmLegacyEnvAliasesActive...)
	legacyEnvAliasWarnings := append([]string{}, s.gpmLegacyEnvAliasWarnings...)
	legacyEnvAliasWarning := ""
	if len(legacyEnvAliasWarnings) > 0 {
		legacyEnvAliasWarning = strings.Join(legacyEnvAliasWarnings, "; ")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"config": map[string]any{
			"connect_require_session":                                s.gpmConnectRequireSession,
			"allow_legacy_connect_override":                          s.gpmAllowLegacyConnectOverride,
			"connect_policy_mode":                                    connectPolicyMode,
			"connect_policy_source":                                  connectPolicySource,
			"gpm_operator_approval_require_session":                  s.gpmOperatorApprovalRequireSession,
			"gpm_operator_approval_require_session_policy_source":    operatorApprovalRequireSessionSource,
			"gpm_manifest_trust_policy_mode":                         manifestTrustPolicyMode,
			"gpm_manifest_trust_policy_source":                       manifestTrustPolicySource,
			"gpm_manifest_require_https":                             s.gpmManifestRequireHTTPS,
			"gpm_manifest_require_https_policy_source":               manifestRequireHTTPSSource,
			"gpm_manifest_require_signature":                         s.gpmManifestRequireSignature,
			"gpm_manifest_require_signature_policy_source":           manifestRequireSigSource,
			"gpm_auth_verify_policy_mode":                            authVerifyPolicyMode,
			"gpm_auth_verify_policy_source":                          authVerifyPolicySource,
			"gpm_auth_verify_require_command":                        s.gpmAuthVerifyRequireCommand,
			"gpm_auth_verify_require_command_policy_source":          authVerifyRequireCommandSource,
			"gpm_auth_verify_require_metadata":                       s.gpmAuthVerifyRequireMetadata,
			"gpm_auth_verify_require_metadata_policy_source":         authVerifyRequireMetadataSource,
			"gpm_auth_verify_require_wallet_extension_source":        s.gpmAuthVerifyRequireWalletExt,
			"gpm_auth_verify_require_wallet_extension_policy_source": authVerifyRequireWalletExtSource,
			"gpm_auth_verify_command_configured":                     strings.TrimSpace(s.gpmAuthVerifyCommand) != "",
			"gpm_main_domain":                                        strings.TrimSpace(s.gpmMainDomain),
			"gpm_manifest_url":                                       strings.TrimSpace(s.gpmManifestURL),
			"gpm_manifest_cache_path":                                strings.TrimSpace(s.gpmManifestCache),
			"gpm_manifest_cache_max_age_sec":                         manifestCacheMaxAgeSec,
			"gpm_manifest_remote_refresh_interval_sec":               manifestRemoteRefreshIntervalSec,
			"gpm_manifest_remote_refresh_interval_source":            manifestRemoteRefreshIntervalSource,
			"gpm_manifest_resolve_policy":                            "cache_first_bounded_remote_refresh",
			"gpm_manifest_resolve_policy_detail":                     "serve trusted cache immediately; when refresh interval elapses for a still-valid cache, attempt remote refresh and fall back to trusted cache if refresh fails",
			"gpm_legacy_env_aliases_active":                          legacyEnvAliasesActive,
			"gpm_legacy_env_aliases_active_count":                    len(legacyEnvAliasesActive),
			"gpm_legacy_env_alias_warnings":                          legacyEnvAliasWarnings,
			"gpm_legacy_env_aliases_warning":                         legacyEnvAliasWarning,
			"command_timeout_sec":                                    commandTimeoutSec,
			"allow_update":                                           s.allowUpdate,
			"allow_remote":                                           !isLoopbackBindAddr(s.addr),
		},
	})
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
	manualOverridesProvided := in.BootstrapDirectory != "" || in.InviteKey != ""
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
	if manualOverridesProvided && (s.gpmConnectRequireSession || !s.gpmAllowLegacyConnectOverride) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "manual bootstrap_directory/invite_key overrides are disabled; connect requires a registered session_token",
		})
		return
	}
	if s.gpmConnectRequireSession {
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
	var sessionResolveErr error
	if in.SessionToken != "" {
		resolvedBootstrapDirectories, sessionInvite, resolvedSessionPathProfile, resolveErr := s.resolveConnectSecretsFromSession(r.Context(), in.SessionToken)
		if resolveErr == nil {
			if in.SessionBootstrapDirectory != "" {
				selectedBootstrapDirectory := in.SessionBootstrapDirectory
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
	if in.SessionToken != "" && sessionResolveErr != nil && (s.gpmConnectRequireSession || !manualOverridesProvided) {
		statusCode := http.StatusBadRequest
		errMsg := "failed to resolve session_token for connect"
		switch {
		case errors.Is(sessionResolveErr, errConnectSessionTokenInvalidOrExpired):
			statusCode = http.StatusUnauthorized
			errMsg = "invalid or expired session_token"
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
	if err := validateInviteKey(in.InviteKey); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}
	defaults := loadConnectDefaultsFromEnv()
	options := resolveConnectOptions(in, defaults)
	if !isAllowedVPNInterfaceName(options.interfaceName) {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "interface must start with wg, use only [a-zA-Z0-9_.-], and be <= 15 characters",
		})
		return
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

	for _, bootstrapDirectory := range bootstrapDirectories {
		if options.runPreflight {
			preflightArgs := []string{
				"client-vpn-preflight",
				"--bootstrap-directory", bootstrapDirectory,
				"--discovery-wait-sec", strconv.Itoa(options.discoveryWaitSec),
				"--prod-profile", strconv.Itoa(policy.prodFlag),
				"--interface", options.interfaceName,
				"--operator-floor-check", strconv.Itoa(policy.operatorFloorCheck),
				"--operator-min-operators", strconv.Itoa(policy.operatorMin),
				"--issuer-quorum-check", strconv.Itoa(policy.issuerQuorumCheck),
				"--issuer-min-operators", strconv.Itoa(policy.issuerMin),
			}
			preflightOut, preflightRC, preflightErr := s.runEasyNode(r.Context(), preflightArgs...)
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
			path, cleanup, stageErr := writeSecretTempFile("tdpn-localapi-invite-", in.InviteKey)
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
		upOut, upRC, upErr := s.runEasyNode(r.Context(), upArgs...)
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
			continue
		}

		statusOut, _, statusErr := s.runEasyNode(r.Context(), "client-vpn-status", "--show-json", "1")
		if errors.Is(statusErr, errCommandConcurrencySaturated) {
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
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                  true,
			"stage":               "connect",
			"output":              upOut,
			"status":              statusPayload,
			"profile":             options.profile,
			"bootstrap_directory": bootstrapDirectory,
		})
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
	out, rc, err := s.runEasyNode(r.Context(), "client-vpn-down", "--force-iface-cleanup", "1")
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
	legacyHint := fmt.Sprintf("prefer /v1/gpm/service/%s with session_token for approved operator/admin sessions", action)
	s.handleLifecycleMutationExecution(w, r, action, command, envVar, map[string]any{"note": legacyHint})
}

func (s *Service) handleGPMServiceStart(w http.ResponseWriter, r *http.Request) {
	s.handleGPMServiceMutation(w, r, "start", s.serviceStart, "LOCAL_CONTROL_API_SERVICE_START_COMMAND")
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
	installRoute := true
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
		if !options.installRouteIsSet {
			policy.installRoute = false
		}
		return policy
	}
	if options.prodProfile {
		policy.prodFlag = 1
	}
	return policy
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
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
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

func validateBootstrapDirectoryURL(raw string) error {
	value := strings.TrimSpace(raw)
	if value == "" {
		return errors.New("bootstrap_directory is required")
	}
	parsed, err := urlpkg.Parse(value)
	if err != nil || !parsed.IsAbs() {
		return errors.New("bootstrap_directory must be an absolute URL with http or https scheme")
	}
	switch parsed.Scheme {
	case "http", "https":
	default:
		return errors.New("bootstrap_directory scheme must be http or https")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return errors.New("bootstrap_directory host is required")
	}
	if parsed.User != nil {
		return errors.New("bootstrap_directory userinfo is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("bootstrap_directory query/fragment are not allowed")
	}
	if parsed.Scheme == "http" && !hostResolvesToLoopback(host) {
		return errors.New("bootstrap_directory must use https for non-loopback hosts")
	}
	return nil
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
	if expected == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "local api auth token not configured (set LOCAL_CONTROL_API_AUTH_TOKEN or LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1 for developer loopback mode)",
		})
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
	if expected == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok":    false,
			"error": "local api auth token not configured (set LOCAL_CONTROL_API_AUTH_TOKEN or LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1 for developer loopback mode)",
		})
		return false
	}
	provided := parseBearerToken(r.Header.Get("Authorization"))
	if !constantTimeTokenEqual(expected, provided) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return false
	}
	return true
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
	if !hostResolvesToLoopback(host) {
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
	return hostResolvesToLoopback(host)
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
