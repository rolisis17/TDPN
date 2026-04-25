package exit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/policy"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
	"privacynode/pkg/securehttp"
	"privacynode/pkg/settlement"
	"privacynode/pkg/wg"

	"github.com/redis/go-redis/v9"
)

type sessionInfo struct {
	claims        crypto.CapabilityClaims
	seenNonces    map[uint64]struct{}
	highestNonce  uint64
	lastActivity  time.Time
	transport     string
	sessionKeyID  string
	clientInnerIP string
	clientPubKey  string
	peerAddr      string
	peerLastSeen  int64
	downNonce     uint64
	ingressBytes  int64
	egressBytes   int64
}

type Service struct {
	addr                             string
	dataAddr                         string
	issuerURL                        string
	issuerURLs                       []string
	issuerMinSources                 int
	issuerMinOperators               int
	issuerMinKeyVotes                int
	issuerRequireID                  bool
	revocationsURL                   string
	revocationsURLs                  []string
	dataMode                         string
	opaqueSinkAddr                   string
	opaqueSourceAddr                 string
	opaqueEcho                       bool
	wgPubKey                         string
	wgExitIP                         string
	wgMTU                            int
	wgKeepaliveSec                   int
	ipAllocCursor                    uint32
	wgInterface                      string
	wgPrivateKey                     string
	wgListenPort                     int
	wgBackend                        string
	wgKernelProxy                    bool
	wgKernelProxyMax                 int
	wgKernelProxyIdle                time.Duration
	sessionCleanupSec                int
	maxActiveSessions                int
	wgKernelTargetUDP                *net.UDPAddr
	wgManager                        wg.Manager
	liveWGMode                       bool
	wgOnlyMode                       bool
	egressBackend                    string
	egressIface                      string
	egressCIDR                       string
	egressChain                      string
	egressConfigured                 bool
	tokenProofReplayGuard            bool
	tokenProofReplaySharedFileMode   bool
	tokenProofReplayLockTimeout      time.Duration
	tokenProofReplayRedisAddr        string
	tokenProofReplayRedisPassword    string
	tokenProofReplayRedisDB          int
	tokenProofReplayRedisTLS         bool
	tokenProofReplayRedisPrefix      string
	tokenProofReplayRedisDialTimeout time.Duration
	peerRebindAfter                  time.Duration
	revocationRefreshSec             int
	accountingFile                   string
	tokenProofReplayStoreFile        string
	accountingFlushSec               int
	settlementReconcileSec           int
	startupSyncTimeout               time.Duration
	verifyRefreshMinInterval         time.Duration
	exitRelayID                      string
	betaStrict                       bool
	prodStrict                       bool
	strictModeParseErr               error
	enforcer                         *policy.Enforcer
	httpClient                       *http.Client
	httpSrv                          *http.Server
	udpConn                          *net.UDPConn
	opaqueSourceConn                 *net.UDPConn
	opaqueSinkUDP                    *net.UDPAddr

	mu                          sync.RWMutex
	issuerPub                   ed25519.PublicKey
	issuerPubs                  map[string]ed25519.PublicKey
	issuerKeyIssuer             map[string]string
	verifyRefreshMu             sync.Mutex
	verifyRefreshLast           time.Time
	sessions                    map[string]sessionInfo
	wgSessionProxies            map[string]*net.UDPConn
	wgProxyLastSeen             map[string]int64
	proofNonceSeen              map[string]map[string]int64
	metrics                     exitMetrics
	revokedJTI                  map[string]int64
	minTokenEpoch               map[string]int64
	revocationVersion           map[string]int64
	settlement                  settlement.Service
	sessionReserve              int64
	settlementStatus            settlementStatusSnapshot
	tokenProofReplayRedisMu     sync.Mutex
	tokenProofReplayRedisClient *redis.Client
}

type exitMetrics struct {
	AcceptedPackets         uint64 `json:"accepted_packets"`
	DroppedPackets          uint64 `json:"dropped_packets"`
	AcceptedBytes           uint64 `json:"accepted_bytes"`
	DroppedBytes            uint64 `json:"dropped_bytes"`
	AcceptedTier1Packets    uint64 `json:"accepted_tier1_packets"`
	AcceptedTier2Packets    uint64 `json:"accepted_tier2_packets"`
	AcceptedTier3Packets    uint64 `json:"accepted_tier3_packets"`
	DroppedTier1Packets     uint64 `json:"dropped_tier1_packets"`
	DroppedTier2Packets     uint64 `json:"dropped_tier2_packets"`
	DroppedTier3Packets     uint64 `json:"dropped_tier3_packets"`
	DroppedTokenRevoked     uint64 `json:"dropped_token_revoked"`
	DroppedTokenKeyEpoch    uint64 `json:"dropped_token_key_epoch"`
	DroppedTokenProofReplay uint64 `json:"dropped_token_proof_replay"`
	DroppedSourceMismatch   uint64 `json:"dropped_source_mismatch"`
	DroppedNonWGLive        uint64 `json:"dropped_non_wg_live"`
	ForwardedDownlinkPkts   uint64 `json:"forwarded_downlink_packets"`
	ForwardedDownlinkBytes  uint64 `json:"forwarded_downlink_bytes"`
	DroppedDownlinkPkts     uint64 `json:"dropped_downlink_packets"`
	WGProxyCreated          uint64 `json:"wg_proxy_created"`
	WGProxyClosed           uint64 `json:"wg_proxy_closed"`
	WGProxyIdleClosed       uint64 `json:"wg_proxy_idle_closed"`
	WGProxyErrors           uint64 `json:"wg_proxy_errors"`
	WGProxyLimitDrops       uint64 `json:"wg_proxy_limit_drops"`
	ActiveWGProxySessions   uint64 `json:"active_wg_proxy_sessions"`
	ActiveSessions          uint64 `json:"active_sessions"`
	AccountingUpdatedUnix   int64  `json:"accounting_updated_unix"`
}

type settlementStatusSnapshot struct {
	lastReport    settlement.ReconcileReport
	lastCheckedAt time.Time
	lastError     string
}

type settlementStatusResponse struct {
	Enabled                   bool      `json:"enabled"`
	Stale                     bool      `json:"stale"`
	CheckedAt                 time.Time `json:"checked_at,omitempty"`
	ReportGeneratedAt         time.Time `json:"report_generated_at,omitempty"`
	PendingAdapterOperations  int       `json:"pending_adapter_operations"`
	ShadowAdapterConfigured   bool      `json:"shadow_adapter_configured"`
	ShadowAttemptedOperations int       `json:"shadow_attempted_operations"`
	ShadowSubmittedOperations int       `json:"shadow_submitted_operations"`
	ShadowFailedOperations    int       `json:"shadow_failed_operations"`
	PendingOperations         int       `json:"pending_operations"`
	SubmittedOperations       int       `json:"submitted_operations"`
	ConfirmedOperations       int       `json:"confirmed_operations"`
	FailedOperations          int       `json:"failed_operations"`
	LastError                 string    `json:"last_error,omitempty"`
}

var deriveWGPublicKeyFromPrivateFile = wg.DerivePublicKeyFromPrivateFile

// Deterministic valid WireGuard public key used only when EXIT_WG_PUBKEY is unset
// in non-command scaffolding modes.
const defaultExitWGPubKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
const pathControlJSONBodyMaxBytes int64 = 64 * 1024
const defaultMaxActiveSessions = 4096
const sessionReplayWindowSize = 8192
const tokenProofReplayMaxTokenIDs = 4096
const tokenProofReplayMaxNoncesPerToken = 4096
const tokenProofReplayStoreMaxBytes int64 = 8 * 1024 * 1024
const defaultTokenProofReplayLockTimeout = 5 * time.Second
const tokenProofReplayLockRetryInterval = 50 * time.Millisecond
const defaultTokenProofReplayRedisPrefix = "gpm:exit:token-proof-replay"
const defaultTokenProofReplayRedisDialTimeout = 5 * time.Second
const capabilityTokenMaxBytes = 16 * 1024
const capabilityTokenPayloadMaxBytes = 8 * 1024
const serverReadHeaderTimeout = 10 * time.Second
const allowDangerousOutboundPrivateDNS = "EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"
const serverReadTimeout = 15 * time.Second
const serverWriteTimeout = 30 * time.Second
const serverIdleTimeout = 60 * time.Second
const serverMaxHeaderBytes = 1 << 20
const remoteResponseMaxBodyBytes int64 = 1 << 20
const defaultVerifyRefreshMinInterval = 2 * time.Second
const allowDangerousIssuerKeysetReplacement = "EXIT_ALLOW_DANGEROUS_ISSUER_KEYSET_REPLACEMENT"
const allowDangerousCosmosAdapterFallback = "SETTLEMENT_ALLOW_DANGEROUS_COSMOS_INIT_FALLBACK"

var (
	egressChainPattern            = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	egressIfacePattern            = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,64}$`)
	sharedAddressSpaceCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
)

func New() *Service {
	addr := os.Getenv("EXIT_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8084"
	}
	dataAddr := os.Getenv("EXIT_DATA_ADDR")
	if dataAddr == "" {
		dataAddr = "127.0.0.1:51821"
	}
	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "http://127.0.0.1:8082"
	}
	issuerURLs := splitCSV(os.Getenv("ISSUER_URLS"))
	if len(issuerURLs) == 0 {
		issuerURLs = []string{issuerURL}
	}
	issuerURLs = normalizeHTTPURLs(issuerURLs)
	if len(issuerURLs) == 0 {
		normalizedIssuerURL := normalizeHTTPURL(issuerURL)
		if normalizedIssuerURL == "" {
			normalizedIssuerURL = "http://127.0.0.1:8082"
		}
		issuerURLs = []string{normalizedIssuerURL}
	}
	issuerURL = issuerURLs[0]
	issuerMinSources := 1
	if raw := strings.TrimSpace(os.Getenv("EXIT_ISSUER_MIN_SOURCES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			issuerMinSources = n
		}
	}
	issuerMinOperators := 1
	if raw := strings.TrimSpace(os.Getenv("EXIT_ISSUER_MIN_OPERATORS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			issuerMinOperators = n
		}
	}
	issuerMinKeyVotes := issuerMinSources
	if raw := strings.TrimSpace(os.Getenv("EXIT_ISSUER_MIN_KEY_VOTES")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			issuerMinKeyVotes = n
		}
	}
	revocationsURL := os.Getenv("ISSUER_REVOCATIONS_URL")
	revocationsURLs := splitCSV(os.Getenv("ISSUER_REVOCATIONS_URLS"))
	if len(revocationsURLs) == 0 {
		if revocationsURL != "" {
			revocationsURLs = []string{revocationsURL}
		} else {
			revocationsURLs = make([]string, 0, len(issuerURLs))
			for _, u := range issuerURLs {
				revocationsURLs = append(revocationsURLs, joinURL(u, "/v1/revocations"))
			}
		}
	}
	revocationsURLs = normalizeHTTPURLs(revocationsURLs)
	if len(revocationsURLs) == 0 {
		revocationsURLs = []string{joinURL(issuerURL, "/v1/revocations")}
	}
	revocationsURL = revocationsURLs[0]
	dataMode := os.Getenv("DATA_PLANE_MODE")
	if dataMode == "" {
		dataMode = "json"
	}
	opaqueSinkAddr := os.Getenv("EXIT_OPAQUE_SINK_ADDR")
	opaqueSourceAddr := os.Getenv("EXIT_OPAQUE_SOURCE_ADDR")
	wgPubKey := strings.TrimSpace(os.Getenv("EXIT_WG_PUBKEY"))
	wgExitIP := os.Getenv("EXIT_WG_EXIT_IP")
	if wgExitIP == "" {
		wgExitIP = "10.90.0.1/32"
	}
	wgInterface := os.Getenv("EXIT_WG_INTERFACE")
	if wgInterface == "" {
		wgInterface = "wg-exit0"
	}
	wgPrivateKey := os.Getenv("EXIT_WG_PRIVATE_KEY_PATH")
	wgListenPort := 51831
	if raw := strings.TrimSpace(os.Getenv("EXIT_WG_LISTEN_PORT")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 65535 {
			wgListenPort = parsed
		}
	}
	wgBackend := os.Getenv("WG_BACKEND")
	if wgBackend == "" {
		wgBackend = "noop"
	}
	if wgPubKey == "" && wgBackend != "command" {
		wgPubKey = defaultExitWGPubKey
	}
	wgKernelProxy := os.Getenv("EXIT_WG_KERNEL_PROXY") == "1"
	wgKernelProxyMax := 2048
	if v := os.Getenv("EXIT_WG_KERNEL_PROXY_MAX_SESSIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			wgKernelProxyMax = n
		}
	}
	wgKernelProxyIdle := 2 * time.Minute
	if v := os.Getenv("EXIT_WG_KERNEL_PROXY_IDLE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			wgKernelProxyIdle = time.Duration(n) * time.Second
		}
	}
	sessionCleanupSec := 30
	if v := os.Getenv("EXIT_SESSION_CLEANUP_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			sessionCleanupSec = n
		}
	}
	maxActiveSessions := defaultMaxActiveSessions
	if v := strings.TrimSpace(os.Getenv("EXIT_MAX_ACTIVE_SESSIONS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxActiveSessions = n
		}
	}
	var wgManager wg.Manager
	switch wgBackend {
	case "command":
		wgManager = wg.NewCommandManager()
	default:
		wgBackend = "noop"
		wgManager = wg.NewNoopManager()
	}
	liveWGMode := os.Getenv("EXIT_LIVE_WG_MODE") == "1"
	opaqueEcho := true
	if wgBackend == "command" || liveWGMode {
		opaqueEcho = false
	}
	if raw := os.Getenv("EXIT_OPAQUE_ECHO"); raw != "" {
		opaqueEcho = raw != "0"
	}
	egressBackend := os.Getenv("EXIT_EGRESS_BACKEND")
	if egressBackend == "" {
		egressBackend = "noop"
	}
	egressIface := os.Getenv("EXIT_EGRESS_IFACE")
	if egressIface == "" {
		egressIface = "eth0"
	}
	egressCIDR := os.Getenv("EXIT_EGRESS_CIDR")
	if egressCIDR == "" {
		egressCIDR = "10.90.0.0/24"
	}
	egressChain := os.Getenv("EXIT_EGRESS_CHAIN")
	if egressChain == "" {
		egressChain = "PRIVNODE_EGRESS"
	}
	tokenProofReplayGuard := os.Getenv("EXIT_TOKEN_PROOF_REPLAY_GUARD") != "0"
	tokenProofReplayStoreFile := strings.TrimSpace(os.Getenv("EXIT_TOKEN_PROOF_REPLAY_STORE_FILE"))
	if tokenProofReplayStoreFile == "" {
		tokenProofReplayStoreFile = "data/exit_token_proof_replay.json"
	}
	tokenProofReplaySharedFileMode := envEnabled("EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE")
	tokenProofReplayLockTimeout := defaultTokenProofReplayLockTimeout
	if raw := strings.TrimSpace(os.Getenv("EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			tokenProofReplayLockTimeout = time.Duration(n) * time.Second
		}
	}
	tokenProofReplayRedisAddr := strings.TrimSpace(os.Getenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR"))
	tokenProofReplayRedisPassword := os.Getenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_PASSWORD")
	tokenProofReplayRedisDB := 0
	if raw := strings.TrimSpace(os.Getenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_DB")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			tokenProofReplayRedisDB = n
		}
	}
	tokenProofReplayRedisTLS := envEnabled("EXIT_TOKEN_PROOF_REPLAY_REDIS_TLS")
	tokenProofReplayRedisPrefix := normalizeTokenProofReplayRedisPrefix(os.Getenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_PREFIX"))
	tokenProofReplayRedisDialTimeout := defaultTokenProofReplayRedisDialTimeout
	if raw := strings.TrimSpace(os.Getenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			tokenProofReplayRedisDialTimeout = time.Duration(n) * time.Second
		}
	}
	peerRebindAfter := time.Duration(0)
	if v := os.Getenv("EXIT_PEER_REBIND_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			peerRebindAfter = time.Duration(n) * time.Second
		}
	}
	revocationRefreshSec := 15
	if v := os.Getenv("EXIT_REVOCATION_REFRESH_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			revocationRefreshSec = n
		}
	}
	accountingFile := strings.TrimSpace(os.Getenv("EXIT_ACCOUNTING_FILE"))
	accountingFlushSec := 10
	if v := os.Getenv("EXIT_ACCOUNTING_FLUSH_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			accountingFlushSec = n
		}
	}
	settlementReconcileSec := 60
	if v := os.Getenv("EXIT_SETTLEMENT_RECONCILE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			settlementReconcileSec = n
		}
	}
	startupSyncTimeout := time.Duration(0)
	if v := strings.TrimSpace(os.Getenv("EXIT_STARTUP_SYNC_TIMEOUT_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			startupSyncTimeout = time.Duration(n) * time.Second
		}
	}
	verifyRefreshMinInterval := defaultVerifyRefreshMinInterval
	if v := strings.TrimSpace(os.Getenv("EXIT_VERIFY_ISSUER_REFRESH_MIN_INTERVAL_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			verifyRefreshMinInterval = time.Duration(n) * time.Millisecond
		}
	}
	exitRelayID := strings.TrimSpace(os.Getenv("EXIT_RELAY_ID"))
	betaStrict, betaStrictErr := envStrictBoolOr("BETA_STRICT_MODE", "EXIT_BETA_STRICT", false)
	prodStrict, prodStrictErr := envStrictBoolOr("PROD_STRICT_MODE", "EXIT_PROD_STRICT", false)
	strictModeParseErr := firstEnvParseError(
		annotateEnvParseError("BETA_STRICT_MODE/EXIT_BETA_STRICT", betaStrictErr),
		annotateEnvParseError("PROD_STRICT_MODE/EXIT_PROD_STRICT", prodStrictErr),
	)
	sessionReserve := int64(200000)
	if raw := strings.TrimSpace(os.Getenv("EXIT_SESSION_RESERVE_MICROS")); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			sessionReserve = n
		}
	}
	wgOnlyMode := os.Getenv("WG_ONLY_MODE") == "1" || os.Getenv("EXIT_WG_ONLY_MODE") == "1"
	if prodStrict {
		wgOnlyMode = true
	}
	rawIssuerRequireID := strings.TrimSpace(os.Getenv("EXIT_ISSUER_REQUIRE_ID"))
	issuerRequireID := rawIssuerRequireID == "1"
	if rawIssuerRequireID == "" && betaStrict && len(issuerURLs) > 1 {
		issuerRequireID = true
	}
	if startupSyncTimeout <= 0 {
		if betaStrict {
			startupSyncTimeout = 30 * time.Second
		} else if wgOnlyMode || wgBackend == "command" {
			startupSyncTimeout = 8 * time.Second
		}
	}

	return &Service{
		addr:                             addr,
		dataAddr:                         dataAddr,
		issuerURL:                        issuerURL,
		issuerURLs:                       issuerURLs,
		issuerMinSources:                 issuerMinSources,
		issuerMinOperators:               issuerMinOperators,
		issuerMinKeyVotes:                issuerMinKeyVotes,
		issuerRequireID:                  issuerRequireID,
		revocationsURL:                   revocationsURL,
		revocationsURLs:                  revocationsURLs,
		dataMode:                         dataMode,
		opaqueSinkAddr:                   opaqueSinkAddr,
		opaqueSourceAddr:                 opaqueSourceAddr,
		opaqueEcho:                       opaqueEcho,
		wgPubKey:                         wgPubKey,
		wgExitIP:                         wgExitIP,
		wgMTU:                            1280,
		wgKeepaliveSec:                   25,
		ipAllocCursor:                    2,
		wgInterface:                      wgInterface,
		wgPrivateKey:                     wgPrivateKey,
		wgListenPort:                     wgListenPort,
		wgBackend:                        wgBackend,
		wgKernelProxy:                    wgKernelProxy,
		wgKernelProxyMax:                 wgKernelProxyMax,
		wgKernelProxyIdle:                wgKernelProxyIdle,
		sessionCleanupSec:                sessionCleanupSec,
		maxActiveSessions:                maxActiveSessions,
		wgManager:                        wgManager,
		liveWGMode:                       liveWGMode,
		wgOnlyMode:                       wgOnlyMode,
		egressBackend:                    egressBackend,
		egressIface:                      egressIface,
		egressCIDR:                       egressCIDR,
		egressChain:                      egressChain,
		tokenProofReplayGuard:            tokenProofReplayGuard,
		tokenProofReplaySharedFileMode:   tokenProofReplaySharedFileMode,
		tokenProofReplayLockTimeout:      tokenProofReplayLockTimeout,
		tokenProofReplayRedisAddr:        tokenProofReplayRedisAddr,
		tokenProofReplayRedisPassword:    tokenProofReplayRedisPassword,
		tokenProofReplayRedisDB:          tokenProofReplayRedisDB,
		tokenProofReplayRedisTLS:         tokenProofReplayRedisTLS,
		tokenProofReplayRedisPrefix:      tokenProofReplayRedisPrefix,
		tokenProofReplayRedisDialTimeout: tokenProofReplayRedisDialTimeout,
		tokenProofReplayStoreFile:        tokenProofReplayStoreFile,
		peerRebindAfter:                  peerRebindAfter,
		revocationRefreshSec:             revocationRefreshSec,
		accountingFile:                   accountingFile,
		accountingFlushSec:               accountingFlushSec,
		settlementReconcileSec:           settlementReconcileSec,
		startupSyncTimeout:               startupSyncTimeout,
		verifyRefreshMinInterval:         verifyRefreshMinInterval,
		exitRelayID:                      exitRelayID,
		betaStrict:                       betaStrict,
		prodStrict:                       prodStrict,
		strictModeParseErr:               strictModeParseErr,
		enforcer:                         policy.NewEnforcer(),
		httpClient:                       &http.Client{Timeout: 5 * time.Second},
		issuerPubs:                       make(map[string]ed25519.PublicKey),
		issuerKeyIssuer:                  make(map[string]string),
		sessions:                         make(map[string]sessionInfo),
		wgSessionProxies:                 make(map[string]*net.UDPConn),
		wgProxyLastSeen:                  make(map[string]int64),
		proofNonceSeen:                   make(map[string]map[string]int64),
		revokedJTI:                       make(map[string]int64),
		minTokenEpoch:                    make(map[string]int64),
		revocationVersion:                make(map[string]int64),
		settlement:                       newSettlementServiceFromEnv(),
		sessionReserve:                   sessionReserve,
	}
}

func newSettlementServiceFromEnv() settlement.Service {
	pricePerMiB := int64(1000)
	if raw := strings.TrimSpace(os.Getenv("SETTLEMENT_PRICE_PER_MIB_MICROS")); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			pricePerMiB = n
		}
	}
	currency := strings.TrimSpace(os.Getenv("SETTLEMENT_CURRENCY"))
	if currency == "" {
		currency = "TDPNC"
	}
	opts := []settlement.MemoryOption{
		settlement.WithPricePerMiBMicros(pricePerMiB),
		settlement.WithCurrency(currency),
	}
	nativeCurrency := strings.ToUpper(strings.TrimSpace(os.Getenv("SETTLEMENT_NATIVE_CURRENCY")))
	if nativeCurrency != "" && nativeCurrency != strings.ToUpper(currency) {
		rateNumerator := int64(1)
		rateDenominator := int64(1)
		if raw := strings.TrimSpace(os.Getenv("SETTLEMENT_NATIVE_RATE_NUMERATOR")); raw != "" {
			if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
				rateNumerator = n
			}
		}
		if raw := strings.TrimSpace(os.Getenv("SETTLEMENT_NATIVE_RATE_DENOMINATOR")); raw != "" {
			if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
				rateDenominator = n
			}
		}
		opts = append(opts, settlement.WithCurrencyRate(nativeCurrency, rateNumerator, rateDenominator))
	}
	newCosmosAdapterFromEnv := func(prefix string) (*settlement.CosmosAdapter, string, error) {
		endpoint := strings.TrimSpace(os.Getenv(prefix + "ENDPOINT"))
		if endpoint == "" {
			return nil, "", nil
		}
		allowInsecureHTTP := false
		if raw := strings.TrimSpace(os.Getenv(prefix + "ALLOW_INSECURE_HTTP")); raw != "" {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, endpoint, fmt.Errorf("%sALLOW_INSECURE_HTTP must be boolean: %w", prefix, err)
			}
			allowInsecureHTTP = v
		}

		queueSize := 256
		if raw := strings.TrimSpace(os.Getenv(prefix + "QUEUE_SIZE")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				queueSize = n
			}
		}
		retries := 3
		if raw := strings.TrimSpace(os.Getenv(prefix + "MAX_RETRIES")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
				retries = n
			}
		}
		backoff := 250 * time.Millisecond
		if raw := strings.TrimSpace(os.Getenv(prefix + "BASE_BACKOFF_MS")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				backoff = time.Duration(n) * time.Millisecond
			}
		}
		timeout := 4 * time.Second
		if raw := strings.TrimSpace(os.Getenv(prefix + "HTTP_TIMEOUT_MS")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				timeout = time.Duration(n) * time.Millisecond
			}
		}
		submitMode := strings.TrimSpace(os.Getenv(prefix + "SUBMIT_MODE"))
		if submitMode == "" {
			submitMode = settlement.CosmosSubmitModeHTTP
		}
		adapter, err := settlement.NewCosmosAdapter(settlement.CosmosAdapterConfig{
			Endpoint:              endpoint,
			APIKey:                strings.TrimSpace(os.Getenv(prefix + "API_KEY")),
			QueueSize:             queueSize,
			MaxRetries:            retries,
			BaseBackoff:           backoff,
			HTTPTimeout:           timeout,
			AllowInsecureHTTP:     allowInsecureHTTP,
			SubmitMode:            submitMode,
			SignedTxBroadcastPath: strings.TrimSpace(os.Getenv(prefix + "SIGNED_TX_BROADCAST_PATH")),
			SignedTxChainID:       strings.TrimSpace(os.Getenv(prefix + "SIGNED_TX_CHAIN_ID")),
			SignedTxSigner:        strings.TrimSpace(os.Getenv(prefix + "SIGNED_TX_SIGNER")),
			SignedTxSecret:        strings.TrimSpace(os.Getenv(prefix + "SIGNED_TX_SECRET")),
			SignedTxSecretFile:    strings.TrimSpace(os.Getenv(prefix + "SIGNED_TX_SECRET_FILE")),
			SignedTxKeyID:         strings.TrimSpace(os.Getenv(prefix + "SIGNED_TX_KEY_ID")),
		})
		if err != nil {
			return nil, endpoint, err
		}
		return adapter, endpoint, nil
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SETTLEMENT_CHAIN_ADAPTER")), "cosmos") {
		allowDangerousCosmosFallback := envEnabled(allowDangerousCosmosAdapterFallback)
		failCosmosInit := func(format string, args ...any) {
			message := fmt.Sprintf(format, args...)
			if allowDangerousCosmosFallback {
				log.Printf("%s; continuing in dangerous memory-only compatibility mode because %s=1", message, allowDangerousCosmosAdapterFallback)
				return
			}
			panic(fmt.Sprintf("%s; refusing startup (set %s=1 only for dangerous compatibility fallback)", message, allowDangerousCosmosAdapterFallback))
		}

		adapter, endpoint, err := newCosmosAdapterFromEnv("COSMOS_SETTLEMENT_")
		if endpoint == "" {
			failCosmosInit("exit settlement: cosmos adapter requested but COSMOS_SETTLEMENT_ENDPOINT is empty")
		} else if err != nil {
			failCosmosInit("exit settlement: cosmos adapter init failed (%v)", err)
		} else {
			opts = append(opts, settlement.WithChainAdapter(adapter), settlement.WithBlockchainMode(true))
			log.Printf("exit settlement: cosmos adapter enabled endpoint=%s", endpoint)
		}

		shadowAdapter, shadowEndpoint, shadowErr := newCosmosAdapterFromEnv("COSMOS_SETTLEMENT_SHADOW_")
		if shadowEndpoint != "" {
			if shadowErr != nil {
				if allowDangerousCosmosFallback {
					log.Printf("exit settlement: cosmos shadow adapter init failed (%v); continuing without shadow adapter because %s=1", shadowErr, allowDangerousCosmosAdapterFallback)
				} else {
					panic(fmt.Sprintf("exit settlement: cosmos shadow adapter init failed (%v); refusing startup (set %s=1 only for dangerous compatibility fallback)", shadowErr, allowDangerousCosmosAdapterFallback))
				}
			} else {
				opts = append(opts, settlement.WithShadowChainAdapter(shadowAdapter))
				log.Printf("exit settlement: cosmos shadow adapter enabled endpoint=%s", shadowEndpoint)
			}
		}
	}
	return settlement.NewMemoryService(opts...)
}

func (s *Service) Run(ctx context.Context) error {
	httpClient, err := securehttp.NewClient(5 * time.Second)
	if err != nil {
		return fmt.Errorf("exit http tls init: %w", err)
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	configureOutboundDialPolicy(httpClient, envEnabled(allowDangerousOutboundPrivateDNS), s.betaStrict || s.prodStrict)
	s.httpClient = httpClient

	replayMode := s.tokenProofReplayMode()
	log.Printf("exit wg backend=%s iface=%s listen_port=%d kernel_proxy=%t kernel_proxy_max_sessions=%d kernel_proxy_idle_sec=%d opaque_echo=%t token_proof_replay_guard=%t token_proof_replay_mode=%s token_proof_replay_lock_timeout_sec=%d peer_rebind_sec=%d startup_sync_timeout_sec=%d issuer_min_sources=%d issuer_min_operators=%d issuer_min_key_votes=%d issuer_require_id=%t wg_only=%t beta_strict=%t settlement_reconcile_sec=%d",
		s.wgBackend, s.wgInterface, s.wgListenPort, s.wgKernelProxy, s.effectiveWGKernelProxyMax(), int(s.wgKernelProxyIdle/time.Second), s.opaqueEcho, s.tokenProofReplayGuard, replayMode, int(s.effectiveTokenProofReplayLockTimeout()/time.Second), int(s.peerRebindAfter/time.Second), int(s.startupSyncTimeout/time.Second), s.issuerMinSources, s.issuerMinOperators, s.issuerMinKeyVotes, s.issuerRequireID, s.wgOnlyMode, s.betaStrict, s.settlementReconcileSec)
	if err := s.validateRuntimeConfig(); err != nil {
		return err
	}
	if s.tokenProofReplayGuard {
		replayStorePath := strings.TrimSpace(s.tokenProofReplayStoreFile)
		switch replayMode {
		case "redis":
			log.Printf("exit token proof replay guard: using redis addr=%s db=%d tls=%t prefix=%s dial_timeout_sec=%d",
				s.tokenProofReplayRedisAddr, s.tokenProofReplayRedisDB, s.tokenProofReplayRedisTLS, s.effectiveTokenProofReplayRedisPrefix(), int(s.effectiveTokenProofReplayRedisDialTimeout()/time.Second))
			if _, err := s.tokenProofReplayRedisClientOrInit(); err != nil {
				return fmt.Errorf("init token proof replay redis: %w", err)
			}
		case "shared-file":
			log.Printf("exit token proof replay guard: using shared file-backed store path=%s lock_timeout_sec=%d", replayStorePath, int(s.effectiveTokenProofReplayLockTimeout()/time.Second))
		case "file":
			log.Printf("exit token proof replay guard: using file-backed store path=%s (instance-local persistence only; use shared durable replay storage for multi-instance deployments)", replayStorePath)
		default:
			log.Printf("exit token proof replay guard: persistence disabled (in-memory only); restart or multi-instance deployments may accept duplicate proofs")
		}
		if replayMode == "file" || replayMode == "shared-file" {
			if err := s.loadTokenProofReplayStore(time.Now().Unix()); err != nil {
				return fmt.Errorf("load token proof replay store: %w", err)
			}
			bucketCount, nonceCount := s.tokenProofReplayStats()
			log.Printf("exit token proof replay guard: loaded buckets=%d nonces=%d", bucketCount, nonceCount)
		}
	}
	defer s.closeAllWGKernelSessionProxies()
	if s.wgBackend == "command" {
		if err := wg.PreflightCommandBackend(ctx, s.wgInterface, s.wgPrivateKey); err != nil {
			return fmt.Errorf("exit wg preflight failed: %w", err)
		}
		if err := s.ensureCommandWGPubKey(ctx); err != nil {
			return fmt.Errorf("exit wg pubkey init failed: %w", err)
		}
	}
	if s.wgKernelProxy {
		targetAddr := fmt.Sprintf("127.0.0.1:%d", s.wgListenPort)
		target, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return fmt.Errorf("invalid wg kernel proxy target: %w", err)
		}
		s.wgKernelTargetUDP = target
		log.Printf("exit wg kernel proxy target=%s", targetAddr)
	}
	if s.opaqueSinkAddr != "" {
		sink, err := net.ResolveUDPAddr("udp", s.opaqueSinkAddr)
		if err != nil {
			return fmt.Errorf("invalid EXIT_OPAQUE_SINK_ADDR: %w", err)
		}
		s.opaqueSinkUDP = sink
		log.Printf("exit opaque sink enabled addr=%s", s.opaqueSinkAddr)
	}
	if err := s.ensureStartupIssuerSync(ctx); err != nil {
		return err
	}
	if err := s.configureEgress(ctx); err != nil {
		log.Printf("exit egress setup failed: %v", err)
	}
	defer func() {
		if err := s.teardownEgress(context.Background()); err != nil {
			log.Printf("exit egress cleanup failed: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/path/open", s.handlePathOpen)
	mux.HandleFunc("/v1/path/close", s.handlePathClose)
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/v1/settlement/status", s.handleSettlementStatus)

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadTimeout:       serverReadTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    serverMaxHeaderBytes,
	}
	errCh := make(chan error, 2)
	go func() {
		log.Printf("exit listening on %s", s.addr)
		errCh <- securehttp.ListenAndServe(s.httpSrv)
	}()

	if err := s.startUDP(ctx, errCh); err != nil {
		return err
	}
	if err := s.startOpaqueSource(ctx, errCh); err != nil {
		return err
	}

	refreshTicker := time.NewTicker(30 * time.Second)
	defer refreshTicker.Stop()
	revocationTicker := time.NewTicker(time.Duration(s.revocationRefreshSec) * time.Second)
	defer revocationTicker.Stop()
	cleanupEvery := s.sessionCleanupSec
	if cleanupEvery <= 0 {
		cleanupEvery = 30
	}
	cleanupTicker := time.NewTicker(time.Duration(cleanupEvery) * time.Second)
	defer cleanupTicker.Stop()
	var accountingTicker *time.Ticker
	if s.accountingFile != "" {
		accountingTicker = time.NewTicker(time.Duration(s.accountingFlushSec) * time.Second)
		defer accountingTicker.Stop()
	}
	var settlementReconcileTicker *time.Ticker
	if s.settlementReconcileSec > 0 && s.settlement != nil {
		settlementReconcileTicker = time.NewTicker(time.Duration(s.settlementReconcileSec) * time.Second)
		defer settlementReconcileTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpSrv.Shutdown(shutdownCtx)
			if s.udpConn != nil {
				_ = s.udpConn.Close()
			}
			if s.opaqueSourceConn != nil {
				_ = s.opaqueSourceConn.Close()
			}
			s.closeAllWGKernelSessionProxies()
			if err := s.flushAccountingSnapshot(time.Now()); err != nil {
				log.Printf("exit accounting flush failed: %v", err)
			}
			return ctx.Err()
		case err := <-errCh:
			if err == http.ErrServerClosed || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		case <-refreshTicker.C:
			if err := s.refreshIssuerKeys(ctx); err != nil {
				log.Printf("exit key refresh failed: %v", err)
			}
		case <-revocationTicker.C:
			if err := s.refreshRevocations(ctx); err != nil {
				log.Printf("exit revocation refresh failed: %v", err)
			}
		case <-cleanupTicker.C:
			s.cleanupExpiredSessions(time.Now())
		case <-tickerC(settlementReconcileTicker):
			reconcileCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			s.reconcileSettlement(reconcileCtx)
			cancel()
		case <-tickerC(accountingTicker):
			if err := s.flushAccountingSnapshot(time.Now()); err != nil {
				log.Printf("exit accounting flush failed: %v", err)
			}
		}
	}
}

func (s *Service) validateRuntimeConfig() error {
	if s.strictModeParseErr != nil {
		return s.strictModeParseErr
	}
	if s.strictPathOpenExitIdentityBinding() && strings.TrimSpace(s.exitRelayID) == "" {
		return fmt.Errorf("strict exit identity binding requires EXIT_RELAY_ID")
	}
	if securehttp.Enabled() {
		if s.prodStrict && securehttp.InsecureSkipVerifyConfigured() {
			return fmt.Errorf("PROD_STRICT_MODE forbids MTLS_INSECURE_SKIP_VERIFY")
		}
		if err := securehttp.Validate(); err != nil {
			return fmt.Errorf("invalid mTLS config: %w", err)
		}
	}
	if s.startupSyncTimeout < 0 {
		return fmt.Errorf("EXIT_STARTUP_SYNC_TIMEOUT_SEC must be >=0")
	}
	if s.wgKernelProxyMax < 0 {
		return fmt.Errorf("EXIT_WG_KERNEL_PROXY_MAX_SESSIONS must be >=0")
	}
	if s.wgKernelProxyIdle < 0 {
		return fmt.Errorf("EXIT_WG_KERNEL_PROXY_IDLE_SEC must be >=0")
	}
	if s.sessionCleanupSec < 0 {
		return fmt.Errorf("EXIT_SESSION_CLEANUP_SEC must be >0")
	}
	if s.sessionCleanupSec == 0 {
		s.sessionCleanupSec = 30
	}
	if s.settlementReconcileSec < 0 {
		return fmt.Errorf("EXIT_SETTLEMENT_RECONCILE_SEC must be >=0")
	}
	if s.wgListenPort == 0 {
		s.wgListenPort = 51831
	}
	if s.wgListenPort <= 0 || s.wgListenPort > 65535 {
		return fmt.Errorf("EXIT_WG_LISTEN_PORT must be in 1..65535")
	}
	if s.wgBackend == "command" {
		if s.dataMode != "opaque" {
			return fmt.Errorf("WG_BACKEND=command requires DATA_PLANE_MODE=opaque")
		}
		if s.wgPrivateKey == "" {
			return fmt.Errorf("WG_BACKEND=command requires EXIT_WG_PRIVATE_KEY_PATH")
		}
		if strings.TrimSpace(s.dataAddr) == "" {
			s.dataAddr = "127.0.0.1:51821"
		}
		dataPort, err := udpPortOf(s.dataAddr)
		if err != nil {
			return fmt.Errorf("invalid EXIT_DATA_ADDR: %w", err)
		}
		if dataPort == s.wgListenPort {
			return fmt.Errorf("EXIT_DATA_ADDR port conflicts with EXIT_WG_LISTEN_PORT; choose distinct ports")
		}
	}
	if s.wgKernelProxy {
		if s.dataMode != "opaque" {
			return fmt.Errorf("EXIT_WG_KERNEL_PROXY requires DATA_PLANE_MODE=opaque")
		}
		if s.wgBackend != "command" {
			return fmt.Errorf("EXIT_WG_KERNEL_PROXY requires WG_BACKEND=command")
		}
	}
	if s.liveWGMode {
		if s.dataMode != "opaque" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires DATA_PLANE_MODE=opaque")
		}
		if s.wgBackend != "command" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires WG_BACKEND=command")
		}
		if s.wgPrivateKey == "" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_WG_PRIVATE_KEY_PATH")
		}
		if s.opaqueEcho {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_OPAQUE_ECHO=0")
		}
		if strings.TrimSpace(s.opaqueSinkAddr) == "" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_OPAQUE_SINK_ADDR")
		}
		if strings.TrimSpace(s.opaqueSourceAddr) == "" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_OPAQUE_SOURCE_ADDR")
		}
	}
	if s.wgOnlyMode {
		if s.dataMode != "opaque" {
			return fmt.Errorf("WG_ONLY_MODE requires DATA_PLANE_MODE=opaque")
		}
		if s.wgBackend != "command" {
			return fmt.Errorf("WG_ONLY_MODE requires WG_BACKEND=command")
		}
		if !s.wgKernelProxy {
			return fmt.Errorf("WG_ONLY_MODE requires EXIT_WG_KERNEL_PROXY=1")
		}
		if !s.liveWGMode {
			return fmt.Errorf("WG_ONLY_MODE requires EXIT_LIVE_WG_MODE=1")
		}
		if s.opaqueEcho {
			return fmt.Errorf("WG_ONLY_MODE requires EXIT_OPAQUE_ECHO=0")
		}
		if strings.TrimSpace(s.opaqueSinkAddr) == "" {
			return fmt.Errorf("WG_ONLY_MODE requires EXIT_OPAQUE_SINK_ADDR")
		}
		if strings.TrimSpace(s.opaqueSourceAddr) == "" {
			return fmt.Errorf("WG_ONLY_MODE requires EXIT_OPAQUE_SOURCE_ADDR")
		}
		if s.startupSyncTimeout <= 0 {
			return fmt.Errorf("WG_ONLY_MODE requires EXIT_STARTUP_SYNC_TIMEOUT_SEC>0")
		}
	}
	if s.wgBackend != "command" {
		if !wg.IsValidPublicKey(strings.TrimSpace(s.wgPubKey)) {
			return fmt.Errorf("EXIT_WG_PUBKEY must be a valid WireGuard public key")
		}
	}
	if s.betaStrict {
		if s.dataMode != "opaque" {
			return fmt.Errorf("BETA_STRICT_MODE requires DATA_PLANE_MODE=opaque")
		}
		if s.wgBackend != "command" {
			return fmt.Errorf("BETA_STRICT_MODE requires WG_BACKEND=command")
		}
		if !s.wgKernelProxy {
			return fmt.Errorf("BETA_STRICT_MODE requires EXIT_WG_KERNEL_PROXY=1")
		}
		if !s.liveWGMode {
			return fmt.Errorf("BETA_STRICT_MODE requires EXIT_LIVE_WG_MODE=1")
		}
		if s.opaqueEcho {
			return fmt.Errorf("BETA_STRICT_MODE requires EXIT_OPAQUE_ECHO=0")
		}
		if !s.tokenProofReplayGuard {
			return fmt.Errorf("BETA_STRICT_MODE requires EXIT_TOKEN_PROOF_REPLAY_GUARD=1")
		}
		if s.peerRebindAfter > 0 {
			return fmt.Errorf("BETA_STRICT_MODE requires EXIT_PEER_REBIND_SEC=0")
		}
		if envEnabled(allowDangerousOutboundPrivateDNS) {
			return fmt.Errorf("BETA_STRICT_MODE forbids %s", allowDangerousOutboundPrivateDNS)
		}
		if envEnabled(allowDangerousIssuerKeysetReplacement) {
			return fmt.Errorf("BETA_STRICT_MODE forbids %s", allowDangerousIssuerKeysetReplacement)
		}
		if envEnabled(allowDangerousCosmosAdapterFallback) {
			return fmt.Errorf("BETA_STRICT_MODE forbids %s", allowDangerousCosmosAdapterFallback)
		}
		if s.startupSyncTimeout <= 0 {
			return fmt.Errorf("BETA_STRICT_MODE requires EXIT_STARTUP_SYNC_TIMEOUT_SEC>0")
		}
		if len(s.issuerURLs) > 1 {
			if s.issuerMinSources < 2 {
				return fmt.Errorf("BETA_STRICT_MODE requires EXIT_ISSUER_MIN_SOURCES>=2 when multiple ISSUER_URLS are configured")
			}
			if s.issuerMinOperators < 2 {
				return fmt.Errorf("BETA_STRICT_MODE requires EXIT_ISSUER_MIN_OPERATORS>=2 when multiple ISSUER_URLS are configured")
			}
			if s.issuerMinKeyVotes < 2 {
				return fmt.Errorf("BETA_STRICT_MODE requires EXIT_ISSUER_MIN_KEY_VOTES>=2 when multiple ISSUER_URLS are configured")
			}
			if !s.issuerRequireID {
				return fmt.Errorf("BETA_STRICT_MODE requires EXIT_ISSUER_REQUIRE_ID=1 when multiple ISSUER_URLS are configured")
			}
		}
	}
	if s.prodStrict {
		if !s.betaStrict {
			return fmt.Errorf("PROD_STRICT_MODE requires BETA_STRICT_MODE=1")
		}
		if !securehttp.Enabled() {
			return fmt.Errorf("PROD_STRICT_MODE requires MTLS_ENABLE=1")
		}
		if len(s.issuerURLs) < 2 {
			return fmt.Errorf("PROD_STRICT_MODE requires at least 2 ISSUER_URLS")
		}
		if s.issuerMinSources < 2 {
			return fmt.Errorf("PROD_STRICT_MODE requires EXIT_ISSUER_MIN_SOURCES>=2")
		}
		if s.issuerMinOperators < 2 {
			return fmt.Errorf("PROD_STRICT_MODE requires EXIT_ISSUER_MIN_OPERATORS>=2")
		}
		if s.issuerMinKeyVotes < 2 {
			return fmt.Errorf("PROD_STRICT_MODE requires EXIT_ISSUER_MIN_KEY_VOTES>=2")
		}
		if !s.issuerRequireID {
			return fmt.Errorf("PROD_STRICT_MODE requires EXIT_ISSUER_REQUIRE_ID=1")
		}
	}
	return nil
}

func (s *Service) ensureStartupIssuerSync(ctx context.Context) error {
	if s.startupSyncTimeout <= 0 {
		if err := s.refreshIssuerKeys(ctx); err != nil {
			log.Printf("exit startup key fetch failed: %v", err)
		}
		if err := s.refreshRevocations(ctx); err != nil {
			log.Printf("exit startup revocation fetch failed: %v", err)
		}
		return nil
	}
	deadline := time.Now().Add(s.startupSyncTimeout)
	wait := 200 * time.Millisecond
	attempts := 0
	var keyErr error
	var revErr error
	for {
		attempts++
		keyErr = s.refreshIssuerKeys(ctx)
		revErr = s.refreshRevocations(ctx)
		if keyErr == nil && revErr == nil {
			log.Printf("exit startup issuer sync ready attempts=%d", attempts)
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait < 2*time.Second {
			wait *= 2
			if wait > 2*time.Second {
				wait = 2 * time.Second
			}
		}
	}
	if keyErr != nil {
		log.Printf("exit startup key fetch failed: %v", keyErr)
	}
	if revErr != nil {
		log.Printf("exit startup revocation fetch failed: %v", revErr)
	}
	return fmt.Errorf("exit startup issuer sync timeout after %s", s.startupSyncTimeout)
}

func (s *Service) effectiveWGKernelProxyMax() int {
	if s.wgKernelProxyMax > 0 {
		return s.wgKernelProxyMax
	}
	return 2048
}

func (s *Service) effectiveMaxActiveSessions() int {
	if s.maxActiveSessions > 0 {
		return s.maxActiveSessions
	}
	return defaultMaxActiveSessions
}

func (s *Service) sessionCapacityReachedLocked(sessionID string) bool {
	if s.sessions == nil {
		return false
	}
	if _, exists := s.sessions[sessionID]; exists {
		return false
	}
	return len(s.sessions) >= s.effectiveMaxActiveSessions()
}

func (s *Service) ensureCommandWGPubKey(ctx context.Context) error {
	if s.wgBackend != "command" {
		return nil
	}
	configured := strings.TrimSpace(s.wgPubKey)
	derived, err := deriveWGPublicKeyFromPrivateFile(ctx, s.wgPrivateKey)
	if err != nil {
		return err
	}
	if wg.IsValidPublicKey(configured) && configured != derived {
		return fmt.Errorf("configured EXIT_WG_PUBKEY does not match EXIT_WG_PRIVATE_KEY_PATH")
	}
	s.wgPubKey = derived
	if configured == "" || configured != derived {
		log.Printf("exit derived wg public key from private key file")
	}
	return nil
}

func (s *Service) startUDP(ctx context.Context, errCh chan<- error) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.dataAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.udpConn = conn
	log.Printf("exit data plane listening on %s mode=%s", s.dataAddr, s.dataMode)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, srcAddr, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				errCh <- readErr
				return
			}

			sessionID, payload, parseErr := relay.ParseDatagram(buf[:n])
			if parseErr != nil {
				continue
			}

			switch s.dataMode {
			case "opaque":
				nonce, raw, err := relay.ParseOpaquePayload(payload)
				if err != nil {
					continue
				}
				if srcAddr != nil {
					allowed, _, currentPeer := s.allowSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped opaque packet session=%s reason=source-mismatch src=%s peer=%s", sessionID, srcAddr.String(), currentPeer)
						s.recordSourceMismatchDrop(uint64(len(raw)))
						continue
					}
				}
				claims, err := s.authorizeNonce(sessionID, nonce, time.Now())
				if err != nil {
					log.Printf("exit dropped opaque packet session=%s reason=%v", sessionID, err)
					s.recordDrop(uint64(len(raw)), 0)
					continue
				}
				if srcAddr != nil {
					allowed, rebound, previousPeer := s.bindSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped opaque packet session=%s reason=peer-bind-failed src=%s", sessionID, srcAddr.String())
						s.recordDrop(uint64(len(raw)), claims.Tier)
						continue
					}
					if rebound {
						log.Printf("exit peer source rebind session=%s old=%s new=%s", sessionID, previousPeer, srcAddr.String())
					}
				}
				if s.liveWGMode && !relay.LooksLikePlausibleWireGuardMessage(raw) {
					log.Printf("exit dropped opaque packet session=%s reason=non-wireguard-live payload_len=%d", sessionID, len(raw))
					s.recordNonWGLiveDrop(uint64(len(raw)), claims.Tier)
					continue
				}
				if relay.LooksLikeWireGuardMessage(raw) {
					log.Printf("exit accepted opaque packet session=%s payload_len=%d wg_like=true", sessionID, len(raw))
				} else {
					log.Printf("exit accepted opaque packet session=%s payload_len=%d wg_like=false", sessionID, len(raw))
				}
				forwardedToWG := false
				if s.wgKernelProxy {
					if err := s.forwardOpaqueToWGKernel(sessionID, raw); err != nil {
						log.Printf("exit dropped opaque packet session=%s reason=wg-kernel-proxy-failed err=%v", sessionID, err)
						s.recordDrop(uint64(len(raw)), claims.Tier)
						continue
					}
					forwardedToWG = true
				}
				if s.opaqueEcho && srcAddr != nil && !forwardedToWG {
					echoFrame := relay.BuildDatagram(sessionID, payload)
					_, _ = conn.WriteToUDP(echoFrame, srcAddr)
				}
				if s.opaqueSinkUDP != nil {
					_, _ = conn.WriteToUDP(raw, s.opaqueSinkUDP)
				}
				s.recordAccept(uint64(len(raw)), claims.Tier)
				s.recordSessionIngress(sessionID, int64(len(raw)))
			default:
				var inner proto.InnerPacket
				if err := json.Unmarshal(payload, &inner); err != nil {
					continue
				}
				if srcAddr != nil {
					allowed, _, currentPeer := s.allowSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped packet session=%s reason=source-mismatch src=%s peer=%s", sessionID, srcAddr.String(), currentPeer)
						s.recordSourceMismatchDrop(uint64(len(inner.Payload)))
						continue
					}
				}
				claims, err := s.authorizePacket(sessionID, inner, time.Now())
				if err != nil {
					log.Printf("exit dropped packet session=%s reason=%v dest_port=%d", sessionID, err, inner.DestinationPort)
					s.recordDrop(uint64(len(inner.Payload)), 0)
					continue
				}
				if srcAddr != nil {
					allowed, rebound, previousPeer := s.bindSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped packet session=%s reason=peer-bind-failed src=%s", sessionID, srcAddr.String())
						s.recordDrop(uint64(len(inner.Payload)), claims.Tier)
						continue
					}
					if rebound {
						log.Printf("exit peer source rebind session=%s old=%s new=%s", sessionID, previousPeer, srcAddr.String())
					}
				}
				log.Printf("exit accepted packet session=%s dest_port=%d payload_len=%d", sessionID, inner.DestinationPort, len(inner.Payload))
				s.recordAccept(uint64(len(inner.Payload)), claims.Tier)
				s.recordSessionIngress(sessionID, int64(len(inner.Payload)))
			}
		}
	}()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return nil
}

func (s *Service) startOpaqueSource(ctx context.Context, errCh chan<- error) error {
	sourceAddr := strings.TrimSpace(s.opaqueSourceAddr)
	if sourceAddr == "" {
		return nil
	}
	if s.udpConn == nil {
		return errors.New("opaque source requires exit udp listener")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", sourceAddr)
	if err != nil {
		return fmt.Errorf("invalid EXIT_OPAQUE_SOURCE_ADDR: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.opaqueSourceConn = conn
	log.Printf("exit opaque source enabled addr=%s", sourceAddr)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				errCh <- readErr
				return
			}
			if n <= 0 {
				continue
			}
			now := time.Now()
			sessionID, payload, ok := s.parseOpaqueDownlinkPacket(buf[:n], now)
			if !ok {
				s.recordDownlinkDrop()
				continue
			}
			targetAddr, nonce, ok := s.resolveDownlinkTarget(sessionID, now)
			if !ok {
				s.recordDownlinkDrop()
				continue
			}
			targetUDP, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				s.recordDownlinkDrop()
				continue
			}
			frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(nonce, payload))
			if _, err := s.udpConn.WriteToUDP(frame, targetUDP); err != nil {
				s.recordDownlinkDrop()
				continue
			}
			s.recordDownlinkForward(uint64(len(payload)))
			s.recordSessionEgress(sessionID, int64(len(payload)))
		}
	}()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return nil
}

func (s *Service) parseOpaqueDownlinkPacket(frame []byte, now time.Time) (string, []byte, bool) {
	if sessionID, payload, err := relay.ParseDatagram(frame); err == nil && strings.TrimSpace(sessionID) != "" {
		if s.liveWGMode && !relay.LooksLikePlausibleWireGuardMessage(payload) {
			return "", nil, false
		}
		return sessionID, append([]byte(nil), payload...), true
	}
	if s.liveWGMode {
		return "", nil, false
	}
	sessionID := s.singleActiveSession(now.Unix())
	if sessionID == "" {
		return "", nil, false
	}
	return sessionID, append([]byte(nil), frame...), true
}

func (s *Service) singleActiveSession(nowUnix int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidate := ""
	for sid, session := range s.sessions {
		if nowUnix >= session.claims.ExpiryUnix {
			continue
		}
		if strings.TrimSpace(session.peerAddr) == "" {
			continue
		}
		if candidate != "" {
			return ""
		}
		candidate = sid
	}
	return candidate
}

func (s *Service) resolveDownlinkTarget(sessionID string, now time.Time) (string, uint64, bool) {
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return "", 0, false
	}
	if now.Unix() >= session.claims.ExpiryUnix {
		s.mu.Unlock()
		teardown := s.teardownSession(context.Background(), sessionID, sessionTeardownOptions{})
		if teardown.wgRemoveErr != nil {
			log.Printf("exit expired session teardown warning session=%s err=%v", sessionID, teardown.wgRemoveErr)
		}
		return "", 0, false
	}
	target := strings.TrimSpace(session.peerAddr)
	if target == "" {
		s.mu.Unlock()
		return "", 0, false
	}
	session.downNonce++
	if session.downNonce == 0 {
		session.downNonce = 1
	}
	session.lastActivity = now
	s.sessions[sessionID] = session
	if _, ok := s.wgSessionProxies[sessionID]; ok {
		if s.wgProxyLastSeen == nil {
			s.wgProxyLastSeen = make(map[string]int64)
		}
		s.wgProxyLastSeen[sessionID] = now.Unix()
	}
	s.mu.Unlock()
	return target, session.downNonce, true
}

func (s *Service) forwardOpaqueToWGKernel(sessionID string, payload []byte) error {
	if !s.wgKernelProxy {
		return nil
	}
	proxyConn, err := s.ensureWGSessionProxy(sessionID)
	if err != nil {
		if errors.Is(err, errWGProxySessionLimit) {
			s.recordWGProxyLimitDrop()
		} else {
			s.recordWGProxyError()
		}
		return err
	}
	target := s.wgKernelTargetUDP
	if target == nil {
		target, err = net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", s.wgListenPort))
		if err != nil {
			s.recordWGProxyError()
			return err
		}
		s.wgKernelTargetUDP = target
	}
	_, err = proxyConn.WriteToUDP(payload, target)
	if err != nil {
		s.recordWGProxyError()
		return err
	}
	s.markWGProxyActivity(sessionID, time.Now())
	return err
}

var errWGProxySessionLimit = errors.New("wg-kernel-proxy session limit reached")

func (s *Service) ensureWGSessionProxy(sessionID string) (*net.UDPConn, error) {
	s.mu.RLock()
	existing := s.wgSessionProxies[sessionID]
	s.mu.RUnlock()
	if existing != nil {
		s.markWGProxyActivity(sessionID, time.Now())
		return existing, nil
	}

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if existing := s.wgSessionProxies[sessionID]; existing != nil {
		if s.wgProxyLastSeen == nil {
			s.wgProxyLastSeen = make(map[string]int64)
		}
		s.wgProxyLastSeen[sessionID] = time.Now().Unix()
		s.mu.Unlock()
		_ = proxyConn.Close()
		return existing, nil
	}
	if maxSessions := s.effectiveWGKernelProxyMax(); maxSessions > 0 && len(s.wgSessionProxies) >= maxSessions {
		s.mu.Unlock()
		_ = proxyConn.Close()
		return nil, errWGProxySessionLimit
	}
	if s.wgSessionProxies == nil {
		s.wgSessionProxies = make(map[string]*net.UDPConn)
	}
	if s.wgProxyLastSeen == nil {
		s.wgProxyLastSeen = make(map[string]int64)
	}
	s.wgSessionProxies[sessionID] = proxyConn
	s.wgProxyLastSeen[sessionID] = time.Now().Unix()
	s.metrics.WGProxyCreated++
	s.metrics.ActiveWGProxySessions = uint64(len(s.wgSessionProxies))
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()

	go s.runWGSessionProxy(sessionID, proxyConn)
	return proxyConn, nil
}

func (s *Service) runWGSessionProxy(sessionID string, proxyConn *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := proxyConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		s.markWGProxyActivity(sessionID, time.Now())
		if s.liveWGMode && !relay.LooksLikePlausibleWireGuardMessage(payload) {
			s.recordDownlinkDrop()
			continue
		}
		targetAddr, nonce, ok := s.resolveDownlinkTarget(sessionID, time.Now())
		if !ok {
			s.recordDownlinkDrop()
			continue
		}
		targetUDP, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			s.recordDownlinkDrop()
			continue
		}
		frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(nonce, payload))
		if s.udpConn == nil {
			s.recordDownlinkDrop()
			continue
		}
		if _, err := s.udpConn.WriteToUDP(frame, targetUDP); err != nil {
			s.recordDownlinkDrop()
			continue
		}
		s.recordDownlinkForward(uint64(len(payload)))
		s.recordSessionEgress(sessionID, int64(len(payload)))
	}
}

func (s *Service) closeWGSessionProxy(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	proxyConn := s.takeWGProxyLocked(sessionID, false)
	s.mu.Unlock()
	if proxyConn != nil {
		_ = proxyConn.Close()
	}
}

func (s *Service) closeAllWGKernelSessionProxies() {
	s.mu.Lock()
	proxies := make([]*net.UDPConn, 0, len(s.wgSessionProxies))
	for sessionID := range s.wgSessionProxies {
		proxy := s.takeWGProxyLocked(sessionID, false)
		if proxy != nil {
			proxies = append(proxies, proxy)
		}
	}
	s.mu.Unlock()
	for _, proxyConn := range proxies {
		_ = proxyConn.Close()
	}
}

func (s *Service) takeWGProxyLocked(sessionID string, idle bool) *net.UDPConn {
	if sessionID == "" {
		return nil
	}
	proxyConn := s.wgSessionProxies[sessionID]
	delete(s.wgSessionProxies, sessionID)
	delete(s.wgProxyLastSeen, sessionID)
	if proxyConn != nil {
		s.metrics.WGProxyClosed++
		if idle {
			s.metrics.WGProxyIdleClosed++
		}
		s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	}
	s.metrics.ActiveWGProxySessions = uint64(len(s.wgSessionProxies))
	return proxyConn
}

func (s *Service) markWGProxyActivity(sessionID string, now time.Time) {
	if strings.TrimSpace(sessionID) == "" {
		return
	}
	s.mu.Lock()
	if _, ok := s.wgSessionProxies[sessionID]; ok {
		if s.wgProxyLastSeen == nil {
			s.wgProxyLastSeen = make(map[string]int64)
		}
		s.wgProxyLastSeen[sessionID] = now.Unix()
	}
	s.mu.Unlock()
}

func (s *Service) allowSessionPeer(sessionID string, peerAddr string, now time.Time) (bool, bool, string) {
	peerAddr = strings.TrimSpace(peerAddr)
	if sessionID == "" || peerAddr == "" {
		return false, false, ""
	}
	nowUnix := now.Unix()
	rebindAfterSec := int64(s.peerRebindAfter / time.Second)
	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		return false, false, ""
	}
	if nowUnix >= session.claims.ExpiryUnix {
		currentPeer := strings.TrimSpace(session.peerAddr)
		teardown := s.teardownSession(context.Background(), sessionID, sessionTeardownOptions{})
		if teardown.wgRemoveErr != nil {
			log.Printf("exit expired session teardown warning session=%s err=%v", sessionID, teardown.wgRemoveErr)
		}
		return false, false, currentPeer
	}
	return peerSessionDecision(session, peerAddr, nowUnix, rebindAfterSec)
}

func (s *Service) bindSessionPeer(sessionID string, peerAddr string, now time.Time) (bool, bool, string) {
	peerAddr = strings.TrimSpace(peerAddr)
	if sessionID == "" || peerAddr == "" {
		return false, false, ""
	}
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return false, false, ""
	}
	nowUnix := now.Unix()
	if nowUnix >= session.claims.ExpiryUnix {
		currentPeer := strings.TrimSpace(session.peerAddr)
		s.mu.Unlock()
		teardown := s.teardownSession(context.Background(), sessionID, sessionTeardownOptions{})
		if teardown.wgRemoveErr != nil {
			log.Printf("exit expired session teardown warning session=%s err=%v", sessionID, teardown.wgRemoveErr)
		}
		return false, false, currentPeer
	}
	allowed, rebound, previousPeer := peerSessionDecision(session, peerAddr, nowUnix, int64(s.peerRebindAfter/time.Second))
	if !allowed {
		s.mu.Unlock()
		return false, false, previousPeer
	}
	session.peerAddr = peerAddr
	session.peerLastSeen = nowUnix
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return true, rebound, previousPeer
}

type sessionTeardownOptions struct {
	requireSessionKeyMatch bool
	expectedSessionKeyID   string
}

type sessionTeardownResult struct {
	closed      bool
	keyMismatch bool
	wgRemoveErr error
}

func (s *Service) sessionWGConfigForTeardown(sessionID string, session sessionInfo) (wg.SessionConfig, bool) {
	if session.transport != "wireguard-udp" {
		return wg.SessionConfig{}, false
	}
	return wg.SessionConfig{
		SessionID:     sessionID,
		SessionKeyID:  session.sessionKeyID,
		Interface:     s.wgInterface,
		ClientPubKey:  session.clientPubKey,
		ClientInnerIP: session.clientInnerIP,
	}, true
}

func sameSessionForTeardown(before, after sessionInfo) bool {
	if subtle.ConstantTimeCompare([]byte(before.sessionKeyID), []byte(after.sessionKeyID)) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(before.clientPubKey), []byte(after.clientPubKey)) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(before.clientInnerIP), []byte(after.clientInnerIP)) != 1 {
		return false
	}
	return before.transport == after.transport && before.claims.ExpiryUnix == after.claims.ExpiryUnix
}

func (s *Service) teardownSession(ctx context.Context, sessionID string, opts sessionTeardownOptions) sessionTeardownResult {
	sessionID = strings.TrimSpace(sessionID)
	opts.expectedSessionKeyID = strings.TrimSpace(opts.expectedSessionKeyID)
	if sessionID == "" {
		return sessionTeardownResult{closed: true}
	}

	s.mu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		s.mu.Unlock()
		return sessionTeardownResult{closed: true}
	}
	if opts.requireSessionKeyMatch &&
		session.sessionKeyID != "" &&
		subtle.ConstantTimeCompare([]byte(opts.expectedSessionKeyID), []byte(session.sessionKeyID)) != 1 {
		s.mu.Unlock()
		return sessionTeardownResult{keyMismatch: true}
	}
	wgCfg, needsWGTeardown := s.sessionWGConfigForTeardown(sessionID, session)
	s.mu.Unlock()

	if needsWGTeardown {
		if s.wgManager == nil {
			return sessionTeardownResult{wgRemoveErr: errors.New("wg manager unavailable")}
		}
		if err := s.wgManager.RemoveSession(ctx, wgCfg); err != nil {
			s.mu.Lock()
			current, exists := s.sessions[sessionID]
			s.mu.Unlock()
			if !exists || !sameSessionForTeardown(session, current) {
				return sessionTeardownResult{closed: true}
			}
			return sessionTeardownResult{wgRemoveErr: err}
		}
	}

	s.mu.Lock()
	current, exists := s.sessions[sessionID]
	if !exists {
		s.mu.Unlock()
		return sessionTeardownResult{closed: true}
	}
	if opts.requireSessionKeyMatch &&
		current.sessionKeyID != "" &&
		subtle.ConstantTimeCompare([]byte(opts.expectedSessionKeyID), []byte(current.sessionKeyID)) != 1 {
		s.mu.Unlock()
		return sessionTeardownResult{keyMismatch: true}
	}
	if !sameSessionForTeardown(session, current) {
		s.mu.Unlock()
		return sessionTeardownResult{}
	}
	staleProxy := s.takeWGProxyLocked(sessionID, false)
	delete(s.sessions, sessionID)
	s.metrics.ActiveSessions = uint64(len(s.sessions))
	s.mu.Unlock()

	if staleProxy != nil {
		_ = staleProxy.Close()
	}
	s.finalizeSettlementForSession(ctx, sessionID, current)
	return sessionTeardownResult{closed: true}
}

func peerSessionDecision(session sessionInfo, peerAddr string, nowUnix int64, rebindAfterSec int64) (bool, bool, string) {
	peerAddr = strings.TrimSpace(peerAddr)
	currentPeer := strings.TrimSpace(session.peerAddr)
	if peerAddr == "" {
		return false, false, currentPeer
	}
	if currentPeer == "" {
		return true, false, ""
	}
	if sameUDPAddr(peerAddr, currentPeer) {
		return true, false, currentPeer
	}
	if rebindAfterSec > 0 {
		lastSeen := session.peerLastSeen
		if lastSeen <= 0 && !session.lastActivity.IsZero() {
			lastSeen = session.lastActivity.Unix()
		}
		if lastSeen <= 0 || nowUnix-lastSeen >= rebindAfterSec {
			return true, true, currentPeer
		}
	}
	return false, false, currentPeer
}

func sameUDPAddr(a, b string) bool {
	aa, errA := net.ResolveUDPAddr("udp", a)
	bb, errB := net.ResolveUDPAddr("udp", b)
	if errA != nil || errB != nil {
		return a == b
	}
	if aa.Port != bb.Port {
		return false
	}
	if aa.IP == nil || bb.IP == nil {
		return aa.IP.String() == bb.IP.String()
	}
	return aa.IP.Equal(bb.IP)
}

func udpPortOf(addr string) (int, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(addr))
	if err != nil {
		return 0, err
	}
	if udpAddr.Port <= 0 || udpAddr.Port > 65535 {
		return 0, fmt.Errorf("invalid udp port")
	}
	return udpAddr.Port, nil
}

func decodeStrictJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = pathControlJSONBodyMaxBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("invalid trailing json")
		}
		return err
	}
	return nil
}

func (s *Service) handlePathOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req proto.PathOpenRequest
	if err := decodeStrictJSONBody(w, r, &req, pathControlJSONBodyMaxBytes); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Transport == "" {
		req.Transport = "policy-json"
	}

	claims, issuerKeyID, err := s.verifyToken(req.Token)
	if err != nil {
		log.Printf("exit token verify failed: %v", err)
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token verification failed"})
		return
	}
	nowUnix := time.Now().Unix()
	if err := validatePathOpenClaims(claims, nowUnix); err != nil {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: err.Error()})
		return
	}
	if s.isRevoked(issuerKeyID, claims.TokenID, nowUnix) {
		s.recordRevokedTokenDrop()
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token revoked"})
		return
	}
	if !s.acceptsTokenKeyEpoch(claims, issuerKeyID) {
		s.recordKeyEpochTokenDrop()
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token key epoch expired"})
		return
	}
	if err := verifyPathOpenTokenProof(req, claims); err != nil {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: err.Error()})
		return
	}
	if s.pathOpenExitIdentityMismatch(req.ExitID) {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "exit identity mismatch"})
		return
	}
	if err := s.checkAndRememberProofNonce(claims, req, nowUnix); err != nil {
		if err.Error() == "token proof replay" {
			s.recordTokenProofReplayDrop()
		}
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: err.Error()})
		return
	}

	if len(claims.ExitScope) == 0 {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token exit scope required"})
		return
	}
	allowed := false
	for _, id := range claims.ExitScope {
		if strings.TrimSpace(id) == req.ExitID {
			allowed = true
			break
		}
	}
	if !allowed {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "exit scope denied"})
		return
	}
	if req.SessionID == "" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "missing session_id"})
		return
	}
	if s.dataMode == "opaque" && req.Transport != "wireguard-udp" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "transport must be wireguard-udp in opaque mode"})
		return
	}
	if s.dataMode == "json" && req.Transport != "policy-json" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "transport must be policy-json in json mode"})
		return
	}
	if s.dataMode == "opaque" && hasPortPolicyClaims(claims) {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "opaque mode cannot enforce port policy"})
		return
	}
	if req.Transport == "wireguard-udp" && req.ClientInnerPub == "" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "missing client_inner_pub"})
		return
	}
	if req.Transport == "wireguard-udp" && !wg.IsValidPublicKey(req.ClientInnerPub) {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "invalid client_inner_pub"})
		return
	}
	sessionKeyID, err := randomIDHex(8)
	if err != nil {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "failed to create session key"})
		return
	}
	clientIP := s.allocateClientInnerIP()

	s.mu.Lock()
	if _, exists := s.sessions[req.SessionID]; exists {
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "session already exists"})
		return
	}
	if s.sessionCapacityReachedLocked(req.SessionID) {
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "session capacity reached"})
		return
	}
	staleProxy := s.takeWGProxyLocked(req.SessionID, false)
	s.sessions[req.SessionID] = sessionInfo{
		claims:        claims,
		seenNonces:    make(map[uint64]struct{}),
		lastActivity:  time.Now(),
		transport:     req.Transport,
		sessionKeyID:  sessionKeyID,
		clientInnerIP: clientIP,
		clientPubKey:  req.ClientInnerPub,
	}
	s.metrics.ActiveSessions = uint64(len(s.sessions))
	s.mu.Unlock()
	if staleProxy != nil {
		_ = staleProxy.Close()
	}
	subjectForSettlement := strings.TrimSpace(claims.Subject)
	if subjectForSettlement == "" {
		subjectForSettlement = "client-anon"
	}
	s.reserveSettlementForSession(r.Context(), req.SessionID, subjectForSettlement)

	if req.Transport == "wireguard-udp" {
		wgCfg := wg.SessionConfig{
			SessionID:      req.SessionID,
			SessionKeyID:   sessionKeyID,
			Interface:      s.wgInterface,
			ExitPrivateKey: s.wgPrivateKey,
			ClientPubKey:   req.ClientInnerPub,
			ClientInnerIP:  clientIP,
			ExitInnerIP:    s.wgExitIP,
			ListenPort:     s.wgListenPort,
			MTU:            s.wgMTU,
			KeepaliveSec:   s.wgKeepaliveSec,
		}
		if err := s.wgManager.ConfigureSession(r.Context(), wgCfg); err != nil {
			s.closeWGSessionProxy(req.SessionID)
			s.mu.Lock()
			delete(s.sessions, req.SessionID)
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "wg configure failed"})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := proto.PathOpenResponse{
		Accepted:     true,
		SessionExp:   claims.ExpiryUnix,
		Transport:    req.Transport,
		SessionKeyID: sessionKeyID,
	}
	if req.Transport == "wireguard-udp" {
		resp.ExitInnerPub = s.wgPubKey
		resp.ClientInnerIP = clientIP
		resp.ExitInnerIP = s.wgExitIP
		resp.InnerMTU = s.wgMTU
		resp.KeepaliveSec = s.wgKeepaliveSec
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) handlePathClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.PathCloseRequest
	if err := decodeStrictJSONBody(w, r, &req, pathControlJSONBodyMaxBytes); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}
	req.SessionKeyID = strings.TrimSpace(req.SessionKeyID)
	w.Header().Set("Content-Type", "application/json")
	teardown := s.teardownSession(r.Context(), req.SessionID, sessionTeardownOptions{
		requireSessionKeyMatch: true,
		expectedSessionKeyID:   req.SessionKeyID,
	})
	if teardown.keyMismatch {
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "session-key-id-mismatch"})
		return
	}
	if teardown.wgRemoveErr != nil {
		// Close requests are idempotent. If a concurrent close completed while this
		// call was handling a transient WG remove error, report success instead of
		// a false-negative failure.
		for attempt := 0; attempt < 5; attempt++ {
			s.mu.RLock()
			_, stillActive := s.sessions[req.SessionID]
			s.mu.RUnlock()
			if !stillActive {
				log.Printf("exit closed session=%s", req.SessionID)
				_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: true})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "wg remove failed"})
		return
	}
	if !teardown.closed {
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "unknown-session"})
		return
	}
	log.Printf("exit closed session=%s", req.SessionID)
	_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: true})
}

func (s *Service) enforcePathOpenExitIdentityBinding() bool {
	if s.strictPathOpenExitIdentityBinding() {
		return true
	}
	return strings.TrimSpace(s.exitRelayID) != ""
}

func (s *Service) strictPathOpenExitIdentityBinding() bool {
	return s.betaStrict || s.prodStrict
}

func (s *Service) pathOpenExitIdentityMismatch(reqExitID string) bool {
	if !s.enforcePathOpenExitIdentityBinding() {
		return false
	}
	configuredExitID := strings.TrimSpace(s.exitRelayID)
	if configuredExitID == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(reqExitID)), []byte(configuredExitID)) != 1
}

func (s *Service) authorizePacket(sessionID string, inner proto.InnerPacket, now time.Time) (crypto.CapabilityClaims, error) {
	claims, err := s.authorizeNonce(sessionID, inner.Nonce, now)
	if err != nil {
		return crypto.CapabilityClaims{}, err
	}
	if err := s.enforcer.Allow(claims, policy.FlowContext{DestinationPort: inner.DestinationPort, Now: now}); err != nil {
		return crypto.CapabilityClaims{}, errors.New("policy-denied")
	}
	return claims, nil
}

func validatePathOpenClaims(claims crypto.CapabilityClaims, nowUnix int64) error {
	if strings.TrimSpace(claims.Audience) != "exit" {
		return errors.New("token audience invalid")
	}
	if strings.TrimSpace(claims.TokenType) != crypto.TokenTypeClientAccess {
		return errors.New("token type invalid")
	}
	if strings.TrimSpace(claims.CNFEd25519) == "" {
		return errors.New("token proof key missing")
	}
	if _, err := crypto.ParseEd25519PublicKey(claims.CNFEd25519); err != nil {
		return errors.New("token proof key invalid")
	}
	if claims.Tier < 1 || claims.Tier > 3 {
		return errors.New("token tier invalid")
	}
	if strings.TrimSpace(claims.TokenID) == "" {
		return errors.New("token id missing")
	}
	hasScopedExit := false
	for _, id := range claims.ExitScope {
		if strings.TrimSpace(id) != "" {
			hasScopedExit = true
			break
		}
	}
	if !hasScopedExit {
		return errors.New("token exit scope required")
	}
	if claims.ExpiryUnix <= 0 || nowUnix >= claims.ExpiryUnix {
		return errors.New("token expired")
	}
	if claims.Tier > 1 && strings.TrimSpace(claims.Subject) == "" {
		return errors.New("token subject required for tier>1")
	}
	return nil
}

func hasPortPolicyClaims(claims crypto.CapabilityClaims) bool {
	return len(claims.AllowPorts) > 0 || len(claims.DenyPorts) > 0
}

func verifyPathOpenTokenProof(req proto.PathOpenRequest, claims crypto.CapabilityClaims) error {
	pub, err := crypto.ParseEd25519PublicKey(claims.CNFEd25519)
	if err != nil {
		return errors.New("token proof key invalid")
	}
	input := crypto.PathOpenProofInput{
		Token:           req.Token,
		ExitID:          req.ExitID,
		MiddleRelayID:   req.MiddleRelayID,
		TokenProofNonce: req.TokenProofNonce,
		ClientInnerPub:  req.ClientInnerPub,
		Transport:       req.Transport,
		RequestedMTU:    req.RequestedMTU,
		RequestedRegion: req.RequestedRegion,
	}
	if err := crypto.VerifyPathOpenProof(req.TokenProof, pub, input); err != nil {
		return errors.New("token proof invalid")
	}
	return nil
}

func (s *Service) checkAndRememberProofNonce(claims crypto.CapabilityClaims, req proto.PathOpenRequest, nowUnix int64) error {
	if !s.tokenProofReplayGuard {
		return nil
	}
	tokenID := strings.TrimSpace(claims.TokenID)
	if tokenID == "" {
		return errors.New("token id missing")
	}
	nonce := strings.TrimSpace(req.TokenProofNonce)
	if nonce == "" {
		return errors.New("token proof nonce required")
	}
	if len(nonce) > 256 {
		return errors.New("token proof nonce invalid")
	}
	exp := claims.ExpiryUnix
	if exp <= nowUnix {
		exp = nowUnix + 1
	}
	if s.tokenProofReplayRedisEnabled() {
		return s.checkAndRememberProofNonceRedis(tokenID, nonce, exp, nowUnix)
	}
	replayStorePath := strings.TrimSpace(s.tokenProofReplayStoreFile)
	if s.tokenProofReplaySharedFileMode {
		return s.checkAndRememberProofNonceShared(tokenID, nonce, exp, nowUnix, replayStorePath)
	}
	needsPersist := replayStorePath != ""
	var snapshot tokenProofReplayStoreSnapshot

	s.mu.Lock()
	if s.proofNonceSeen == nil {
		s.proofNonceSeen = make(map[string]map[string]int64)
	}
	seen := s.proofNonceSeen[tokenID]
	if seen == nil {
		if len(s.proofNonceSeen) >= tokenProofReplayMaxTokenIDs {
			pruneExpiredProofNonceBucketsLocked(s.proofNonceSeen, nowUnix)
			if len(s.proofNonceSeen) >= tokenProofReplayMaxTokenIDs {
				s.mu.Unlock()
				return errors.New("token proof replay cache saturated")
			}
		}
		seen = make(map[string]int64)
		s.proofNonceSeen[tokenID] = seen
	}
	for k, until := range seen {
		if nowUnix >= until {
			delete(seen, k)
		}
	}
	if _, exists := seen[nonce]; exists {
		s.mu.Unlock()
		return errors.New("token proof replay")
	}
	if len(seen) >= tokenProofReplayMaxNoncesPerToken {
		s.mu.Unlock()
		return errors.New("token proof replay cache saturated")
	}
	seen[nonce] = exp
	if needsPersist {
		snapshot = tokenProofReplayStoreSnapshot{
			Version:     1,
			SavedAtUnix: nowUnix,
			Buckets:     cloneProofNonceBuckets(s.proofNonceSeen),
		}
	}
	s.mu.Unlock()

	if !needsPersist {
		return nil
	}
	if err := persistTokenProofReplayStoreSnapshot(replayStorePath, snapshot); err != nil {
		s.mu.Lock()
		seen = s.proofNonceSeen[tokenID]
		if seen != nil {
			if until, exists := seen[nonce]; exists && until == exp {
				delete(seen, nonce)
				if len(seen) == 0 {
					delete(s.proofNonceSeen, tokenID)
				}
			}
		}
		s.mu.Unlock()
		return fmt.Errorf("token proof replay persistence failed: %w", err)
	}
	return nil
}

func pruneExpiredProofNonceBucketsLocked(buckets map[string]map[string]int64, nowUnix int64) {
	for tokenID, seen := range buckets {
		for nonce, until := range seen {
			if nowUnix >= until {
				delete(seen, nonce)
			}
		}
		if len(seen) == 0 {
			delete(buckets, tokenID)
		}
	}
}

func cloneProofNonceBuckets(src map[string]map[string]int64) map[string]map[string]int64 {
	cloned := make(map[string]map[string]int64, len(src))
	for tokenID, seen := range src {
		if len(seen) == 0 {
			continue
		}
		copied := make(map[string]int64, len(seen))
		for nonce, until := range seen {
			copied[nonce] = until
		}
		cloned[tokenID] = copied
	}
	return cloned
}

type tokenProofReplayStoreSnapshot struct {
	Version     int                         `json:"version"`
	SavedAtUnix int64                       `json:"saved_at_unix"`
	Buckets     map[string]map[string]int64 `json:"buckets"`
}

func (s *Service) loadTokenProofReplayStore(nowUnix int64) error {
	path := strings.TrimSpace(s.tokenProofReplayStoreFile)
	if path == "" {
		return nil
	}
	buckets, err := loadTokenProofReplayStoreBuckets(path, nowUnix)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.proofNonceSeen = buckets
	s.mu.Unlock()
	return nil
}

func (s *Service) tokenProofReplayStats() (int, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bucketCount := len(s.proofNonceSeen)
	nonceCount := 0
	for _, seen := range s.proofNonceSeen {
		nonceCount += len(seen)
	}
	return bucketCount, nonceCount
}

func trimReplayBucketsToCaps(in map[string]map[string]int64) map[string]map[string]int64 {
	type nonceItem struct {
		nonce string
		until int64
	}
	type bucketItem struct {
		tokenID  string
		maxUntil int64
		nonces   map[string]int64
	}
	buckets := make([]bucketItem, 0, len(in))
	for tokenID, seen := range in {
		if len(seen) == 0 {
			continue
		}
		items := make([]nonceItem, 0, len(seen))
		for nonce, until := range seen {
			items = append(items, nonceItem{nonce: nonce, until: until})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].until == items[j].until {
				return items[i].nonce < items[j].nonce
			}
			return items[i].until > items[j].until
		})
		if len(items) > tokenProofReplayMaxNoncesPerToken {
			items = items[:tokenProofReplayMaxNoncesPerToken]
		}
		clamped := make(map[string]int64, len(items))
		maxUntil := int64(0)
		for _, item := range items {
			clamped[item.nonce] = item.until
			if item.until > maxUntil {
				maxUntil = item.until
			}
		}
		buckets = append(buckets, bucketItem{
			tokenID:  tokenID,
			maxUntil: maxUntil,
			nonces:   clamped,
		})
	}
	sort.Slice(buckets, func(i, j int) bool {
		if buckets[i].maxUntil == buckets[j].maxUntil {
			return buckets[i].tokenID < buckets[j].tokenID
		}
		return buckets[i].maxUntil > buckets[j].maxUntil
	})
	if len(buckets) > tokenProofReplayMaxTokenIDs {
		buckets = buckets[:tokenProofReplayMaxTokenIDs]
	}
	out := make(map[string]map[string]int64, len(buckets))
	for _, bucket := range buckets {
		out[bucket.tokenID] = bucket.nonces
	}
	return out
}

func (s *Service) persistTokenProofReplayStoreLocked(nowUnix int64) error {
	path := strings.TrimSpace(s.tokenProofReplayStoreFile)
	if path == "" {
		return nil
	}
	snapshot := tokenProofReplayStoreSnapshot{
		Version:     1,
		SavedAtUnix: nowUnix,
		Buckets:     cloneProofNonceBuckets(s.proofNonceSeen),
	}
	return persistTokenProofReplayStoreSnapshot(path, snapshot)
}

type tokenProofReplayFileLock struct {
	path string
	file *os.File
}

func (l *tokenProofReplayFileLock) release() error {
	if l == nil {
		return nil
	}
	var firstErr error
	if l.file != nil {
		if err := l.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.path != "" {
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func acquireTokenProofReplayFileLock(storePath string, timeout time.Duration) (*tokenProofReplayFileLock, error) {
	storePath = strings.TrimSpace(storePath)
	if storePath == "" {
		return nil, errors.New("token proof replay store file path is required")
	}
	lockPath := storePath + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultTokenProofReplayLockTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			if _, writeErr := fmt.Fprintf(file, "%d\n", os.Getpid()); writeErr != nil {
				_ = file.Close()
				_ = os.Remove(lockPath)
				return nil, writeErr
			}
			return &tokenProofReplayFileLock{
				path: lockPath,
				file: file,
			}, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout acquiring replay store lock %s after %s", lockPath, timeout)
		}
		time.Sleep(tokenProofReplayLockRetryInterval)
	}
}

func loadTokenProofReplayStoreBuckets(path string, nowUnix int64) (map[string]map[string]int64, error) {
	b, err := readRegularFileBounded(path, tokenProofReplayStoreMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]map[string]int64), nil
		}
		return nil, err
	}
	var snapshot tokenProofReplayStoreSnapshot
	if err := json.Unmarshal(b, &snapshot); err != nil {
		return nil, fmt.Errorf("invalid replay store json: %w", err)
	}
	buckets := snapshot.Buckets
	if buckets == nil {
		buckets = make(map[string]map[string]int64)
	}
	pruneExpiredProofNonceBucketsLocked(buckets, nowUnix)
	buckets = trimReplayBucketsToCaps(buckets)
	return buckets, nil
}

func (s *Service) effectiveTokenProofReplayLockTimeout() time.Duration {
	if s.tokenProofReplayLockTimeout > 0 {
		return s.tokenProofReplayLockTimeout
	}
	return defaultTokenProofReplayLockTimeout
}

func normalizeTokenProofReplayRedisPrefix(raw string) string {
	prefix := strings.TrimSpace(raw)
	if prefix == "" {
		prefix = defaultTokenProofReplayRedisPrefix
	}
	return strings.TrimRight(prefix, ":")
}

func (s *Service) tokenProofReplayRedisEnabled() bool {
	return strings.TrimSpace(s.tokenProofReplayRedisAddr) != ""
}

func (s *Service) effectiveTokenProofReplayRedisPrefix() string {
	return normalizeTokenProofReplayRedisPrefix(s.tokenProofReplayRedisPrefix)
}

func (s *Service) effectiveTokenProofReplayRedisDialTimeout() time.Duration {
	if s.tokenProofReplayRedisDialTimeout > 0 {
		return s.tokenProofReplayRedisDialTimeout
	}
	return defaultTokenProofReplayRedisDialTimeout
}

func (s *Service) tokenProofReplayMode() string {
	if s.tokenProofReplayRedisEnabled() {
		return "redis"
	}
	if s.tokenProofReplaySharedFileMode {
		return "shared-file"
	}
	if strings.TrimSpace(s.tokenProofReplayStoreFile) != "" {
		return "file"
	}
	return "in-memory"
}

func (s *Service) tokenProofReplayRedisClientOrInit() (*redis.Client, error) {
	if !s.tokenProofReplayRedisEnabled() {
		return nil, errors.New("token proof replay redis not configured")
	}
	s.tokenProofReplayRedisMu.Lock()
	defer s.tokenProofReplayRedisMu.Unlock()
	if s.tokenProofReplayRedisClient != nil {
		return s.tokenProofReplayRedisClient, nil
	}
	opts := &redis.Options{
		Addr:         strings.TrimSpace(s.tokenProofReplayRedisAddr),
		Password:     s.tokenProofReplayRedisPassword,
		DB:           s.tokenProofReplayRedisDB,
		DialTimeout:  s.effectiveTokenProofReplayRedisDialTimeout(),
		ReadTimeout:  s.effectiveTokenProofReplayRedisDialTimeout(),
		WriteTimeout: s.effectiveTokenProofReplayRedisDialTimeout(),
	}
	if s.tokenProofReplayRedisTLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), s.effectiveTokenProofReplayRedisDialTimeout())
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	s.tokenProofReplayRedisClient = client
	return client, nil
}

func (s *Service) checkAndRememberProofNonceRedis(tokenID string, nonce string, exp int64, nowUnix int64) error {
	client, err := s.tokenProofReplayRedisClientOrInit()
	if err != nil {
		return fmt.Errorf("token proof replay redis init failed: %w", err)
	}
	ttlSec := exp - nowUnix
	if ttlSec < 1 {
		ttlSec = 1
	}
	key := fmt.Sprintf("%s:%s:%s", s.effectiveTokenProofReplayRedisPrefix(), tokenID, nonce)
	ctx, cancel := context.WithTimeout(context.Background(), s.effectiveTokenProofReplayRedisDialTimeout())
	defer cancel()
	ok, err := client.SetNX(ctx, key, "1", time.Duration(ttlSec)*time.Second).Result()
	if err != nil {
		return fmt.Errorf("token proof replay redis failed: %w", err)
	}
	if !ok {
		return errors.New("token proof replay")
	}
	return nil
}

func (s *Service) checkAndRememberProofNonceShared(tokenID string, nonce string, exp int64, nowUnix int64, replayStorePath string) error {
	if replayStorePath == "" {
		return errors.New("token proof replay shared file mode requires replay store file path")
	}
	lock, err := acquireTokenProofReplayFileLock(replayStorePath, s.effectiveTokenProofReplayLockTimeout())
	if err != nil {
		return fmt.Errorf("token proof replay lock failed: %w", err)
	}
	defer func() {
		if releaseErr := lock.release(); releaseErr != nil {
			log.Printf("exit token proof replay guard: release lock failed path=%s err=%v", replayStorePath, releaseErr)
		}
	}()

	buckets, err := loadTokenProofReplayStoreBuckets(replayStorePath, nowUnix)
	if err != nil {
		return fmt.Errorf("token proof replay store load failed: %w", err)
	}
	s.mu.Lock()
	s.proofNonceSeen = cloneProofNonceBuckets(buckets)
	s.mu.Unlock()
	seen := buckets[tokenID]
	if seen == nil {
		if len(buckets) >= tokenProofReplayMaxTokenIDs {
			pruneExpiredProofNonceBucketsLocked(buckets, nowUnix)
			if len(buckets) >= tokenProofReplayMaxTokenIDs {
				return errors.New("token proof replay cache saturated")
			}
		}
		seen = make(map[string]int64)
		buckets[tokenID] = seen
	}
	for k, until := range seen {
		if nowUnix >= until {
			delete(seen, k)
		}
	}
	if _, exists := seen[nonce]; exists {
		return errors.New("token proof replay")
	}
	if len(seen) >= tokenProofReplayMaxNoncesPerToken {
		return errors.New("token proof replay cache saturated")
	}
	seen[nonce] = exp
	snapshot := tokenProofReplayStoreSnapshot{
		Version:     1,
		SavedAtUnix: nowUnix,
		Buckets:     cloneProofNonceBuckets(buckets),
	}
	if err := persistTokenProofReplayStoreSnapshot(replayStorePath, snapshot); err != nil {
		return fmt.Errorf("token proof replay persistence failed: %w", err)
	}

	s.mu.Lock()
	s.proofNonceSeen = cloneProofNonceBuckets(snapshot.Buckets)
	s.mu.Unlock()
	return nil
}

func persistTokenProofReplayStoreSnapshot(path string, snapshot tokenProofReplayStoreSnapshot) error {
	b, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o600)
}

func readRegularFileBounded(path string, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("file path is required")
	}
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lstatInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("file %s must not be a symlink", path)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("file %s must be a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, statErr := file.Stat()
	if statErr != nil {
		return nil, statErr
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file %s must be a regular file", path)
	}
	if !os.SameFile(lstatInfo, info) {
		return nil, fmt.Errorf("file %s changed during open", path)
	}
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	limit := maxBytes
	if limit <= 0 {
		limit = 1
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if maxBytes > 0 && int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	return payload, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("file %s must not be a symlink", path)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("file %s must be a regular file", path)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmpDir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(tmpDir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if perm != 0 {
		if err := tmpFile.Chmod(perm); err != nil {
			_ = tmpFile.Close()
			return err
		}
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (s *Service) authorizeNonce(sessionID string, nonce uint64, now time.Time) (crypto.CapabilityClaims, error) {
	s.mu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("unknown-session")
	}
	if now.Unix() >= session.claims.ExpiryUnix {
		s.mu.Unlock()
		teardown := s.teardownSession(context.Background(), sessionID, sessionTeardownOptions{})
		if teardown.wgRemoveErr != nil {
			log.Printf("exit expired session teardown warning session=%s err=%v", sessionID, teardown.wgRemoveErr)
		}
		return crypto.CapabilityClaims{}, errors.New("session-expired")
	}
	if nonce == 0 {
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("missing-nonce")
	}
	if _, seen := session.seenNonces[nonce]; seen {
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("replay-detected")
	}
	if session.highestNonce > sessionReplayWindowSize {
		minAccepted := session.highestNonce - sessionReplayWindowSize
		if nonce <= minAccepted {
			s.mu.Unlock()
			return crypto.CapabilityClaims{}, errors.New("replay-window-expired")
		}
	}
	if nonce > session.highestNonce {
		session.highestNonce = nonce
	}
	if len(session.seenNonces) >= sessionReplayWindowSize*2 {
		pruneBefore := uint64(0)
		if session.highestNonce > sessionReplayWindowSize {
			pruneBefore = session.highestNonce - sessionReplayWindowSize
		}
		for existing := range session.seenNonces {
			if existing <= pruneBefore {
				delete(session.seenNonces, existing)
			}
		}
	}
	session.seenNonces[nonce] = struct{}{}
	session.lastActivity = now
	claims := session.claims
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return claims, nil
}

func (s *Service) cleanupExpiredSessions(now time.Time) {
	nowUnix := now.Unix()
	s.mu.RLock()
	expiredSessions := make([]string, 0)
	for sid, session := range s.sessions {
		if nowUnix >= session.claims.ExpiryUnix {
			expiredSessions = append(expiredSessions, sid)
		}
	}
	s.mu.RUnlock()
	for _, sid := range expiredSessions {
		teardown := s.teardownSession(context.Background(), sid, sessionTeardownOptions{})
		if teardown.wgRemoveErr != nil {
			log.Printf("exit cleanup expired session teardown warning session=%s err=%v", sid, teardown.wgRemoveErr)
		}
	}

	s.mu.Lock()
	var staleProxies []*net.UDPConn
	if s.wgKernelProxyIdle > 0 {
		cutoff := now.Add(-s.wgKernelProxyIdle).Unix()
		idleSessions := make([]string, 0)
		for sid := range s.wgSessionProxies {
			lastSeen := s.wgProxyLastSeen[sid]
			if lastSeen <= 0 {
				if session, ok := s.sessions[sid]; ok {
					if session.peerLastSeen > 0 {
						lastSeen = session.peerLastSeen
					} else if !session.lastActivity.IsZero() {
						lastSeen = session.lastActivity.Unix()
					}
				}
			}
			if lastSeen > 0 && lastSeen <= cutoff {
				idleSessions = append(idleSessions, sid)
			}
		}
		for _, sid := range idleSessions {
			if proxyConn := s.takeWGProxyLocked(sid, true); proxyConn != nil {
				staleProxies = append(staleProxies, proxyConn)
			}
		}
	}
	for tokenID, seen := range s.proofNonceSeen {
		active := false
		for nonce, until := range seen {
			if nowUnix >= until {
				delete(seen, nonce)
				continue
			}
			active = true
		}
		if !active {
			delete(s.proofNonceSeen, tokenID)
		}
	}
	s.metrics.ActiveSessions = uint64(len(s.sessions))
	s.metrics.ActiveWGProxySessions = uint64(len(s.wgSessionProxies))
	s.mu.Unlock()
	for _, proxyConn := range staleProxies {
		_ = proxyConn.Close()
	}
}

func (s *Service) verifyToken(token string) (crypto.CapabilityClaims, string, error) {
	token = strings.TrimSpace(token)
	if err := validateCapabilityTokenFormat(token); err != nil {
		return crypto.CapabilityClaims{}, "", err
	}

	snapshotKeys := func() (map[string]ed25519.PublicKey, map[string]string) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		keys := make(map[string]ed25519.PublicKey, len(s.issuerPubs))
		for id, pub := range s.issuerPubs {
			keys[id] = pub
		}
		issuers := make(map[string]string, len(s.issuerKeyIssuer))
		for keyID, issuerID := range s.issuerKeyIssuer {
			issuerID = strings.TrimSpace(issuerID)
			if issuerID == "" {
				continue
			}
			issuers[keyID] = issuerID
		}
		if len(keys) == 0 && len(s.issuerPub) > 0 {
			id := issuerKeyID(s.issuerPub)
			keys[id] = s.issuerPub
		}
		return keys, issuers
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		keys, keyIssuers := snapshotKeys()
		if len(keys) == 0 {
			if err := s.refreshIssuerKeysForVerify(context.Background()); err != nil {
				lastErr = errors.New("issuer pubkey unavailable")
				continue
			}
			keys, keyIssuers = snapshotKeys()
		}
		for keyID, pub := range keys {
			claims, err := crypto.VerifyClaims(token, pub)
			if err == nil {
				if expectedIssuer := strings.TrimSpace(keyIssuers[keyID]); expectedIssuer != "" {
					if strings.TrimSpace(claims.Issuer) != expectedIssuer {
						lastErr = errors.New("token issuer mismatch")
						continue
					}
				}
				return claims, keyID, nil
			}
			lastErr = err
		}
		if attempt == 0 {
			if err := s.refreshIssuerKeysForVerify(context.Background()); err != nil {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no issuer keys available")
	}
	return crypto.CapabilityClaims{}, "", lastErr
}

func validateCapabilityTokenFormat(token string) error {
	if token == "" {
		return errors.New("missing token")
	}
	if len(token) > capabilityTokenMaxBytes {
		return errors.New("token too large")
	}
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok || payloadB64 == "" || sigB64 == "" {
		return errors.New("invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return errors.New("invalid token payload encoding")
	}
	if len(payload) == 0 || len(payload) > capabilityTokenPayloadMaxBytes {
		return errors.New("invalid token payload size")
	}
	if !json.Valid(payload) {
		return errors.New("invalid token payload json")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("invalid token signature encoding")
	}
	if len(sig) != ed25519.SignatureSize {
		return errors.New("invalid token signature size")
	}
	return nil
}

func (s *Service) refreshIssuerKeysForVerify(ctx context.Context) error {
	if !s.verifyRefreshMu.TryLock() {
		return fmt.Errorf("issuer key refresh already in progress")
	}
	defer s.verifyRefreshMu.Unlock()
	now := time.Now()
	if s.verifyRefreshMinInterval > 0 && !s.verifyRefreshLast.IsZero() {
		if now.Sub(s.verifyRefreshLast) < s.verifyRefreshMinInterval {
			return fmt.Errorf("issuer key refresh throttled")
		}
	}
	s.verifyRefreshLast = now
	return s.refreshIssuerKeys(ctx)
}

func (s *Service) refreshIssuerKeys(ctx context.Context) error {
	if len(s.issuerURLs) == 0 {
		if s.issuerURL == "" {
			return errors.New("missing issuer url")
		}
		s.issuerURLs = []string{normalizeHTTPURL(s.issuerURL)}
	}
	requiredOperators := s.issuerMinOperators
	if requiredOperators < 1 {
		requiredOperators = 1
	}
	updated := make(map[string]ed25519.PublicKey)
	updatedIssuers := make(map[string]string)
	updatedMinEpoch := make(map[string]int64)
	keyVoters := make(map[string]map[string]struct{})
	successSources := 0
	successOperators := make(map[string]struct{})
	var lastErr error
	for _, issuerURL := range s.issuerURLs {
		bundle, err := s.fetchIssuerPubKeysFrom(ctx, issuerURL)
		if err != nil {
			lastErr = err
			continue
		}
		sourceOperator := strings.TrimSpace(bundle.issuerID)
		if sourceOperator == "" && (s.issuerRequireID || requiredOperators > 1) {
			lastErr = fmt.Errorf("issuer identity missing for source %s", normalizeHTTPURL(issuerURL))
			continue
		}
		successSources++
		if sourceOperator == "" {
			sourceOperator = normalizeHTTPURL(issuerURL)
		}
		if sourceOperator != "" {
			successOperators[sourceOperator] = struct{}{}
		}
		for _, pub := range bundle.pubs {
			keyID := issuerKeyID(pub)
			updated[keyID] = pub
			voters := keyVoters[keyID]
			if voters == nil {
				voters = make(map[string]struct{})
				keyVoters[keyID] = voters
			}
			voters[sourceOperator] = struct{}{}
			if issuerID := strings.TrimSpace(bundle.issuerID); issuerID != "" {
				if existingIssuerID, exists := updatedIssuers[keyID]; exists && existingIssuerID != issuerID {
					return fmt.Errorf("issuer identity conflict for key %s: %s vs %s", keyID, existingIssuerID, issuerID)
				}
				updatedIssuers[keyID] = issuerID
			}
		}
		if bundle.issuerID != "" && bundle.minTokenEpoch > 0 {
			if bundle.minTokenEpoch > updatedMinEpoch[bundle.issuerID] {
				updatedMinEpoch[bundle.issuerID] = bundle.minTokenEpoch
			}
		}
	}
	if len(updated) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no issuer keys fetched")
		}
		return lastErr
	}
	requiredSources := s.issuerMinSources
	if requiredSources < 1 {
		requiredSources = 1
	}
	if successSources < requiredSources {
		return fmt.Errorf("issuer source quorum not met: success=%d required=%d", successSources, requiredSources)
	}
	if len(successOperators) < requiredOperators {
		return fmt.Errorf("issuer operator quorum not met: operators=%d required=%d", len(successOperators), requiredOperators)
	}
	requiredKeyVotes := s.issuerMinKeyVotes
	if requiredKeyVotes < 1 {
		requiredKeyVotes = 1
	}
	filtered := make(map[string]ed25519.PublicKey, len(updated))
	filteredIssuers := make(map[string]string, len(updatedIssuers))
	for keyID, pub := range updated {
		if len(keyVoters[keyID]) < requiredKeyVotes {
			continue
		}
		filtered[keyID] = pub
		if issuerID := updatedIssuers[keyID]; issuerID != "" {
			filteredIssuers[keyID] = issuerID
		}
	}
	if len(filtered) == 0 {
		return fmt.Errorf("issuer key quorum not met: key_votes_required=%d", requiredKeyVotes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.issuerPubs) > 0 &&
		!envEnabled(allowDangerousIssuerKeysetReplacement) &&
		!issuerKeysetHasOverlap(s.issuerPubs, filtered) {
		return errors.New("issuer key continuity check failed: no overlap with existing trusted keys")
	}
	s.issuerPubs = filtered
	s.issuerKeyIssuer = filteredIssuers
	if s.minTokenEpoch == nil {
		s.minTokenEpoch = make(map[string]int64)
	}
	for issuerID, minEpoch := range updatedMinEpoch {
		if minEpoch > s.minTokenEpoch[issuerID] {
			s.minTokenEpoch[issuerID] = minEpoch
		}
	}
	for _, pub := range filtered {
		s.issuerPub = pub
		break
	}
	return nil
}

func issuerKeysetHasOverlap(existing map[string]ed25519.PublicKey, next map[string]ed25519.PublicKey) bool {
	if len(existing) == 0 || len(next) == 0 {
		return false
	}
	for keyID := range existing {
		if _, ok := next[keyID]; ok {
			return true
		}
	}
	return false
}

type issuerKeyBundle struct {
	pubs          []ed25519.PublicKey
	issuerID      string
	minTokenEpoch int64
}

func (s *Service) fetchIssuerPubKeysFrom(ctx context.Context, issuerURL string) (issuerKeyBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(issuerURL, "/v1/pubkeys"), nil)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return s.fetchIssuerPubKeyLegacy(ctx, issuerURL)
	}
	if resp.StatusCode != http.StatusOK {
		return issuerKeyBundle{}, errors.New("issuer key endpoint returned non-200")
	}
	var out proto.IssuerPubKeysResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return issuerKeyBundle{}, err
	}
	pubs := make([]ed25519.PublicKey, 0, len(out.PubKeys))
	for _, pubB64 := range out.PubKeys {
		pubB64 = strings.TrimSpace(pubB64)
		raw, err := base64.RawURLEncoding.DecodeString(pubB64)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return issuerKeyBundle{}, fmt.Errorf("invalid issuer pubkey entry")
		}
		pubs = append(pubs, ed25519.PublicKey(raw))
	}
	if len(pubs) == 0 {
		return issuerKeyBundle{}, errors.New("issuer pubkeys endpoint returned empty list")
	}
	return issuerKeyBundle{
		pubs:          pubs,
		issuerID:      strings.TrimSpace(out.Issuer),
		minTokenEpoch: out.MinTokenEpoch,
	}, nil
}

func (s *Service) fetchIssuerPubKeyLegacy(ctx context.Context, issuerURL string) (issuerKeyBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(issuerURL, "/v1/pubkey"), nil)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return issuerKeyBundle{}, errors.New("issuer key endpoint returned non-200")
	}
	var out map[string]string
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return issuerKeyBundle{}, err
	}
	pubB64 := strings.TrimSpace(out["pub_key"])
	pub, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return issuerKeyBundle{}, errors.New("invalid issuer pubkey")
	}
	return issuerKeyBundle{pubs: []ed25519.PublicKey{ed25519.PublicKey(pub)}}, nil
}

func randomIDHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func (s *Service) allocateClientInnerIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipAllocCursor >= 250 {
		s.ipAllocCursor = 2
	}
	ip := fmt.Sprintf("10.90.0.%d/32", s.ipAllocCursor)
	s.ipAllocCursor++
	return ip
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Service) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	m := s.metrics
	m.ActiveSessions = uint64(len(s.sessions))
	m.ActiveWGProxySessions = uint64(len(s.wgSessionProxies))
	s.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(m)
}

func (s *Service) handleSettlementStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := settlementStatusResponse{
		Enabled: s.settlement != nil,
	}
	if s.settlement != nil {
		reconcileCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		report, stale, checkedAt, lastError, err := s.reconcileSettlementStatus(reconcileCtx)
		cancel()
		if err != nil {
			log.Printf("exit settlement status warning err=%v", err)
		}
		resp.CheckedAt = checkedAt
		resp.LastError = lastError
		resp.Stale = stale
		resp.ReportGeneratedAt = report.GeneratedAt
		resp.PendingAdapterOperations = report.PendingAdapterOperations
		resp.ShadowAdapterConfigured = report.ShadowAdapterConfigured
		resp.ShadowAttemptedOperations = report.ShadowAttemptedOperations
		resp.ShadowSubmittedOperations = report.ShadowSubmittedOperations
		resp.ShadowFailedOperations = report.ShadowFailedOperations
		resp.PendingOperations = report.PendingOperations
		resp.SubmittedOperations = report.SubmittedOperations
		resp.ConfirmedOperations = report.ConfirmedOperations
		resp.FailedOperations = report.FailedOperations
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) reserveSettlementForSession(ctx context.Context, sessionID string, subjectID string) {
	if s.settlement == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	subjectID = strings.TrimSpace(subjectID)
	if sessionID == "" || subjectID == "" {
		return
	}
	amount := s.sessionReserve
	if amount <= 0 {
		amount = 200000
	}
	_, err := s.settlement.ReserveFunds(ctx, settlement.FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: amount,
	})
	if err != nil {
		log.Printf("exit settlement reserve warning session=%s err=%v", sessionID, err)
	}
}

func (s *Service) finalizeSettlementForSession(ctx context.Context, sessionID string, session sessionInfo) {
	if s.settlement == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return
	}
	subjectID := strings.TrimSpace(session.claims.Subject)
	if subjectID == "" {
		subjectID = "client-anon"
	}
	if err := s.settlement.RecordUsage(ctx, settlement.UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: session.ingressBytes,
		BytesEgress:  session.egressBytes,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		log.Printf("exit settlement usage warning session=%s err=%v", sessionID, err)
		return
	}
	sessionSettlement, err := s.settlement.SettleSession(ctx, sessionID)
	if err != nil {
		log.Printf("exit settlement finalize warning session=%s err=%v", sessionID, err)
		return
	}
	rewardMicros := sessionSettlement.ChargedMicros / 2
	if rewardMicros <= 0 {
		return
	}
	providerSubjectID := "exit:" + strings.ReplaceAll(s.addr, ":", "_")
	if _, err := s.settlement.IssueReward(ctx, settlement.RewardIssue{
		RewardID:          "rew-" + sessionID,
		ProviderSubjectID: providerSubjectID,
		SessionID:         sessionID,
		RewardMicros:      rewardMicros,
		Currency:          sessionSettlement.Currency,
		IssuedAt:          time.Now().UTC(),
	}); err != nil {
		log.Printf("exit settlement reward warning session=%s err=%v", sessionID, err)
	}
}

func (s *Service) reconcileSettlement(ctx context.Context) {
	report, _, _, _, err := s.reconcileSettlementStatus(ctx)
	if err != nil {
		log.Printf("exit settlement reconcile warning err=%v", err)
		return
	}
	if report.PendingAdapterOperations > 0 || report.FailedOperations > 0 {
		log.Printf("exit settlement reconcile pending=%d failed=%d", report.PendingAdapterOperations, report.FailedOperations)
	}
}

func (s *Service) reconcileSettlementStatus(ctx context.Context) (settlement.ReconcileReport, bool, time.Time, string, error) {
	if s.settlement == nil {
		return settlement.ReconcileReport{}, false, time.Time{}, "", nil
	}
	report, err := s.settlement.Reconcile(ctx)
	checkedAt := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settlementStatus.lastCheckedAt = checkedAt
	if err != nil {
		s.settlementStatus.lastError = err.Error()
		return s.settlementStatus.lastReport, true, checkedAt, s.settlementStatus.lastError, err
	}
	s.settlementStatus.lastReport = report
	s.settlementStatus.lastError = ""
	return report, false, checkedAt, "", nil
}

func (s *Service) recordAccept(bytes uint64, tier int) {
	s.mu.Lock()
	s.metrics.AcceptedPackets++
	s.metrics.AcceptedBytes += bytes
	switch tier {
	case 1:
		s.metrics.AcceptedTier1Packets++
	case 2:
		s.metrics.AcceptedTier2Packets++
	case 3:
		s.metrics.AcceptedTier3Packets++
	}
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordSessionIngress(sessionID string, bytes int64) {
	if bytes <= 0 || strings.TrimSpace(sessionID) == "" {
		return
	}
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if ok {
		session.ingressBytes += bytes
		s.sessions[sessionID] = session
	}
	s.mu.Unlock()
}

func (s *Service) recordSessionEgress(sessionID string, bytes int64) {
	if bytes <= 0 || strings.TrimSpace(sessionID) == "" {
		return
	}
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if ok {
		session.egressBytes += bytes
		s.sessions[sessionID] = session
	}
	s.mu.Unlock()
}

func (s *Service) recordDrop(bytes uint64, tier int) {
	s.mu.Lock()
	s.metrics.DroppedPackets++
	s.metrics.DroppedBytes += bytes
	switch tier {
	case 1:
		s.metrics.DroppedTier1Packets++
	case 2:
		s.metrics.DroppedTier2Packets++
	case 3:
		s.metrics.DroppedTier3Packets++
	}
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordRevokedTokenDrop() {
	s.mu.Lock()
	s.metrics.DroppedTokenRevoked++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordKeyEpochTokenDrop() {
	s.mu.Lock()
	s.metrics.DroppedTokenKeyEpoch++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordTokenProofReplayDrop() {
	s.mu.Lock()
	s.metrics.DroppedTokenProofReplay++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordSourceMismatchDrop(bytes uint64) {
	s.mu.Lock()
	s.metrics.DroppedSourceMismatch++
	s.metrics.DroppedPackets++
	s.metrics.DroppedBytes += bytes
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordNonWGLiveDrop(bytes uint64, tier int) {
	s.mu.Lock()
	s.metrics.DroppedNonWGLive++
	s.metrics.DroppedPackets++
	s.metrics.DroppedBytes += bytes
	switch tier {
	case 1:
		s.metrics.DroppedTier1Packets++
	case 2:
		s.metrics.DroppedTier2Packets++
	case 3:
		s.metrics.DroppedTier3Packets++
	}
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordDownlinkForward(bytes uint64) {
	s.mu.Lock()
	s.metrics.ForwardedDownlinkPkts++
	s.metrics.ForwardedDownlinkBytes += bytes
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordDownlinkDrop() {
	s.mu.Lock()
	s.metrics.DroppedDownlinkPkts++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordWGProxyError() {
	s.mu.Lock()
	s.metrics.WGProxyErrors++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordWGProxyLimitDrop() {
	s.mu.Lock()
	s.metrics.WGProxyLimitDrops++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) configureEgress(ctx context.Context) error {
	if s.egressBackend != "command" {
		return nil
	}
	chain, cidr, iface, err := sanitizeEgressCommandInputs(s.egressChain, s.egressCIDR, s.egressIface)
	if err != nil {
		return err
	}
	for _, cmdStr := range buildEgressSetupCommands(chain, cidr, iface) {
		if err := runShell(ctx, cmdStr); err != nil {
			return fmt.Errorf("egress setup failed cmd=%q: %w", cmdStr, err)
		}
	}
	s.egressConfigured = true
	return nil
}

func (s *Service) teardownEgress(ctx context.Context) error {
	if s.egressBackend != "command" || !s.egressConfigured {
		return nil
	}
	chain, cidr, iface, err := sanitizeEgressCommandInputs(s.egressChain, s.egressCIDR, s.egressIface)
	if err != nil {
		return err
	}
	var firstErr error
	for _, cmdStr := range buildEgressCleanupCommands(chain, cidr, iface) {
		if err := runShell(ctx, cmdStr); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("egress cleanup failed cmd=%q: %w", cmdStr, err)
		}
	}
	s.egressConfigured = false
	return firstErr
}

func sanitizeEgressCommandInputs(chain string, cidr string, iface string) (string, string, string, error) {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		chain = "PRIVNODE_EGRESS"
	}
	if !egressChainPattern.MatchString(chain) || strings.HasPrefix(chain, "-") {
		return "", "", "", fmt.Errorf("invalid EXIT_EGRESS_CHAIN: %q", chain)
	}

	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return "", "", "", errors.New("invalid EXIT_EGRESS_CIDR: empty")
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", "", "", fmt.Errorf("invalid EXIT_EGRESS_CIDR: %q", cidr)
	}

	iface = strings.TrimSpace(iface)
	if iface == "" {
		return "", "", "", errors.New("invalid EXIT_EGRESS_IFACE: empty")
	}
	if !egressIfacePattern.MatchString(iface) || strings.HasPrefix(iface, "-") {
		return "", "", "", fmt.Errorf("invalid EXIT_EGRESS_IFACE: %q", iface)
	}

	return chain, cidr, iface, nil
}

func buildEgressSetupCommands(chain string, cidr string, iface string) []string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		chain = "PRIVNODE_EGRESS"
	}
	return []string{
		"sysctl -w net.ipv4.ip_forward=1 >/dev/null",
		fmt.Sprintf("iptables -t nat -N %s 2>/dev/null || true", chain),
		fmt.Sprintf("iptables -t nat -F %s", chain),
		fmt.Sprintf("iptables -t nat -A %s -s %s -o %s -j MASQUERADE", chain, cidr, iface),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -j %s 2>/dev/null || iptables -t nat -A POSTROUTING -j %s", chain, chain),
		fmt.Sprintf("iptables -C FORWARD -s %s -o %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -s %s -o %s -j ACCEPT", cidr, iface, cidr, iface),
		fmt.Sprintf("iptables -C FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -i %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -i %s -j ACCEPT", cidr, iface, cidr, iface),
	}
}

func buildEgressCleanupCommands(chain string, cidr string, iface string) []string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		chain = "PRIVNODE_EGRESS"
	}
	return []string{
		fmt.Sprintf("iptables -D FORWARD -s %s -o %s -j ACCEPT 2>/dev/null || true", cidr, iface),
		fmt.Sprintf("iptables -D FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -i %s -j ACCEPT 2>/dev/null || true", cidr, iface),
		fmt.Sprintf("iptables -t nat -D POSTROUTING -j %s 2>/dev/null || true", chain),
		fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chain),
		fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chain),
	}
}

func runShell(ctx context.Context, cmdStr string) error {
	cmd := exec.CommandContext(ctx, "sh", "-lc", cmdStr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Service) flushAccountingSnapshot(now time.Time) error {
	if strings.TrimSpace(s.accountingFile) == "" {
		return nil
	}
	s.mu.RLock()
	metrics := s.metrics
	metrics.ActiveSessions = uint64(len(s.sessions))
	metrics.ActiveWGProxySessions = uint64(len(s.wgSessionProxies))
	s.mu.RUnlock()
	snapshot := map[string]interface{}{
		"generated_at": now.Unix(),
		"metrics":      metrics,
	}
	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.accountingFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeFileAtomic(s.accountingFile, b, 0o644)
}

func tickerC(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func (s *Service) refreshRevocations(ctx context.Context) error {
	// Keep issuer keys fresh before validating signed revocation feeds.
	// This prevents false signature failures during issuer key rollover.
	_ = s.refreshIssuerKeys(ctx)

	urls := s.revocationsURLs
	if len(urls) == 0 && s.revocationsURL != "" {
		urls = []string{s.revocationsURL}
	}
	if len(urls) == 0 {
		return errors.New("missing revocation urls")
	}
	now := time.Now().Unix()
	success := 0
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("revocations endpoint returned %d", resp.StatusCode)
			log.Printf("exit revocation source rejected url=%s err=%v", u, lastErr)
			continue
		}
		var out proto.RevocationListResponse
		if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
			_ = resp.Body.Close()
			lastErr = err
			log.Printf("exit revocation source rejected url=%s err=%v", u, lastErr)
			continue
		}
		_ = resp.Body.Close()
		if err := s.applyRevocationFeed(out, now); err != nil {
			lastErr = err
			log.Printf("exit revocation source rejected url=%s err=%v", u, lastErr)
			continue
		}
		success++
	}
	if success == 0 {
		if lastErr == nil {
			lastErr = errors.New("no revocation feed updated")
		}
		return lastErr
	}
	return nil
}

func decodeBoundedJSONResponse(body io.Reader, dst any, maxBytes int64) error {
	if body == nil {
		return fmt.Errorf("empty response body")
	}
	if maxBytes <= 0 {
		return fmt.Errorf("invalid response size limit: %d", maxBytes)
	}
	reader := &io.LimitedReader{R: body, N: maxBytes + 1}
	dec := json.NewDecoder(reader)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if reader.N <= 0 {
		return fmt.Errorf("response body exceeds %d bytes", maxBytes)
	}
	var trailer json.RawMessage
	if err := dec.Decode(&trailer); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing json content")
		}
		return err
	}
	if reader.N <= 0 {
		return fmt.Errorf("response body exceeds %d bytes", maxBytes)
	}
	return nil
}

func (s *Service) applyRevocationFeed(feed proto.RevocationListResponse, now int64) error {
	keyID, err := s.verifyRevocationFeed(feed, now)
	if err != nil {
		return err
	}
	issuerID := strings.TrimSpace(feed.Issuer)

	s.mu.Lock()
	if mappedIssuer := strings.TrimSpace(s.issuerKeyIssuer[keyID]); mappedIssuer != "" {
		if issuerID == "" {
			issuerID = mappedIssuer
		} else if issuerID != mappedIssuer {
			s.mu.Unlock()
			return fmt.Errorf("revocation feed issuer %q does not match signer issuer %q", issuerID, mappedIssuer)
		}
	}
	if issuerID == "" {
		issuerID = keyID
	}
	if s.revocationVersion == nil {
		s.revocationVersion = make(map[string]int64)
	}
	if s.minTokenEpoch == nil {
		s.minTokenEpoch = make(map[string]int64)
	}
	if s.revokedJTI == nil {
		s.revokedJTI = make(map[string]int64)
	}
	prevVersion, hasPrevVersion := s.revocationVersion[issuerID]
	if feed.Version > 0 {
		if hasPrevVersion && feed.Version < prevVersion {
			s.mu.Unlock()
			return fmt.Errorf(
				"revocation feed version rollback detected issuer=%q signer=%q incoming_version=%d current_version=%d",
				issuerID,
				keyID,
				feed.Version,
				prevVersion,
			)
		}
	}
	requiredEpoch := feed.MinTokenEpoch
	if requiredEpoch <= 0 {
		requiredEpoch = feed.KeyEpoch
	}
	if requiredEpoch > 0 {
		if prev := s.minTokenEpoch[issuerID]; requiredEpoch > prev {
			s.minTokenEpoch[issuerID] = requiredEpoch
		}
	}
	keyPrefix := keyID + "|"
	existingByJTI := make(map[string]int64)
	for k, until := range s.revokedJTI {
		if !strings.HasPrefix(k, keyPrefix) {
			continue
		}
		if now >= until {
			delete(s.revokedJTI, k)
			continue
		}
		existingByJTI[strings.TrimPrefix(k, keyPrefix)] = until
	}

	incomingByJTI := make(map[string]int64, len(feed.Revocations))
	for _, r := range feed.Revocations {
		if r.JTI == "" || now >= r.Until {
			continue
		}
		if prevUntil, ok := incomingByJTI[r.JTI]; !ok || r.Until > prevUntil {
			incomingByJTI[r.JTI] = r.Until
		}
	}

	if feed.Version > 0 && hasPrevVersion && feed.Version == prevVersion {
		missingActive := 0
		shortenedActive := 0
		sampleJTI := ""
		for jti, existingUntil := range existingByJTI {
			incomingUntil, ok := incomingByJTI[jti]
			if !ok {
				missingActive++
				if sampleJTI == "" {
					sampleJTI = jti
				}
				continue
			}
			if incomingUntil < existingUntil {
				shortenedActive++
				if sampleJTI == "" {
					sampleJTI = jti
				}
			}
		}
		if missingActive > 0 || shortenedActive > 0 {
			s.mu.Unlock()
			return fmt.Errorf(
				"revocation feed conflict detected issuer=%q signer=%q version=%d generated_at=%d missing_active=%d shortened_active=%d sample_jti=%q",
				issuerID,
				keyID,
				feed.Version,
				feed.GeneratedAt,
				missingActive,
				shortenedActive,
				sampleJTI,
			)
		}
	}

	for jti, until := range incomingByJTI {
		compound := keyPrefix + jti
		if prevUntil, ok := s.revokedJTI[compound]; !ok || until > prevUntil {
			s.revokedJTI[compound] = until
		}
	}

	if feed.Version > 0 && (!hasPrevVersion || feed.Version > prevVersion) {
		s.revocationVersion[issuerID] = feed.Version
	}
	s.mu.Unlock()
	return nil
}

func (s *Service) acceptsTokenKeyEpoch(claims crypto.CapabilityClaims, issuerKeyID string) bool {
	issuerID := strings.TrimSpace(claims.Issuer)
	s.mu.RLock()
	if mapped := strings.TrimSpace(s.issuerKeyIssuer[issuerKeyID]); mapped != "" {
		issuerID = mapped
	}
	minEpoch := s.minTokenEpoch[issuerID]
	s.mu.RUnlock()
	if issuerID == "" || minEpoch <= 0 {
		return true
	}
	return claims.KeyEpoch >= minEpoch
}

func (s *Service) verifyRevocationFeed(feed proto.RevocationListResponse, now int64) (string, error) {
	if feed.Signature == "" {
		return "", errors.New("revocation feed signature missing")
	}
	if feed.ExpiresAt > 0 && now >= feed.ExpiresAt {
		return "", errors.New("revocation feed expired")
	}
	if feed.GeneratedAt > 0 && feed.GeneratedAt > now+60 {
		return "", errors.New("revocation feed generated_at too far in future")
	}

	sigRaw, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		return "", fmt.Errorf("invalid revocation signature encoding: %w", err)
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", fmt.Errorf("marshal revocation feed: %w", err)
	}

	s.mu.RLock()
	keys := make(map[string]ed25519.PublicKey, len(s.issuerPubs))
	for id, pub := range s.issuerPubs {
		keys[id] = pub
	}
	if len(keys) == 0 && len(s.issuerPub) > 0 {
		id := issuerKeyID(s.issuerPub)
		keys[id] = s.issuerPub
	}
	s.mu.RUnlock()

	if len(keys) == 0 {
		return "", errors.New("issuer pubkey unavailable for revocation verification")
	}
	for keyID, pub := range keys {
		if ed25519.Verify(pub, payload, sigRaw) {
			return keyID, nil
		}
	}
	return "", errors.New("revocation feed signature invalid")
}

func (s *Service) isRevoked(issuerKeyID string, jti string, now int64) bool {
	if jti == "" {
		return false
	}
	s.mu.RLock()
	until, ok := s.revokedJTI[issuerKeyID+"|"+jti]
	if !ok {
		until, ok = s.revokedJTI["*|"+jti]
	}
	s.mu.RUnlock()
	return ok && now < until
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func envEnabled(name string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseStrictBool(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("expected one of: 1|0|true|false|yes|no|on|off")
	}
}

func envStrictBoolOr(primary string, fallback string, def bool) (bool, error) {
	primarySet := false
	primaryValue := false
	if raw, ok := os.LookupEnv(primary); ok {
		primarySet = true
		if strings.TrimSpace(raw) == "" {
			return false, fmt.Errorf("value must not be empty")
		}
		parsed, err := parseStrictBool(raw)
		if err != nil {
			return false, err
		}
		primaryValue = parsed
	}

	fallbackSet := false
	fallbackValue := false
	if fallback != "" {
		if raw, ok := os.LookupEnv(fallback); ok {
			fallbackSet = true
			if strings.TrimSpace(raw) == "" {
				return false, fmt.Errorf("value must not be empty")
			}
			parsed, err := parseStrictBool(raw)
			if err != nil {
				return false, err
			}
			fallbackValue = parsed
		}
	}

	if primarySet && fallbackSet {
		return primaryValue || fallbackValue, nil
	}
	if primarySet {
		return primaryValue, nil
	}
	if fallbackSet {
		return fallbackValue, nil
	}
	return def, nil
}

func annotateEnvParseError(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s invalid: %w", name, err)
}

func firstEnvParseError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func normalizeHTTPURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		base := strings.TrimRight(v, "/")
		host := base
		if cut, _, ok := strings.Cut(base, "/"); ok {
			host = cut
		}
		if isLoopbackURLHost(host) {
			v = "http://" + base
		} else {
			v = "https://" + base
		}
	}
	parsed, err := url.Parse(v)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.Scheme == "http" &&
		!isLoopbackURLHost(parsed.Host) &&
		!isLocalDevelopmentURLHost(parsed.Host) &&
		enforceHTTPSControlURL() &&
		!allowDangerousInsecureControlURLHTTP() {
		return ""
	}
	return strings.TrimRight(parsed.String(), "/")
}

func enforceHTTPSControlURL() bool {
	raw := strings.TrimSpace(os.Getenv("EXIT_REQUIRE_HTTPS_CONTROL_URL"))
	if raw == "" {
		return true
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func allowDangerousInsecureControlURLHTTP() bool {
	raw := strings.TrimSpace(os.Getenv("EXIT_ALLOW_INSECURE_CONTROL_URL_HTTP"))
	return raw == "1" || strings.EqualFold(raw, "true")
}

func isLoopbackURLHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.Count(host, ":") == 1 || strings.HasPrefix(host, "[") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func isLocalDevelopmentURLHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.Count(host, ":") == 1 || strings.HasPrefix(host, "[") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	host = strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	return host != "" && (host == "localhost" || strings.HasSuffix(host, ".local"))
}

type outboundIPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

func configureOutboundDialPolicy(client *http.Client, allowDangerousPrivateDNS bool, strictBlockPrivateLiteral bool) {
	if client == nil {
		return
	}
	transport := cloneHTTPTransport(client.Transport)
	transport.Proxy = nil
	if envEnabled("MTLS_ALLOW_PROXY_FROM_ENV") {
		transport.Proxy = http.ProxyFromEnvironment
	}
	resolver := net.DefaultResolver
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		safeAddress, err := resolveSafeDialAddress(ctx, resolver, address, allowDangerousPrivateDNS, strictBlockPrivateLiteral)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, safeAddress)
	}
	client.Transport = transport
}

func cloneHTTPTransport(base http.RoundTripper) *http.Transport {
	if tr, ok := base.(*http.Transport); ok && tr != nil {
		return tr.Clone()
	}
	if tr, ok := http.DefaultTransport.(*http.Transport); ok && tr != nil {
		return tr.Clone()
	}
	return &http.Transport{}
}

func resolveSafeDialAddress(ctx context.Context, resolver outboundIPResolver, address string, allowDangerousPrivateDNS bool, strictBlockPrivateLiteral bool) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("invalid outbound address %q: %w", address, err)
	}
	if hasZoneIdentifierHost(host) {
		return "", fmt.Errorf("outbound host %q includes unsupported zone identifier", host)
	}
	host = normalizeHostForCompare(host)
	if host == "" {
		return "", fmt.Errorf("outbound host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedOutboundDialIP(ip) {
			if strictBlockPrivateLiteral {
				return "", fmt.Errorf("outbound literal host %q is blocked by outbound dial policy (strict mode)", ip.String())
			}
			if !allowDangerousPrivateDNS {
				return "", fmt.Errorf("outbound literal host %q is blocked by outbound dial policy", ip.String())
			}
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve outbound host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve outbound host %q returned no addresses", host)
	}
	loopbackHostname := host == "localhost"
	if loopbackHostname && !allowDangerousPrivateDNS {
		var selectedLoopback net.IP
		for _, candidate := range ips {
			ip := candidate.IP
			if ip == nil {
				continue
			}
			if !ip.IsLoopback() {
				return "", fmt.Errorf("outbound host %q resolved to non-loopback address %q", host, ip.String())
			}
			if selectedLoopback == nil {
				selectedLoopback = ip
			}
		}
		if selectedLoopback == nil {
			return "", fmt.Errorf("outbound host %q resolved only to blocked address classes", host)
		}
		return net.JoinHostPort(selectedLoopback.String(), port), nil
	}
	for _, candidate := range ips {
		ip := candidate.IP
		if ip == nil {
			continue
		}
		if allowDangerousPrivateDNS {
			return net.JoinHostPort(ip.String(), port), nil
		}
		if isDisallowedOutboundDialIP(ip) {
			if loopbackHostname && ip.IsLoopback() {
				return net.JoinHostPort(ip.String(), port), nil
			}
			continue
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	return "", fmt.Errorf("outbound host %q resolved only to blocked address classes", host)
}

func isDisallowedOutboundDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		if addr, ok := netip.AddrFromSlice(ipv4); ok && sharedAddressSpaceCGNATPrefix.Contains(addr) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func hasZoneIdentifierHost(host string) bool {
	normalized := strings.TrimSpace(strings.Trim(host, "[]"))
	return strings.Contains(normalized, "%")
}

func normalizeHostForCompare(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	return strings.TrimRight(normalized, ".")
}

func normalizeHTTPURLs(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		norm := normalizeHTTPURL(u)
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

func joinURL(base string, path string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}

func issuerKeyID(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}
