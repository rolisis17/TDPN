package directory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
	urlpkg "net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
	"privacynode/pkg/securehttp"
)

type Service struct {
	addr                             string
	localURL                         string
	operatorID                       string
	pubKey                           ed25519.PublicKey
	privKey                          ed25519.PrivateKey
	server                           *http.Server
	entryEndpoints                   []string
	endpointRotateSec                int64
	descriptorEpoch                  time.Duration
	descriptorTTL                    time.Duration
	selectionFeedTTL                 time.Duration
	selectionEpoch                   time.Duration
	trustFeedTTL                     time.Duration
	trustEpoch                       time.Duration
	adminToken                       string
	previousPubKeysFile              string
	providerIssuerURLs               []string
	providerIssuerPubCacheTTL        time.Duration
	providerRelayMaxTTL              time.Duration
	providerMinEntryTier             int
	providerMinExitTier              int
	providerMaxPerOperator           int
	providerSplitRoles               bool
	issuerTrustURLs                  []string
	issuerTrustedKeysFile            string
	issuerTrustedKeys                []ed25519.PublicKey
	issuerSyncSec                    int
	issuerTrustMinVotes              int
	issuerDisputeMinVotes            int
	issuerAppealMinVotes             int
	peerURLs                         []string
	peerSyncSec                      int
	gossipSec                        int
	gossipFanout                     int
	peerListTTL                      time.Duration
	peerDiscoveryEnabled             bool
	peerDiscoveryMax                 int
	peerDiscoveryTTL                 time.Duration
	peerDiscoveryMinVotes            int
	peerDiscoveryRequireHint         bool
	peerDiscoveryMaxPerSrc           int
	peerDiscoveryMaxPerOp            int
	peerDiscoveryFailN               int
	peerDiscoveryBackoff             time.Duration
	peerDiscoveryBackoffMax          time.Duration
	peerDiscoveryDNSSeeds            []string
	peerDiscoveryDNSRefresh          time.Duration
	peerMinOperators                 int
	peerMinVotes                     int
	peerScoreMinVotes                int
	peerTrustMinVotes                int
	peerSignalFreshnessMaxAge        time.Duration
	peerDisputeMinVotes              int
	peerAppealMinVotes               int
	adjudicationMetaMin              int
	finalAdjudicationOps             int
	finalAdjudicationSources         int
	finalDisputeMinVotes             int
	finalAppealMinVotes              int
	finalAdjudicationMin             float64
	disputeMaxTTL                    time.Duration
	appealMaxTTL                     time.Duration
	issuerMinOperators               int
	issuerSignalFreshnessMaxAge      time.Duration
	peerMaxHops                      int
	peerMu                           sync.RWMutex
	peerRelays                       map[string]proto.RelayDescriptor
	providerMu                       sync.RWMutex
	providerRelays                   map[string]proto.RelayDescriptor
	providerTokenProofSeen           map[string]time.Time
	providerTokenProofStoreFile      string
	providerTokenProofSharedFileMode bool
	providerTokenProofLockTimeout    time.Duration
	providerTokenProofRedisAddr      string
	providerTokenProofRedisPassword  string
	providerTokenProofRedisDB        int
	providerTokenProofRedisTLS       bool
	providerTokenProofRedisPrefix    string
	providerTokenProofRedisDial      time.Duration
	providerTokenProofRedisMu        sync.Mutex
	providerTokenProofRedisClient    *redis.Client
	peerScores                       map[string]proto.RelaySelectionScore
	peerTrust                        map[string]proto.RelayTrustAttestation
	issuerTrust                      map[string]proto.RelayTrustAttestation
	discoveredPeers                  map[string]time.Time
	discoveredPeerVoters             map[string]map[string]time.Time
	discoveredPeerHealth             map[string]discoveredPeerHealth
	peerHintPubKeys                  map[string]string
	peerHintOperators                map[string]string
	peerPubKeyCache                  map[string]peerPubKeyCacheEntry
	peerRelayETags                   map[string]string
	peerRelayCache                   map[string][]proto.RelayDescriptor
	peerScoreETags                   map[string]string
	peerScoreCache                   map[string]map[string]proto.RelaySelectionScore
	peerScoreCacheExpiresAt          map[string]int64
	peerTrustETags                   map[string]string
	peerTrustCache                   map[string]map[string]proto.RelayTrustAttestation
	peerTrustCacheExpiresAt          map[string]int64
	issuerTrustETags                 map[string]string
	issuerTrustCache                 map[string]map[string]proto.RelayTrustAttestation
	issuerTrustCacheExpiresAt        map[string]int64
	peerScoreLastFreshAt             time.Time
	peerTrustLastFreshAt             time.Time
	issuerTrustLastFreshAt           time.Time
	providerIssuerPubCacheMu         sync.RWMutex
	providerIssuerPubCache           map[string]providerIssuerPubCacheEntry
	peerTrustStrict                  bool
	peerTrustTOFU                    bool
	peerTrustFile                    string
	betaStrict                       bool
	prodStrict                       bool
	strictModeParseErr               error
	peerTrustMu                      sync.Mutex
	syncStatusMu                     sync.RWMutex
	peerSyncStatus                   proto.DirectorySyncRunStatus
	issuerSyncStatus                 proto.DirectorySyncRunStatus
	keyMu                            sync.RWMutex
	httpClient                       *http.Client
	privateKeyPath                   string
	keyRotateEvery                   time.Duration
	keyHistory                       int
	dnsLookupTXT                     func(context.Context, string) ([]string, error)
}

type discoveredPeerHealth struct {
	lastSuccess         time.Time
	lastFailure         time.Time
	consecutiveFailures int
	cooldownUntil       time.Time
	lastError           string
}

type providerIssuerPubCacheEntry struct {
	pubs      []ed25519.PublicKey
	issuerID  string
	fetchedAt time.Time
}

type peerPubKeyCacheEntry struct {
	pubs             []ed25519.PublicKey
	operatorID       string
	fetchedAt        time.Time
	lastFetchAttempt time.Time
}

const discoveredPeerUnknownOperator = "_unknown"
const providerRelayUpsertMaxBodyBytes int64 = 128 * 1024
const providerRelayUpsertProofContext = "provider_relay_upsert_v1"
const providerRelayUpsertProofReplayTTL = 15 * time.Minute
const providerRelayUpsertProofNonceMaxLen = 128
const providerRelayUpsertProofReplayMaxEntries = 8192
const providerRelayUpsertProofReplayMaxPerToken = 512
const providerRelayUpsertProofReplayDefaultLockTimeout = 5 * time.Second
const providerRelayUpsertProofReplayLockRetryInterval = 50 * time.Millisecond
const providerRelayUpsertProofReplayRedisDefaultDialTimeout = 5 * time.Second
const providerRelayUpsertProofReplayRedisDefaultPrefix = "directory:provider_token_proof_replay:"
const gossipRelaysMaxBodyBytes int64 = 1024 * 1024
const gossipRelaysMaxDescriptors = 512
const remoteResponseMaxBodyBytes int64 = 1024 * 1024
const serverReadHeaderTimeout = 10 * time.Second
const serverReadTimeout = 15 * time.Second
const serverWriteTimeout = 30 * time.Second
const serverIdleTimeout = 60 * time.Second
const serverMaxHeaderBytes = 1 << 20
const allowInsecureAdminPublicBind = "DIRECTORY_ALLOW_DANGEROUS_INSECURE_ADMIN_PUBLIC_BIND"
const allowDangerousDevAdminTokenFallback = "DIRECTORY_ALLOW_DANGEROUS_DEV_ADMIN_TOKEN_FALLBACK"
const allowDangerousIssuerTrustWithoutAnchors = "DIRECTORY_ALLOW_DANGEROUS_ISSUER_TRUST_WITHOUT_ANCHORS"
const allowDangerousOutboundPrivateDNS = "DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"
const allowDangerousProviderTokenBypass = "DIRECTORY_ALLOW_DANGEROUS_PROVIDER_RELAY_TOKEN_BYPASS"
const defaultIssuerTrustedKeysFile = "data/directory_issuer_trusted_keys.txt"
const directoryPrivateKeyMaxBytes int64 = 16 * 1024
const directoryTrustedKeysFileMaxBytes int64 = 1 * 1024 * 1024
const directoryPreviousPubKeysFileMaxBytes int64 = 1 * 1024 * 1024
const directoryProviderReplayStoreMaxBytes int64 = 4 * 1024 * 1024
const defaultProviderIssuerPubCacheTTL = 30 * time.Second
const peerGossipPubKeyCacheTTL = 5 * time.Minute
const peerGossipPubKeyFetchMinInterval = 15 * time.Second
const defaultSignalFreshnessFloor = 5 * time.Minute
const defaultSignalFreshnessMultiplier = 6
const microRelayMinReputationScore = 0.5
const microRelayMinUptimeScore = 0.5
const microRelayMinCapacityScore = 0.5
const microRelayMaxAbusePenalty = 0.5

var errProviderRelayOwnershipConflict = errors.New("provider relay owned by different operator")
var sharedAddressSpaceCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")

func New() *Service {
	addr := os.Getenv("DIRECTORY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	localURL := normalizePeerURL(os.Getenv("DIRECTORY_PUBLIC_URL"))
	if localURL == "" {
		localURL = normalizePeerURL(addr)
	}
	rawEndpoints := os.Getenv("ENTRY_ENDPOINTS")
	var eps []string
	if rawEndpoints != "" {
		for _, p := range strings.Split(rawEndpoints, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				eps = append(eps, p)
			}
		}
	}
	if len(eps) == 0 {
		eps = []string{endpointWithDefault("ENTRY_ENDPOINT", "127.0.0.1:51820")}
	}
	rotateSec := int64(30)
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ROTATE_SEC")); err == nil && v > 0 {
		rotateSec = int64(v)
	}
	selectionFeedTTL := 30 * time.Second
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_SELECTION_FEED_TTL_SEC")); err == nil && v > 0 {
		selectionFeedTTL = time.Duration(v) * time.Second
	}
	selectionEpoch := 10 * time.Second
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_SELECTION_FEED_EPOCH_SEC")); err == nil && v > 0 {
		selectionEpoch = time.Duration(v) * time.Second
	}
	trustFeedTTL := 30 * time.Second
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_TRUST_FEED_TTL_SEC")); err == nil && v > 0 {
		trustFeedTTL = time.Duration(v) * time.Second
	}
	trustEpoch := selectionEpoch
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_TRUST_FEED_EPOCH_SEC")); err == nil && v > 0 {
		trustEpoch = time.Duration(v) * time.Second
	}
	descriptorEpoch := 10 * time.Second
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_DESCRIPTOR_EPOCH_SEC")); err == nil && v > 0 {
		descriptorEpoch = time.Duration(v) * time.Second
	}
	descriptorTTL := 30 * time.Minute
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_DESCRIPTOR_TTL_SEC")); err == nil && v > 0 {
		descriptorTTL = time.Duration(v) * time.Second
	}
	peerSyncSec := 10
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_SYNC_SEC")); err == nil && v > 0 {
		peerSyncSec = v
	}
	gossipSec := 0
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_GOSSIP_SEC")); err == nil && v > 0 {
		gossipSec = v
	}
	gossipFanout := 2
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_GOSSIP_FANOUT")); err == nil && v > 0 {
		gossipFanout = v
	}
	peerListTTL := 45 * time.Second
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_LIST_TTL_SEC")); err == nil && v > 0 {
		peerListTTL = time.Duration(v) * time.Second
	}
	peerDiscoveryEnabled := os.Getenv("DIRECTORY_PEER_DISCOVERY") != "0"
	peerDiscoveryMax := 64
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_MAX")); err == nil && v > 0 {
		peerDiscoveryMax = v
	}
	peerDiscoveryTTL := 15 * time.Minute
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_TTL_SEC")); err == nil && v > 0 {
		peerDiscoveryTTL = time.Duration(v) * time.Second
	}
	peerDiscoveryMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_MIN_VOTES")); err == nil && v > 0 {
		peerDiscoveryMinVotes = v
	}
	peerDiscoveryRequireHint := os.Getenv("DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT") == "1"
	peerDiscoveryMaxPerSrc := 0
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE")); err == nil && v > 0 {
		peerDiscoveryMaxPerSrc = v
	}
	peerDiscoveryMaxPerOp := 0
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR")); err == nil && v > 0 {
		peerDiscoveryMaxPerOp = v
	}
	peerDiscoveryFailN := 3
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_FAIL_THRESHOLD")); err == nil && v > 0 {
		peerDiscoveryFailN = v
	}
	peerDiscoveryBackoff := 60 * time.Second
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_BACKOFF_SEC")); err == nil && v > 0 {
		peerDiscoveryBackoff = time.Duration(v) * time.Second
	}
	peerDiscoveryBackoffMax := 15 * time.Minute
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_MAX_BACKOFF_SEC")); err == nil && v > 0 {
		peerDiscoveryBackoffMax = time.Duration(v) * time.Second
	}
	if peerDiscoveryBackoffMax < peerDiscoveryBackoff {
		peerDiscoveryBackoffMax = peerDiscoveryBackoff
	}
	peerDiscoveryDNSSeeds := parseDNSSeeds(splitCSV(os.Getenv("DIRECTORY_PEER_DISCOVERY_DNS_SEEDS")))
	peerDiscoveryDNSRefresh := time.Duration(0)
	if len(peerDiscoveryDNSSeeds) > 0 {
		peerDiscoveryDNSRefresh = 2 * time.Minute
	}
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISCOVERY_DNS_REFRESH_SEC")); err == nil && v > 0 {
		peerDiscoveryDNSRefresh = time.Duration(v) * time.Second
	}
	issuerSyncSec := 10
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ISSUER_SYNC_SEC")); err == nil && v > 0 {
		issuerSyncSec = v
	}
	peerSignalFreshnessMaxAge := defaultPeerSignalFreshnessMaxAge(peerSyncSec, selectionFeedTTL, trustFeedTTL)
	if v, ok := envPositiveDurationSeconds("DIRECTORY_PEER_SIGNAL_MAX_AGE_SEC"); ok {
		peerSignalFreshnessMaxAge = v
	}
	issuerSignalFreshnessMaxAge := defaultIssuerSignalFreshnessMaxAge(issuerSyncSec, trustFeedTTL)
	if v, ok := envPositiveDurationSeconds("DIRECTORY_ISSUER_TRUST_MAX_AGE_SEC"); ok {
		issuerSignalFreshnessMaxAge = v
	}
	directoryMinOperators := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_MIN_OPERATORS")); err == nil && v > 0 {
		directoryMinOperators = v
	}
	peerMinOperators := directoryMinOperators
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_MIN_OPERATORS")); err == nil && v > 0 {
		peerMinOperators = v
	}
	peerMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_MIN_VOTES")); err == nil && v > 0 {
		peerMinVotes = v
	}
	peerScoreMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_SCORE_MIN_VOTES")); err == nil && v > 0 {
		peerScoreMinVotes = v
	}
	peerTrustMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_TRUST_MIN_VOTES")); err == nil && v > 0 {
		peerTrustMinVotes = v
	}
	peerDisputeMinVotes := peerTrustMinVotes
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_DISPUTE_MIN_VOTES")); err == nil && v > 0 {
		peerDisputeMinVotes = v
	}
	peerAppealMinVotes := peerDisputeMinVotes
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_APPEAL_MIN_VOTES")); err == nil && v > 0 {
		peerAppealMinVotes = v
	}
	adjudicationMetaMin := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ADJUDICATION_META_MIN_VOTES")); err == nil && v > 0 {
		adjudicationMetaMin = v
	}
	finalAdjudicationOps := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS")); err == nil && v > 0 {
		finalAdjudicationOps = v
	}
	finalAdjudicationSources := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES")); err == nil && v > 0 {
		finalAdjudicationSources = v
	}
	finalAdjudicationMin := 0.5
	if raw := strings.TrimSpace(os.Getenv("DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO")); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			finalAdjudicationMin = clampScore(v)
		}
	}
	disputeMaxTTL := 7 * 24 * time.Hour
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_DISPUTE_MAX_TTL_SEC")); err == nil && v > 0 {
		disputeMaxTTL = time.Duration(v) * time.Second
	}
	appealMaxTTL := disputeMaxTTL
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_APPEAL_MAX_TTL_SEC")); err == nil && v > 0 {
		appealMaxTTL = time.Duration(v) * time.Second
	}
	issuerTrustMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ISSUER_TRUST_MIN_VOTES")); err == nil && v > 0 {
		issuerTrustMinVotes = v
	}
	issuerMinOperators := directoryMinOperators
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ISSUER_MIN_OPERATORS")); err == nil && v > 0 {
		issuerMinOperators = v
	}
	issuerDisputeMinVotes := issuerTrustMinVotes
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ISSUER_DISPUTE_MIN_VOTES")); err == nil && v > 0 {
		issuerDisputeMinVotes = v
	}
	issuerAppealMinVotes := issuerDisputeMinVotes
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ISSUER_APPEAL_MIN_VOTES")); err == nil && v > 0 {
		issuerAppealMinVotes = v
	}
	finalDisputeMinVotes := maxInt(1, maxInt(peerDisputeMinVotes, issuerDisputeMinVotes))
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_FINAL_DISPUTE_MIN_VOTES")); err == nil && v > 0 {
		finalDisputeMinVotes = v
	}
	finalAppealMinVotes := maxInt(1, maxInt(peerAppealMinVotes, issuerAppealMinVotes))
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_FINAL_APPEAL_MIN_VOTES")); err == nil && v > 0 {
		finalAppealMinVotes = v
	}
	peerMaxHops := 2
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PEER_MAX_HOPS")); err == nil && v > 0 {
		peerMaxHops = v
	}
	peerURLs := normalizePeerURLs(splitCSV(os.Getenv("DIRECTORY_PEERS")))
	issuerTrustURLs := normalizePeerURLs(splitCSV(os.Getenv("DIRECTORY_ISSUER_TRUST_URLS")))
	if len(issuerTrustURLs) == 0 {
		issuerTrustURLs = normalizePeerURLs(splitCSV(os.Getenv("ISSUER_URLS")))
	}
	if len(issuerTrustURLs) == 0 {
		if v := strings.TrimSpace(os.Getenv("ISSUER_URL")); v != "" {
			issuerTrustURLs = normalizePeerURLs([]string{v})
		}
	}
	providerIssuerURLs := normalizePeerURLs(splitCSV(os.Getenv("DIRECTORY_PROVIDER_ISSUER_URLS")))
	if len(providerIssuerURLs) == 0 {
		providerIssuerURLs = append([]string(nil), issuerTrustURLs...)
	}
	providerTokenProofStoreFile := strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE"))
	if providerTokenProofStoreFile == "" {
		providerTokenProofStoreFile = "data/directory_provider_token_proof_replay.json"
	}
	providerTokenProofSharedFileMode := envEnabled("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE")
	providerTokenProofLockTimeout := providerRelayUpsertProofReplayDefaultLockTimeout
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC")); err == nil && v > 0 {
		providerTokenProofLockTimeout = time.Duration(v) * time.Second
	}
	providerTokenProofRedisAddr := strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_ADDR"))
	providerTokenProofRedisPassword := os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_PASSWORD")
	providerTokenProofRedisDB := 0
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DB"))); err == nil && v >= 0 {
		providerTokenProofRedisDB = v
	}
	providerTokenProofRedisTLS := envEnabled("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_TLS")
	providerTokenProofRedisPrefix := strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_PREFIX"))
	if providerTokenProofRedisPrefix == "" {
		providerTokenProofRedisPrefix = providerRelayUpsertProofReplayRedisDefaultPrefix
	}
	providerTokenProofRedisDial := providerRelayUpsertProofReplayRedisDefaultDialTimeout
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC"))); err == nil && v > 0 {
		providerTokenProofRedisDial = time.Duration(v) * time.Second
	}
	providerRelayMaxTTL := 5 * time.Minute
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PROVIDER_RELAY_MAX_TTL_SEC")); err == nil && v > 0 {
		providerRelayMaxTTL = time.Duration(v) * time.Second
	}
	providerIssuerPubCacheTTL := defaultProviderIssuerPubCacheTTL
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PROVIDER_ISSUER_PUBKEY_CACHE_SEC")); err == nil && v >= 0 {
		providerIssuerPubCacheTTL = time.Duration(v) * time.Second
	}
	providerMinEntryTier := 1
	if v := strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_MIN_ENTRY_TIER")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			providerMinEntryTier = clampProviderTier(parsed)
		}
	}
	providerMinExitTier := 1
	if v := strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_MIN_EXIT_TIER")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			providerMinExitTier = clampProviderTier(parsed)
		}
	}
	providerMaxPerOperator := 0
	if v := strings.TrimSpace(os.Getenv("DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			providerMaxPerOperator = parsed
		}
	}
	providerSplitRoles := os.Getenv("DIRECTORY_PROVIDER_SPLIT_ROLES") == "1"
	peerTrustStrict, peerTrustStrictErr := envStrictBoolOr("DIRECTORY_PEER_TRUST_STRICT", "", false)
	peerTrustTOFU, peerTrustTOFUErr := envStrictBoolOr("DIRECTORY_PEER_TRUST_TOFU", "", false)
	peerTrustFile := os.Getenv("DIRECTORY_PEER_TRUSTED_KEYS_FILE")
	if peerTrustFile == "" {
		peerTrustFile = "data/directory_peer_trusted_keys.txt"
	}
	issuerTrustedKeysFile := strings.TrimSpace(os.Getenv("DIRECTORY_ISSUER_TRUSTED_KEYS_FILE"))
	if issuerTrustedKeysFile == "" {
		issuerTrustedKeysFile = defaultIssuerTrustedKeysFile
	}
	betaStrict, betaStrictErr := envStrictBoolOr("BETA_STRICT_MODE", "DIRECTORY_BETA_STRICT", false)
	prodStrict, prodStrictErr := envStrictBoolOr("PROD_STRICT_MODE", "DIRECTORY_PROD_STRICT", false)
	strictModeParseErr := firstEnvParseError(
		annotateEnvParseError("BETA_STRICT_MODE/DIRECTORY_BETA_STRICT", betaStrictErr),
		annotateEnvParseError("PROD_STRICT_MODE/DIRECTORY_PROD_STRICT", prodStrictErr),
		annotateEnvParseError("DIRECTORY_PEER_TRUST_STRICT", peerTrustStrictErr),
		annotateEnvParseError("DIRECTORY_PEER_TRUST_TOFU", peerTrustTOFUErr),
	)
	if betaStrict {
		providerSplitRoles = true
	}
	adminToken := strings.TrimSpace(os.Getenv("DIRECTORY_ADMIN_TOKEN"))
	if adminToken == "" && envEnabled(allowDangerousDevAdminTokenFallback) {
		adminToken = "dev-admin-token"
	}
	previousPubKeysFile := os.Getenv("DIRECTORY_PREVIOUS_PUBKEYS_FILE")
	if previousPubKeysFile == "" {
		previousPubKeysFile = "data/directory_previous_pubkeys.txt"
	}
	operatorID := operatorIDWithDefault("DIRECTORY_OPERATOR_ID", "operator-local")
	privateKeyPath := os.Getenv("DIRECTORY_PRIVATE_KEY_FILE")
	if privateKeyPath == "" {
		privateKeyPath = "runtime/directory/directory_ed25519.key"
	}
	keyRotateEvery := time.Duration(0)
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_KEY_ROTATE_SEC")); err == nil && v > 0 {
		keyRotateEvery = time.Duration(v) * time.Second
	}
	keyHistory := 3
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_KEY_HISTORY")); err == nil && v > 0 {
		keyHistory = v
	}
	return &Service{
		addr:                             addr,
		localURL:                         localURL,
		operatorID:                       operatorID,
		entryEndpoints:                   eps,
		endpointRotateSec:                rotateSec,
		descriptorEpoch:                  descriptorEpoch,
		descriptorTTL:                    descriptorTTL,
		selectionFeedTTL:                 selectionFeedTTL,
		selectionEpoch:                   selectionEpoch,
		trustFeedTTL:                     trustFeedTTL,
		trustEpoch:                       trustEpoch,
		adminToken:                       adminToken,
		previousPubKeysFile:              previousPubKeysFile,
		providerIssuerURLs:               providerIssuerURLs,
		providerIssuerPubCacheTTL:        providerIssuerPubCacheTTL,
		providerRelayMaxTTL:              providerRelayMaxTTL,
		providerMinEntryTier:             providerMinEntryTier,
		providerMinExitTier:              providerMinExitTier,
		providerMaxPerOperator:           providerMaxPerOperator,
		providerSplitRoles:               providerSplitRoles,
		issuerTrustURLs:                  issuerTrustURLs,
		issuerSyncSec:                    issuerSyncSec,
		issuerTrustMinVotes:              issuerTrustMinVotes,
		issuerDisputeMinVotes:            issuerDisputeMinVotes,
		issuerAppealMinVotes:             issuerAppealMinVotes,
		issuerSignalFreshnessMaxAge:      issuerSignalFreshnessMaxAge,
		peerURLs:                         peerURLs,
		peerSyncSec:                      peerSyncSec,
		gossipSec:                        gossipSec,
		gossipFanout:                     gossipFanout,
		peerListTTL:                      peerListTTL,
		peerDiscoveryEnabled:             peerDiscoveryEnabled,
		peerDiscoveryMax:                 peerDiscoveryMax,
		peerDiscoveryTTL:                 peerDiscoveryTTL,
		peerDiscoveryMinVotes:            peerDiscoveryMinVotes,
		peerDiscoveryRequireHint:         peerDiscoveryRequireHint,
		peerDiscoveryMaxPerSrc:           peerDiscoveryMaxPerSrc,
		peerDiscoveryMaxPerOp:            peerDiscoveryMaxPerOp,
		peerDiscoveryFailN:               peerDiscoveryFailN,
		peerDiscoveryBackoff:             peerDiscoveryBackoff,
		peerDiscoveryBackoffMax:          peerDiscoveryBackoffMax,
		peerDiscoveryDNSSeeds:            peerDiscoveryDNSSeeds,
		peerDiscoveryDNSRefresh:          peerDiscoveryDNSRefresh,
		peerMinOperators:                 peerMinOperators,
		peerMinVotes:                     peerMinVotes,
		peerScoreMinVotes:                peerScoreMinVotes,
		peerTrustMinVotes:                peerTrustMinVotes,
		peerSignalFreshnessMaxAge:        peerSignalFreshnessMaxAge,
		peerDisputeMinVotes:              peerDisputeMinVotes,
		peerAppealMinVotes:               peerAppealMinVotes,
		adjudicationMetaMin:              adjudicationMetaMin,
		finalAdjudicationOps:             finalAdjudicationOps,
		finalAdjudicationSources:         finalAdjudicationSources,
		finalDisputeMinVotes:             finalDisputeMinVotes,
		finalAppealMinVotes:              finalAppealMinVotes,
		finalAdjudicationMin:             finalAdjudicationMin,
		disputeMaxTTL:                    disputeMaxTTL,
		appealMaxTTL:                     appealMaxTTL,
		issuerMinOperators:               issuerMinOperators,
		peerMaxHops:                      peerMaxHops,
		peerRelays:                       make(map[string]proto.RelayDescriptor),
		providerRelays:                   make(map[string]proto.RelayDescriptor),
		providerTokenProofSeen:           make(map[string]time.Time),
		providerTokenProofStoreFile:      providerTokenProofStoreFile,
		providerTokenProofSharedFileMode: providerTokenProofSharedFileMode,
		providerTokenProofLockTimeout:    providerTokenProofLockTimeout,
		providerTokenProofRedisAddr:      providerTokenProofRedisAddr,
		providerTokenProofRedisPassword:  providerTokenProofRedisPassword,
		providerTokenProofRedisDB:        providerTokenProofRedisDB,
		providerTokenProofRedisTLS:       providerTokenProofRedisTLS,
		providerTokenProofRedisPrefix:    providerTokenProofRedisPrefix,
		providerTokenProofRedisDial:      providerTokenProofRedisDial,
		peerScores:                       make(map[string]proto.RelaySelectionScore),
		peerTrust:                        make(map[string]proto.RelayTrustAttestation),
		issuerTrust:                      make(map[string]proto.RelayTrustAttestation),
		discoveredPeers:                  make(map[string]time.Time),
		discoveredPeerVoters:             make(map[string]map[string]time.Time),
		discoveredPeerHealth:             make(map[string]discoveredPeerHealth),
		peerHintPubKeys:                  make(map[string]string),
		peerHintOperators:                make(map[string]string),
		peerPubKeyCache:                  make(map[string]peerPubKeyCacheEntry),
		peerRelayETags:                   make(map[string]string),
		peerRelayCache:                   make(map[string][]proto.RelayDescriptor),
		peerScoreETags:                   make(map[string]string),
		peerScoreCache:                   make(map[string]map[string]proto.RelaySelectionScore),
		peerScoreCacheExpiresAt:          make(map[string]int64),
		peerTrustETags:                   make(map[string]string),
		peerTrustCache:                   make(map[string]map[string]proto.RelayTrustAttestation),
		peerTrustCacheExpiresAt:          make(map[string]int64),
		issuerTrustETags:                 make(map[string]string),
		issuerTrustCache:                 make(map[string]map[string]proto.RelayTrustAttestation),
		issuerTrustCacheExpiresAt:        make(map[string]int64),
		providerIssuerPubCache:           make(map[string]providerIssuerPubCacheEntry),
		peerTrustStrict:                  peerTrustStrict,
		peerTrustTOFU:                    peerTrustTOFU,
		peerTrustFile:                    peerTrustFile,
		issuerTrustedKeysFile:            issuerTrustedKeysFile,
		betaStrict:                       betaStrict,
		prodStrict:                       prodStrict,
		strictModeParseErr:               strictModeParseErr,
		httpClient:                       &http.Client{Timeout: 5 * time.Second},
		privateKeyPath:                   privateKeyPath,
		keyRotateEvery:                   keyRotateEvery,
		keyHistory:                       keyHistory,
		dnsLookupTXT:                     net.DefaultResolver.LookupTXT,
	}
}

func (s *Service) Run(ctx context.Context) error {
	httpClient, err := securehttp.NewClient(5 * time.Second)
	if err != nil {
		return fmt.Errorf("directory http tls init: %w", err)
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	configureOutboundDialPolicy(httpClient, envEnabled(allowDangerousOutboundPrivateDNS), s.betaStrict || s.prodStrict)
	s.httpClient = httpClient

	if err := s.validateRuntimeConfig(); err != nil {
		return err
	}
	if err := s.loadIssuerTrustedKeys(); err != nil {
		return err
	}
	replayStorePath := strings.TrimSpace(s.providerTokenProofStoreFile)
	switch s.providerTokenProofReplayMode() {
	case "redis":
		log.Printf(
			"directory provider token proof replay guard: redis mode enabled addr=%s db=%d tls=%t prefix=%q dial_timeout_sec=%d ttl_sec=%d",
			strings.TrimSpace(s.providerTokenProofRedisAddr),
			s.providerTokenProofRedisDB,
			s.providerTokenProofRedisTLS,
			s.providerTokenProofRedisPrefix,
			int(s.providerTokenProofRedisDial/time.Second),
			int(providerRelayUpsertProofReplayTTL/time.Second),
		)
	case "shared-file":
		log.Printf("directory provider token proof replay guard: shared file mode enabled path=%s lock_timeout_sec=%d", replayStorePath, int(s.providerTokenProofLockTimeout/time.Second))
	case "file":
		log.Printf("directory provider token proof replay guard: using file-backed store path=%s (instance-local persistence only; use shared durable replay storage for multi-instance deployments)", replayStorePath)
	default:
		log.Printf("directory provider token proof replay guard: persistence disabled (in-memory only); restart or multi-instance deployments may accept duplicate proofs")
	}
	if err := s.loadProviderTokenProofReplayStore(time.Now()); err != nil {
		return fmt.Errorf("load provider token proof replay store: %w", err)
	}
	log.Printf("directory provider token proof replay guard: loaded entries=%d", s.providerTokenProofReplayCount())
	if (s.betaStrict || s.prodStrict) && len(s.issuerTrustedKeys) == 0 {
		return fmt.Errorf("strict mode requires at least one issuer trust anchor key in %s", strings.TrimSpace(s.issuerTrustedKeysFile))
	}
	pub, priv, err := s.loadOrCreateKeypair()
	if err != nil {
		return fmt.Errorf("directory key init: %w", err)
	}
	s.keyMu.Lock()
	s.pubKey = pub
	s.privKey = priv
	s.keyMu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/relays", s.handleRelays)
	mux.HandleFunc("/v1/selection-feed", s.handleSelectionFeed)
	mux.HandleFunc("/v1/trust-attestations", s.handleTrustAttestations)
	mux.HandleFunc("/v1/gossip/relays", s.handleGossipRelays)
	mux.HandleFunc("/v1/peers", s.handlePeers)
	mux.HandleFunc("/v1/provider/relay/upsert", s.handleProviderRelayUpsert)
	mux.HandleFunc("/v1/pubkey", s.handlePubKey)
	mux.HandleFunc("/v1/pubkeys", s.handlePubKeys)
	mux.HandleFunc("/v1/admin/rotate-key", s.handleRotateKey)
	mux.HandleFunc("/v1/admin/sync-status", s.handleSyncStatus)
	mux.HandleFunc("/v1/admin/governance-status", s.handleGovernanceStatus)
	mux.HandleFunc("/v1/admin/peer-status", s.handlePeerStatus)

	s.server = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		ReadTimeout:       serverReadTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    serverMaxHeaderBytes,
	}
	log.Printf("directory federation policy: peers=%d peer_min_operators=%d peer_min_votes=%d peer_discovery_min_votes=%d peer_discovery_require_hint=%t peer_discovery_max_per_source=%d peer_discovery_max_per_operator=%d peer_discovery_fail_threshold=%d peer_discovery_backoff_sec=%d peer_discovery_max_backoff_sec=%d peer_discovery_dns_seeds=%d peer_discovery_dns_refresh_sec=%d adjudication_meta_min_votes=%d final_dispute_min_votes=%d final_appeal_min_votes=%d final_adjudication_min_operators=%d final_adjudication_min_sources=%d final_adjudication_min_ratio=%.2f dispute_max_ttl_sec=%d appeal_max_ttl_sec=%d issuer_urls=%d issuer_min_operators=%d issuer_min_votes=%d provider_issuer_urls=%d provider_relay_max_ttl_sec=%d provider_min_entry_tier=%d provider_min_exit_tier=%d provider_max_relays_per_operator=%d provider_split_roles=%t key_rotate_sec=%d key_history=%d",
		len(s.peerURLs), s.peerMinOperators, s.peerMinVotes, maxInt(1, s.peerDiscoveryMinVotes), s.peerDiscoveryRequireHint, maxInt(0, s.peerDiscoveryMaxPerSrc), maxInt(0, s.peerDiscoveryMaxPerOp), maxInt(1, s.peerDiscoveryFailN), int(s.peerDiscoveryBackoff/time.Second), int(s.peerDiscoveryBackoffMax/time.Second), len(s.peerDiscoveryDNSSeeds), int(s.peerDiscoveryDNSRefresh/time.Second), maxInt(1, s.adjudicationMetaMin), s.effectiveFinalDisputeMinVotes(), s.effectiveFinalAppealMinVotes(), s.effectiveFinalAdjudicationMinOperators(), s.effectiveFinalAdjudicationMinSources(), s.effectiveFinalAdjudicationMinRatio(), int(s.disputeMaxTTL/time.Second), int(s.appealMaxTTL/time.Second), len(s.issuerTrustURLs), s.issuerMinOperators, s.issuerTrustMinVotes, len(s.providerIssuerURLs), int(s.providerRelayMaxTTL/time.Second), s.effectiveProviderMinEntryTier(), s.effectiveProviderMinExitTier(), s.effectiveProviderMaxRelaysPerOperator(), s.providerSplitRoles, int(s.keyRotateEvery/time.Second), s.effectiveKeyHistory())

	errCh := make(chan error, 1)
	go func() {
		log.Printf("directory listening on %s", s.addr)
		errCh <- securehttp.ListenAndServe(s.server)
	}()
	if len(s.peerURLs) > 0 || len(s.issuerTrustURLs) > 0 {
		go s.runPeerSync(ctx)
	}
	if s.keyRotateEvery > 0 {
		go s.runKeyRotation(ctx)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Service) validateRuntimeConfig() error {
	if s.strictModeParseErr != nil {
		return s.strictModeParseErr
	}
	if securehttp.Enabled() {
		if s.prodStrict && securehttp.InsecureSkipVerifyConfigured() {
			return fmt.Errorf("PROD_STRICT_MODE forbids MTLS_INSECURE_SKIP_VERIFY")
		}
		if err := securehttp.Validate(); err != nil {
			return fmt.Errorf("invalid mTLS config: %w", err)
		}
	}
	publicBind := !isLoopbackBindAddr(s.addr)
	if publicBind && strings.TrimSpace(s.privateKeyPath) == "data/directory_ed25519.key" {
		return fmt.Errorf("public bind rejects legacy DIRECTORY_PRIVATE_KEY_FILE path data/directory_ed25519.key")
	}
	if publicBind && isWeakAdminToken(s.adminToken) {
		return fmt.Errorf("public bind requires strong DIRECTORY_ADMIN_TOKEN (len>=16, non-default)")
	}
	if publicBind && !securehttp.Enabled() && strings.TrimSpace(s.adminToken) != "" && !envEnabled(allowInsecureAdminPublicBind) {
		return fmt.Errorf("public bind with DIRECTORY_ADMIN_TOKEN requires MTLS_ENABLE=1 or %s=1", allowInsecureAdminPublicBind)
	}
	if err := s.validateIssuerTrustAnchorPolicy(); err != nil {
		return err
	}
	if !s.betaStrict {
		if s.prodStrict {
			return fmt.Errorf("PROD_STRICT_MODE requires BETA_STRICT_MODE=1")
		}
		return nil
	}
	if !s.peerDiscoveryEnabled {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY=1")
	}
	if s.peerMinOperators < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_MIN_OPERATORS>=2")
	}
	if s.peerMinVotes < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_MIN_VOTES>=2")
	}
	if maxInt(1, s.peerDiscoveryMinVotes) < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_MIN_VOTES>=2")
	}
	if len(s.issuerTrustURLs) < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires at least 2 DIRECTORY_ISSUER_TRUST_URLS")
	}
	if s.issuerMinOperators < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_ISSUER_MIN_OPERATORS>=2")
	}
	if s.issuerTrustMinVotes < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_ISSUER_TRUST_MIN_VOTES>=2")
	}
	if s.issuerDisputeMinVotes < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_ISSUER_DISPUTE_MIN_VOTES>=2")
	}
	if s.issuerAppealMinVotes < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_ISSUER_APPEAL_MIN_VOTES>=2")
	}
	if !s.peerDiscoveryRequireHint {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_REQUIRE_HINT=1")
	}
	if s.peerDiscoveryMaxPerSource() <= 0 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE>0")
	}
	if s.peerDiscoveryMaxPerOperator() <= 0 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR>0")
	}
	if !s.peerTrustStrict {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_TRUST_STRICT=1")
	}
	if s.peerTrustTOFU {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_PEER_TRUST_TOFU=0")
	}
	if envEnabled(allowDangerousIssuerTrustWithoutAnchors) {
		return fmt.Errorf("BETA_STRICT_MODE forbids %s", allowDangerousIssuerTrustWithoutAnchors)
	}
	if envEnabled(allowDangerousOutboundPrivateDNS) {
		return fmt.Errorf("BETA_STRICT_MODE forbids %s", allowDangerousOutboundPrivateDNS)
	}
	if envEnabled(allowDangerousProviderTokenBypass) {
		return fmt.Errorf("BETA_STRICT_MODE forbids %s", allowDangerousProviderTokenBypass)
	}
	if s.finalAdjudicationOps < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS>=2")
	}
	if s.effectiveFinalAdjudicationMinSources() < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES>=2")
	}
	if s.effectiveFinalDisputeMinVotes() < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_FINAL_DISPUTE_MIN_VOTES>=2")
	}
	if s.effectiveFinalAppealMinVotes() < 2 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_FINAL_APPEAL_MIN_VOTES>=2")
	}
	if s.keyRotateEvery <= 0 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_KEY_ROTATE_SEC>0")
	}
	adminToken := strings.TrimSpace(s.adminToken)
	if adminToken == "" || adminToken == "dev-admin-token" {
		return fmt.Errorf("BETA_STRICT_MODE requires non-default DIRECTORY_ADMIN_TOKEN")
	}
	if len(adminToken) < 16 {
		return fmt.Errorf("BETA_STRICT_MODE requires DIRECTORY_ADMIN_TOKEN length>=16")
	}
	if s.prodStrict {
		if !securehttp.Enabled() {
			return fmt.Errorf("PROD_STRICT_MODE requires MTLS_ENABLE=1")
		}
	}
	return nil
}

func (s *Service) validateIssuerTrustAnchorPolicy() error {
	if len(s.issuerTrustURLs) == 0 {
		return nil
	}
	if !issuerTrustURLsRequireAnchors(s.issuerTrustURLs) {
		return nil
	}
	if envEnabled(allowDangerousIssuerTrustWithoutAnchors) {
		return nil
	}
	if len(s.issuerTrustedKeys) > 0 {
		return nil
	}

	path := strings.TrimSpace(s.issuerTrustedKeysFile)
	if path == "" {
		path = defaultIssuerTrustedKeysFile
	}
	keys, err := loadIssuerTrustedKeys(path)
	if err != nil {
		return fmt.Errorf("load issuer trusted keys: %w", err)
	}
	if len(keys) > 0 {
		return nil
	}
	return fmt.Errorf("non-loopback issuer trust urls require configured issuer trust anchors in %s (set %s=1 only for trusted lab compatibility)", path, allowDangerousIssuerTrustWithoutAnchors)
}

func issuerTrustURLsRequireAnchors(urls []string) bool {
	for _, raw := range urls {
		normalized := normalizePeerURL(raw)
		if normalized == "" {
			continue
		}
		parsed, err := urlpkg.Parse(normalized)
		if err != nil || parsed.Hostname() == "" {
			return true
		}
		if !isLoopbackURLHost(parsed.Hostname()) {
			return true
		}
	}
	return false
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
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

func isWeakAdminToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return true
	}
	if token == "dev-admin-token" || token == "change-me" {
		return true
	}
	return len(token) < 16
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

func (s *Service) runPeerSync(ctx context.Context) {
	peerErrLogEvery := 60 * time.Second
	if s.peerSyncSec > 0 {
		candidate := time.Duration(maxInt(1, s.peerSyncSec*6)) * time.Second
		if candidate > peerErrLogEvery {
			peerErrLogEvery = candidate
		}
	}
	lastPeerErr := ""
	lastPeerErrLogAt := time.Time{}
	peerErrStreak := 0
	recordPeerSyncFailure := func(label string, err error) {
		if err == nil {
			return
		}
		peerErrStreak++
		now := time.Now().UTC()
		msg := strings.TrimSpace(err.Error())
		if msg == "" {
			msg = "unknown error"
		}
		if peerErrStreak == 1 || msg != lastPeerErr {
			if label == "" {
				log.Printf("directory peer sync failed: %v", err)
			} else {
				log.Printf("directory peer sync %s failed: %v", label, err)
			}
			lastPeerErr = msg
			lastPeerErrLogAt = now
			return
		}
		if lastPeerErrLogAt.IsZero() || now.Sub(lastPeerErrLogAt) >= peerErrLogEvery {
			log.Printf("directory peer sync still failing: consecutive=%d error=%s", peerErrStreak, msg)
			lastPeerErrLogAt = now
		}
	}
	recordPeerSyncRecovery := func() {
		if peerErrStreak <= 0 {
			return
		}
		log.Printf("directory peer sync recovered after %d consecutive failures", peerErrStreak)
		peerErrStreak = 0
		lastPeerErr = ""
		lastPeerErrLogAt = time.Time{}
	}

	if err := s.syncDNSDiscoveredPeers(ctx, time.Now()); err != nil && len(s.peerDiscoveryDNSSeeds) > 0 {
		log.Printf("directory dns peer discovery initial failed: %v", err)
	}
	if err := s.syncPeerRelays(ctx); err != nil && len(s.peerURLs) > 0 {
		recordPeerSyncFailure("initial", err)
	} else {
		recordPeerSyncRecovery()
	}
	if err := s.syncIssuerTrust(ctx); err != nil && len(s.issuerTrustURLs) > 0 {
		log.Printf("directory issuer trust sync initial failed: %v", err)
	}
	peerTicker := time.NewTicker(time.Duration(maxInt(1, s.peerSyncSec)) * time.Second)
	defer peerTicker.Stop()
	issuerTicker := time.NewTicker(time.Duration(maxInt(1, s.issuerSyncSec)) * time.Second)
	defer issuerTicker.Stop()
	var gossipTicker *time.Ticker
	if s.gossipSec > 0 && len(s.peerURLs) > 0 {
		gossipTicker = time.NewTicker(time.Duration(maxInt(1, s.gossipSec)) * time.Second)
		defer gossipTicker.Stop()
	}
	var dnsTicker *time.Ticker
	if len(s.peerDiscoveryDNSSeeds) > 0 && s.peerDiscoveryDNSRefresh > 0 {
		dnsTicker = time.NewTicker(s.peerDiscoveryDNSRefresh)
		defer dnsTicker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-peerTicker.C:
			if err := s.syncPeerRelays(ctx); err != nil {
				recordPeerSyncFailure("", err)
			} else {
				recordPeerSyncRecovery()
			}
		case <-issuerTicker.C:
			if err := s.syncIssuerTrust(ctx); err != nil {
				log.Printf("directory issuer trust sync failed: %v", err)
			}
		case <-tickerC(gossipTicker):
			if err := s.gossipPeerRelays(ctx); err != nil {
				log.Printf("directory gossip push failed: %v", err)
			}
		case <-tickerC(dnsTicker):
			if err := s.syncDNSDiscoveredPeers(ctx, time.Now()); err != nil {
				log.Printf("directory dns peer discovery refresh failed: %v", err)
			}
		}
	}
}

func (s *Service) runKeyRotation(ctx context.Context) {
	interval := s.keyRotateEvery
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.rotateSigningKey(); err != nil {
				log.Printf("directory auto key rotation failed: %v", err)
				continue
			}
			pub, _ := s.currentKeypair()
			log.Printf("directory auto key rotation complete pub=%s", base64.RawURLEncoding.EncodeToString(pub))
		}
	}
}

func (s *Service) syncPeerRelays(ctx context.Context) (retErr error) {
	startedAt := time.Now().UTC()
	peerURLs := s.snapshotSyncPeers(time.Now())
	success := 0
	successOperators := make(map[string]struct{})
	requiredOperators := maxInt(1, s.peerMinOperators)
	defer func() {
		s.setPeerSyncStatus(proto.DirectorySyncRunStatus{
			LastRunAt:         startedAt.Unix(),
			Success:           retErr == nil,
			SuccessSources:    success,
			SourceOperators:   operatorSetList(successOperators),
			RequiredOperators: requiredOperators,
			QuorumMet:         success > 0 && len(successOperators) >= requiredOperators,
			Error:             errorString(retErr),
		})
	}()
	if len(peerURLs) == 0 {
		return nil
	}
	type peerCandidate struct {
		desc  proto.RelayDescriptor
		votes int
	}
	type scoreCandidate struct {
		relayID      string
		role         string
		votes        int
		reputation   float64
		uptime       float64
		capacity     float64
		abusePenalty float64
		bondScore    float64
		stakeScore   float64
	}
	type trustCandidate struct {
		relayID      string
		role         string
		operatorID   string
		votes        int
		reputation   float64
		uptime       float64
		capacity     float64
		abusePenalty float64
		bondScore    float64
		stakeScore   float64
		confidence   float64
		disputeVotes int
		disputeOps   map[string]struct{}
		disputeCaps  map[int]int
		disputeUntil []int64
		disputeMeta  map[adjudicationMetadataPair]int
		appealVotes  int
		appealOps    map[string]struct{}
		appealUntil  []int64
		appealMeta   map[adjudicationMetadataPair]int
	}
	candidates := make(map[string]map[string]peerCandidate)
	relayVoters := make(map[string]map[string]map[string]struct{})
	scoreCandidates := make(map[string]scoreCandidate)
	scoreVoters := make(map[string]map[string]struct{})
	scoreSignalSources := 0
	trustCandidates := make(map[string]trustCandidate)
	trustVoters := make(map[string]map[string]struct{})
	trustSignalSources := 0
	minVotes := s.peerMinVotes
	if minVotes <= 0 {
		minVotes = 1
	}
	scoreMinVotes := s.peerScoreMinVotes
	if scoreMinVotes <= 0 {
		scoreMinVotes = 1
	}
	trustMinVotes := s.peerTrustMinVotes
	if trustMinVotes <= 0 {
		trustMinVotes = 1
	}
	disputeMinVotes := s.peerDisputeMinVotes
	if disputeMinVotes <= 0 {
		disputeMinVotes = trustMinVotes
	}
	appealMinVotes := s.peerAppealMinVotes
	if appealMinVotes <= 0 {
		appealMinVotes = disputeMinVotes
	}
	metaMinVotes := maxInt(1, s.adjudicationMetaMin)
	var lastErr error
	nowUnix := time.Now().Unix()
	for _, peerURL := range peerURLs {
		peerNow := time.Now().UTC()
		pubs, declaredOperator, err := s.fetchPeerPubKeys(ctx, peerURL)
		if err != nil {
			lastErr = err
			s.recordPeerSyncFailure(peerURL, peerNow, fmt.Errorf("fetch peer pubkeys: %w", err))
			continue
		}
		sourceOperator := s.resolveQuorumSourceOperator(peerURL, declaredOperator, pubs)
		discoveredPeers, peersErr := s.fetchPeerDirectoryPeers(ctx, peerURL, pubs)
		if peersErr != nil {
			lastErr = peersErr
		}
		if len(discoveredPeers) > 0 {
			s.ingestDiscoveredPeers(peerURL, sourceOperator, discoveredPeers, time.Now())
		}
		relays, err := s.fetchPeerRelaysWithPubs(ctx, peerURL, pubs)
		if err != nil {
			lastErr = err
			s.recordPeerSyncFailure(peerURL, peerNow, fmt.Errorf("fetch peer relays: %w", err))
			continue
		}
		s.recordPeerSyncSuccess(peerURL, peerNow)
		scores, scoreErr := s.fetchPeerSelectionScores(ctx, peerURL, pubs)
		if scoreErr != nil {
			lastErr = scoreErr
		} else if scores != nil {
			scoreSignalSources++
		}
		attestations, trustErr := s.fetchPeerTrustAttestations(ctx, peerURL, pubs)
		if trustErr != nil {
			lastErr = trustErr
		} else if attestations != nil {
			trustSignalSources++
		}
		success++
		successOperators[sourceOperator] = struct{}{}
		for _, desc := range relays {
			desc, ok := s.preparePeerDescriptor(desc)
			if !ok {
				continue
			}
			key := relayKey(desc.RelayID, desc.Role)
			fingerprint, err := peerDescriptorFingerprint(desc)
			if err != nil {
				lastErr = err
				continue
			}
			if _, ok := candidates[key]; !ok {
				candidates[key] = make(map[string]peerCandidate)
			}
			if !markVariantVoter(relayVoters, key, fingerprint, sourceOperator) {
				continue
			}
			cand := candidates[key][fingerprint]
			cand.votes++
			if cand.desc.RelayID == "" || desc.ValidUntil.After(cand.desc.ValidUntil) {
				cand.desc = desc
				cand.desc.Signature = ""
			}
			candidates[key][fingerprint] = cand
		}
		for _, score := range scores {
			role, ok := canonicalizeSignalRole(score.Role)
			if !ok || strings.TrimSpace(score.RelayID) == "" {
				continue
			}
			key := relayKey(score.RelayID, role)
			if !markCandidateVoter(scoreVoters, key, sourceOperator) {
				continue
			}
			cand := scoreCandidates[key]
			cand.relayID = score.RelayID
			cand.role = role
			cand.votes++
			cand.reputation += clampScore(score.Reputation)
			cand.uptime += clampScore(score.Uptime)
			cand.capacity += clampScore(score.Capacity)
			cand.abusePenalty += clampScore(score.AbusePenalty)
			cand.bondScore += clampScore(score.BondScore)
			cand.stakeScore += clampScore(score.StakeScore)
			scoreCandidates[key] = cand
		}
		for _, att := range attestations {
			role, ok := canonicalizeSignalRole(att.Role)
			if !ok || strings.TrimSpace(att.RelayID) == "" {
				continue
			}
			key := relayKey(att.RelayID, role)
			if !markCandidateVoter(trustVoters, key, sourceOperator) {
				continue
			}
			cand := trustCandidates[key]
			cand.relayID = att.RelayID
			cand.role = role
			cand.operatorID = strings.TrimSpace(att.OperatorID)
			cand.votes++
			cand.reputation += clampScore(att.Reputation)
			cand.uptime += clampScore(att.Uptime)
			cand.capacity += clampScore(att.Capacity)
			cand.abusePenalty += clampScore(att.AbusePenalty)
			cand.bondScore += clampScore(att.BondScore)
			cand.stakeScore += clampScore(att.StakeScore)
			cand.confidence += clampScore(att.Confidence)
			if capTier, until, ok := s.activeDispute(att, nowUnix); ok {
				cand.disputeVotes++
				if cand.disputeCaps == nil {
					cand.disputeCaps = make(map[int]int)
				}
				cand.disputeCaps[capTier]++
				cand.disputeUntil = append(cand.disputeUntil, until)
				recordMetadataPairVote(&cand.disputeMeta, att.DisputeCase, att.DisputeRef)
			}
			if appealUntil, ok := s.activeAppeal(att, nowUnix); ok {
				cand.appealVotes++
				cand.appealUntil = append(cand.appealUntil, appealUntil)
				recordMetadataPairVote(&cand.appealMeta, att.AppealCase, att.AppealRef)
			}
			trustCandidates[key] = cand
		}
	}
	if success == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no peer directory responses")
		}
		s.dropStalePeerSignalCacheOnSyncFailure(time.Now().UTC(), scoreSignalSources, scoreMinVotes, trustSignalSources, trustMinVotes)
		return lastErr
	}
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient peer operators")
		}
		s.dropStalePeerSignalCacheOnSyncFailure(time.Now().UTC(), scoreSignalSources, scoreMinVotes, trustSignalSources, trustMinVotes)
		return fmt.Errorf("peer operator quorum not met: operators=%d required=%d: %w", len(successOperators), requiredOperators, lastErr)
	}

	merged := make(map[string]proto.RelayDescriptor)
	for key, variants := range candidates {
		bestVotes := 0
		bestFingerprint := ""
		var best proto.RelayDescriptor
		for fingerprint, cand := range variants {
			if cand.votes < minVotes {
				continue
			}
			if cand.votes > bestVotes ||
				(cand.votes == bestVotes && cand.desc.ValidUntil.After(best.ValidUntil)) ||
				(cand.votes == bestVotes && cand.desc.ValidUntil.Equal(best.ValidUntil) && (bestFingerprint == "" || fingerprint < bestFingerprint)) {
				bestVotes = cand.votes
				bestFingerprint = fingerprint
				best = cand.desc
			}
		}
		if best.RelayID == "" {
			log.Printf("directory peer conflict unresolved key=%s min_votes=%d variants=%d", key, minVotes, len(variants))
			continue
		}
		merged[key] = best
	}
	mergedScores := make(map[string]proto.RelaySelectionScore)
	for key, cand := range scoreCandidates {
		if cand.votes < scoreMinVotes {
			continue
		}
		n := float64(cand.votes)
		mergedScores[key] = proto.RelaySelectionScore{
			RelayID:      cand.relayID,
			Role:         cand.role,
			Reputation:   clampScore(cand.reputation / n),
			Uptime:       clampScore(cand.uptime / n),
			Capacity:     clampScore(cand.capacity / n),
			AbusePenalty: clampScore(cand.abusePenalty / n),
			BondScore:    clampScore(cand.bondScore / n),
			StakeScore:   clampScore(cand.stakeScore / n),
		}
	}
	mergedTrust := make(map[string]proto.RelayTrustAttestation)
	for key, cand := range trustCandidates {
		if cand.votes < trustMinVotes {
			continue
		}
		n := float64(cand.votes)
		att := proto.RelayTrustAttestation{
			RelayID:      cand.relayID,
			Role:         cand.role,
			OperatorID:   cand.operatorID,
			Reputation:   clampScore(cand.reputation / n),
			Uptime:       clampScore(cand.uptime / n),
			Capacity:     clampScore(cand.capacity / n),
			AbusePenalty: clampScore(cand.abusePenalty / n),
			BondScore:    clampScore(cand.bondScore / n),
			StakeScore:   clampScore(cand.stakeScore / n),
			Confidence:   clampScore(cand.confidence / n),
		}
		if cand.disputeVotes >= disputeMinVotes {
			if tierCap, ok := pickConsensusTier(cand.disputeCaps); ok {
				att.TierCap = tierCap
				att.DisputeUntil = pickMedianUnix(cand.disputeUntil)
				att.DisputeCase, att.DisputeRef = pickVotedMetadataPair(cand.disputeMeta, metaMinVotes)
			}
		}
		if cand.appealVotes >= appealMinVotes {
			att.AppealUntil = pickMedianUnix(cand.appealUntil)
			att.AppealCase, att.AppealRef = pickVotedMetadataPair(cand.appealMeta, metaMinVotes)
		}
		mergedTrust[key] = att
	}
	syncNow := time.Now().UTC()
	peerSignalMaxAge := s.effectivePeerSignalFreshnessMaxAge()
	peerSignalMaxAgeSec := int64(peerSignalMaxAge / time.Second)
	var scoreCacheAgeSec int64
	var trustCacheAgeSec int64
	scoreCacheTimestampInitialized := false
	trustCacheTimestampInitialized := false
	staleCachedScoresDropped := false
	staleCachedTrustDropped := false
	s.peerMu.Lock()
	s.peerRelays = merged
	scoreSourcesInsufficient := scoreSignalSources < scoreMinVotes
	scoreMergedEmptyWithCache := len(mergedScores) == 0 && len(s.peerScores) > 0
	useCachedScores := scoreSourcesInsufficient || scoreMergedEmptyWithCache
	if useCachedScores {
		if len(s.peerScores) > 0 {
			stale, age, initialized := evaluateSignalCacheFreshness(&s.peerScoreLastFreshAt, syncNow, peerSignalMaxAge)
			scoreCacheTimestampInitialized = initialized
			scoreCacheAgeSec = int64(age / time.Second)
			if stale {
				s.peerScores = make(map[string]proto.RelaySelectionScore)
				s.peerScoreLastFreshAt = time.Time{}
				staleCachedScoresDropped = true
			} else {
				s.peerScores = cloneSelectionScores(s.peerScores)
			}
		} else {
			s.peerScoreLastFreshAt = time.Time{}
			s.peerScores = cloneSelectionScores(s.peerScores)
		}
	} else {
		s.peerScores = mergedScores
		s.peerScoreLastFreshAt = syncNow
	}
	trustSourcesInsufficient := trustSignalSources < trustMinVotes
	trustMergedEmptyWithCache := len(mergedTrust) == 0 && len(s.peerTrust) > 0
	useCachedTrust := trustSourcesInsufficient || trustMergedEmptyWithCache
	if useCachedTrust {
		if len(s.peerTrust) > 0 {
			stale, age, initialized := evaluateSignalCacheFreshness(&s.peerTrustLastFreshAt, syncNow, peerSignalMaxAge)
			trustCacheTimestampInitialized = initialized
			trustCacheAgeSec = int64(age / time.Second)
			if stale {
				s.peerTrust = make(map[string]proto.RelayTrustAttestation)
				s.peerTrustLastFreshAt = time.Time{}
				staleCachedTrustDropped = true
			} else {
				s.peerTrust = cloneTrustAttestations(s.peerTrust)
			}
		} else {
			s.peerTrustLastFreshAt = time.Time{}
			s.peerTrust = cloneTrustAttestations(s.peerTrust)
		}
	} else {
		s.peerTrust = mergedTrust
		s.peerTrustLastFreshAt = syncNow
	}
	s.peerMu.Unlock()
	if useCachedScores {
		if scoreCacheTimestampInitialized {
			log.Printf(
				"directory peer score sync: initialized cached score freshness timestamp (max_age_sec=%d)",
				peerSignalMaxAgeSec,
			)
		}
		if staleCachedScoresDropped {
			log.Printf(
				"directory peer score sync: dropping stale cached scores (sources_insufficient=%t merged_empty_with_cache=%t sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
				scoreSourcesInsufficient,
				scoreMergedEmptyWithCache,
				scoreSignalSources,
				scoreMinVotes,
				scoreCacheAgeSec,
				peerSignalMaxAgeSec,
			)
		} else {
			log.Printf(
				"directory peer score sync: preserving cached scores (sources_insufficient=%t merged_empty_with_cache=%t sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
				scoreSourcesInsufficient,
				scoreMergedEmptyWithCache,
				scoreSignalSources,
				scoreMinVotes,
				scoreCacheAgeSec,
				peerSignalMaxAgeSec,
			)
		}
	}
	if useCachedTrust {
		if trustCacheTimestampInitialized {
			log.Printf(
				"directory peer trust sync: initialized cached trust freshness timestamp (max_age_sec=%d)",
				peerSignalMaxAgeSec,
			)
		}
		if staleCachedTrustDropped {
			log.Printf(
				"directory peer trust sync: dropping stale cached trust attestations (sources_insufficient=%t merged_empty_with_cache=%t sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
				trustSourcesInsufficient,
				trustMergedEmptyWithCache,
				trustSignalSources,
				trustMinVotes,
				trustCacheAgeSec,
				peerSignalMaxAgeSec,
			)
		} else {
			log.Printf(
				"directory peer trust sync: preserving cached trust attestations (sources_insufficient=%t merged_empty_with_cache=%t sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
				trustSourcesInsufficient,
				trustMergedEmptyWithCache,
				trustSignalSources,
				trustMinVotes,
				trustCacheAgeSec,
				peerSignalMaxAgeSec,
			)
		}
	}
	return nil
}

func (s *Service) gossipPeerRelays(ctx context.Context) error {
	peers := s.selectGossipPeers(time.Now().UTC())
	if len(peers) == 0 {
		return nil
	}
	now := time.Now().UTC()
	stableNow := s.stableTime(now, s.descriptorEpoch)
	relays := s.buildRelayDescriptors(stableNow)
	if len(relays) == 0 {
		return nil
	}
	_, priv := s.currentKeypair()
	for i := range relays {
		relays[i].Signature = signDescriptor(relays[i], priv)
	}
	req := proto.RelayGossipPushRequest{
		PeerURL: s.localURL,
		Relays:  relays,
	}
	success := 0
	var lastErr error
	selfURL := normalizePeerURL(s.localURL)
	for _, peerURL := range peers {
		peerURL = normalizePeerURL(peerURL)
		if peerURL == "" || peerURL == selfURL {
			continue
		}
		if err := s.pushGossipRelays(ctx, peerURL, req); err != nil {
			lastErr = err
			continue
		}
		success++
	}
	if success == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

func (s *Service) selectGossipPeers(now time.Time) []string {
	peers := s.snapshotSyncPeers(now)
	if len(peers) == 0 {
		return nil
	}
	sort.Strings(peers)
	fanout := s.gossipFanout
	if fanout <= 0 || fanout >= len(peers) {
		return peers
	}
	start := int(now.Unix() % int64(len(peers)))
	out := make([]string, 0, fanout)
	for i := 0; i < fanout; i++ {
		out = append(out, peers[(start+i)%len(peers)])
	}
	return out
}

func (s *Service) pushGossipRelays(ctx context.Context, peerURL string, in proto.RelayGossipPushRequest) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(peerURL, "/v1/gossip/relays"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer gossip status %d", resp.StatusCode)
	}
	return nil
}

func (s *Service) syncIssuerTrust(ctx context.Context) (retErr error) {
	startedAt := time.Now().UTC()
	success := 0
	successOperators := make(map[string]struct{})
	requiredOperators := maxInt(1, s.issuerMinOperators)
	defer func() {
		s.setIssuerSyncStatus(proto.DirectorySyncRunStatus{
			LastRunAt:         startedAt.Unix(),
			Success:           retErr == nil,
			SuccessSources:    success,
			SourceOperators:   operatorSetList(successOperators),
			RequiredOperators: requiredOperators,
			QuorumMet:         success > 0 && len(successOperators) >= requiredOperators,
			Error:             errorString(retErr),
		})
	}()
	if len(s.issuerTrustURLs) == 0 {
		return nil
	}
	type trustCandidate struct {
		relayID      string
		role         string
		operatorID   string
		votes        int
		reputation   float64
		uptime       float64
		capacity     float64
		abusePenalty float64
		bondScore    float64
		stakeScore   float64
		confidence   float64
		disputeVotes int
		disputeOps   map[string]struct{}
		disputeCaps  map[int]int
		disputeUntil []int64
		disputeMeta  map[adjudicationMetadataPair]int
		appealVotes  int
		appealOps    map[string]struct{}
		appealUntil  []int64
		appealMeta   map[adjudicationMetadataPair]int
	}
	minVotes := s.issuerTrustMinVotes
	if minVotes <= 0 {
		minVotes = 1
	}
	disputeMinVotes := s.issuerDisputeMinVotes
	if disputeMinVotes <= 0 {
		disputeMinVotes = minVotes
	}
	appealMinVotes := s.issuerAppealMinVotes
	if appealMinVotes <= 0 {
		appealMinVotes = disputeMinVotes
	}
	metaMinVotes := maxInt(1, s.adjudicationMetaMin)
	candidates := make(map[string]trustCandidate)
	trustVoters := make(map[string]map[string]struct{})
	trustSignalSources := 0
	var lastErr error
	nowUnix := time.Now().Unix()
	for _, issuerURL := range s.issuerTrustURLs {
		pubs, declaredOperator, err := s.fetchIssuerPubKeys(ctx, issuerURL)
		if err != nil {
			lastErr = err
			continue
		}
		verifyPubs, err := issuerVerificationKeysForTrustFeed(pubs, s.issuerTrustedKeys)
		if err != nil {
			lastErr = fmt.Errorf("issuer %s trust key validation failed: %w", issuerURL, err)
			continue
		}
		sourceOperator := s.resolveQuorumSourceOperator(issuerURL, declaredOperator, verifyPubs)
		attestations, err := s.fetchIssuerTrustAttestations(ctx, issuerURL, verifyPubs)
		if err != nil {
			lastErr = err
			continue
		}
		if attestations != nil {
			trustSignalSources++
		}
		success++
		successOperators[sourceOperator] = struct{}{}
		for _, att := range attestations {
			role, ok := canonicalizeSignalRole(att.Role)
			if !ok || strings.TrimSpace(att.RelayID) == "" {
				continue
			}
			key := relayKey(att.RelayID, role)
			if !markCandidateVoter(trustVoters, key, sourceOperator) {
				continue
			}
			cand := candidates[key]
			cand.relayID = att.RelayID
			cand.role = role
			if strings.TrimSpace(att.OperatorID) != "" {
				cand.operatorID = strings.TrimSpace(att.OperatorID)
			}
			cand.votes++
			cand.reputation += clampScore(att.Reputation)
			cand.uptime += clampScore(att.Uptime)
			cand.capacity += clampScore(att.Capacity)
			cand.abusePenalty += clampScore(att.AbusePenalty)
			cand.bondScore += clampScore(att.BondScore)
			cand.stakeScore += clampScore(att.StakeScore)
			cand.confidence += clampScore(att.Confidence)
			if capTier, until, ok := s.activeDispute(att, nowUnix); ok {
				cand.disputeVotes++
				if cand.disputeCaps == nil {
					cand.disputeCaps = make(map[int]int)
				}
				cand.disputeCaps[capTier]++
				cand.disputeUntil = append(cand.disputeUntil, until)
				recordMetadataPairVote(&cand.disputeMeta, att.DisputeCase, att.DisputeRef)
			}
			if appealUntil, ok := s.activeAppeal(att, nowUnix); ok {
				cand.appealVotes++
				cand.appealUntil = append(cand.appealUntil, appealUntil)
				recordMetadataPairVote(&cand.appealMeta, att.AppealCase, att.AppealRef)
			}
			candidates[key] = cand
		}
	}
	if success == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no issuer trust responses")
		}
		s.dropStaleIssuerTrustCacheOnSyncFailure(time.Now().UTC(), trustSignalSources, minVotes)
		return lastErr
	}
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient issuer operators")
		}
		s.dropStaleIssuerTrustCacheOnSyncFailure(time.Now().UTC(), trustSignalSources, minVotes)
		return fmt.Errorf("issuer operator quorum not met: operators=%d required=%d: %w", len(successOperators), requiredOperators, lastErr)
	}
	merged := make(map[string]proto.RelayTrustAttestation)
	for key, cand := range candidates {
		if cand.votes < minVotes {
			continue
		}
		n := float64(cand.votes)
		att := proto.RelayTrustAttestation{
			RelayID:      cand.relayID,
			Role:         cand.role,
			OperatorID:   cand.operatorID,
			Reputation:   clampScore(cand.reputation / n),
			Uptime:       clampScore(cand.uptime / n),
			Capacity:     clampScore(cand.capacity / n),
			AbusePenalty: clampScore(cand.abusePenalty / n),
			BondScore:    clampScore(cand.bondScore / n),
			StakeScore:   clampScore(cand.stakeScore / n),
			Confidence:   clampScore(cand.confidence / n),
		}
		if cand.disputeVotes >= disputeMinVotes {
			if tierCap, ok := pickConsensusTier(cand.disputeCaps); ok {
				att.TierCap = tierCap
				att.DisputeUntil = pickMedianUnix(cand.disputeUntil)
				att.DisputeCase, att.DisputeRef = pickVotedMetadataPair(cand.disputeMeta, metaMinVotes)
			}
		}
		if cand.appealVotes >= appealMinVotes {
			att.AppealUntil = pickMedianUnix(cand.appealUntil)
			att.AppealCase, att.AppealRef = pickVotedMetadataPair(cand.appealMeta, metaMinVotes)
		}
		merged[key] = att
	}
	syncNow := time.Now().UTC()
	issuerSignalMaxAge := s.effectiveIssuerSignalFreshnessMaxAge()
	issuerSignalMaxAgeSec := int64(issuerSignalMaxAge / time.Second)
	var issuerCacheAgeSec int64
	issuerCacheTimestampInitialized := false
	staleIssuerCacheDropped := false
	s.peerMu.Lock()
	trustSourcesInsufficient := trustSignalSources < minVotes
	trustMergedEmptyWithCache := len(merged) == 0 && len(s.issuerTrust) > 0
	useCachedTrust := trustSourcesInsufficient || trustMergedEmptyWithCache
	if useCachedTrust {
		if len(s.issuerTrust) > 0 {
			stale, age, initialized := evaluateSignalCacheFreshness(&s.issuerTrustLastFreshAt, syncNow, issuerSignalMaxAge)
			issuerCacheTimestampInitialized = initialized
			issuerCacheAgeSec = int64(age / time.Second)
			if stale {
				s.issuerTrust = make(map[string]proto.RelayTrustAttestation)
				s.issuerTrustLastFreshAt = time.Time{}
				staleIssuerCacheDropped = true
			} else {
				s.issuerTrust = cloneTrustAttestations(s.issuerTrust)
			}
		} else {
			s.issuerTrustLastFreshAt = time.Time{}
			s.issuerTrust = cloneTrustAttestations(s.issuerTrust)
		}
	} else {
		s.issuerTrust = merged
		s.issuerTrustLastFreshAt = syncNow
	}
	s.peerMu.Unlock()
	if useCachedTrust {
		if issuerCacheTimestampInitialized {
			log.Printf(
				"directory issuer trust sync: initialized cached trust freshness timestamp (max_age_sec=%d)",
				issuerSignalMaxAgeSec,
			)
		}
		if staleIssuerCacheDropped {
			log.Printf(
				"directory issuer trust sync: dropping stale cached trust attestations (sources_insufficient=%t merged_empty_with_cache=%t sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
				trustSourcesInsufficient,
				trustMergedEmptyWithCache,
				trustSignalSources,
				minVotes,
				issuerCacheAgeSec,
				issuerSignalMaxAgeSec,
			)
		} else {
			log.Printf(
				"directory issuer trust sync: preserving cached trust attestations (sources_insufficient=%t merged_empty_with_cache=%t sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
				trustSourcesInsufficient,
				trustMergedEmptyWithCache,
				trustSignalSources,
				minVotes,
				issuerCacheAgeSec,
				issuerSignalMaxAgeSec,
			)
		}
	}
	return nil
}

func (s *Service) fetchIssuerPubKeys(ctx context.Context, issuerURL string) ([]ed25519.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(issuerURL, "/v1/pubkeys"), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("issuer pubkeys status %d", resp.StatusCode)
	}
	var out proto.IssuerPubKeysResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, "", err
	}
	keys := make([]ed25519.PublicKey, 0, len(out.PubKeys))
	for _, key := range dedupeStrings(out.PubKeys) {
		raw, decErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key))
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid issuer pubkey")
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("issuer returned no pubkeys")
	}
	return keys, strings.TrimSpace(out.Issuer), nil
}

func cloneIssuerPubKeys(in []ed25519.PublicKey) []ed25519.PublicKey {
	if len(in) == 0 {
		return nil
	}
	out := make([]ed25519.PublicKey, 0, len(in))
	for _, key := range in {
		if len(key) == 0 {
			continue
		}
		dup := make(ed25519.PublicKey, len(key))
		copy(dup, key)
		out = append(out, dup)
	}
	return out
}

func (s *Service) fetchIssuerPubKeysForProviderToken(ctx context.Context, issuerURL string, now time.Time) ([]ed25519.PublicKey, string, error) {
	cacheTTL := s.providerIssuerPubCacheTTL
	if cacheTTL <= 0 {
		return s.fetchIssuerPubKeys(ctx, issuerURL)
	}
	s.providerIssuerPubCacheMu.RLock()
	if entry, ok := s.providerIssuerPubCache[issuerURL]; ok {
		if now.Sub(entry.fetchedAt) <= cacheTTL {
			s.providerIssuerPubCacheMu.RUnlock()
			return cloneIssuerPubKeys(entry.pubs), entry.issuerID, nil
		}
	}
	s.providerIssuerPubCacheMu.RUnlock()
	pubs, issuerID, err := s.fetchIssuerPubKeys(ctx, issuerURL)
	if err != nil {
		return nil, "", err
	}
	s.providerIssuerPubCacheMu.Lock()
	defer s.providerIssuerPubCacheMu.Unlock()
	if entry, ok := s.providerIssuerPubCache[issuerURL]; ok {
		if now.Sub(entry.fetchedAt) <= cacheTTL {
			return cloneIssuerPubKeys(entry.pubs), entry.issuerID, nil
		}
	}
	s.providerIssuerPubCache[issuerURL] = providerIssuerPubCacheEntry{
		pubs:      cloneIssuerPubKeys(pubs),
		issuerID:  strings.TrimSpace(issuerID),
		fetchedAt: now,
	}
	return pubs, issuerID, nil
}

func (s *Service) fetchIssuerTrustAttestations(ctx context.Context, issuerURL string, pubs []ed25519.PublicKey) (map[string]proto.RelayTrustAttestation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(issuerURL, "/v1/trust/relays"), nil)
	if err != nil {
		return nil, err
	}
	if etag := s.cachedIssuerTrustETag(issuerURL); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if cached, ok := s.cachedIssuerTrust(issuerURL, time.Now().UTC()); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("issuer trust feed 304 without valid cache")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer trust feed status %d", resp.StatusCode)
	}
	var feed proto.RelayTrustAttestationFeedResponse
	if err := decodeBoundedJSONResponse(resp.Body, &feed, remoteResponseMaxBodyBytes); err != nil {
		return nil, err
	}
	if err := verifyIssuerTrustFeedAny(feed, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("issuer trust feed verify failed: %w", err)
	}
	out := make(map[string]proto.RelayTrustAttestation, len(feed.Attestations))
	for _, att := range feed.Attestations {
		role, ok := canonicalizeSignalRole(att.Role)
		if !ok || strings.TrimSpace(att.RelayID) == "" {
			continue
		}
		key := relayKey(att.RelayID, role)
		att.Role = role
		att.Reputation = clampScore(att.Reputation)
		att.Uptime = clampScore(att.Uptime)
		att.Capacity = clampScore(att.Capacity)
		att.AbusePenalty = clampScore(att.AbusePenalty)
		att.BondScore = clampScore(att.BondScore)
		att.StakeScore = clampScore(att.StakeScore)
		att.Confidence = clampScore(att.Confidence)
		att.TierCap, att.DisputeUntil = normalizeDispute(att.TierCap, att.DisputeUntil, time.Now().Unix())
		att.AppealUntil = normalizeAppeal(att.AppealUntil, time.Now().Unix())
		att.DisputeCase = normalizeCaseID(att.DisputeCase)
		att.DisputeRef = normalizeEvidenceRef(att.DisputeRef)
		att.AppealCase = normalizeCaseID(att.AppealCase)
		att.AppealRef = normalizeEvidenceRef(att.AppealRef)
		out[key] = att
	}
	s.setIssuerTrustCache(issuerURL, resp.Header.Get("ETag"), out, time.Unix(feed.ExpiresAt, 0).UTC())
	return out, nil
}

func verifyIssuerTrustFeedAny(feed proto.RelayTrustAttestationFeedResponse, pubs []ed25519.PublicKey, now time.Time) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no issuer pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("trust feed signature verification failed")
	}
	return lastErr
}

func (s *Service) loadIssuerTrustedKeys() error {
	path := strings.TrimSpace(s.issuerTrustedKeysFile)
	keys, err := loadIssuerTrustedKeys(path)
	if err != nil {
		return fmt.Errorf("load issuer trusted keys: %w", err)
	}
	s.issuerTrustedKeys = keys
	if len(keys) > 0 {
		log.Printf("directory loaded issuer trust anchors count=%d file=%s", len(keys), path)
	}
	return nil
}

func loadIssuerTrustedKeys(path string) ([]ed25519.PublicKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	b, err := readFileBounded(path, directoryTrustedKeysFileMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	seen := make(map[string]struct{})
	out := make([]ed25519.PublicKey, 0)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		key := fields[len(fields)-1]
		raw, decErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key))
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid issuer trusted key: %s", key)
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		if _, ok := seen[encoded]; ok {
			continue
		}
		seen[encoded] = struct{}{}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out, nil
}

func issuerVerificationKeysForTrustFeed(remote []ed25519.PublicKey, anchors []ed25519.PublicKey) ([]ed25519.PublicKey, error) {
	if len(remote) == 0 {
		return nil, fmt.Errorf("no issuer pubkeys available")
	}
	if len(anchors) == 0 {
		return remote, nil
	}
	for _, remotePub := range remote {
		for _, anchor := range anchors {
			if len(remotePub) == ed25519.PublicKeySize &&
				len(anchor) == ed25519.PublicKeySize &&
				subtle.ConstantTimeCompare(remotePub, anchor) == 1 {
				return anchors, nil
			}
		}
	}
	return nil, fmt.Errorf("remote issuer pubkeys do not match configured trust anchors")
}

func (s *Service) fetchPeerRelays(ctx context.Context, peerURL string) ([]proto.RelayDescriptor, error) {
	pubs, _, err := s.fetchPeerPubKeys(ctx, peerURL)
	if err != nil {
		return nil, fmt.Errorf("fetch peer pubkey %s: %w", peerURL, err)
	}
	return s.fetchPeerRelaysWithPubs(ctx, peerURL, pubs)
}

func (s *Service) fetchPeerRelaysWithPub(ctx context.Context, peerURL string, pub ed25519.PublicKey) ([]proto.RelayDescriptor, error) {
	return s.fetchPeerRelaysWithPubs(ctx, peerURL, []ed25519.PublicKey{pub})
}

func (s *Service) fetchPeerRelaysWithPubs(ctx context.Context, peerURL string, pubs []ed25519.PublicKey) ([]proto.RelayDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(peerURL, "/v1/relays"), nil)
	if err != nil {
		return nil, err
	}
	if etag := s.cachedPeerRelayETag(peerURL); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if cached, ok := s.cachedPeerRelays(peerURL); ok {
			return filterUnexpiredRelayDescriptors(cached, time.Now().UTC()), nil
		}
		return nil, fmt.Errorf("peer relays 304 without cache")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer relays status %d", resp.StatusCode)
	}

	var out proto.RelayListResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, err
	}
	verified := make([]proto.RelayDescriptor, 0, len(out.Relays))
	var firstVerifyErr error
	now := time.Now().UTC()
	for _, desc := range out.Relays {
		role, err := canonicalizePeerRelayRole(desc.Role)
		if desc.RelayID == "" || err != nil {
			continue
		}
		if err := verifyRelayDescriptorAny(desc, pubs); err != nil {
			if firstVerifyErr == nil {
				firstVerifyErr = fmt.Errorf("verify peer descriptor relay=%s: %w", desc.RelayID, err)
			}
			continue
		}
		if desc.ValidUntil.IsZero() || now.After(desc.ValidUntil) {
			continue
		}
		desc.Role = role
		desc.Signature = ""
		verified = append(verified, desc)
	}
	if len(verified) == 0 && firstVerifyErr != nil {
		return nil, firstVerifyErr
	}
	s.setPeerRelayCache(peerURL, resp.Header.Get("ETag"), verified)
	return verified, nil
}

func filterUnexpiredRelayDescriptors(relays []proto.RelayDescriptor, now time.Time) []proto.RelayDescriptor {
	if len(relays) == 0 {
		return nil
	}
	out := make([]proto.RelayDescriptor, 0, len(relays))
	for _, desc := range relays {
		if desc.ValidUntil.IsZero() || now.After(desc.ValidUntil) {
			continue
		}
		out = append(out, desc)
	}
	return out
}

func (s *Service) fetchPeerSelectionScores(ctx context.Context, peerURL string, pubs []ed25519.PublicKey) (map[string]proto.RelaySelectionScore, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(peerURL, "/v1/selection-feed"), nil)
	if err != nil {
		return nil, err
	}
	if etag := s.cachedPeerScoreETag(peerURL); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if cached, ok := s.cachedPeerScores(peerURL, time.Now().UTC()); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("peer selection feed 304 without valid cache")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer selection feed status %d", resp.StatusCode)
	}
	var feed proto.RelaySelectionFeedResponse
	if err := decodeBoundedJSONResponse(resp.Body, &feed, remoteResponseMaxBodyBytes); err != nil {
		return nil, err
	}
	if err := verifyRelaySelectionFeedAny(feed, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("peer selection feed verify failed: %w", err)
	}
	out := make(map[string]proto.RelaySelectionScore, len(feed.Scores))
	for _, score := range feed.Scores {
		role, ok := canonicalizeSignalRole(score.Role)
		if !ok || strings.TrimSpace(score.RelayID) == "" {
			continue
		}
		key := relayKey(score.RelayID, role)
		score.Role = role
		score.Reputation = clampScore(score.Reputation)
		score.Uptime = clampScore(score.Uptime)
		score.Capacity = clampScore(score.Capacity)
		score.AbusePenalty = clampScore(score.AbusePenalty)
		score.BondScore = clampScore(score.BondScore)
		score.StakeScore = clampScore(score.StakeScore)
		out[key] = score
	}
	s.setPeerScoreCache(peerURL, resp.Header.Get("ETag"), out, time.Unix(feed.ExpiresAt, 0).UTC())
	return out, nil
}

func (s *Service) fetchPeerTrustAttestations(ctx context.Context, peerURL string, pubs []ed25519.PublicKey) (map[string]proto.RelayTrustAttestation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(peerURL, "/v1/trust-attestations"), nil)
	if err != nil {
		return nil, err
	}
	if etag := s.cachedPeerTrustETag(peerURL); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if cached, ok := s.cachedPeerTrust(peerURL, time.Now().UTC()); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("peer trust feed 304 without valid cache")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer trust feed status %d", resp.StatusCode)
	}
	var feed proto.RelayTrustAttestationFeedResponse
	if err := decodeBoundedJSONResponse(resp.Body, &feed, remoteResponseMaxBodyBytes); err != nil {
		return nil, err
	}
	if err := verifyRelayTrustFeedAny(feed, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("peer trust feed verify failed: %w", err)
	}
	out := make(map[string]proto.RelayTrustAttestation, len(feed.Attestations))
	for _, att := range feed.Attestations {
		role, ok := canonicalizeSignalRole(att.Role)
		if !ok || strings.TrimSpace(att.RelayID) == "" {
			continue
		}
		key := relayKey(att.RelayID, role)
		att.Role = role
		att.Reputation = clampScore(att.Reputation)
		att.Uptime = clampScore(att.Uptime)
		att.Capacity = clampScore(att.Capacity)
		att.AbusePenalty = clampScore(att.AbusePenalty)
		att.BondScore = clampScore(att.BondScore)
		att.StakeScore = clampScore(att.StakeScore)
		att.Confidence = clampScore(att.Confidence)
		att.TierCap, att.DisputeUntil = normalizeDispute(att.TierCap, att.DisputeUntil, time.Now().Unix())
		att.AppealUntil = normalizeAppeal(att.AppealUntil, time.Now().Unix())
		att.DisputeCase = normalizeCaseID(att.DisputeCase)
		att.DisputeRef = normalizeEvidenceRef(att.DisputeRef)
		att.AppealCase = normalizeCaseID(att.AppealCase)
		att.AppealRef = normalizeEvidenceRef(att.AppealRef)
		out[key] = att
	}
	s.setPeerTrustCache(peerURL, resp.Header.Get("ETag"), out, time.Unix(feed.ExpiresAt, 0).UTC())
	return out, nil
}

func (s *Service) fetchPeerPubKey(ctx context.Context, peerURL string) (ed25519.PublicKey, error) {
	pubs, _, err := s.fetchPeerPubKeys(ctx, peerURL)
	if err != nil {
		return nil, err
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("peer returned no pubkeys")
	}
	return pubs[0], nil
}

func (s *Service) fetchPeerPubKeyForGossip(ctx context.Context, peerURL string, now time.Time) (ed25519.PublicKey, error) {
	pubs, _, ok := s.cachedPeerPubKeys(peerURL, now)
	if ok && len(pubs) > 0 {
		return pubs[0], nil
	}
	if !s.beginPeerPubKeyFetch(peerURL, now) {
		return nil, fmt.Errorf("peer pubkey refresh cooldown")
	}
	pubs, _, err := s.fetchPeerPubKeys(ctx, peerURL)
	if err != nil {
		return nil, err
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("peer returned no pubkeys")
	}
	return pubs[0], nil
}

func (s *Service) fetchPeerPubKeys(ctx context.Context, peerURL string) ([]ed25519.PublicKey, string, error) {
	peerURL = normalizePeerURL(peerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(peerURL, "/v1/pubkeys"), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		if s.betaStrict || s.prodStrict {
			return nil, "", fmt.Errorf("peer legacy /v1/pubkey fallback is not allowed in strict mode")
		}
		keys, operatorID, legacyErr := s.fetchPeerPubKeyLegacy(ctx, peerURL)
		if legacyErr != nil {
			return nil, "", legacyErr
		}
		s.setPeerPubKeyCache(peerURL, keys, operatorID, time.Now().UTC())
		return keys, operatorID, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("peer pubkeys status %d", resp.StatusCode)
	}
	var out proto.DirectoryPubKeysResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, "", err
	}
	keysByB64 := make(map[string]ed25519.PublicKey, len(out.PubKeys))
	keysB64 := make([]string, 0, len(out.PubKeys))
	for _, key := range dedupeStrings(out.PubKeys) {
		raw, decErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key))
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid peer pubkey")
		}
		canonical := base64.RawURLEncoding.EncodeToString(raw)
		if _, exists := keysByB64[canonical]; exists {
			continue
		}
		keysByB64[canonical] = ed25519.PublicKey(raw)
		keysB64 = append(keysB64, canonical)
	}
	if len(keysB64) == 0 {
		return nil, "", fmt.Errorf("peer returned no pubkeys")
	}
	if expected := s.peerHintPubKey(peerURL); expected != "" && !containsString(keysB64, expected) {
		return nil, "", fmt.Errorf("peer pubkey mismatch with signed hint for %s", peerURL)
	}
	selectedKeysB64, err := s.selectTrustedPeerPubKeys(peerURL, keysB64)
	if err != nil {
		return nil, "", err
	}
	keys := make([]ed25519.PublicKey, 0, len(selectedKeysB64))
	for _, key := range selectedKeysB64 {
		raw, ok := keysByB64[key]
		if !ok {
			return nil, "", fmt.Errorf("peer returned invalid trusted key set")
		}
		keys = append(keys, raw)
	}
	operatorID := normalizeOperatorID(out.Operator)
	s.setPeerPubKeyCache(peerURL, keys, operatorID, time.Now().UTC())
	return keys, operatorID, nil
}

func (s *Service) fetchPeerPubKeyLegacy(ctx context.Context, peerURL string) ([]ed25519.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(peerURL, "/v1/pubkey"), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("peer pubkey status %d", resp.StatusCode)
	}
	var out map[string]string
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, "", err
	}
	pubB64 := strings.TrimSpace(out["pub_key"])
	if expected := s.peerHintPubKey(peerURL); expected != "" && expected != pubB64 {
		return nil, "", fmt.Errorf("peer pubkey mismatch with signed hint for %s", peerURL)
	}
	if err := s.enforcePeerTrust(peerURL, pubB64); err != nil {
		return nil, "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid peer pubkey")
	}
	return []ed25519.PublicKey{ed25519.PublicKey(raw)}, s.peerHintOperator(peerURL), nil
}

func (s *Service) fetchPeerDirectoryPeers(ctx context.Context, peerURL string, pubs []ed25519.PublicKey) ([]proto.DirectoryPeerHint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(peerURL, "/v1/peers"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer list status %d", resp.StatusCode)
	}
	var out proto.DirectoryPeerListResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, err
	}
	if err := verifyDirectoryPeerListAny(out, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("peer list verify failed: %w", err)
	}
	return normalizePeerHints(out.Peers, out.PeerHints), nil
}

func (s *Service) snapshotSyncPeers(now time.Time) []string {
	if !s.peerDiscoveryEnabled {
		return normalizePeerURLs(append([]string(nil), s.peerURLs...))
	}
	peers := make([]string, 0, len(s.peerURLs)+len(s.discoveredPeers))
	s.peerMu.Lock()
	if s.discoveredPeers == nil {
		s.discoveredPeers = make(map[string]time.Time)
	}
	if s.discoveredPeerVoters == nil {
		s.discoveredPeerVoters = make(map[string]map[string]time.Time)
	}
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	if s.peerHintPubKeys == nil {
		s.peerHintPubKeys = make(map[string]string)
	}
	if s.peerHintOperators == nil {
		s.peerHintOperators = make(map[string]string)
	}
	s.pruneDiscoveredPeersLocked(now)
	for _, configuredURL := range s.peerURLs {
		configuredURL = normalizePeerURL(configuredURL)
		if configuredURL == "" {
			continue
		}
		if s.isPeerCoolingDownLocked(configuredURL, now) {
			continue
		}
		peers = append(peers, configuredURL)
	}
	for peerURL := range s.discoveredPeers {
		if s.isPeerCoolingDownLocked(peerURL, now) {
			continue
		}
		peers = append(peers, peerURL)
	}
	s.peerMu.Unlock()
	return normalizePeerURLs(peers)
}

func (s *Service) snapshotKnownPeers(now time.Time) []string {
	peers := append([]string(nil), s.peerURLs...)
	if s.peerDiscoveryEnabled {
		s.peerMu.Lock()
		if s.discoveredPeers == nil {
			s.discoveredPeers = make(map[string]time.Time)
		}
		if s.discoveredPeerVoters == nil {
			s.discoveredPeerVoters = make(map[string]map[string]time.Time)
		}
		if s.discoveredPeerHealth == nil {
			s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
		}
		if s.peerHintPubKeys == nil {
			s.peerHintPubKeys = make(map[string]string)
		}
		if s.peerHintOperators == nil {
			s.peerHintOperators = make(map[string]string)
		}
		s.pruneDiscoveredPeersLocked(now)
		for peerURL := range s.discoveredPeers {
			peers = append(peers, peerURL)
		}
		s.peerMu.Unlock()
	}
	self := normalizePeerURL(s.localURL)
	if self != "" {
		peers = append(peers, self)
	}
	peers = normalizePeerURLs(peers)
	sort.Strings(peers)
	return peers
}

func (s *Service) snapshotKnownPeerHints(now time.Time) []proto.DirectoryPeerHint {
	peers := s.snapshotKnownPeers(now)
	if len(peers) == 0 {
		return nil
	}
	self := normalizePeerURL(s.localURL)
	selfPub, _ := s.currentKeypair()
	selfPubB64 := ""
	if len(selfPub) == ed25519.PublicKeySize {
		selfPubB64 = base64.RawURLEncoding.EncodeToString(selfPub)
	}
	s.peerMu.RLock()
	hintKeys := make(map[string]string, len(s.peerHintPubKeys))
	for url, key := range s.peerHintPubKeys {
		hintKeys[url] = key
	}
	hintOperators := make(map[string]string, len(s.peerHintOperators))
	for url, operator := range s.peerHintOperators {
		hintOperators[url] = operator
	}
	s.peerMu.RUnlock()

	out := make([]proto.DirectoryPeerHint, 0, len(peers))
	for _, peerURL := range peers {
		hint := proto.DirectoryPeerHint{URL: peerURL}
		if operator := normalizeOperatorID(hintOperators[peerURL]); operator != "" {
			hint.Operator = operator
		}
		if key := normalizePeerPubKey(hintKeys[peerURL]); key != "" {
			hint.PubKey = key
		}
		if peerURL == self {
			hint.Operator = s.operatorID
			if selfPubB64 != "" {
				hint.PubKey = selfPubB64
			}
		}
		out = append(out, hint)
	}
	return out
}

func (s *Service) ingestDiscoveredPeers(sourceURL string, sourceOperator string, hints []proto.DirectoryPeerHint, now time.Time) int {
	if !s.peerDiscoveryEnabled || len(hints) == 0 {
		return 0
	}
	self := normalizePeerURL(s.localURL)
	sourceURL = normalizePeerURL(sourceURL)
	sourceOperator = normalizeSourceOperator(sourceOperator, nil, sourceURL)
	requiredVotes := maxInt(1, s.peerDiscoveryMinVotes)
	requireHint := s.peerDiscoveryRequireHint
	maxPerSource := s.peerDiscoveryMaxPerSource()
	maxPerOperator := s.peerDiscoveryMaxPerOperator()
	discovered := 0

	s.peerMu.Lock()
	if s.discoveredPeers == nil {
		s.discoveredPeers = make(map[string]time.Time)
	}
	if s.discoveredPeerVoters == nil {
		s.discoveredPeerVoters = make(map[string]map[string]time.Time)
	}
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	if s.peerHintPubKeys == nil {
		s.peerHintPubKeys = make(map[string]string)
	}
	if s.peerHintOperators == nil {
		s.peerHintOperators = make(map[string]string)
	}
	s.pruneDiscoveredPeersLocked(now)
	for _, hint := range hints {
		peerURL := normalizePeerURL(hint.URL)
		if peerURL == "" {
			continue
		}
		if isDisallowedDiscoveredPeerURL(peerURL) {
			continue
		}
		if operator := normalizeOperatorID(hint.Operator); operator != "" {
			s.peerHintOperators[peerURL] = operator
		}
		if key := normalizePeerPubKey(hint.PubKey); key != "" {
			s.peerHintPubKeys[peerURL] = key
		}
		if peerURL == self || peerURL == sourceURL {
			continue
		}
		if requireHint {
			if normalizeOperatorID(s.peerHintOperators[peerURL]) == "" || normalizePeerPubKey(s.peerHintPubKeys[peerURL]) == "" {
				continue
			}
		}
		if s.isConfiguredPeerLocked(peerURL) {
			continue
		}
		if sourceOperator != "" {
			if s.discoveredPeerVoters[peerURL] == nil {
				s.discoveredPeerVoters[peerURL] = make(map[string]time.Time)
			}
			if _, seen := s.discoveredPeerVoters[peerURL][sourceOperator]; !seen && maxPerSource > 0 &&
				s.activeDiscoveredPeerVotesBySourceLocked(sourceOperator) >= maxPerSource {
				continue
			}
			s.discoveredPeerVoters[peerURL][sourceOperator] = now
		}
		if s.activeDiscoveredPeerVotesLocked(peerURL) < requiredVotes {
			continue
		}
		hintOperatorKey := discoveredPeerOperatorKey(s.peerHintOperators[peerURL])
		if maxPerOperator > 0 {
			if _, alreadyDiscovered := s.discoveredPeers[peerURL]; !alreadyDiscovered &&
				s.activeDiscoveredPeersByHintOperatorLocked(hintOperatorKey) >= maxPerOperator {
				continue
			}
		}
		prev, ok := s.discoveredPeers[peerURL]
		if !ok || now.After(prev) {
			s.discoveredPeers[peerURL] = now
			discovered++
		}
	}
	s.trimDiscoveredPeersLocked()
	s.peerMu.Unlock()
	return discovered
}

func (s *Service) syncDNSDiscoveredPeers(ctx context.Context, now time.Time) error {
	if !s.peerDiscoveryEnabled || len(s.peerDiscoveryDNSSeeds) == 0 {
		return nil
	}
	lookup := s.dnsLookupTXT
	if lookup == nil {
		return fmt.Errorf("dns txt lookup unavailable")
	}
	totalDiscovered := 0
	var errs []string
	for _, seed := range s.peerDiscoveryDNSSeeds {
		records, err := lookup(ctx, seed)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s:%v", seed, err))
			continue
		}
		hints := parseDNSPeerHints(records)
		if len(hints) == 0 {
			continue
		}
		sourceOperator := "dns-seed:" + seed
		discovered := s.ingestDiscoveredPeers("", sourceOperator, hints, now)
		totalDiscovered += discovered
	}
	if totalDiscovered > 0 {
		log.Printf("directory dns peer discovery admitted=%d seeds=%d", totalDiscovered, len(s.peerDiscoveryDNSSeeds))
	}
	if len(errs) > 0 {
		return fmt.Errorf("dns seed lookup errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func parseDNSPeerHints(records []string) []proto.DirectoryPeerHint {
	if len(records) == 0 {
		return nil
	}
	hints := make([]proto.DirectoryPeerHint, 0, len(records))
	for _, rec := range records {
		hint, ok := parseDNSPeerHintRecord(rec)
		if !ok {
			continue
		}
		hints = append(hints, hint)
	}
	return normalizePeerHints(nil, hints)
}

func parseDNSPeerHintRecord(record string) (proto.DirectoryPeerHint, bool) {
	record = strings.TrimSpace(record)
	if record == "" {
		return proto.DirectoryPeerHint{}, false
	}
	fields := strings.Fields(strings.NewReplacer(";", " ", ",", " ").Replace(record))
	if len(fields) == 0 {
		return proto.DirectoryPeerHint{}, false
	}
	hint := proto.DirectoryPeerHint{}
	hasKV := false
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		hasKV = true
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "url", "peer", "peer_url", "peer-url":
			if hint.URL == "" {
				hint.URL = normalizePeerURL(value)
			}
		case "operator", "op":
			if hint.Operator == "" {
				hint.Operator = normalizeOperatorID(value)
			}
		case "pub_key", "pubkey", "pub-key":
			if hint.PubKey == "" {
				hint.PubKey = normalizePeerPubKey(value)
			}
		}
	}
	if !hasKV {
		if validDNSDiscoveryURL(record) {
			return proto.DirectoryPeerHint{URL: normalizePeerURL(record)}, true
		}
		return proto.DirectoryPeerHint{}, false
	}
	if !validDNSDiscoveryURL(hint.URL) {
		return proto.DirectoryPeerHint{}, false
	}
	return hint, true
}

func validDNSDiscoveryURL(raw string) bool {
	url := normalizePeerURL(raw)
	if url == "" {
		return false
	}
	parsed, err := urlpkg.Parse(url)
	if err != nil {
		return false
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return false
	}
	if isDisallowedDiscoveredPeerHost(host) {
		return false
	}
	if !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return false
	}
	return true
}

func isDisallowedDiscoveredPeerURL(raw string) bool {
	parsed, err := urlpkg.Parse(raw)
	if err != nil {
		return true
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return true
	}
	return isDisallowedDiscoveredPeerHost(host)
}

func isDisallowedDiscoveredPeerHost(host string) bool {
	if hasZoneIdentifierHost(host) {
		return true
	}
	normalized := normalizeHostForCompare(host)
	if normalized == "" {
		return true
	}
	if normalized == "localhost" || strings.HasSuffix(normalized, ".localhost") {
		return true
	}
	if isAmbiguousNumericHostAlias(normalized) {
		return true
	}
	ip := net.ParseIP(normalized)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

func (s *Service) peerDiscoveryMaxPerSource() int {
	if s.peerDiscoveryMaxPerSrc > 0 {
		return s.peerDiscoveryMaxPerSrc
	}
	return 0
}

func (s *Service) peerDiscoveryMaxPerOperator() int {
	if s.peerDiscoveryMaxPerOp > 0 {
		return s.peerDiscoveryMaxPerOp
	}
	return 0
}

func (s *Service) pruneDiscoveredPeersLocked(now time.Time) {
	if len(s.discoveredPeers) == 0 && len(s.discoveredPeerVoters) == 0 && len(s.discoveredPeerHealth) == 0 {
		return
	}
	ttl := s.peerDiscoveryTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	cutoff := now.Add(-ttl)
	for peerURL, voters := range s.discoveredPeerVoters {
		for sourceOperator, seenAt := range voters {
			if seenAt.Before(cutoff) {
				delete(voters, sourceOperator)
			}
		}
		if len(voters) == 0 {
			delete(s.discoveredPeerVoters, peerURL)
		}
	}
	requiredVotes := maxInt(1, s.peerDiscoveryMinVotes)
	for peerURL, seenAt := range s.discoveredPeers {
		quorumDropped := requiredVotes > 1 && s.activeDiscoveredPeerVotesLocked(peerURL) < requiredVotes
		if seenAt.Before(cutoff) || quorumDropped {
			delete(s.discoveredPeers, peerURL)
			delete(s.discoveredPeerVoters, peerURL)
			delete(s.discoveredPeerHealth, peerURL)
			delete(s.peerHintPubKeys, peerURL)
			delete(s.peerHintOperators, peerURL)
		}
	}
}

func (s *Service) trimDiscoveredPeersLocked() {
	maxPeers := s.peerDiscoveryMax
	if maxPeers <= 0 || len(s.discoveredPeers) <= maxPeers {
		return
	}
	type peerSeen struct {
		url    string
		seenAt time.Time
	}
	list := make([]peerSeen, 0, len(s.discoveredPeers))
	for peerURL, seenAt := range s.discoveredPeers {
		list = append(list, peerSeen{url: peerURL, seenAt: seenAt})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].seenAt.Equal(list[j].seenAt) {
			return list[i].url < list[j].url
		}
		return list[i].seenAt.After(list[j].seenAt)
	})
	for i := maxPeers; i < len(list); i++ {
		delete(s.discoveredPeers, list[i].url)
		delete(s.discoveredPeerVoters, list[i].url)
		delete(s.discoveredPeerHealth, list[i].url)
		delete(s.peerHintPubKeys, list[i].url)
		delete(s.peerHintOperators, list[i].url)
	}
}

func (s *Service) activeDiscoveredPeerVotesLocked(peerURL string) int {
	voters, ok := s.discoveredPeerVoters[peerURL]
	if !ok {
		return 0
	}
	return len(voters)
}

func (s *Service) activeDiscoveredPeerVotesBySourceLocked(sourceOperator string) int {
	sourceOperator = strings.TrimSpace(sourceOperator)
	if sourceOperator == "" || len(s.discoveredPeerVoters) == 0 {
		return 0
	}
	count := 0
	for _, voters := range s.discoveredPeerVoters {
		if _, ok := voters[sourceOperator]; ok {
			count++
		}
	}
	return count
}

func (s *Service) activeDiscoveredPeersByHintOperatorLocked(hintOperator string) int {
	hintOperator = discoveredPeerOperatorKey(hintOperator)
	if hintOperator == "" || len(s.discoveredPeers) == 0 {
		return 0
	}
	count := 0
	for peerURL := range s.discoveredPeers {
		if discoveredPeerOperatorKey(s.peerHintOperators[peerURL]) == hintOperator {
			count++
		}
	}
	return count
}

func discoveredPeerOperatorKey(operator string) string {
	operator = normalizeOperatorID(operator)
	if operator != "" {
		return operator
	}
	return discoveredPeerUnknownOperator
}

func (s *Service) isConfiguredPeerLocked(peerURL string) bool {
	for _, configured := range s.peerURLs {
		if normalizePeerURL(configured) == peerURL {
			return true
		}
	}
	return false
}

func (s *Service) isDiscoveredPeerCoolingDownLocked(peerURL string, now time.Time) bool {
	return s.isPeerCoolingDownLocked(peerURL, now)
}

func (s *Service) isPeerCoolingDownLocked(peerURL string, now time.Time) bool {
	health, ok := s.discoveredPeerHealth[peerURL]
	if !ok {
		return false
	}
	return !health.cooldownUntil.IsZero() && now.Before(health.cooldownUntil)
}

func (s *Service) isDiscoveredPeer(peerURL string) bool {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return false
	}
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	_, ok := s.discoveredPeers[peerURL]
	return ok
}

func (s *Service) recordPeerSyncSuccess(peerURL string, now time.Time) {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return
	}
	logRecovery := false
	recoveredFailures := 0
	recoveredAt := time.Time{}
	s.peerMu.Lock()
	isConfigured := s.isConfiguredPeerLocked(peerURL)
	_, isDiscovered := s.discoveredPeers[peerURL]
	if !isConfigured && !isDiscovered {
		s.peerMu.Unlock()
		return
	}
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	health := s.discoveredPeerHealth[peerURL]
	if !health.cooldownUntil.IsZero() {
		logRecovery = true
		recoveredFailures = health.consecutiveFailures
		recoveredAt = health.cooldownUntil
	}
	health.lastSuccess = now
	health.consecutiveFailures = 0
	health.cooldownUntil = time.Time{}
	health.lastError = ""
	s.discoveredPeerHealth[peerURL] = health
	s.peerMu.Unlock()
	if logRecovery {
		retryAfterSec := int64(0)
		if now.Before(recoveredAt) {
			retryAfterSec = int64(recoveredAt.Sub(now).Seconds())
		}
		log.Printf(
			"directory peer cooldown recovered: peer=%s previous_failures=%d previous_retry_after_sec=%d previous_cooldown_until=%s",
			peerURL,
			recoveredFailures,
			retryAfterSec,
			recoveredAt.UTC().Format(time.RFC3339),
		)
	}
}

func (s *Service) recordPeerSyncFailure(peerURL string, now time.Time, err error) {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return
	}
	logCooldown := false
	cooldownFailures := 0
	cooldownUntil := time.Time{}
	cooldownError := ""
	s.peerMu.Lock()
	isConfigured := s.isConfiguredPeerLocked(peerURL)
	_, isDiscovered := s.discoveredPeers[peerURL]
	if !isConfigured && !isDiscovered {
		s.peerMu.Unlock()
		return
	}
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	health := s.discoveredPeerHealth[peerURL]
	wasCoolingDown := !health.cooldownUntil.IsZero() && now.Before(health.cooldownUntil)
	health.lastFailure = now
	health.consecutiveFailures++
	if err != nil {
		msg := strings.TrimSpace(err.Error())
		if len(msg) > 256 {
			msg = msg[:256]
		}
		health.lastError = msg
	}
	if isDiscovered || (isConfigured && s.peerDiscoveryEnabled) {
		failThreshold := maxInt(1, s.peerDiscoveryFailN)
		if health.consecutiveFailures >= failThreshold {
			base := s.peerDiscoveryBackoff
			if base <= 0 {
				base = 60 * time.Second
			}
			maxBackoff := s.peerDiscoveryBackoffMax
			if maxBackoff < base {
				maxBackoff = base
			}
			step := health.consecutiveFailures - failThreshold
			if step < 0 {
				step = 0
			}
			backoff := base
			for i := 0; i < step; i++ {
				if backoff >= maxBackoff {
					backoff = maxBackoff
					break
				}
				next := backoff * 2
				if next <= 0 || next > maxBackoff {
					backoff = maxBackoff
					break
				}
				backoff = next
			}
			health.cooldownUntil = now.Add(backoff)
		}
	}
	isCoolingDown := !health.cooldownUntil.IsZero() && now.Before(health.cooldownUntil)
	if !wasCoolingDown && isCoolingDown {
		logCooldown = true
		cooldownFailures = health.consecutiveFailures
		cooldownUntil = health.cooldownUntil
		cooldownError = health.lastError
	}
	s.discoveredPeerHealth[peerURL] = health
	s.peerMu.Unlock()
	if logCooldown {
		retryAfterSec := int64(0)
		if now.Before(cooldownUntil) {
			retryAfterSec = int64(cooldownUntil.Sub(now).Seconds())
		}
		log.Printf(
			"directory peer cooldown entered: peer=%s consecutive_failures=%d retry_after_sec=%d cooldown_until=%s last_error=%q",
			peerURL,
			cooldownFailures,
			retryAfterSec,
			cooldownUntil.UTC().Format(time.RFC3339),
			cooldownError,
		)
	}
}

func (s *Service) preparePeerDescriptor(desc proto.RelayDescriptor) (proto.RelayDescriptor, bool) {
	origin := strings.TrimSpace(desc.OriginOperator)
	if origin == "" {
		origin = strings.TrimSpace(desc.OperatorID)
	}
	if origin == "" {
		origin = "operator-unknown"
	}
	if origin == s.operatorID {
		return desc, false
	}
	hop := desc.HopCount + 1
	if hop <= 0 {
		hop = 1
	}
	if s.peerMaxHops > 0 && hop > s.peerMaxHops {
		return desc, false
	}
	desc.OriginOperator = origin
	desc.HopCount = hop
	return desc, true
}

func (s *Service) cachedPeerRelayETag(peerURL string) string {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.peerRelayETags[normalizePeerURL(peerURL)]
}

func (s *Service) cachedPeerRelays(peerURL string) ([]proto.RelayDescriptor, bool) {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	relays, ok := s.peerRelayCache[normalizePeerURL(peerURL)]
	if !ok {
		return nil, false
	}
	return cloneRelayDescriptors(relays), true
}

func (s *Service) setPeerRelayCache(peerURL string, etag string, relays []proto.RelayDescriptor) {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerRelayCache == nil {
		s.peerRelayCache = make(map[string][]proto.RelayDescriptor)
	}
	if s.peerRelayETags == nil {
		s.peerRelayETags = make(map[string]string)
	}
	s.peerRelayCache[peerURL] = cloneRelayDescriptors(relays)
	if strings.TrimSpace(etag) != "" {
		s.peerRelayETags[peerURL] = strings.TrimSpace(etag)
	}
}

func (s *Service) cachedPeerScoreETag(peerURL string) string {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.peerScoreETags[normalizePeerURL(peerURL)]
}

func (s *Service) cachedPeerScores(peerURL string, now time.Time) (map[string]proto.RelaySelectionScore, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	peerURL = normalizePeerURL(peerURL)
	scores, ok := s.peerScoreCache[peerURL]
	if !ok {
		return nil, false
	}
	expiresAtUnix, ok := s.peerScoreCacheExpiresAt[peerURL]
	if !ok || expiresAtUnix <= 0 || now.Unix() >= expiresAtUnix {
		return nil, false
	}
	return cloneSelectionScores(scores), true
}

func (s *Service) setPeerScoreCache(peerURL string, etag string, scores map[string]proto.RelaySelectionScore, expiresAt time.Time) {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerScoreCache == nil {
		s.peerScoreCache = make(map[string]map[string]proto.RelaySelectionScore)
	}
	if s.peerScoreCacheExpiresAt == nil {
		s.peerScoreCacheExpiresAt = make(map[string]int64)
	}
	if s.peerScoreETags == nil {
		s.peerScoreETags = make(map[string]string)
	}
	s.peerScoreCache[peerURL] = cloneSelectionScores(scores)
	s.peerScoreCacheExpiresAt[peerURL] = expiresAt.Unix()
	if strings.TrimSpace(etag) != "" {
		s.peerScoreETags[peerURL] = strings.TrimSpace(etag)
	}
}

func (s *Service) cachedPeerTrustETag(peerURL string) string {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.peerTrustETags[normalizePeerURL(peerURL)]
}

func (s *Service) cachedPeerTrust(peerURL string, now time.Time) (map[string]proto.RelayTrustAttestation, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	peerURL = normalizePeerURL(peerURL)
	attestations, ok := s.peerTrustCache[peerURL]
	if !ok {
		return nil, false
	}
	expiresAtUnix, ok := s.peerTrustCacheExpiresAt[peerURL]
	if !ok || expiresAtUnix <= 0 || now.Unix() >= expiresAtUnix {
		return nil, false
	}
	return cloneTrustAttestations(attestations), true
}

func (s *Service) setPeerTrustCache(peerURL string, etag string, attestations map[string]proto.RelayTrustAttestation, expiresAt time.Time) {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerTrustCache == nil {
		s.peerTrustCache = make(map[string]map[string]proto.RelayTrustAttestation)
	}
	if s.peerTrustCacheExpiresAt == nil {
		s.peerTrustCacheExpiresAt = make(map[string]int64)
	}
	if s.peerTrustETags == nil {
		s.peerTrustETags = make(map[string]string)
	}
	s.peerTrustCache[peerURL] = cloneTrustAttestations(attestations)
	s.peerTrustCacheExpiresAt[peerURL] = expiresAt.Unix()
	if strings.TrimSpace(etag) != "" {
		s.peerTrustETags[peerURL] = strings.TrimSpace(etag)
	}
}

func (s *Service) cachedIssuerTrustETag(issuerURL string) string {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.issuerTrustETags[normalizePeerURL(issuerURL)]
}

func (s *Service) cachedIssuerTrust(issuerURL string, now time.Time) (map[string]proto.RelayTrustAttestation, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	issuerURL = normalizePeerURL(issuerURL)
	attestations, ok := s.issuerTrustCache[issuerURL]
	if !ok {
		return nil, false
	}
	expiresAtUnix, ok := s.issuerTrustCacheExpiresAt[issuerURL]
	if !ok || expiresAtUnix <= 0 || now.Unix() >= expiresAtUnix {
		return nil, false
	}
	return cloneTrustAttestations(attestations), true
}

func (s *Service) setIssuerTrustCache(issuerURL string, etag string, attestations map[string]proto.RelayTrustAttestation, expiresAt time.Time) {
	issuerURL = normalizePeerURL(issuerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.issuerTrustCache == nil {
		s.issuerTrustCache = make(map[string]map[string]proto.RelayTrustAttestation)
	}
	if s.issuerTrustCacheExpiresAt == nil {
		s.issuerTrustCacheExpiresAt = make(map[string]int64)
	}
	if s.issuerTrustETags == nil {
		s.issuerTrustETags = make(map[string]string)
	}
	s.issuerTrustCache[issuerURL] = cloneTrustAttestations(attestations)
	s.issuerTrustCacheExpiresAt[issuerURL] = expiresAt.Unix()
	if strings.TrimSpace(etag) != "" {
		s.issuerTrustETags[issuerURL] = strings.TrimSpace(etag)
	}
}

func clonePeerPubKeys(in []ed25519.PublicKey) []ed25519.PublicKey {
	if len(in) == 0 {
		return nil
	}
	out := make([]ed25519.PublicKey, 0, len(in))
	for _, key := range in {
		if len(key) == 0 {
			continue
		}
		dup := make(ed25519.PublicKey, len(key))
		copy(dup, key)
		out = append(out, dup)
	}
	return out
}

func (s *Service) cachedPeerPubKeys(peerURL string, now time.Time) ([]ed25519.PublicKey, string, bool) {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return nil, "", false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.peerMu.RLock()
	entry, ok := s.peerPubKeyCache[peerURL]
	s.peerMu.RUnlock()
	if !ok || len(entry.pubs) == 0 {
		return nil, "", false
	}
	if now.Sub(entry.fetchedAt) > peerGossipPubKeyCacheTTL {
		return nil, "", false
	}
	return clonePeerPubKeys(entry.pubs), normalizeOperatorID(entry.operatorID), true
}

func (s *Service) beginPeerPubKeyFetch(peerURL string, now time.Time) bool {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerPubKeyCache == nil {
		s.peerPubKeyCache = make(map[string]peerPubKeyCacheEntry)
	}
	entry := s.peerPubKeyCache[peerURL]
	if !entry.lastFetchAttempt.IsZero() && now.Sub(entry.lastFetchAttempt) < peerGossipPubKeyFetchMinInterval {
		return false
	}
	entry.lastFetchAttempt = now
	s.peerPubKeyCache[peerURL] = entry
	return true
}

func (s *Service) setPeerPubKeyCache(peerURL string, pubs []ed25519.PublicKey, operatorID string, fetchedAt time.Time) {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" || len(pubs) == 0 {
		return
	}
	if fetchedAt.IsZero() {
		fetchedAt = time.Now().UTC()
	}
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerPubKeyCache == nil {
		s.peerPubKeyCache = make(map[string]peerPubKeyCacheEntry)
	}
	entry := s.peerPubKeyCache[peerURL]
	entry.pubs = clonePeerPubKeys(pubs)
	entry.operatorID = normalizeOperatorID(operatorID)
	entry.fetchedAt = fetchedAt
	s.peerPubKeyCache[peerURL] = entry
}

func (s *Service) peerHintPubKey(peerURL string) string {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return normalizePeerPubKey(s.peerHintPubKeys[peerURL])
}

func (s *Service) peerHintOperator(peerURL string) string {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return normalizeOperatorID(s.peerHintOperators[peerURL])
}

func (s *Service) enforcePeerTrust(peerURL string, pubB64 string) error {
	return s.enforcePeerTrustSet(peerURL, []string{pubB64})
}

func (s *Service) enforcePeerTrustSet(peerURL string, pubB64Set []string) error {
	_, err := s.selectTrustedPeerPubKeys(peerURL, pubB64Set)
	return err
}

func (s *Service) selectTrustedPeerPubKeys(peerURL string, pubB64Set []string) ([]string, error) {
	filtered := make([]string, 0, len(pubB64Set))
	seen := make(map[string]struct{}, len(pubB64Set))
	for _, candidate := range pubB64Set {
		normalized := normalizePeerPubKey(candidate)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		filtered = append(filtered, normalized)
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("peer returned no valid pubkeys")
	}
	if !s.peerTrustStrict {
		return filtered, nil
	}
	peerURL = normalizePeerURL(peerURL)
	s.peerTrustMu.Lock()
	defer s.peerTrustMu.Unlock()
	trusted, err := loadPeerTrustedKeys(s.peerTrustFile)
	if err != nil {
		return nil, err
	}
	if pinned, ok := trusted[peerURL]; ok {
		for _, key := range filtered {
			if pinned == key {
				if len(filtered) > 1 {
					log.Printf("directory ignored %d untrusted peer pubkeys for %s in strict mode", len(filtered)-1, peerURL)
				}
				return []string{pinned}, nil
			}
		}
		return nil, fmt.Errorf("peer key mismatch for %s", peerURL)
	}
	if s.peerTrustTOFU {
		if len(filtered) != 1 {
			return nil, fmt.Errorf("peer returned %d candidate pubkeys for initial TOFU trust bootstrap for %s", len(filtered), peerURL)
		}
		if err := appendPeerTrustedKey(s.peerTrustFile, peerURL, filtered[0]); err != nil {
			return nil, err
		}
		log.Printf("directory TOFU pinned peer key for %s to %s", peerURL, s.peerTrustFile)
		return []string{filtered[0]}, nil
	}
	return nil, fmt.Errorf("peer key is not trusted for %s", peerURL)
}

func (s *Service) loadOrCreateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if s.privateKeyPath == "" {
		return crypto.GenerateEd25519Keypair()
	}
	b, err := readFileBounded(s.privateKeyPath, directoryPrivateKeyMaxBytes)
	if err == nil {
		trimmed := strings.TrimSpace(string(b))
		raw, decErr := base64.RawURLEncoding.DecodeString(trimmed)
		if decErr != nil {
			return nil, nil, decErr
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid private key size")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		return nil, nil, err
	}
	if err := s.persistPrivateKey(priv); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func (s *Service) handleRelays(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	stableNow := s.stableTime(now, s.descriptorEpoch)
	relays := s.buildRelayDescriptors(stableNow)
	_, priv := s.currentKeypair()

	for i := range relays {
		relays[i].Signature = signDescriptor(relays[i], priv)
	}

	resp := proto.RelayListResponse{Relays: relays}
	if err := writeJSONWithETag(w, r, resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleSelectionFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	stableNow := s.stableTime(now, s.selectionEpoch)
	relays := s.buildRelayDescriptors(stableNow)
	scores := s.buildSelectionScores(relays)
	feed := proto.RelaySelectionFeedResponse{
		Operator:    s.operatorID,
		GeneratedAt: stableNow.Unix(),
		ExpiresAt:   stableNow.Add(s.selectionFeedTTL).Unix(),
		Scores:      scores,
	}
	_, priv := s.currentKeypair()
	sig, err := crypto.SignRelaySelectionFeed(feed, priv)
	if err != nil {
		http.Error(w, "failed to sign selection feed", http.StatusInternalServerError)
		return
	}
	feed.Signature = sig

	if err := writeJSONWithETag(w, r, feed); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleTrustAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	stableNow := s.stableTime(now, s.trustEpoch)
	relays := s.buildRelayDescriptors(stableNow)
	attestations := s.buildTrustAttestations(relays)
	feed := proto.RelayTrustAttestationFeedResponse{
		Operator:     s.operatorID,
		GeneratedAt:  stableNow.Unix(),
		ExpiresAt:    stableNow.Add(s.trustFeedTTL).Unix(),
		Attestations: attestations,
	}
	_, priv := s.currentKeypair()
	sig, err := crypto.SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		http.Error(w, "failed to sign trust feed", http.StatusInternalServerError)
		return
	}
	feed.Signature = sig

	if err := writeJSONWithETag(w, r, feed); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleGossipRelays(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.RelayGossipPushRequest
	if err := decodeStrictJSONBody(w, r, &req, gossipRelaysMaxBodyBytes); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	peerURL := normalizePeerURL(req.PeerURL)
	if peerURL == "" || !s.isKnownPeer(peerURL) {
		http.Error(w, "unknown peer", http.StatusForbidden)
		return
	}
	if len(req.Relays) > gossipRelaysMaxDescriptors {
		http.Error(w, "too many relays", http.StatusRequestEntityTooLarge)
		return
	}
	now := time.Now().UTC()
	candidates := make([]proto.RelayDescriptor, 0, len(req.Relays))
	for _, desc := range req.Relays {
		if strings.TrimSpace(desc.RelayID) == "" {
			continue
		}
		if _, err := canonicalizePeerRelayRole(desc.Role); err != nil {
			continue
		}
		if desc.ValidUntil.IsZero() || now.After(desc.ValidUntil) {
			continue
		}
		candidates = append(candidates, desc)
	}
	if len(candidates) == 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.RelayGossipPushResponse{Imported: 0})
		return
	}
	pub, err := s.fetchPeerPubKeyForGossip(r.Context(), peerURL, now)
	if err != nil {
		http.Error(w, "peer pubkey unavailable", http.StatusBadGateway)
		return
	}
	validated := make([]proto.RelayDescriptor, 0, len(candidates))
	for _, desc := range candidates {
		if err := crypto.VerifyRelayDescriptor(desc, pub); err != nil {
			continue
		}
		role, err := canonicalizePeerRelayRole(desc.Role)
		if err != nil {
			continue
		}
		desc.Role = role
		desc.Signature = ""
		normalized, ok := s.preparePeerDescriptor(desc)
		if !ok {
			continue
		}
		validated = append(validated, normalized)
	}
	imported := s.ingestGossipPeerRelays(validated)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.RelayGossipPushResponse{Imported: imported})
}

func (s *Service) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	now := time.Now().UTC()
	ttl := s.peerListTTL
	if ttl <= 0 {
		ttl = 45 * time.Second
	}
	feed := proto.DirectoryPeerListResponse{
		Operator:    s.operatorID,
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(ttl).Unix(),
		Peers:       s.snapshotKnownPeers(now),
		PeerHints:   s.snapshotKnownPeerHints(now),
	}
	_, priv := s.currentKeypair()
	sig, err := signDirectoryPeerList(feed, priv)
	if err != nil {
		http.Error(w, "failed to sign peers", http.StatusInternalServerError)
		return
	}
	feed.Signature = sig
	if err := writeJSONWithETag(w, r, feed); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleProviderRelayUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.ProviderRelayUpsertRequest
	if err := decodeStrictJSONBody(w, r, &req, providerRelayUpsertMaxBodyBytes); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if err := validateProviderRelayUpsertShape(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token := providerTokenFromRequest(r, req.Token)
	now := time.Now().UTC()
	claims, err := s.verifyProviderToken(r.Context(), token, now.Unix())
	if err != nil {
		http.Error(w, "provider token invalid", http.StatusUnauthorized)
		return
	}

	desc, err := s.buildProviderRelayDescriptor(req, claims, now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.upsertProviderRelay(desc); err != nil {
		status := http.StatusTooManyRequests
		if errors.Is(err, errProviderRelayOwnershipConflict) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.ProviderRelayUpsertResponse{Accepted: true, Relay: desc})
}

func canonicalizeProviderRelayRole(raw string) (string, error) {
	role := strings.TrimSpace(strings.ToLower(raw))
	switch role {
	case "entry", "exit", "micro-relay":
		return role, nil
	case "micro_relay", "middle", "relay", "transit", "three-hop-middle":
		return "micro-relay", nil
	default:
		return "", fmt.Errorf("provider relay role must be entry, exit, or micro-relay (aliases: micro_relay, middle, relay, transit, three-hop-middle)")
	}
}

func canonicalizePeerRelayRole(raw string) (string, error) {
	role := strings.TrimSpace(strings.ToLower(raw))
	switch role {
	case "entry", "exit", "micro-relay":
		return role, nil
	case "micro_relay", "middle", "relay", "transit", "three-hop-middle":
		return "micro-relay", nil
	default:
		return "", fmt.Errorf("relay role must be entry, exit, or micro-relay (aliases: micro_relay, middle, relay, transit, three-hop-middle)")
	}
}

func canonicalizeSignalRole(raw string) (string, bool) {
	role := strings.TrimSpace(raw)
	if role == "" {
		role = "exit"
	}
	canonicalRole, err := canonicalizePeerRelayRole(role)
	if err != nil {
		return "", false
	}
	if canonicalRole != "exit" && canonicalRole != "micro-relay" {
		return "", false
	}
	return canonicalRole, true
}

func validateProviderRelayUpsertShape(req proto.ProviderRelayUpsertRequest) error {
	if _, err := canonicalizeProviderRelayRole(req.Role); err != nil {
		return err
	}
	if strings.TrimSpace(req.RelayID) == "" {
		return fmt.Errorf("provider relay_id is required")
	}
	if normalizePeerPubKey(req.PubKey) == "" {
		return fmt.Errorf("provider pub_key invalid")
	}
	if strings.TrimSpace(req.Endpoint) == "" {
		return fmt.Errorf("provider endpoint is required")
	}
	if normalizeHTTPURL(req.ControlURL) == "" {
		return fmt.Errorf("provider control_url is required")
	}
	return nil
}

func validateProviderRelayRuntimeAdmission(desc proto.RelayDescriptor) error {
	role, err := canonicalizeProviderRelayRole(desc.Role)
	if err != nil {
		return err
	}
	if strings.TrimSpace(desc.RelayID) == "" {
		return fmt.Errorf("provider relay_id is required")
	}
	if role != "micro-relay" {
		return nil
	}
	if normalizeOperatorID(desc.OperatorID) == "" {
		return fmt.Errorf("provider micro-relay operator id invalid")
	}
	for _, hopRole := range normalizeHopRoles(desc.HopRoles) {
		if hopRole != "middle" {
			return fmt.Errorf("provider micro-relay hop_roles must only include middle")
		}
	}
	for _, capability := range normalizeCapabilities(desc.Capabilities, role) {
		if capability == "two-hop" || capability == "tiered-policy" {
			return fmt.Errorf("provider micro-relay capability %q is not allowed", capability)
		}
	}
	if desc.Reputation < microRelayMinReputationScore {
		return fmt.Errorf("provider micro-relay reputation score %.2f below minimum %.2f", desc.Reputation, microRelayMinReputationScore)
	}
	if desc.Uptime < microRelayMinUptimeScore {
		return fmt.Errorf("provider micro-relay uptime score %.2f below minimum %.2f", desc.Uptime, microRelayMinUptimeScore)
	}
	if desc.Capacity < microRelayMinCapacityScore {
		return fmt.Errorf("provider micro-relay capacity score %.2f below minimum %.2f", desc.Capacity, microRelayMinCapacityScore)
	}
	if desc.AbusePenalty > microRelayMaxAbusePenalty {
		return fmt.Errorf("provider micro-relay abuse penalty %.2f exceeds maximum %.2f", desc.AbusePenalty, microRelayMaxAbusePenalty)
	}
	return nil
}

func decodeStrictJSONBody(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing json")
		}
		return err
	}
	return nil
}

func decodeBoundedJSONResponse(body io.Reader, dst any, maxBytes int64) error {
	payload, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > maxBytes {
		return fmt.Errorf("response body too large")
	}
	return json.NewDecoder(bytes.NewReader(payload)).Decode(dst)
}

func providerTokenFromRequest(r *http.Request, bodyToken string) string {
	if token := parseBearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}
	_ = bodyToken
	return ""
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

func (s *Service) verifyProviderToken(ctx context.Context, token string, nowUnix int64) (crypto.CapabilityClaims, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return crypto.CapabilityClaims{}, fmt.Errorf("missing provider token")
	}
	issuerURLs := normalizePeerURLs(s.providerIssuerURLs)
	if len(issuerURLs) == 0 {
		return crypto.CapabilityClaims{}, fmt.Errorf("provider issuer urls unavailable")
	}
	if len(s.issuerTrustedKeys) == 0 {
		if s.betaStrict || s.prodStrict {
			return crypto.CapabilityClaims{}, fmt.Errorf("provider token verification requires issuer trust anchors in strict mode")
		}
		for _, issuerURL := range issuerURLs {
			if !isLocalDevelopmentIssuerURL(issuerURL) {
				return crypto.CapabilityClaims{}, fmt.Errorf(
					"provider token verification requires issuer trust anchors for non-local issuer url %q",
					issuerURL,
				)
			}
		}
	}

	var lastErr error
	for _, issuerURL := range issuerURLs {
		pubs, declaredIssuer, err := s.fetchIssuerPubKeysForProviderToken(ctx, issuerURL, time.Now())
		if err != nil {
			lastErr = err
			continue
		}
		verifyPubs, verifyErr := issuerVerificationKeysForTrustFeed(pubs, s.issuerTrustedKeys)
		if verifyErr != nil {
			lastErr = verifyErr
			continue
		}
		for _, pub := range verifyPubs {
			claims, verifyErr := crypto.VerifyClaims(token, pub)
			if verifyErr != nil {
				lastErr = verifyErr
				continue
			}
			if declaredIssuer != "" {
				claimIssuer := strings.TrimSpace(claims.Issuer)
				if claimIssuer == "" {
					lastErr = fmt.Errorf("provider token issuer missing")
					continue
				}
				if claimIssuer != declaredIssuer {
					lastErr = fmt.Errorf("provider token issuer mismatch")
					continue
				}
			}
			if validateErr := validateProviderTokenClaims(claims, nowUnix); validateErr != nil {
				lastErr = validateErr
				continue
			}
			return claims, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("provider token verification failed")
	}
	return crypto.CapabilityClaims{}, lastErr
}

func validateProviderTokenClaims(claims crypto.CapabilityClaims, nowUnix int64) error {
	if strings.TrimSpace(claims.Audience) != "provider" {
		return fmt.Errorf("provider token audience invalid")
	}
	if strings.TrimSpace(claims.TokenType) != crypto.TokenTypeProviderRole {
		return fmt.Errorf("provider token type invalid")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return fmt.Errorf("provider token subject missing")
	}
	if strings.TrimSpace(claims.TokenID) == "" {
		return fmt.Errorf("provider token id missing")
	}
	if claims.Tier < 1 || claims.Tier > 3 {
		return fmt.Errorf("provider token tier invalid")
	}
	if claims.ExpiryUnix <= 0 || nowUnix >= claims.ExpiryUnix {
		return fmt.Errorf("provider token expired")
	}
	return nil
}

func (s *Service) validateProviderTokenCNFBinding(claims crypto.CapabilityClaims, relayPubKey string) error {
	cnf := strings.TrimSpace(claims.CNFEd25519)
	allowDangerousBypass := envEnabled(allowDangerousProviderTokenBypass) && !(s.betaStrict || s.prodStrict)
	if cnf == "" {
		if allowDangerousBypass {
			return nil
		}
		return fmt.Errorf("provider token cnf_ed25519 missing")
	}
	normalizedCNF, err := crypto.NormalizeEd25519PublicKey(cnf)
	if err != nil {
		return fmt.Errorf("provider token cnf_ed25519 invalid")
	}
	if relayPubKey == "" {
		return fmt.Errorf("provider pub_key invalid")
	}
	if subtle.ConstantTimeCompare([]byte(normalizedCNF), []byte(relayPubKey)) != 1 {
		return fmt.Errorf("provider token cnf_ed25519 must match relay pub_key")
	}
	return nil
}

func (s *Service) validateProviderTokenProof(
	req proto.ProviderRelayUpsertRequest,
	claims crypto.CapabilityClaims,
	relayID string,
	role string,
	relayPubKey string,
	endpoint string,
	controlURL string,
	now time.Time,
) error {
	cnf := strings.TrimSpace(claims.CNFEd25519)
	allowDangerousBypass := envEnabled(allowDangerousProviderTokenBypass) && !(s.betaStrict || s.prodStrict)
	if cnf == "" {
		if allowDangerousBypass {
			return nil
		}
		return fmt.Errorf("provider token cnf_ed25519 missing")
	}

	nonce := strings.TrimSpace(req.TokenProofNonce)
	proof := strings.TrimSpace(req.TokenProof)
	if nonce == "" || proof == "" {
		if allowDangerousBypass {
			return nil
		}
		return fmt.Errorf("provider token proof and token_proof_nonce are required")
	}
	if len(nonce) > providerRelayUpsertProofNonceMaxLen {
		return fmt.Errorf("provider token proof nonce exceeds %d characters", providerRelayUpsertProofNonceMaxLen)
	}
	if strings.ContainsAny(nonce, " \t\r\n") {
		return fmt.Errorf("provider token proof nonce must not contain whitespace")
	}

	pubKey, err := crypto.ParseEd25519PublicKey(cnf)
	if err != nil {
		return fmt.Errorf("provider token cnf_ed25519 invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return fmt.Errorf("provider token proof encoding invalid")
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("provider token proof signature size invalid")
	}

	message, err := providerRelayUpsertProofMessage(claims.TokenID, claims.Subject, relayID, role, relayPubKey, endpoint, controlURL, nonce)
	if err != nil {
		return fmt.Errorf("provider token proof payload invalid")
	}
	if !ed25519.Verify(pubKey, message, signature) {
		return fmt.Errorf("provider token proof signature invalid")
	}
	if err := s.markProviderTokenProofReplay(claims.TokenID, nonce, now); err != nil {
		return err
	}
	return nil
}

func providerRelayUpsertProofMessage(
	tokenID string,
	subject string,
	relayID string,
	role string,
	relayPubKey string,
	endpoint string,
	controlURL string,
	nonce string,
) ([]byte, error) {
	normalizedRole := strings.TrimSpace(strings.ToLower(role))
	if canonicalRole, err := canonicalizeProviderRelayRole(normalizedRole); err == nil {
		normalizedRole = canonicalRole
	}
	payload := struct {
		Context    string `json:"context"`
		TokenID    string `json:"token_id"`
		Subject    string `json:"subject"`
		RelayID    string `json:"relay_id"`
		Role       string `json:"role"`
		PubKey     string `json:"pub_key"`
		Endpoint   string `json:"endpoint"`
		ControlURL string `json:"control_url"`
		Nonce      string `json:"nonce"`
	}{
		Context:    providerRelayUpsertProofContext,
		TokenID:    strings.TrimSpace(tokenID),
		Subject:    normalizeOperatorID(subject),
		RelayID:    strings.TrimSpace(relayID),
		Role:       normalizedRole,
		PubKey:     strings.TrimSpace(relayPubKey),
		Endpoint:   strings.TrimSpace(endpoint),
		ControlURL: strings.TrimSpace(controlURL),
		Nonce:      strings.TrimSpace(nonce),
	}
	return json.Marshal(payload)
}

func (s *Service) markProviderTokenProofReplay(tokenID string, nonce string, now time.Time) error {
	tokenID = strings.TrimSpace(tokenID)
	nonce = strings.TrimSpace(nonce)
	if tokenID == "" || nonce == "" {
		return fmt.Errorf("provider token proof token id and nonce are required")
	}
	if s.providerTokenProofReplayRedisEnabled() {
		return s.markProviderTokenProofReplayRedis(tokenID, nonce, now)
	}
	if s.providerTokenProofSharedFileMode {
		return s.markProviderTokenProofReplayShared(tokenID, nonce, now)
	}
	return s.markProviderTokenProofReplayInstanceLocal(tokenID, nonce, now)
}

func (s *Service) markProviderTokenProofReplayInstanceLocal(tokenID string, nonce string, now time.Time) error {
	replayStorePath := strings.TrimSpace(s.providerTokenProofStoreFile)
	needsPersist := replayStorePath != ""
	var before map[string]time.Time
	var snapshot map[string]time.Time

	s.providerMu.Lock()
	if s.providerTokenProofSeen == nil {
		s.providerTokenProofSeen = make(map[string]time.Time)
	}
	if needsPersist {
		before = cloneProviderTokenProofSeen(s.providerTokenProofSeen)
	}
	if providerTokenProofReplaySeenMapMarkAndCheck(s.providerTokenProofSeen, tokenID, nonce, now) {
		s.providerMu.Unlock()
		return fmt.Errorf("provider token proof nonce replayed")
	}
	if needsPersist {
		snapshot = cloneProviderTokenProofSeen(s.providerTokenProofSeen)
	}
	s.providerMu.Unlock()
	if !needsPersist {
		return nil
	}
	if err := persistProviderTokenProofReplayStoreSnapshot(replayStorePath, now, snapshot); err != nil {
		s.providerMu.Lock()
		s.providerTokenProofSeen = before
		s.providerMu.Unlock()
		return fmt.Errorf("provider token proof replay persistence failed: %w", err)
	}
	return nil
}

func (s *Service) markProviderTokenProofReplayShared(tokenID string, nonce string, now time.Time) error {
	replayStorePath := strings.TrimSpace(s.providerTokenProofStoreFile)
	if replayStorePath == "" {
		return fmt.Errorf("provider token proof shared replay mode requires DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE")
	}
	releaseLock, err := acquireProviderTokenProofReplayStoreLock(replayStorePath, s.providerTokenProofLockTimeout)
	if err != nil {
		return fmt.Errorf("provider token proof replay lock failed: %w", err)
	}
	defer releaseLock()

	seen, _, err := loadProviderTokenProofReplayStoreSnapshot(replayStorePath, now)
	if err != nil {
		return fmt.Errorf("provider token proof replay store load failed: %w", err)
	}
	if seen == nil {
		seen = make(map[string]time.Time)
	}
	if providerTokenProofReplaySeenMapMarkAndCheck(seen, tokenID, nonce, now) {
		s.providerMu.Lock()
		s.providerTokenProofSeen = cloneProviderTokenProofSeen(seen)
		s.providerMu.Unlock()
		return fmt.Errorf("provider token proof nonce replayed")
	}
	if err := persistProviderTokenProofReplayStoreSnapshot(replayStorePath, now, seen); err != nil {
		return fmt.Errorf("provider token proof replay persistence failed: %w", err)
	}
	s.providerMu.Lock()
	s.providerTokenProofSeen = cloneProviderTokenProofSeen(seen)
	s.providerMu.Unlock()
	return nil
}

func (s *Service) markProviderTokenProofReplayRedis(tokenID string, nonce string, now time.Time) error {
	client, err := s.providerTokenProofReplayRedisClient()
	if err != nil {
		return fmt.Errorf("provider token proof replay redis client init failed: %w", err)
	}
	key := s.providerTokenProofReplayRedisKey(tokenID, nonce)
	dialTimeout := s.providerTokenProofRedisDial
	if dialTimeout <= 0 {
		dialTimeout = providerRelayUpsertProofReplayRedisDefaultDialTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	seen, err := client.SetNX(ctx, key, strconv.FormatInt(now.Unix(), 10), providerRelayUpsertProofReplayTTL).Result()
	if err != nil {
		return fmt.Errorf("provider token proof replay redis setnx failed: %w", err)
	}
	if !seen {
		return fmt.Errorf("provider token proof nonce replayed")
	}
	s.providerMu.Lock()
	if s.providerTokenProofSeen == nil {
		s.providerTokenProofSeen = make(map[string]time.Time)
	}
	providerTokenProofReplaySeenMapMarkAndCheck(s.providerTokenProofSeen, tokenID, nonce, now)
	s.providerMu.Unlock()
	return nil
}

func providerTokenProofReplaySeenMapMarkAndCheck(seen map[string]time.Time, tokenID string, nonce string, now time.Time) bool {
	cutoff := now.Add(-providerRelayUpsertProofReplayTTL)
	for key, seenAt := range seen {
		if seenAt.Before(cutoff) {
			delete(seen, key)
		}
	}
	replayKey := tokenID + ":" + nonce
	if seenAt, ok := seen[replayKey]; ok && !seenAt.Before(cutoff) {
		return true
	}
	tokenCount := 0
	oldestTokenKey := ""
	oldestTokenSeenAt := now
	for key, seenAt := range seen {
		if !strings.HasPrefix(key, tokenID+":") {
			continue
		}
		tokenCount++
		if oldestTokenKey == "" || seenAt.Before(oldestTokenSeenAt) {
			oldestTokenKey = key
			oldestTokenSeenAt = seenAt
		}
	}
	if tokenCount >= providerRelayUpsertProofReplayMaxPerToken && oldestTokenKey != "" {
		delete(seen, oldestTokenKey)
	}
	for len(seen) >= providerRelayUpsertProofReplayMaxEntries {
		oldestKey := ""
		oldestSeenAt := now
		for key, seenAt := range seen {
			if oldestKey == "" || seenAt.Before(oldestSeenAt) {
				oldestKey = key
				oldestSeenAt = seenAt
			}
		}
		if oldestKey == "" {
			break
		}
		delete(seen, oldestKey)
	}
	seen[replayKey] = now
	return false
}

func acquireProviderTokenProofReplayStoreLock(path string, timeout time.Duration) (func(), error) {
	lockPath := strings.TrimSpace(path) + ".lock"
	if lockPath == ".lock" {
		return nil, fmt.Errorf("provider token proof replay lock path is required")
	}
	if timeout <= 0 {
		timeout = providerRelayUpsertProofReplayDefaultLockTimeout
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, _ = file.WriteString(strconv.Itoa(os.Getpid()))
			_ = file.Close()
			return func() {
				_ = os.Remove(lockPath)
			}, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out after %s acquiring replay lock %s", timeout, lockPath)
		}
		time.Sleep(providerRelayUpsertProofReplayLockRetryInterval)
	}
}

type providerTokenReplayStoreSnapshot struct {
	Version     int              `json:"version"`
	SavedAtUnix int64            `json:"saved_at_unix"`
	Seen        map[string]int64 `json:"seen"`
}

func (s *Service) loadProviderTokenProofReplayStore(now time.Time) error {
	if s.providerTokenProofReplayRedisEnabled() {
		return nil
	}
	path := strings.TrimSpace(s.providerTokenProofStoreFile)
	if path == "" {
		return nil
	}
	seen, exists, err := loadProviderTokenProofReplayStoreSnapshot(path, now)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	s.providerMu.Lock()
	s.providerTokenProofSeen = seen
	s.providerMu.Unlock()
	return nil
}

func loadProviderTokenProofReplayStoreSnapshot(path string, now time.Time) (map[string]time.Time, bool, error) {
	b, err := readFileBounded(path, directoryProviderReplayStoreMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]time.Time), false, nil
		}
		return nil, false, err
	}
	var snapshot providerTokenReplayStoreSnapshot
	if err := json.Unmarshal(b, &snapshot); err != nil {
		return nil, true, fmt.Errorf("invalid replay store json: %w", err)
	}
	return normalizeProviderTokenProofReplayStoreSnapshot(snapshot, now), true, nil
}

func normalizeProviderTokenProofReplayStoreSnapshot(snapshot providerTokenReplayStoreSnapshot, now time.Time) map[string]time.Time {
	cutoff := now.Add(-providerRelayUpsertProofReplayTTL)
	type replayItem struct {
		key    string
		seenAt time.Time
	}
	items := make([]replayItem, 0, len(snapshot.Seen))
	for key, seenUnix := range snapshot.Seen {
		seenAt := time.Unix(seenUnix, 0)
		if seenAt.Before(cutoff) {
			continue
		}
		items = append(items, replayItem{key: key, seenAt: seenAt})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].seenAt.Equal(items[j].seenAt) {
			return items[i].key < items[j].key
		}
		return items[i].seenAt.After(items[j].seenAt)
	})
	if len(items) > providerRelayUpsertProofReplayMaxEntries {
		items = items[:providerRelayUpsertProofReplayMaxEntries]
	}
	perTokenCounts := make(map[string]int)
	seen := make(map[string]time.Time, len(items))
	for _, item := range items {
		tokenID := item.key
		if cut := strings.IndexByte(tokenID, ':'); cut >= 0 {
			tokenID = tokenID[:cut]
		}
		if tokenID != "" {
			if perTokenCounts[tokenID] >= providerRelayUpsertProofReplayMaxPerToken {
				continue
			}
			perTokenCounts[tokenID]++
		}
		seen[item.key] = item.seenAt
	}
	return seen
}

func (s *Service) providerTokenProofReplayCount() int {
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	return len(s.providerTokenProofSeen)
}

func (s *Service) persistProviderTokenProofReplayLocked(now time.Time) error {
	path := strings.TrimSpace(s.providerTokenProofStoreFile)
	if path == "" {
		return nil
	}
	return persistProviderTokenProofReplayStoreSnapshot(path, now, cloneProviderTokenProofSeen(s.providerTokenProofSeen))
}

func cloneProviderTokenProofSeen(src map[string]time.Time) map[string]time.Time {
	cloned := make(map[string]time.Time, len(src))
	for key, seenAt := range src {
		cloned[key] = seenAt
	}
	return cloned
}

func (s *Service) providerTokenProofReplayMode() string {
	if s.providerTokenProofReplayRedisEnabled() {
		return "redis"
	}
	if s.providerTokenProofSharedFileMode {
		return "shared-file"
	}
	if strings.TrimSpace(s.providerTokenProofStoreFile) != "" {
		return "file"
	}
	return "in-memory"
}

func (s *Service) providerTokenProofReplayRedisEnabled() bool {
	return strings.TrimSpace(s.providerTokenProofRedisAddr) != ""
}

func (s *Service) providerTokenProofReplayRedisKey(tokenID string, nonce string) string {
	prefix := s.providerTokenProofRedisPrefix
	if prefix == "" {
		prefix = providerRelayUpsertProofReplayRedisDefaultPrefix
	}
	return prefix + tokenID + ":" + nonce
}

func (s *Service) providerTokenProofReplayRedisClient() (*redis.Client, error) {
	if !s.providerTokenProofReplayRedisEnabled() {
		return nil, fmt.Errorf("redis replay backend disabled")
	}
	s.providerTokenProofRedisMu.Lock()
	defer s.providerTokenProofRedisMu.Unlock()
	if s.providerTokenProofRedisClient != nil {
		return s.providerTokenProofRedisClient, nil
	}
	dialTimeout := s.providerTokenProofRedisDial
	if dialTimeout <= 0 {
		dialTimeout = providerRelayUpsertProofReplayRedisDefaultDialTimeout
	}
	opts := &redis.Options{
		Addr:         strings.TrimSpace(s.providerTokenProofRedisAddr),
		Password:     s.providerTokenProofRedisPassword,
		DB:           s.providerTokenProofRedisDB,
		DialTimeout:  dialTimeout,
		ReadTimeout:  dialTimeout,
		WriteTimeout: dialTimeout,
	}
	if s.providerTokenProofRedisTLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}
	s.providerTokenProofRedisClient = client
	return client, nil
}

func persistProviderTokenProofReplayStoreSnapshot(path string, now time.Time, seen map[string]time.Time) error {
	snapshot := providerTokenReplayStoreSnapshot{
		Version:     1,
		SavedAtUnix: now.Unix(),
		Seen:        make(map[string]int64, len(seen)),
	}
	for key, seenAt := range seen {
		snapshot.Seen[key] = seenAt.Unix()
	}
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

func isLocalDevelopmentIssuerURL(raw string) bool {
	parsed, err := urlpkg.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	if isLoopbackURLHost(parsed.Host) {
		return true
	}
	host := normalizeHostForCompare(parsed.Hostname())
	return host != "" && (host == "localhost" || strings.HasSuffix(host, ".local"))
}

func (s *Service) buildProviderRelayDescriptor(req proto.ProviderRelayUpsertRequest, claims crypto.CapabilityClaims, now time.Time) (proto.RelayDescriptor, error) {
	role, err := canonicalizeProviderRelayRole(req.Role)
	if err != nil {
		return proto.RelayDescriptor{}, err
	}
	minTier := s.providerTierMinForRole(role)
	if claims.Tier < minTier {
		return proto.RelayDescriptor{}, fmt.Errorf("provider token tier below minimum for role")
	}
	relayID := strings.TrimSpace(req.RelayID)
	if relayID == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider relay_id is required")
	}
	pubKey := normalizePeerPubKey(req.PubKey)
	if pubKey == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider pub_key invalid")
	}
	if err := s.validateProviderTokenCNFBinding(claims, pubKey); err != nil {
		return proto.RelayDescriptor{}, err
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	if endpoint == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider endpoint is required")
	}
	controlURL := normalizeHTTPURL(req.ControlURL)
	if controlURL == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider control_url is required")
	}
	if err := validateProviderControlURL(controlURL, endpoint, s.betaStrict || s.prodStrict); err != nil {
		return proto.RelayDescriptor{}, err
	}
	if err := s.validateProviderTokenProof(req, claims, relayID, role, pubKey, endpoint, controlURL, now); err != nil {
		return proto.RelayDescriptor{}, err
	}
	operatorID := normalizeOperatorID(claims.Subject)
	if operatorID == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider operator id invalid")
	}
	ttl := s.providerRelayMaxTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if req.ValidForSec > 0 {
		requestedTTL := time.Duration(req.ValidForSec) * time.Second
		if requestedTTL < ttl {
			ttl = requestedTTL
		}
	}
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	desc := proto.RelayDescriptor{
		RelayID:        relayID,
		Role:           role,
		OperatorID:     operatorID,
		OriginOperator: operatorID,
		HopCount:       0,
		PubKey:         pubKey,
		Endpoint:       endpoint,
		ControlURL:     controlURL,
		CountryCode:    normalizeCountryCode(req.CountryCode),
		GeoConfidence:  clampScore(req.GeoConfidence),
		Region:         normalizeRegion(req.Region),
		Capabilities:   normalizeCapabilities(req.Capabilities, role),
		HopRoles:       normalizeHopRoles(req.HopRoles),
		ValidUntil:     now.Add(ttl),
	}
	desc.Reputation = clampScore(req.Reputation)
	desc.Uptime = clampScore(req.Uptime)
	desc.Capacity = clampScore(req.Capacity)
	desc.AbusePenalty = clampScore(req.AbusePenalty)
	desc.BondScore = clampScore(req.BondScore)
	desc.StakeScore = clampScore(req.StakeScore)
	if err := validateProviderRelayRuntimeAdmission(desc); err != nil {
		return proto.RelayDescriptor{}, err
	}
	return desc, nil
}

func (s *Service) upsertProviderRelay(desc proto.RelayDescriptor) error {
	role, err := canonicalizeProviderRelayRole(desc.Role)
	if err != nil {
		return err
	}
	desc.Role = role
	if err := validateProviderRelayRuntimeAdmission(desc); err != nil {
		return err
	}
	key := relayKey(desc.RelayID, desc.Role)
	desc.Signature = ""
	s.providerMu.Lock()
	defer s.providerMu.Unlock()
	if s.providerRelays == nil {
		s.providerRelays = make(map[string]proto.RelayDescriptor)
	}
	prev, ok := s.providerRelays[key]
	if ok {
		prevOperatorID := normalizeOperatorID(prev.OperatorID)
		nextOperatorID := normalizeOperatorID(desc.OperatorID)
		if prevOperatorID != "" && prevOperatorID != nextOperatorID {
			return fmt.Errorf("%w: relay_id=%s role=%s existing_operator=%s requested_operator=%s", errProviderRelayOwnershipConflict, desc.RelayID, desc.Role, prevOperatorID, nextOperatorID)
		}
	}
	maxPerOperator := s.effectiveProviderMaxRelaysPerOperator()
	if maxPerOperator > 0 {
		count := s.providerRelayCountByOperatorLocked(desc.OperatorID)
		if !ok && count >= maxPerOperator {
			return fmt.Errorf("provider operator relay limit reached")
		}
	}
	if ok && prev.ValidUntil.After(desc.ValidUntil) {
		desc.ValidUntil = prev.ValidUntil
	}
	if err := s.enforceProviderSplitRolesLocked(key, desc); err != nil {
		return err
	}
	s.providerRelays[key] = desc
	return nil
}

func (s *Service) enforceProviderSplitRolesLocked(relayKey string, desc proto.RelayDescriptor) error {
	if !s.providerSplitRoles {
		return nil
	}
	operatorID := normalizeOperatorID(desc.OperatorID)
	if operatorID == "" {
		return nil
	}
	for key, existing := range s.providerRelays {
		if key == relayKey {
			continue
		}
		if normalizeOperatorID(existing.OperatorID) != operatorID {
			continue
		}
		if strings.TrimSpace(existing.Role) == strings.TrimSpace(desc.Role) {
			continue
		}
		return fmt.Errorf("provider split-role policy violation")
	}
	return nil
}

func (s *Service) effectiveProviderMinEntryTier() int {
	return clampProviderTier(s.providerMinEntryTier)
}

func (s *Service) effectiveProviderMinExitTier() int {
	return clampProviderTier(s.providerMinExitTier)
}

func (s *Service) effectiveProviderMaxRelaysPerOperator() int {
	if s.providerMaxPerOperator > 0 {
		return s.providerMaxPerOperator
	}
	return 0
}

func (s *Service) providerTierMinForRole(role string) int {
	role = strings.TrimSpace(strings.ToLower(role))
	if role == "exit" {
		return s.effectiveProviderMinExitTier()
	}
	return s.effectiveProviderMinEntryTier()
}

func (s *Service) providerRelayCountByOperatorLocked(operatorID string) int {
	operatorID = normalizeOperatorID(operatorID)
	if operatorID == "" || len(s.providerRelays) == 0 {
		return 0
	}
	count := 0
	for _, desc := range s.providerRelays {
		if normalizeOperatorID(desc.OperatorID) == operatorID {
			count++
		}
	}
	return count
}

func (s *Service) isKnownPeer(peerURL string) bool {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return false
	}
	for _, known := range s.snapshotKnownPeers(time.Now()) {
		if known == peerURL {
			return true
		}
	}
	return false
}

func (s *Service) ingestGossipPeerRelays(relays []proto.RelayDescriptor) int {
	if len(relays) == 0 {
		return 0
	}
	imported := 0
	s.peerMu.Lock()
	if s.peerRelays == nil {
		s.peerRelays = make(map[string]proto.RelayDescriptor)
	}
	for _, desc := range relays {
		key := relayKey(desc.RelayID, desc.Role)
		prev, ok := s.peerRelays[key]
		if ok && prev.ValidUntil.After(desc.ValidUntil) {
			continue
		}
		s.peerRelays[key] = desc
		imported++
	}
	s.peerMu.Unlock()
	return imported
}

func (s *Service) buildRelayDescriptors(now time.Time) []proto.RelayDescriptor {
	pub, _ := s.currentKeypair()
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	ttl := s.descriptorTTL
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	entryRelayID := valueWithDefault("ENTRY_RELAY_ID", "entry-local-1")
	exitRelayID := valueWithDefault("EXIT_RELAY_ID", "exit-local-1")
	entryRegion := valueWithDefault("ENTRY_REGION", "local")
	exitRegion := valueWithDefault("EXIT_REGION", "local")
	entryCountry := countryCodeWithDefault("ENTRY_COUNTRY_CODE", "ZZ")
	exitCountry := countryCodeWithDefault("EXIT_COUNTRY_CODE", "ZZ")
	entryGeoConfidence := scoreWithDefault("ENTRY_GEO_CONFIDENCE", 1)
	exitGeoConfidence := scoreWithDefault("EXIT_GEO_CONFIDENCE", 1)
	defaultOperator := s.operatorID
	entryOperator := operatorIDWithDefault("ENTRY_OPERATOR_ID", defaultOperator)
	exitOperator := operatorIDWithDefault("EXIT_OPERATOR_ID", defaultOperator)
	exitReputation := scoreWithDefault("EXIT_REPUTATION_SCORE", 0)
	exitUptime := scoreWithDefault("EXIT_UPTIME_SCORE", 0)
	exitCapacity := scoreWithDefault("EXIT_CAPACITY_SCORE", 0)
	exitAbusePenalty := scoreWithDefault("EXIT_ABUSE_PENALTY", 0)
	exitBondScore := scoreWithDefault("EXIT_BOND_SCORE", 0)
	exitStakeScore := scoreWithDefault("EXIT_STAKE_SCORE", 0)

	local := []proto.RelayDescriptor{
		{
			RelayID:        entryRelayID,
			Role:           "entry",
			OperatorID:     entryOperator,
			OriginOperator: entryOperator,
			HopCount:       0,
			PubKey:         pubB64,
			Endpoint:       s.pickEntryEndpoint(now),
			ControlURL:     endpointWithDefault("ENTRY_URL", "http://127.0.0.1:8083"),
			CountryCode:    entryCountry,
			GeoConfidence:  entryGeoConfidence,
			Region:         entryRegion,
			Capabilities:   []string{"wg", "two-hop"},
			ValidUntil:     now.Add(ttl),
		},
		{
			RelayID:        exitRelayID,
			Role:           "exit",
			OperatorID:     exitOperator,
			OriginOperator: exitOperator,
			HopCount:       0,
			PubKey:         pubB64,
			Endpoint:       endpointWithDefault("EXIT_ENDPOINT", "127.0.0.1:51821"),
			ControlURL:     endpointWithDefault("EXIT_CONTROL_URL", "http://127.0.0.1:8084"),
			CountryCode:    exitCountry,
			GeoConfidence:  exitGeoConfidence,
			Region:         exitRegion,
			Reputation:     exitReputation,
			Uptime:         exitUptime,
			Capacity:       exitCapacity,
			AbusePenalty:   exitAbusePenalty,
			BondScore:      exitBondScore,
			StakeScore:     exitStakeScore,
			Capabilities:   []string{"wg", "tiered-policy"},
			ValidUntil:     now.Add(ttl),
		},
	}
	providers := s.snapshotProviderRelays(now)
	peers := s.snapshotPeerRelays()
	merged := make([]proto.RelayDescriptor, 0, len(local)+len(providers)+len(peers))
	seen := make(map[string]struct{}, len(local))
	for _, desc := range local {
		key := relayKey(desc.RelayID, desc.Role)
		seen[key] = struct{}{}
		merged = append(merged, desc)
	}
	for _, desc := range providers {
		key := relayKey(desc.RelayID, desc.Role)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, desc)
	}
	for _, desc := range peers {
		key := relayKey(desc.RelayID, desc.Role)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, desc)
	}
	peerScores := s.snapshotPeerScores()
	peerTrust := s.snapshotPeerTrust()
	issuerTrust := s.snapshotIssuerTrust()
	nowUnix := now.Unix()
	actuated := make([]proto.RelayDescriptor, 0, len(merged))
	for _, desc := range merged {
		if role, ok := canonicalizeSignalRole(desc.Role); ok && role == "micro-relay" {
			desc.Role = role
			if !s.microRelayEligibleForPublication(desc, nowUnix, peerScores, peerTrust, issuerTrust) {
				continue
			}
		}
		actuated = append(actuated, desc)
	}
	return actuated
}

func (s *Service) microRelayEligibleForPublication(
	desc proto.RelayDescriptor,
	nowUnix int64,
	peerScores map[string]proto.RelaySelectionScore,
	peerTrust map[string]proto.RelayTrustAttestation,
	issuerTrust map[string]proto.RelayTrustAttestation,
) bool {
	relayID := strings.TrimSpace(desc.RelayID)
	if relayID == "" {
		return false
	}
	if normalizeOperatorID(desc.OperatorID) == "" {
		return false
	}
	key := relayKey(relayID, "micro-relay")
	localScore := proto.RelaySelectionScore{
		RelayID:      relayID,
		Role:         "micro-relay",
		Reputation:   desc.Reputation,
		Uptime:       desc.Uptime,
		Capacity:     desc.Capacity,
		AbusePenalty: desc.AbusePenalty,
	}
	if !microRelayScoreEligible(localScore) {
		return false
	}
	if score, ok := peerScores[key]; ok && !microRelayScoreEligible(score) {
		return false
	}
	if att, ok := peerTrust[key]; ok {
		if _, _, disputed := s.activeDispute(att, nowUnix); disputed {
			return false
		}
	}
	if att, ok := issuerTrust[key]; ok {
		if _, _, disputed := s.activeDispute(att, nowUnix); disputed {
			return false
		}
	}
	return true
}

func microRelayScoreEligible(score proto.RelaySelectionScore) bool {
	if score.Reputation < microRelayMinReputationScore {
		return false
	}
	if score.Uptime < microRelayMinUptimeScore {
		return false
	}
	if score.Capacity < microRelayMinCapacityScore {
		return false
	}
	if score.AbusePenalty > microRelayMaxAbusePenalty {
		return false
	}
	return true
}

func (s *Service) buildSelectionScores(relays []proto.RelayDescriptor) []proto.RelaySelectionScore {
	type scoreAgg struct {
		relayID      string
		role         string
		count        int
		reputation   float64
		uptime       float64
		capacity     float64
		abusePenalty float64
		bondScore    float64
		stakeScore   float64
	}
	agg := make(map[string]scoreAgg)
	add := func(score proto.RelaySelectionScore) {
		role, ok := canonicalizeSignalRole(score.Role)
		if !ok || strings.TrimSpace(score.RelayID) == "" {
			return
		}
		score.Role = role
		key := relayKey(score.RelayID, role)
		a := agg[key]
		a.relayID = score.RelayID
		a.role = role
		a.count++
		a.reputation += clampScore(score.Reputation)
		a.uptime += clampScore(score.Uptime)
		a.capacity += clampScore(score.Capacity)
		a.abusePenalty += clampScore(score.AbusePenalty)
		a.bondScore += clampScore(score.BondScore)
		a.stakeScore += clampScore(score.StakeScore)
		agg[key] = a
	}

	for _, relayDesc := range relays {
		role, ok := canonicalizeSignalRole(relayDesc.Role)
		if !ok {
			continue
		}
		add(proto.RelaySelectionScore{
			RelayID:      relayDesc.RelayID,
			Role:         role,
			Reputation:   relayDesc.Reputation,
			Uptime:       relayDesc.Uptime,
			Capacity:     relayDesc.Capacity,
			AbusePenalty: relayDesc.AbusePenalty,
			BondScore:    relayDesc.BondScore,
			StakeScore:   relayDesc.StakeScore,
		})
	}
	for _, score := range s.snapshotPeerScores() {
		add(score)
	}
	nowUnix := time.Now().Unix()
	disputeMaxUntil := s.maxDisputeUntil(nowUnix)
	appealMaxUntil := s.maxAppealUntil(nowUnix)
	for _, att := range s.buildTrustAttestations(relays) {
		add(selectionFromTrustAttestationCapped(att, nowUnix, disputeMaxUntil, appealMaxUntil))
	}

	keys := make([]string, 0, len(agg))
	for key := range agg {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]proto.RelaySelectionScore, 0, len(keys))
	for _, key := range keys {
		a := agg[key]
		if a.count <= 0 {
			continue
		}
		n := float64(a.count)
		out = append(out, proto.RelaySelectionScore{
			RelayID:      a.relayID,
			Role:         a.role,
			Reputation:   clampScore(a.reputation / n),
			Uptime:       clampScore(a.uptime / n),
			Capacity:     clampScore(a.capacity / n),
			AbusePenalty: clampScore(a.abusePenalty / n),
			BondScore:    clampScore(a.bondScore / n),
			StakeScore:   clampScore(a.stakeScore / n),
		})
	}
	return out
}

func (s *Service) buildTrustAttestations(relays []proto.RelayDescriptor) []proto.RelayTrustAttestation {
	type trustAgg struct {
		relayID      string
		role         string
		operatorID   string
		count        int
		reputation   float64
		uptime       float64
		capacity     float64
		abusePenalty float64
		bondScore    float64
		stakeScore   float64
		confidence   float64
		disputeVotes int
		disputeOps   map[string]struct{}
		disputeCaps  map[int]int
		disputeUntil []int64
		disputeMeta  map[adjudicationMetadataPair]int
		disputeSrcs  map[string]struct{}
		appealVotes  int
		appealOps    map[string]struct{}
		appealUntil  []int64
		appealMeta   map[adjudicationMetadataPair]int
		appealSrcs   map[string]struct{}
	}
	agg := make(map[string]trustAgg)
	nowUnix := time.Now().Unix()
	metaMinVotes := maxInt(1, s.adjudicationMetaMin)
	disputeMinVotes := s.effectiveFinalDisputeMinVotes()
	appealMinVotes := s.effectiveFinalAppealMinVotes()
	adjudicationMinOperators := s.effectiveFinalAdjudicationMinOperators()
	adjudicationMinSources := s.effectiveFinalAdjudicationMinSources()
	adjudicationMinRatio := s.effectiveFinalAdjudicationMinRatio()
	add := func(att proto.RelayTrustAttestation, sourceClass string) {
		role, ok := canonicalizeSignalRole(att.Role)
		if !ok || strings.TrimSpace(att.RelayID) == "" {
			return
		}
		att.Role = role
		key := relayKey(att.RelayID, role)
		a := agg[key]
		a.relayID = att.RelayID
		a.role = role
		attOperator := normalizeOperatorID(att.OperatorID)
		if attOperator != "" {
			a.operatorID = attOperator
		}
		voteOperator := attOperator
		if voteOperator == "" {
			voteOperator = "operator-unknown"
		}
		a.count++
		a.reputation += clampScore(att.Reputation)
		a.uptime += clampScore(att.Uptime)
		a.capacity += clampScore(att.Capacity)
		a.abusePenalty += clampScore(att.AbusePenalty)
		a.bondScore += clampScore(att.BondScore)
		a.stakeScore += clampScore(att.StakeScore)
		a.confidence += clampScore(att.Confidence)
		if capTier, until, ok := s.activeDispute(att, nowUnix); ok {
			a.disputeVotes++
			if a.disputeOps == nil {
				a.disputeOps = make(map[string]struct{})
			}
			a.disputeOps[voteOperator] = struct{}{}
			if a.disputeSrcs == nil {
				a.disputeSrcs = make(map[string]struct{})
			}
			a.disputeSrcs[sourceClass] = struct{}{}
			if a.disputeCaps == nil {
				a.disputeCaps = make(map[int]int)
			}
			a.disputeCaps[capTier]++
			a.disputeUntil = append(a.disputeUntil, until)
			recordMetadataPairVote(&a.disputeMeta, att.DisputeCase, att.DisputeRef)
		}
		if appealUntil, ok := s.activeAppeal(att, nowUnix); ok {
			a.appealVotes++
			if a.appealOps == nil {
				a.appealOps = make(map[string]struct{})
			}
			a.appealOps[voteOperator] = struct{}{}
			if a.appealSrcs == nil {
				a.appealSrcs = make(map[string]struct{})
			}
			a.appealSrcs[sourceClass] = struct{}{}
			a.appealUntil = append(a.appealUntil, appealUntil)
			recordMetadataPairVote(&a.appealMeta, att.AppealCase, att.AppealRef)
		}
		agg[key] = a
	}

	for _, relayDesc := range relays {
		role, ok := canonicalizeSignalRole(relayDesc.Role)
		if !ok {
			continue
		}
		add(proto.RelayTrustAttestation{
			RelayID:      relayDesc.RelayID,
			Role:         role,
			OperatorID:   relayDesc.OperatorID,
			Reputation:   relayDesc.Reputation,
			Uptime:       relayDesc.Uptime,
			Capacity:     relayDesc.Capacity,
			AbusePenalty: relayDesc.AbusePenalty,
			BondScore:    relayDesc.BondScore,
			StakeScore:   relayDesc.StakeScore,
			Confidence:   1,
		}, "descriptor")
	}
	for _, att := range s.snapshotPeerTrust() {
		add(att, "peer")
	}
	for _, att := range s.snapshotIssuerTrust() {
		add(att, "issuer")
	}

	keys := make([]string, 0, len(agg))
	for key := range agg {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]proto.RelayTrustAttestation, 0, len(keys))
	for _, key := range keys {
		a := agg[key]
		if a.count <= 0 {
			continue
		}
		n := float64(a.count)
		att := proto.RelayTrustAttestation{
			RelayID:      a.relayID,
			Role:         a.role,
			OperatorID:   a.operatorID,
			Reputation:   clampScore(a.reputation / n),
			Uptime:       clampScore(a.uptime / n),
			Capacity:     clampScore(a.capacity / n),
			AbusePenalty: clampScore(a.abusePenalty / n),
			BondScore:    clampScore(a.bondScore / n),
			StakeScore:   clampScore(a.stakeScore / n),
			Confidence:   clampScore(a.confidence / n),
		}
		if meetsAdjudicationQuorum(a.disputeVotes, a.count, disputeMinVotes, adjudicationMinRatio) &&
			len(a.disputeOps) >= adjudicationMinOperators &&
			len(a.disputeSrcs) >= adjudicationMinSources {
			if tierCap, ok := pickConsensusTier(a.disputeCaps); ok {
				att.TierCap = tierCap
				att.DisputeUntil = pickMedianUnix(a.disputeUntil)
				att.DisputeCase, att.DisputeRef = pickVotedMetadataPair(a.disputeMeta, metaMinVotes)
			}
		}
		if meetsAdjudicationQuorum(a.appealVotes, a.count, appealMinVotes, adjudicationMinRatio) &&
			len(a.appealOps) >= adjudicationMinOperators &&
			len(a.appealSrcs) >= adjudicationMinSources {
			att.AppealUntil = pickMedianUnix(a.appealUntil)
			att.AppealCase, att.AppealRef = pickVotedMetadataPair(a.appealMeta, metaMinVotes)
		}
		out = append(out, att)
	}
	return out
}

func (s *Service) snapshotPeerRelays() []proto.RelayDescriptor {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	out := make([]proto.RelayDescriptor, 0, len(s.peerRelays))
	for _, desc := range s.peerRelays {
		out = append(out, desc)
	}
	sort.Slice(out, func(i, j int) bool {
		ik := relayKey(out[i].RelayID, out[i].Role)
		jk := relayKey(out[j].RelayID, out[j].Role)
		return ik < jk
	})
	return out
}

func (s *Service) snapshotProviderRelays(now time.Time) []proto.RelayDescriptor {
	nowUnix := now.Unix()
	s.providerMu.Lock()
	defer s.providerMu.Unlock()
	if len(s.providerRelays) == 0 {
		return nil
	}
	out := make([]proto.RelayDescriptor, 0, len(s.providerRelays))
	for key, desc := range s.providerRelays {
		if !desc.ValidUntil.IsZero() && nowUnix >= desc.ValidUntil.Unix() {
			delete(s.providerRelays, key)
			continue
		}
		out = append(out, desc)
	}
	sort.Slice(out, func(i, j int) bool {
		ik := relayKey(out[i].RelayID, out[i].Role)
		jk := relayKey(out[j].RelayID, out[j].Role)
		return ik < jk
	})
	return out
}

func (s *Service) snapshotPeerScores() map[string]proto.RelaySelectionScore {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return cloneSelectionScores(s.peerScores)
}

func (s *Service) snapshotPeerTrust() map[string]proto.RelayTrustAttestation {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return cloneTrustAttestations(s.peerTrust)
}

func (s *Service) snapshotIssuerTrust() map[string]proto.RelayTrustAttestation {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return cloneTrustAttestations(s.issuerTrust)
}

func (s *Service) pickEntryEndpoint(now time.Time) string {
	if len(s.entryEndpoints) == 0 {
		return endpointWithDefault("ENTRY_ENDPOINT", "127.0.0.1:51820")
	}
	if len(s.entryEndpoints) == 1 {
		return s.entryEndpoints[0]
	}
	if s.endpointRotateSec <= 0 {
		return s.entryEndpoints[0]
	}
	slot := now.Unix() / s.endpointRotateSec
	idx := int(slot % int64(len(s.entryEndpoints)))
	return s.entryEndpoints[idx]
}

func endpointWithDefault(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func valueWithDefault(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func envPositiveDurationSeconds(key string) (time.Duration, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func defaultSignalFreshnessMaxAge(syncSec int, floor time.Duration, feedTTLs ...time.Duration) time.Duration {
	base := time.Duration(syncSec) * time.Second
	for _, ttl := range feedTTLs {
		if ttl > base {
			base = ttl
		}
	}
	if base <= 0 {
		base = time.Second
	}
	maxAge := time.Duration(defaultSignalFreshnessMultiplier) * base
	if maxAge < floor {
		maxAge = floor
	}
	return maxAge
}

func defaultPeerSignalFreshnessMaxAge(peerSyncSec int, selectionFeedTTL, trustFeedTTL time.Duration) time.Duration {
	return defaultSignalFreshnessMaxAge(peerSyncSec, defaultSignalFreshnessFloor, selectionFeedTTL, trustFeedTTL)
}

func defaultIssuerSignalFreshnessMaxAge(issuerSyncSec int, trustFeedTTL time.Duration) time.Duration {
	return defaultSignalFreshnessMaxAge(issuerSyncSec, defaultSignalFreshnessFloor, trustFeedTTL)
}

func (s *Service) effectivePeerSignalFreshnessMaxAge() time.Duration {
	if s.peerSignalFreshnessMaxAge > 0 {
		return s.peerSignalFreshnessMaxAge
	}
	return defaultPeerSignalFreshnessMaxAge(s.peerSyncSec, s.selectionFeedTTL, s.trustFeedTTL)
}

func (s *Service) effectiveIssuerSignalFreshnessMaxAge() time.Duration {
	if s.issuerSignalFreshnessMaxAge > 0 {
		return s.issuerSignalFreshnessMaxAge
	}
	return defaultIssuerSignalFreshnessMaxAge(s.issuerSyncSec, s.trustFeedTTL)
}

func evaluateSignalCacheFreshness(lastFreshAt *time.Time, now time.Time, maxAge time.Duration) (stale bool, age time.Duration, initialized bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if lastFreshAt == nil {
		return false, 0, false
	}
	if lastFreshAt.IsZero() {
		*lastFreshAt = now
		return false, 0, true
	}
	age = now.Sub(*lastFreshAt)
	if age < 0 {
		age = 0
	}
	if maxAge > 0 && age > maxAge {
		return true, age, false
	}
	return false, age, false
}

func (s *Service) dropStalePeerSignalCacheOnSyncFailure(now time.Time, scoreSignalSources int, scoreMinVotes int, trustSignalSources int, trustMinVotes int) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	peerSignalMaxAge := s.effectivePeerSignalFreshnessMaxAge()
	peerSignalMaxAgeSec := int64(peerSignalMaxAge / time.Second)
	var scoreCacheAgeSec int64
	var trustCacheAgeSec int64
	scoreCacheTimestampInitialized := false
	trustCacheTimestampInitialized := false
	staleCachedScoresDropped := false
	staleCachedTrustDropped := false

	s.peerMu.Lock()
	if len(s.peerScores) > 0 {
		stale, age, initialized := evaluateSignalCacheFreshness(&s.peerScoreLastFreshAt, now, peerSignalMaxAge)
		scoreCacheTimestampInitialized = initialized
		scoreCacheAgeSec = int64(age / time.Second)
		if stale {
			s.peerScores = make(map[string]proto.RelaySelectionScore)
			s.peerScoreLastFreshAt = time.Time{}
			staleCachedScoresDropped = true
		}
	} else {
		s.peerScoreLastFreshAt = time.Time{}
	}
	if len(s.peerTrust) > 0 {
		stale, age, initialized := evaluateSignalCacheFreshness(&s.peerTrustLastFreshAt, now, peerSignalMaxAge)
		trustCacheTimestampInitialized = initialized
		trustCacheAgeSec = int64(age / time.Second)
		if stale {
			s.peerTrust = make(map[string]proto.RelayTrustAttestation)
			s.peerTrustLastFreshAt = time.Time{}
			staleCachedTrustDropped = true
		}
	} else {
		s.peerTrustLastFreshAt = time.Time{}
	}
	s.peerMu.Unlock()

	if scoreCacheTimestampInitialized {
		log.Printf(
			"directory peer score sync: initialized cached score freshness timestamp on quorum failure (max_age_sec=%d)",
			peerSignalMaxAgeSec,
		)
	}
	if staleCachedScoresDropped {
		log.Printf(
			"directory peer score sync: dropping stale cached scores on quorum failure (sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
			scoreSignalSources,
			scoreMinVotes,
			scoreCacheAgeSec,
			peerSignalMaxAgeSec,
		)
	}
	if trustCacheTimestampInitialized {
		log.Printf(
			"directory peer trust sync: initialized cached trust freshness timestamp on quorum failure (max_age_sec=%d)",
			peerSignalMaxAgeSec,
		)
	}
	if staleCachedTrustDropped {
		log.Printf(
			"directory peer trust sync: dropping stale cached trust attestations on quorum failure (sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
			trustSignalSources,
			trustMinVotes,
			trustCacheAgeSec,
			peerSignalMaxAgeSec,
		)
	}
}

func (s *Service) dropStaleIssuerTrustCacheOnSyncFailure(now time.Time, trustSignalSources int, trustMinVotes int) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	issuerSignalMaxAge := s.effectiveIssuerSignalFreshnessMaxAge()
	issuerSignalMaxAgeSec := int64(issuerSignalMaxAge / time.Second)
	var issuerCacheAgeSec int64
	issuerCacheTimestampInitialized := false
	staleIssuerCacheDropped := false

	s.peerMu.Lock()
	if len(s.issuerTrust) > 0 {
		stale, age, initialized := evaluateSignalCacheFreshness(&s.issuerTrustLastFreshAt, now, issuerSignalMaxAge)
		issuerCacheTimestampInitialized = initialized
		issuerCacheAgeSec = int64(age / time.Second)
		if stale {
			s.issuerTrust = make(map[string]proto.RelayTrustAttestation)
			s.issuerTrustLastFreshAt = time.Time{}
			staleIssuerCacheDropped = true
		}
	} else {
		s.issuerTrustLastFreshAt = time.Time{}
	}
	s.peerMu.Unlock()

	if issuerCacheTimestampInitialized {
		log.Printf(
			"directory issuer trust sync: initialized cached trust freshness timestamp on quorum failure (max_age_sec=%d)",
			issuerSignalMaxAgeSec,
		)
	}
	if staleIssuerCacheDropped {
		log.Printf(
			"directory issuer trust sync: dropping stale cached trust attestations on quorum failure (sources=%d required=%d cache_age_sec=%d max_age_sec=%d)",
			trustSignalSources,
			trustMinVotes,
			issuerCacheAgeSec,
			issuerSignalMaxAgeSec,
		)
	}
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func parseDNSSeeds(seeds []string) []string {
	if len(seeds) == 0 {
		return nil
	}
	out := make([]string, 0, len(seeds))
	seen := make(map[string]struct{}, len(seeds))
	for _, seed := range seeds {
		seed = strings.ToLower(strings.TrimSpace(seed))
		seed = strings.TrimSuffix(seed, ".")
		if seed == "" {
			continue
		}
		if strings.Contains(seed, "/") || strings.Contains(seed, "://") {
			continue
		}
		if _, ok := seen[seed]; ok {
			continue
		}
		seen[seed] = struct{}{}
		out = append(out, seed)
	}
	return out
}

func normalizePeerURL(raw string) string {
	v := normalizeHTTPURL(raw)
	return strings.TrimRight(v, "/")
}

func normalizePeerURLs(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		v := normalizePeerURL(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizePeerHints(peers []string, hints []proto.DirectoryPeerHint) []proto.DirectoryPeerHint {
	out := make([]proto.DirectoryPeerHint, 0, len(peers)+len(hints))
	seen := make(map[string]int, len(peers)+len(hints))
	appendHint := func(h proto.DirectoryPeerHint) {
		url := normalizePeerURL(h.URL)
		if url == "" {
			return
		}
		h.URL = url
		h.Operator = normalizeOperatorID(h.Operator)
		h.PubKey = normalizePeerPubKey(h.PubKey)
		if idx, ok := seen[url]; ok {
			if out[idx].Operator == "" && h.Operator != "" {
				out[idx].Operator = h.Operator
			}
			if out[idx].PubKey == "" && h.PubKey != "" {
				out[idx].PubKey = h.PubKey
			}
			return
		}
		seen[url] = len(out)
		out = append(out, h)
	}
	for _, peerURL := range peers {
		appendHint(proto.DirectoryPeerHint{URL: peerURL})
	}
	for _, hint := range hints {
		appendHint(hint)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].URL < out[j].URL
	})
	return out
}

func joinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
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
	parsed, err := urlpkg.Parse(v)
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
	raw := strings.TrimSpace(os.Getenv("DIRECTORY_REQUIRE_HTTPS_CONTROL_URL"))
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
	raw := strings.TrimSpace(os.Getenv("DIRECTORY_ALLOW_INSECURE_CONTROL_URL_HTTP"))
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

func validateProviderControlURL(controlURL, endpoint string, strict bool) error {
	parsed, err := urlpkg.Parse(controlURL)
	if err != nil {
		return fmt.Errorf("provider control_url invalid")
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("provider control_url invalid")
	}
	if strict && scheme != "https" {
		return fmt.Errorf("provider control_url must use https in strict mode")
	}
	controlHost := normalizeHostForCompare(parsed.Hostname())
	if controlHost == "" {
		return fmt.Errorf("provider control_url host is required")
	}
	if strict && isDisallowedStrictControlHost(controlHost) {
		return fmt.Errorf("provider control_url host is not allowed")
	}
	endpointHost := hostFromEndpoint(endpoint)
	if endpointHost == "" {
		return fmt.Errorf("provider endpoint host is invalid")
	}
	if !strings.EqualFold(endpointHost, controlHost) {
		return fmt.Errorf("provider control_url host must match endpoint host")
	}
	return nil
}

func hostFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	if hasZoneIdentifierHost(host) {
		return ""
	}
	return normalizeHostForCompare(host)
}

func normalizeHostForCompare(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	return strings.TrimRight(normalized, ".")
}

func hasZoneIdentifierHost(host string) bool {
	normalized := strings.TrimSpace(strings.Trim(host, "[]"))
	return strings.Contains(normalized, "%")
}

func isAmbiguousNumericHostAlias(host string) bool {
	host = normalizeHostForCompare(host)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	decimalOrDotted := true
	for _, ch := range host {
		if (ch < '0' || ch > '9') && ch != '.' {
			decimalOrDotted = false
			break
		}
	}
	if decimalOrDotted {
		return true
	}
	if strings.HasPrefix(host, "0x") {
		hexPart := strings.TrimPrefix(host, "0x")
		if hexPart == "" {
			return false
		}
		for _, ch := range hexPart {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return false
			}
		}
		return true
	}
	return false
}

func isDisallowedStrictControlHost(host string) bool {
	if hasZoneIdentifierHost(host) {
		return true
	}
	host = normalizeHostForCompare(host)
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if isAmbiguousNumericHostAlias(host) {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
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

func relayKey(relayID, role string) string {
	return relayID + "|" + role
}

func splitRelayKey(v string) (string, string, bool) {
	relayID, role, ok := strings.Cut(v, "|")
	relayID = strings.TrimSpace(relayID)
	role = strings.TrimSpace(role)
	if !ok || relayID == "" {
		return "", "", false
	}
	if role == "" {
		role = "exit"
	}
	return relayID, role, true
}

func verifyRelayDescriptorAny(desc proto.RelayDescriptor, pubs []ed25519.PublicKey) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no peer pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelayDescriptor(desc, pub); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("descriptor signature verification failed")
	}
	return lastErr
}

func verifyRelaySelectionFeedAny(feed proto.RelaySelectionFeedResponse, pubs []ed25519.PublicKey, now time.Time) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no peer pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelaySelectionFeed(feed, pub, now); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("selection feed signature verification failed")
	}
	return lastErr
}

func verifyRelayTrustFeedAny(feed proto.RelayTrustAttestationFeedResponse, pubs []ed25519.PublicKey, now time.Time) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no peer pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("trust feed signature verification failed")
	}
	return lastErr
}

func verifyDirectoryPeerListAny(feed proto.DirectoryPeerListResponse, pubs []ed25519.PublicKey, now time.Time) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no peer pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := verifyDirectoryPeerList(feed, pub, now); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("peer list signature verification failed")
	}
	return lastErr
}

func keyDerivedSourceOperator(pubKeys []ed25519.PublicKey) string {
	if len(pubKeys) == 0 {
		return ""
	}
	keys := make([]string, 0, len(pubKeys))
	seen := make(map[string]struct{}, len(pubKeys))
	for _, pub := range pubKeys {
		if len(pub) != ed25519.PublicKeySize {
			continue
		}
		key := base64.RawURLEncoding.EncodeToString(pub)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return "key:" + keys[0]
}

func sourceOperatorHintAnchoredByPubKey(sourceURL string, pubKeys []ed25519.PublicKey, hintOperator string, hintPubKey string) bool {
	sourceURL = normalizePeerURL(sourceURL)
	hintOperator = normalizeOperatorID(hintOperator)
	hintPubKey = normalizePeerPubKey(hintPubKey)
	if sourceURL == "" || hintOperator == "" || hintPubKey == "" || len(pubKeys) == 0 {
		return false
	}
	for _, pub := range pubKeys {
		if len(pub) != ed25519.PublicKeySize {
			continue
		}
		if base64.RawURLEncoding.EncodeToString(pub) == hintPubKey {
			return true
		}
	}
	return false
}

func (s *Service) resolveQuorumSourceOperator(sourceURL string, declaredOperator string, pubKeys []ed25519.PublicKey) string {
	sourceURL = normalizePeerURL(sourceURL)
	declaredOperator = normalizeOperatorID(declaredOperator)
	hintOperator := s.peerHintOperator(sourceURL)
	hintPubKey := s.peerHintPubKey(sourceURL)
	if sourceOperatorHintAnchoredByPubKey(sourceURL, pubKeys, hintOperator, hintPubKey) {
		return hintOperator
	}
	if declaredOperator != "" {
		if hintOperator != "" || hintPubKey != "" {
			log.Printf("directory ignored unverified declared source operator=%q for %s (signed hint not anchored)", declaredOperator, sourceURL)
		}
	}
	if keySource := keyDerivedSourceOperator(pubKeys); keySource != "" {
		return keySource
	}
	return normalizeSourceOperator("", pubKeys, sourceURL)
}

func normalizeSourceOperator(operator string, pubKeys []ed25519.PublicKey, sourceURL string) string {
	operator = normalizeOperatorID(operator)
	if operator != "" {
		return operator
	}
	for _, pub := range pubKeys {
		if len(pub) != ed25519.PublicKeySize {
			continue
		}
		return "key:" + base64.RawURLEncoding.EncodeToString(pub)
	}
	sourceURL = normalizePeerURL(sourceURL)
	if sourceURL != "" {
		return "url:" + sourceURL
	}
	return "operator-unknown"
}

func markCandidateVoter(voters map[string]map[string]struct{}, candidateKey string, operator string) bool {
	candidateKey = strings.TrimSpace(candidateKey)
	operator = strings.TrimSpace(operator)
	if candidateKey == "" || operator == "" {
		return false
	}
	ops, ok := voters[candidateKey]
	if !ok {
		ops = make(map[string]struct{})
		voters[candidateKey] = ops
	}
	if _, exists := ops[operator]; exists {
		return false
	}
	ops[operator] = struct{}{}
	return true
}

func markVariantVoter(voters map[string]map[string]map[string]struct{}, candidateKey string, variant string, operator string) bool {
	candidateKey = strings.TrimSpace(candidateKey)
	variant = strings.TrimSpace(variant)
	operator = strings.TrimSpace(operator)
	if candidateKey == "" || variant == "" || operator == "" {
		return false
	}
	variantVoters, ok := voters[candidateKey]
	if !ok {
		variantVoters = make(map[string]map[string]struct{})
		voters[candidateKey] = variantVoters
	}
	ops, ok := variantVoters[variant]
	if !ok {
		ops = make(map[string]struct{})
		variantVoters[variant] = ops
	}
	if _, exists := ops[operator]; exists {
		return false
	}
	ops[operator] = struct{}{}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func peerDescriptorFingerprint(desc proto.RelayDescriptor) (string, error) {
	clone := desc
	clone.Signature = ""
	clone.ValidUntil = time.Time{}
	// Keep descriptor variant quorum stable when operators publish role-agnostic
	// quality scores. These scores have dedicated consensus in selection feeds.
	clone.Reputation = 0
	clone.Uptime = 0
	clone.Capacity = 0
	clone.AbusePenalty = 0
	clone.BondScore = 0
	clone.StakeScore = 0
	caps := append([]string(nil), clone.Capabilities...)
	sort.Strings(caps)
	clone.Capabilities = caps
	hopRoles := append([]string(nil), clone.HopRoles...)
	sort.Strings(hopRoles)
	clone.HopRoles = hopRoles
	b, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func signDirectoryPeerList(feed proto.DirectoryPeerListResponse, priv ed25519.PrivateKey) (string, error) {
	if len(priv) == 0 {
		return "", fmt.Errorf("missing directory private key")
	}
	unsigned := feed
	unsigned.Signature = ""
	b, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, b)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func verifyDirectoryPeerList(feed proto.DirectoryPeerListResponse, pub ed25519.PublicKey, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid peer pubkey")
	}
	if strings.TrimSpace(feed.Signature) == "" {
		return fmt.Errorf("missing peer list signature")
	}
	nowUnix := now.Unix()
	if feed.ExpiresAt <= nowUnix {
		return fmt.Errorf("peer list expired")
	}
	if feed.GeneratedAt > feed.ExpiresAt {
		return fmt.Errorf("invalid peer list timestamps")
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("peer list signature verification failed")
	}
	return nil
}

func loadPeerTrustedKeys(path string) (map[string]string, error) {
	keys := make(map[string]string)
	b, err := readFileBounded(path, directoryTrustedKeysFileMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid peer trusted key entry: %s", line)
		}
		peerURL := normalizePeerURL(fields[0])
		key := strings.TrimSpace(fields[1])
		raw, decErr := base64.RawURLEncoding.DecodeString(key)
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid peer trusted key: %s", key)
		}
		keys[peerURL] = key
	}
	return keys, nil
}

func appendPeerTrustedKey(path string, peerURL string, key string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("peer trusted keys file path is required")
	}
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return fmt.Errorf("peer trusted key peer url is required")
	}
	key = normalizePeerPubKey(key)
	if key == "" {
		return fmt.Errorf("invalid peer trusted key")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	existing, err := loadPeerTrustedKeys(path)
	if err != nil {
		return err
	}
	if pinned, ok := existing[peerURL]; ok {
		if pinned == key {
			return nil
		}
		return fmt.Errorf("peer trusted key conflict for %s", peerURL)
	}
	existingData, err := readFileBounded(path, directoryTrustedKeysFileMaxBytes)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(existingData) > 0 && existingData[len(existingData)-1] != '\n' {
		existingData = append(existingData, '\n')
	}
	existingData = append(existingData, []byte(peerURL+" "+key+"\n")...)
	return writeFileAtomic(path, existingData, 0o644)
}

func normalizeCountryCode(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "ZZ"
	}
	if len(v) > 2 {
		v = v[:2]
	}
	return v
}

func normalizeRegion(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "local"
	}
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}

func normalizeCapabilities(values []string, role string) []string {
	role = strings.TrimSpace(strings.ToLower(role))
	base := []string{"wg"}
	if role == "exit" {
		base = append(base, "tiered-policy")
	} else if role == "entry" {
		base = append(base, "two-hop")
	}
	base = append(base, values...)
	seen := make(map[string]struct{}, len(base))
	out := make([]string, 0, len(base))
	for _, value := range base {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeHopRoles(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		switch value {
		case "entry", "ingress", "guard":
			value = "entry"
		case "middle", "relay", "micro-relay", "micro_relay":
			value = "middle"
		case "exit", "egress":
			value = "exit"
		default:
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func countryCodeWithDefault(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		v = fallback
	}
	return normalizeCountryCode(v)
}

func operatorIDWithDefault(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		v = strings.TrimSpace(fallback)
	}
	if v == "" {
		return "operator-unknown"
	}
	return v
}

func normalizeOperatorID(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

func normalizePeerPubKey(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func normalizeCaseID(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

func normalizeEvidenceRef(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 512 {
		v = v[:512]
	}
	return v
}

type adjudicationMetadataPair struct {
	caseID      string
	evidenceRef string
}

func recordMetadataPairVote(target *map[adjudicationMetadataPair]int, caseID string, evidenceRef string) {
	caseID = normalizeCaseID(caseID)
	evidenceRef = normalizeEvidenceRef(evidenceRef)
	if caseID == "" || evidenceRef == "" {
		return
	}
	if *target == nil {
		*target = make(map[adjudicationMetadataPair]int)
	}
	(*target)[adjudicationMetadataPair{caseID: caseID, evidenceRef: evidenceRef}]++
}

func pickVotedMetadataPair(votes map[adjudicationMetadataPair]int, minVotes int) (string, string) {
	if len(votes) == 0 {
		return "", ""
	}
	if minVotes <= 0 {
		minVotes = 1
	}
	best := adjudicationMetadataPair{}
	bestVotes := 0
	for pair, count := range votes {
		if count < minVotes {
			continue
		}
		if pair.caseID == "" || pair.evidenceRef == "" {
			continue
		}
		if count > bestVotes ||
			(count == bestVotes && (best.caseID == "" || pair.caseID < best.caseID ||
				(pair.caseID == best.caseID && pair.evidenceRef < best.evidenceRef))) {
			best = pair
			bestVotes = count
		}
	}
	if bestVotes <= 0 {
		return "", ""
	}
	return best.caseID, best.evidenceRef
}

func scoreWithDefault(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return clampScore(fallback)
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return clampScore(fallback)
	}
	return clampScore(v)
}

func clampScore(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func clampProviderTier(v int) int {
	switch {
	case v < 1:
		return 1
	case v > 3:
		return 3
	default:
		return v
	}
}

func normalizeDispute(tierCap int, disputeUntil int64, nowUnix int64) (int, int64) {
	return normalizeDisputeWithMax(tierCap, disputeUntil, nowUnix, 0)
}

func normalizeDisputeWithMax(tierCap int, disputeUntil int64, nowUnix int64, maxUntil int64) (int, int64) {
	if tierCap < 1 || tierCap > 3 {
		return 0, 0
	}
	if disputeUntil <= nowUnix {
		return 0, 0
	}
	if maxUntil > nowUnix && disputeUntil > maxUntil {
		disputeUntil = maxUntil
	}
	return tierCap, disputeUntil
}

func normalizeAppeal(appealUntil int64, nowUnix int64) int64 {
	return normalizeAppealWithMax(appealUntil, nowUnix, 0)
}

func normalizeAppealWithMax(appealUntil int64, nowUnix int64, maxUntil int64) int64 {
	if appealUntil <= nowUnix {
		return 0
	}
	if maxUntil > nowUnix && appealUntil > maxUntil {
		return maxUntil
	}
	return appealUntil
}

func activeDispute(att proto.RelayTrustAttestation, nowUnix int64) (int, int64, bool) {
	return activeDisputeWithMax(att, nowUnix, 0)
}

func activeDisputeWithMax(att proto.RelayTrustAttestation, nowUnix int64, maxUntil int64) (int, int64, bool) {
	tierCap, disputeUntil := normalizeDisputeWithMax(att.TierCap, att.DisputeUntil, nowUnix, maxUntil)
	if tierCap == 0 {
		return 0, 0, false
	}
	return tierCap, disputeUntil, true
}

func activeAppeal(att proto.RelayTrustAttestation, nowUnix int64) (int64, bool) {
	return activeAppealWithMax(att, nowUnix, 0)
}

func activeAppealWithMax(att proto.RelayTrustAttestation, nowUnix int64, maxUntil int64) (int64, bool) {
	appealUntil := normalizeAppealWithMax(att.AppealUntil, nowUnix, maxUntil)
	if appealUntil == 0 {
		return 0, false
	}
	return appealUntil, true
}

func (s *Service) maxDisputeUntil(nowUnix int64) int64 {
	return maxUntilFromTTL(nowUnix, s.disputeMaxTTL)
}

func (s *Service) maxAppealUntil(nowUnix int64) int64 {
	return maxUntilFromTTL(nowUnix, s.appealMaxTTL)
}

func (s *Service) effectiveFinalDisputeMinVotes() int {
	if s.finalDisputeMinVotes > 0 {
		return s.finalDisputeMinVotes
	}
	return maxInt(1, maxInt(s.peerDisputeMinVotes, s.issuerDisputeMinVotes))
}

func (s *Service) effectiveFinalAppealMinVotes() int {
	if s.finalAppealMinVotes > 0 {
		return s.finalAppealMinVotes
	}
	return maxInt(1, maxInt(s.peerAppealMinVotes, s.issuerAppealMinVotes))
}

func (s *Service) effectiveFinalAdjudicationMinOperators() int {
	if s.finalAdjudicationOps > 0 {
		return s.finalAdjudicationOps
	}
	return 1
}

func (s *Service) effectiveFinalAdjudicationMinSources() int {
	if s.finalAdjudicationSources > 0 {
		return s.finalAdjudicationSources
	}
	return 1
}

func (s *Service) effectiveFinalAdjudicationMinRatio() float64 {
	return clampScore(s.finalAdjudicationMin)
}

func (s *Service) activeDispute(att proto.RelayTrustAttestation, nowUnix int64) (int, int64, bool) {
	return activeDisputeWithMax(att, nowUnix, s.maxDisputeUntil(nowUnix))
}

func (s *Service) activeAppeal(att proto.RelayTrustAttestation, nowUnix int64) (int64, bool) {
	return activeAppealWithMax(att, nowUnix, s.maxAppealUntil(nowUnix))
}

func minPositiveTier(curr int, next int) int {
	if next < 1 || next > 3 {
		return curr
	}
	if curr < 1 || curr > 3 {
		return next
	}
	if next < curr {
		return next
	}
	return curr
}

func pickConsensusTier(votes map[int]int) (int, bool) {
	if len(votes) == 0 {
		return 0, false
	}
	bestTier := 0
	bestVotes := 0
	for tier, count := range votes {
		if tier < 1 || tier > 3 {
			continue
		}
		if count > bestVotes || (count == bestVotes && (bestTier == 0 || tier < bestTier)) {
			bestTier = tier
			bestVotes = count
		}
	}
	if bestTier == 0 || bestVotes == 0 {
		return 0, false
	}
	return bestTier, true
}

func pickMedianUnix(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	filtered := make([]int64, 0, len(values))
	for _, v := range values {
		if v > 0 {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		return 0
	}
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i] < filtered[j]
	})
	mid := len(filtered) / 2
	if len(filtered)%2 == 0 {
		return filtered[mid-1]
	}
	return filtered[mid]
}

func pickVotedString(votes map[string]int, minVotes int) string {
	if len(votes) == 0 {
		return ""
	}
	if minVotes <= 0 {
		minVotes = 1
	}
	bestValue := ""
	bestVotes := 0
	for value, count := range votes {
		if count < minVotes {
			continue
		}
		if count > bestVotes || (count == bestVotes && (bestValue == "" || value < bestValue)) {
			bestVotes = count
			bestValue = value
		}
	}
	return bestValue
}

func meetsAdjudicationQuorum(votes int, total int, minVotes int, minRatio float64) bool {
	if votes <= 0 || total <= 0 {
		return false
	}
	if minVotes <= 0 {
		minVotes = 1
	}
	if votes < minVotes {
		return false
	}
	minRatio = clampScore(minRatio)
	if minRatio <= 0 {
		return true
	}
	return float64(votes)/float64(total) >= minRatio
}

func disputePenaltyFromTierCap(tierCap int) float64 {
	switch tierCap {
	case 1:
		return 0.85
	case 2:
		return 0.55
	case 3:
		return 0.25
	default:
		return 0
	}
}

func selectionFromTrustAttestation(att proto.RelayTrustAttestation, nowUnix int64) proto.RelaySelectionScore {
	return selectionFromTrustAttestationCapped(att, nowUnix, 0, 0)
}

func selectionFromTrustAttestationCapped(att proto.RelayTrustAttestation, nowUnix int64, disputeMaxUntil int64, appealMaxUntil int64) proto.RelaySelectionScore {
	score := proto.RelaySelectionScore{
		RelayID:      att.RelayID,
		Role:         att.Role,
		Reputation:   att.Reputation,
		Uptime:       att.Uptime,
		Capacity:     att.Capacity,
		AbusePenalty: att.AbusePenalty,
		BondScore:    att.BondScore,
		StakeScore:   att.StakeScore,
	}
	if tierCap, _, ok := activeDisputeWithMax(att, nowUnix, disputeMaxUntil); ok {
		penalty := disputePenaltyFromTierCap(tierCap)
		if _, appealActive := activeAppealWithMax(att, nowUnix, appealMaxUntil); appealActive {
			penalty = clampScore(penalty * 0.7)
		}
		score.AbusePenalty = clampScore(maxFloat(score.AbusePenalty, penalty))
	}
	return score
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxUntilFromTTL(nowUnix int64, ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	sec := int64(ttl / time.Second)
	if sec <= 0 {
		return 0
	}
	return nowUnix + sec
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func operatorSetList(in map[string]struct{}) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for operator := range in {
		operator = strings.TrimSpace(operator)
		if operator == "" {
			continue
		}
		out = append(out, operator)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func operatorSetDifference(left map[string]struct{}, right map[string]struct{}) map[string]struct{} {
	if len(left) == 0 {
		return nil
	}
	out := make(map[string]struct{})
	for operator := range left {
		if _, ok := right[operator]; ok {
			continue
		}
		op := strings.TrimSpace(operator)
		if op == "" {
			continue
		}
		out[op] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func tickerC(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func maxFloat(a float64, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func cloneRelayDescriptors(in []proto.RelayDescriptor) []proto.RelayDescriptor {
	if len(in) == 0 {
		return nil
	}
	out := make([]proto.RelayDescriptor, len(in))
	copy(out, in)
	return out
}

func cloneSelectionScores(in map[string]proto.RelaySelectionScore) map[string]proto.RelaySelectionScore {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]proto.RelaySelectionScore, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneTrustAttestations(in map[string]proto.RelayTrustAttestation) map[string]proto.RelayTrustAttestation {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]proto.RelayTrustAttestation, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneDirectorySyncRunStatus(in proto.DirectorySyncRunStatus) proto.DirectorySyncRunStatus {
	out := in
	if len(in.SourceOperators) > 0 {
		out.SourceOperators = append([]string(nil), in.SourceOperators...)
	}
	return out
}

func secureTokenMatch(candidate string, expected string) bool {
	candidate = strings.TrimSpace(candidate)
	expected = strings.TrimSpace(expected)
	if expected == "" || len(candidate) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func (s *Service) handlePubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pub, _ := s.currentKeypair()
	resp := map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handlePubKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pub, _ := s.currentKeypair()
	keys := []string{base64.RawURLEncoding.EncodeToString(pub)}
	prev, err := loadPreviousPubKeys(s.previousPubKeysFile)
	if err != nil {
		http.Error(w, "invalid previous pubkeys file", http.StatusInternalServerError)
		return
	}
	historyLimit := s.effectiveKeyHistory()
	if historyLimit > 0 && len(prev) > historyLimit {
		prev = prev[:historyLimit]
	}
	keys = dedupeStrings(append(keys, prev...))
	resp := proto.DirectoryPubKeysResponse{
		Operator: s.operatorID,
		PubKeys:  keys,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Service) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !secureTokenMatch(r.Header.Get("X-Admin-Token"), s.adminToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.rotateSigningKey(); err != nil {
		http.Error(w, "rotate failed", http.StatusInternalServerError)
		return
	}
	pub, _ := s.currentKeypair()
	resp := map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !secureTokenMatch(r.Header.Get("X-Admin-Token"), s.adminToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	peer, issuer := s.snapshotSyncStatus()
	resp := proto.DirectorySyncStatusResponse{
		GeneratedAt: time.Now().UTC().Unix(),
		Peer:        peer,
		Issuer:      issuer,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) handlePeerStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !secureTokenMatch(r.Header.Get("X-Admin-Token"), s.adminToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now().UTC()
	resp := proto.DirectoryPeerStatusResponse{
		GeneratedAt: now.Unix(),
		Peers:       s.snapshotPeerStatus(now),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) handleGovernanceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !secureTokenMatch(r.Header.Get("X-Admin-Token"), s.adminToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now().UTC()
	resp := s.snapshotGovernanceStatus(now)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) snapshotPeerStatus(now time.Time) []proto.DirectoryPeerStatus {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.discoveredPeers == nil {
		s.discoveredPeers = make(map[string]time.Time)
	}
	if s.discoveredPeerVoters == nil {
		s.discoveredPeerVoters = make(map[string]map[string]time.Time)
	}
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	if s.peerHintPubKeys == nil {
		s.peerHintPubKeys = make(map[string]string)
	}
	if s.peerHintOperators == nil {
		s.peerHintOperators = make(map[string]string)
	}
	s.pruneDiscoveredPeersLocked(now)

	peerMap := make(map[string]proto.DirectoryPeerStatus)
	ensure := func(url string) proto.DirectoryPeerStatus {
		url = normalizePeerURL(url)
		if url == "" {
			return proto.DirectoryPeerStatus{}
		}
		status, ok := peerMap[url]
		if !ok {
			status = proto.DirectoryPeerStatus{URL: url}
		}
		return status
	}
	store := func(status proto.DirectoryPeerStatus) {
		if strings.TrimSpace(status.URL) == "" {
			return
		}
		peerMap[status.URL] = status
	}

	for _, url := range s.peerURLs {
		status := ensure(url)
		if status.URL == "" {
			continue
		}
		status.Configured = true
		store(status)
	}
	for url, seenAt := range s.discoveredPeers {
		status := ensure(url)
		if status.URL == "" {
			continue
		}
		status.Discovered = true
		status.LastSeenAt = seenAt.Unix()
		store(status)
	}
	for url, hintOperator := range s.peerHintOperators {
		status := ensure(url)
		if status.URL == "" {
			continue
		}
		status.HintOperator = normalizeOperatorID(hintOperator)
		store(status)
	}
	for url, hintPub := range s.peerHintPubKeys {
		status := ensure(url)
		if status.URL == "" {
			continue
		}
		status.HintPubKey = normalizePeerPubKey(hintPub)
		store(status)
	}
	for url, voters := range s.discoveredPeerVoters {
		status := ensure(url)
		if status.URL == "" {
			continue
		}
		status.VoteOperators = len(voters)
		store(status)
	}
	for url, health := range s.discoveredPeerHealth {
		status := ensure(url)
		if status.URL == "" {
			continue
		}
		if !health.lastSuccess.IsZero() {
			status.LastSuccessAt = health.lastSuccess.Unix()
		}
		if !health.lastFailure.IsZero() {
			status.LastFailureAt = health.lastFailure.Unix()
		}
		if !health.cooldownUntil.IsZero() {
			status.CooldownUntil = health.cooldownUntil.Unix()
			retryAfterSec := health.cooldownUntil.Unix() - now.Unix()
			if retryAfterSec > 0 {
				status.RetryAfterSec = retryAfterSec
			}
		}
		status.ConsecutiveFailures = health.consecutiveFailures
		status.LastError = strings.TrimSpace(health.lastError)
		store(status)
	}

	keys := make([]string, 0, len(peerMap))
	for url := range peerMap {
		keys = append(keys, url)
	}
	sort.Strings(keys)
	out := make([]proto.DirectoryPeerStatus, 0, len(keys))
	for _, url := range keys {
		status := peerMap[url]
		status.CoolingDown = s.isPeerCoolingDownLocked(url, now)
		status.Eligible = (status.Configured || status.Discovered) && !status.CoolingDown
		out = append(out, status)
	}
	return out
}

func writeJSONWithETag(w http.ResponseWriter, r *http.Request, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	etag := fmt.Sprintf("\"%x\"", sum[:8])
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	_, err = w.Write(b)
	return err
}

func (s *Service) stableTime(now time.Time, epoch time.Duration) time.Time {
	now = now.UTC()
	if epoch <= 0 {
		return now.Truncate(time.Second)
	}
	return now.Truncate(epoch)
}

func (s *Service) currentKeypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	pub := append(ed25519.PublicKey(nil), s.pubKey...)
	priv := append(ed25519.PrivateKey(nil), s.privKey...)
	return pub, priv
}

func (s *Service) setPeerSyncStatus(status proto.DirectorySyncRunStatus) {
	s.syncStatusMu.Lock()
	s.peerSyncStatus = status
	s.syncStatusMu.Unlock()
}

func (s *Service) setIssuerSyncStatus(status proto.DirectorySyncRunStatus) {
	s.syncStatusMu.Lock()
	s.issuerSyncStatus = status
	s.syncStatusMu.Unlock()
}

func (s *Service) snapshotSyncStatus() (proto.DirectorySyncRunStatus, proto.DirectorySyncRunStatus) {
	s.syncStatusMu.RLock()
	defer s.syncStatusMu.RUnlock()
	return cloneDirectorySyncRunStatus(s.peerSyncStatus), cloneDirectorySyncRunStatus(s.issuerSyncStatus)
}

func (s *Service) snapshotGovernanceStatus(now time.Time) proto.DirectoryGovernanceStatusResponse {
	peerTrust := s.snapshotPeerTrust()
	issuerTrust := s.snapshotIssuerTrust()
	peerCandidates := len(peerTrust)
	issuerCandidates := len(issuerTrust)
	relays := s.buildRelayDescriptors(s.stableTime(now, s.descriptorEpoch))
	aggregated := s.buildTrustAttestations(relays)
	relayOperators := make(map[string]string, len(relays)+len(aggregated))
	for _, desc := range relays {
		role, ok := canonicalizeSignalRole(desc.Role)
		if !ok {
			continue
		}
		if strings.TrimSpace(desc.RelayID) == "" {
			continue
		}
		if operator := normalizeOperatorID(desc.OperatorID); operator != "" {
			relayOperators[relayKey(desc.RelayID, role)] = operator
		}
	}
	for _, att := range aggregated {
		role, ok := canonicalizeSignalRole(att.Role)
		if !ok {
			continue
		}
		if strings.TrimSpace(att.RelayID) == "" {
			continue
		}
		if operator := normalizeOperatorID(att.OperatorID); operator != "" {
			relayOperators[relayKey(att.RelayID, role)] = operator
		}
	}
	operatorForSignal := func(relayID string, role string, operatorID string) string {
		if operator := normalizeOperatorID(operatorID); operator != "" {
			return operator
		}
		return normalizeOperatorID(relayOperators[relayKey(relayID, role)])
	}
	nowUnix := now.Unix()
	disputed := 0
	appealed := 0
	disputeSignals := make(map[string]struct{})
	appealSignals := make(map[string]struct{})
	disputeSignalOperators := make(map[string]struct{})
	appealSignalOperators := make(map[string]struct{})
	disputedOperators := make(map[string]struct{})
	appealedOperators := make(map[string]struct{})
	disputeRelayOperators := make(map[string]map[string]struct{})
	appealRelayOperators := make(map[string]map[string]struct{})
	publishedDisputeRelayOperators := make(map[string]map[string]struct{})
	publishedAppealRelayOperators := make(map[string]map[string]struct{})
	publishedDisputeRelays := make(map[string]struct{})
	publishedAppealRelays := make(map[string]struct{})
	markRelayOperator := func(target map[string]map[string]struct{}, relay string, operator string) {
		operator = normalizeOperatorID(operator)
		if relay == "" || operator == "" {
			return
		}
		bucket, ok := target[relay]
		if !ok {
			bucket = make(map[string]struct{})
			target[relay] = bucket
		}
		bucket[operator] = struct{}{}
	}
	markSignal := func(att proto.RelayTrustAttestation) {
		role, ok := canonicalizeSignalRole(att.Role)
		if !ok || strings.TrimSpace(att.RelayID) == "" {
			return
		}
		key := relayKey(att.RelayID, role)
		if _, _, ok := s.activeDispute(att, nowUnix); ok {
			disputeSignals[key] = struct{}{}
			if operator := operatorForSignal(att.RelayID, role, att.OperatorID); operator != "" {
				disputeSignalOperators[operator] = struct{}{}
				markRelayOperator(disputeRelayOperators, key, operator)
			}
		}
		if _, ok := s.activeAppeal(att, nowUnix); ok {
			appealSignals[key] = struct{}{}
			if operator := operatorForSignal(att.RelayID, role, att.OperatorID); operator != "" {
				appealSignalOperators[operator] = struct{}{}
				markRelayOperator(appealRelayOperators, key, operator)
			}
		}
	}
	for _, desc := range relays {
		markSignal(proto.RelayTrustAttestation{
			RelayID:      desc.RelayID,
			Role:         desc.Role,
			OperatorID:   desc.OperatorID,
			TierCap:      0,
			DisputeUntil: 0,
			AppealUntil:  0,
		})
	}
	for _, att := range peerTrust {
		markSignal(att)
	}
	for _, att := range issuerTrust {
		markSignal(att)
	}
	for _, att := range aggregated {
		role, ok := canonicalizeSignalRole(att.Role)
		if !ok || strings.TrimSpace(att.RelayID) == "" {
			continue
		}
		key := relayKey(att.RelayID, role)
		if _, _, ok := s.activeDispute(att, nowUnix); ok {
			disputed++
			publishedDisputeRelays[key] = struct{}{}
			if operator := operatorForSignal(att.RelayID, role, att.OperatorID); operator != "" {
				disputedOperators[operator] = struct{}{}
				markRelayOperator(publishedDisputeRelayOperators, key, operator)
			}
		}
		if _, ok := s.activeAppeal(att, nowUnix); ok {
			appealed++
			publishedAppealRelays[key] = struct{}{}
			if operator := operatorForSignal(att.RelayID, role, att.OperatorID); operator != "" {
				appealedOperators[operator] = struct{}{}
				markRelayOperator(publishedAppealRelayOperators, key, operator)
			}
		}
	}
	suppressedDisputed := maxInt(0, len(disputeSignals)-disputed)
	suppressedAppealed := maxInt(0, len(appealSignals)-appealed)
	suppressedDisputeOperatorsSet := operatorSetDifference(disputeSignalOperators, disputedOperators)
	suppressedAppealOperatorsSet := operatorSetDifference(appealSignalOperators, appealedOperators)
	disputeSignalOperatorIDs := operatorSetList(disputeSignalOperators)
	appealSignalOperatorIDs := operatorSetList(appealSignalOperators)
	aggregatedDisputedOperatorIDs := operatorSetList(disputedOperators)
	aggregatedAppealedOperatorIDs := operatorSetList(appealedOperators)
	suppressedDisputeOperatorIDs := operatorSetList(suppressedDisputeOperatorsSet)
	suppressedAppealOperatorIDs := operatorSetList(suppressedAppealOperatorsSet)
	relayKeysSet := make(map[string]struct{})
	for key := range disputeSignals {
		relayKeysSet[key] = struct{}{}
	}
	for key := range appealSignals {
		relayKeysSet[key] = struct{}{}
	}
	for key := range publishedDisputeRelays {
		relayKeysSet[key] = struct{}{}
	}
	for key := range publishedAppealRelays {
		relayKeysSet[key] = struct{}{}
	}
	relayKeys := make([]string, 0, len(relayKeysSet))
	for key := range relayKeysSet {
		relayKeys = append(relayKeys, key)
	}
	sort.Strings(relayKeys)
	relayStatuses := make([]proto.DirectoryGovernanceRelayStatus, 0, len(relayKeys))
	for _, key := range relayKeys {
		relayID, role, ok := splitRelayKey(key)
		if !ok {
			continue
		}
		_, upstreamDisputeSignal := disputeSignals[key]
		_, upstreamAppealSignal := appealSignals[key]
		_, publishedDisputed := publishedDisputeRelays[key]
		_, publishedAppealed := publishedAppealRelays[key]
		relayStatuses = append(relayStatuses, proto.DirectoryGovernanceRelayStatus{
			RelayID:                      relayID,
			Role:                         role,
			UpstreamDisputeSignal:        upstreamDisputeSignal,
			UpstreamAppealSignal:         upstreamAppealSignal,
			UpstreamDisputeOperatorIDs:   operatorSetList(disputeRelayOperators[key]),
			UpstreamAppealOperatorIDs:    operatorSetList(appealRelayOperators[key]),
			PublishedDisputed:            publishedDisputed,
			PublishedAppealed:            publishedAppealed,
			PublishedDisputeOperatorIDs:  operatorSetList(publishedDisputeRelayOperators[key]),
			PublishedAppealOperatorIDs:   operatorSetList(publishedAppealRelayOperators[key]),
			SuppressedDisputed:           upstreamDisputeSignal && !publishedDisputed,
			SuppressedAppealed:           upstreamAppealSignal && !publishedAppealed,
			SuppressedDisputeOperatorIDs: operatorSetList(operatorSetDifference(disputeRelayOperators[key], publishedDisputeRelayOperators[key])),
			SuppressedAppealOperatorIDs:  operatorSetList(operatorSetDifference(appealRelayOperators[key], publishedAppealRelayOperators[key])),
		})
	}
	return proto.DirectoryGovernanceStatusResponse{
		GeneratedAt: nowUnix,
		Policy: proto.DirectoryAdjudicationPolicy{
			MetaMinVotes:      maxInt(1, s.adjudicationMetaMin),
			FinalDisputeMin:   s.effectiveFinalDisputeMinVotes(),
			FinalAppealMin:    s.effectiveFinalAppealMinVotes(),
			FinalMinOperators: s.effectiveFinalAdjudicationMinOperators(),
			FinalMinSources:   s.effectiveFinalAdjudicationMinSources(),
			FinalDisputeRatio: s.effectiveFinalAdjudicationMinRatio(),
		},
		PeerTrustCandidates:           peerCandidates,
		IssuerTrustCandidates:         issuerCandidates,
		AggregatedTrustAttestations:   len(aggregated),
		AggregatedDisputeSignals:      len(disputeSignals),
		AggregatedAppealSignals:       len(appealSignals),
		DisputeSignalOperators:        len(disputeSignalOperators),
		AppealSignalOperators:         len(appealSignalOperators),
		DisputeSignalOperatorIDs:      disputeSignalOperatorIDs,
		AppealSignalOperatorIDs:       appealSignalOperatorIDs,
		AggregatedDisputed:            disputed,
		AggregatedAppealed:            appealed,
		AggregatedDisputedOperators:   len(disputedOperators),
		AggregatedAppealedOperators:   len(appealedOperators),
		AggregatedDisputedOperatorIDs: aggregatedDisputedOperatorIDs,
		AggregatedAppealedOperatorIDs: aggregatedAppealedOperatorIDs,
		SuppressedDisputed:            suppressedDisputed,
		SuppressedAppealed:            suppressedAppealed,
		SuppressedDisputeOperators:    len(suppressedDisputeOperatorsSet),
		SuppressedAppealOperators:     len(suppressedAppealOperatorsSet),
		SuppressedDisputeOperatorIDs:  suppressedDisputeOperatorIDs,
		SuppressedAppealOperatorIDs:   suppressedAppealOperatorIDs,
		Relays:                        relayStatuses,
	}
}

func (s *Service) rotateSigningKey() error {
	pub, _ := s.currentKeypair()
	if len(pub) > 0 {
		if err := appendPreviousPubKey(s.previousPubKeysFile, base64.RawURLEncoding.EncodeToString(pub), s.effectiveKeyHistory()); err != nil {
			return err
		}
	}
	newPub, newPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		return err
	}
	if err := s.persistPrivateKey(newPriv); err != nil {
		return err
	}
	s.keyMu.Lock()
	s.pubKey = newPub
	s.privKey = newPriv
	s.keyMu.Unlock()
	return nil
}

func (s *Service) effectiveKeyHistory() int {
	if s.keyHistory > 0 {
		return s.keyHistory
	}
	return 3
}

func (s *Service) persistPrivateKey(priv ed25519.PrivateKey) error {
	if strings.TrimSpace(s.privateKeyPath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.privateKeyPath), 0o755); err != nil {
		return err
	}
	enc := base64.RawURLEncoding.EncodeToString(priv)
	return writeFileAtomic(s.privateKeyPath, []byte(enc+"\n"), 0o600)
}

func appendPreviousPubKey(path string, key string, maxHistory int) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(key) == "" {
		return nil
	}
	keys, err := loadPreviousPubKeys(path)
	if err != nil {
		return err
	}
	keys = dedupeStrings(append([]string{key}, keys...))
	if maxHistory > 0 && len(keys) > maxHistory {
		keys = keys[:maxHistory]
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data := strings.Join(keys, "\n")
	if data != "" {
		data += "\n"
	}
	return writeFileAtomic(path, []byte(data), 0o644)
}

func loadPreviousPubKeys(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := readFileBounded(path, directoryPreviousPubKeysFileMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(line)
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid previous pubkey: %s", line)
		}
		out = append(out, line)
	}
	return out, nil
}

func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("file path is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("max bytes must be positive")
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
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	return b, nil
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

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func signDescriptor(desc proto.RelayDescriptor, priv ed25519.PrivateKey) string {
	desc.Signature = ""
	payload, err := json.Marshal(desc)
	if err != nil {
		return ""
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(sig)
}
