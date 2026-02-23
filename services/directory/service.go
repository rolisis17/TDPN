package directory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

type Service struct {
	addr                     string
	localURL                 string
	operatorID               string
	pubKey                   ed25519.PublicKey
	privKey                  ed25519.PrivateKey
	server                   *http.Server
	entryEndpoints           []string
	endpointRotateSec        int64
	descriptorEpoch          time.Duration
	descriptorTTL            time.Duration
	selectionFeedTTL         time.Duration
	selectionEpoch           time.Duration
	trustFeedTTL             time.Duration
	trustEpoch               time.Duration
	adminToken               string
	previousPubKeysFile      string
	providerIssuerURLs       []string
	providerRelayMaxTTL      time.Duration
	issuerTrustURLs          []string
	issuerSyncSec            int
	issuerTrustMinVotes      int
	issuerDisputeMinVotes    int
	issuerAppealMinVotes     int
	peerURLs                 []string
	peerSyncSec              int
	gossipSec                int
	gossipFanout             int
	peerListTTL              time.Duration
	peerDiscoveryEnabled     bool
	peerDiscoveryMax         int
	peerDiscoveryTTL         time.Duration
	peerDiscoveryMinVotes    int
	peerDiscoveryRequireHint bool
	peerDiscoveryFailN       int
	peerDiscoveryBackoff     time.Duration
	peerDiscoveryBackoffMax  time.Duration
	peerMinOperators         int
	peerMinVotes             int
	peerScoreMinVotes        int
	peerTrustMinVotes        int
	peerDisputeMinVotes      int
	peerAppealMinVotes       int
	adjudicationMetaMin      int
	finalAdjudicationOps     int
	finalDisputeMinVotes     int
	finalAppealMinVotes      int
	finalAdjudicationMin     float64
	disputeMaxTTL            time.Duration
	appealMaxTTL             time.Duration
	issuerMinOperators       int
	peerMaxHops              int
	peerMu                   sync.RWMutex
	peerRelays               map[string]proto.RelayDescriptor
	providerMu               sync.RWMutex
	providerRelays           map[string]proto.RelayDescriptor
	peerScores               map[string]proto.RelaySelectionScore
	peerTrust                map[string]proto.RelayTrustAttestation
	issuerTrust              map[string]proto.RelayTrustAttestation
	discoveredPeers          map[string]time.Time
	discoveredPeerVoters     map[string]map[string]time.Time
	discoveredPeerHealth     map[string]discoveredPeerHealth
	peerHintPubKeys          map[string]string
	peerHintOperators        map[string]string
	peerRelayETags           map[string]string
	peerRelayCache           map[string][]proto.RelayDescriptor
	peerScoreETags           map[string]string
	peerScoreCache           map[string]map[string]proto.RelaySelectionScore
	peerTrustETags           map[string]string
	peerTrustCache           map[string]map[string]proto.RelayTrustAttestation
	issuerTrustETags         map[string]string
	issuerTrustCache         map[string]map[string]proto.RelayTrustAttestation
	peerTrustStrict          bool
	peerTrustTOFU            bool
	peerTrustFile            string
	peerTrustMu              sync.Mutex
	syncStatusMu             sync.RWMutex
	peerSyncStatus           proto.DirectorySyncRunStatus
	issuerSyncStatus         proto.DirectorySyncRunStatus
	keyMu                    sync.RWMutex
	httpClient               *http.Client
	privateKeyPath           string
	keyRotateEvery           time.Duration
	keyHistory               int
}

type discoveredPeerHealth struct {
	lastSuccess         time.Time
	lastFailure         time.Time
	consecutiveFailures int
	cooldownUntil       time.Time
	lastError           string
}

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
	issuerSyncSec := 10
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_ISSUER_SYNC_SEC")); err == nil && v > 0 {
		issuerSyncSec = v
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
	providerRelayMaxTTL := 5 * time.Minute
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_PROVIDER_RELAY_MAX_TTL_SEC")); err == nil && v > 0 {
		providerRelayMaxTTL = time.Duration(v) * time.Second
	}
	peerTrustStrict := os.Getenv("DIRECTORY_PEER_TRUST_STRICT") == "1"
	peerTrustTOFU := os.Getenv("DIRECTORY_PEER_TRUST_TOFU") != "0"
	peerTrustFile := os.Getenv("DIRECTORY_PEER_TRUSTED_KEYS_FILE")
	if peerTrustFile == "" {
		peerTrustFile = "data/directory_peer_trusted_keys.txt"
	}
	adminToken := os.Getenv("DIRECTORY_ADMIN_TOKEN")
	if adminToken == "" {
		adminToken = "dev-admin-token"
	}
	previousPubKeysFile := os.Getenv("DIRECTORY_PREVIOUS_PUBKEYS_FILE")
	if previousPubKeysFile == "" {
		previousPubKeysFile = "data/directory_previous_pubkeys.txt"
	}
	operatorID := operatorIDWithDefault("DIRECTORY_OPERATOR_ID", "operator-local")
	privateKeyPath := os.Getenv("DIRECTORY_PRIVATE_KEY_FILE")
	if privateKeyPath == "" {
		privateKeyPath = "data/directory_ed25519.key"
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
		addr:                     addr,
		localURL:                 localURL,
		operatorID:               operatorID,
		entryEndpoints:           eps,
		endpointRotateSec:        rotateSec,
		descriptorEpoch:          descriptorEpoch,
		descriptorTTL:            descriptorTTL,
		selectionFeedTTL:         selectionFeedTTL,
		selectionEpoch:           selectionEpoch,
		trustFeedTTL:             trustFeedTTL,
		trustEpoch:               trustEpoch,
		adminToken:               adminToken,
		previousPubKeysFile:      previousPubKeysFile,
		providerIssuerURLs:       providerIssuerURLs,
		providerRelayMaxTTL:      providerRelayMaxTTL,
		issuerTrustURLs:          issuerTrustURLs,
		issuerSyncSec:            issuerSyncSec,
		issuerTrustMinVotes:      issuerTrustMinVotes,
		issuerDisputeMinVotes:    issuerDisputeMinVotes,
		issuerAppealMinVotes:     issuerAppealMinVotes,
		peerURLs:                 peerURLs,
		peerSyncSec:              peerSyncSec,
		gossipSec:                gossipSec,
		gossipFanout:             gossipFanout,
		peerListTTL:              peerListTTL,
		peerDiscoveryEnabled:     peerDiscoveryEnabled,
		peerDiscoveryMax:         peerDiscoveryMax,
		peerDiscoveryTTL:         peerDiscoveryTTL,
		peerDiscoveryMinVotes:    peerDiscoveryMinVotes,
		peerDiscoveryRequireHint: peerDiscoveryRequireHint,
		peerDiscoveryFailN:       peerDiscoveryFailN,
		peerDiscoveryBackoff:     peerDiscoveryBackoff,
		peerDiscoveryBackoffMax:  peerDiscoveryBackoffMax,
		peerMinOperators:         peerMinOperators,
		peerMinVotes:             peerMinVotes,
		peerScoreMinVotes:        peerScoreMinVotes,
		peerTrustMinVotes:        peerTrustMinVotes,
		peerDisputeMinVotes:      peerDisputeMinVotes,
		peerAppealMinVotes:       peerAppealMinVotes,
		adjudicationMetaMin:      adjudicationMetaMin,
		finalAdjudicationOps:     finalAdjudicationOps,
		finalDisputeMinVotes:     finalDisputeMinVotes,
		finalAppealMinVotes:      finalAppealMinVotes,
		finalAdjudicationMin:     finalAdjudicationMin,
		disputeMaxTTL:            disputeMaxTTL,
		appealMaxTTL:             appealMaxTTL,
		issuerMinOperators:       issuerMinOperators,
		peerMaxHops:              peerMaxHops,
		peerRelays:               make(map[string]proto.RelayDescriptor),
		providerRelays:           make(map[string]proto.RelayDescriptor),
		peerScores:               make(map[string]proto.RelaySelectionScore),
		peerTrust:                make(map[string]proto.RelayTrustAttestation),
		issuerTrust:              make(map[string]proto.RelayTrustAttestation),
		discoveredPeers:          make(map[string]time.Time),
		discoveredPeerVoters:     make(map[string]map[string]time.Time),
		discoveredPeerHealth:     make(map[string]discoveredPeerHealth),
		peerHintPubKeys:          make(map[string]string),
		peerHintOperators:        make(map[string]string),
		peerRelayETags:           make(map[string]string),
		peerRelayCache:           make(map[string][]proto.RelayDescriptor),
		peerScoreETags:           make(map[string]string),
		peerScoreCache:           make(map[string]map[string]proto.RelaySelectionScore),
		peerTrustETags:           make(map[string]string),
		peerTrustCache:           make(map[string]map[string]proto.RelayTrustAttestation),
		issuerTrustETags:         make(map[string]string),
		issuerTrustCache:         make(map[string]map[string]proto.RelayTrustAttestation),
		peerTrustStrict:          peerTrustStrict,
		peerTrustTOFU:            peerTrustTOFU,
		peerTrustFile:            peerTrustFile,
		httpClient:               &http.Client{Timeout: 5 * time.Second},
		privateKeyPath:           privateKeyPath,
		keyRotateEvery:           keyRotateEvery,
		keyHistory:               keyHistory,
	}
}

func (s *Service) Run(ctx context.Context) error {
	pub, priv, err := s.loadOrCreateKeypair()
	if err != nil {
		return fmt.Errorf("directory key init: %w", err)
	}
	s.keyMu.Lock()
	s.pubKey = pub
	s.privKey = priv
	s.keyMu.Unlock()

	mux := http.NewServeMux()
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
		Addr:    s.addr,
		Handler: mux,
	}
	log.Printf("directory federation policy: peers=%d peer_min_operators=%d peer_min_votes=%d peer_discovery_min_votes=%d peer_discovery_require_hint=%t peer_discovery_fail_threshold=%d peer_discovery_backoff_sec=%d peer_discovery_max_backoff_sec=%d adjudication_meta_min_votes=%d final_dispute_min_votes=%d final_appeal_min_votes=%d final_adjudication_min_operators=%d final_adjudication_min_ratio=%.2f dispute_max_ttl_sec=%d appeal_max_ttl_sec=%d issuer_urls=%d issuer_min_operators=%d issuer_min_votes=%d provider_issuer_urls=%d provider_relay_max_ttl_sec=%d key_rotate_sec=%d key_history=%d",
		len(s.peerURLs), s.peerMinOperators, s.peerMinVotes, maxInt(1, s.peerDiscoveryMinVotes), s.peerDiscoveryRequireHint, maxInt(1, s.peerDiscoveryFailN), int(s.peerDiscoveryBackoff/time.Second), int(s.peerDiscoveryBackoffMax/time.Second), maxInt(1, s.adjudicationMetaMin), s.effectiveFinalDisputeMinVotes(), s.effectiveFinalAppealMinVotes(), s.effectiveFinalAdjudicationMinOperators(), s.effectiveFinalAdjudicationMinRatio(), int(s.disputeMaxTTL/time.Second), int(s.appealMaxTTL/time.Second), len(s.issuerTrustURLs), s.issuerMinOperators, s.issuerTrustMinVotes, len(s.providerIssuerURLs), int(s.providerRelayMaxTTL/time.Second), int(s.keyRotateEvery/time.Second), s.effectiveKeyHistory())

	errCh := make(chan error, 1)
	go func() {
		log.Printf("directory listening on %s", s.addr)
		errCh <- s.server.ListenAndServe()
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

func (s *Service) runPeerSync(ctx context.Context) {
	if err := s.syncPeerRelays(ctx); err != nil && len(s.peerURLs) > 0 {
		log.Printf("directory peer sync initial failed: %v", err)
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
	for {
		select {
		case <-ctx.Done():
			return
		case <-peerTicker.C:
			if err := s.syncPeerRelays(ctx); err != nil {
				log.Printf("directory peer sync failed: %v", err)
			}
		case <-issuerTicker.C:
			if err := s.syncIssuerTrust(ctx); err != nil {
				log.Printf("directory issuer trust sync failed: %v", err)
			}
		case <-tickerC(gossipTicker):
			if err := s.gossipPeerRelays(ctx); err != nil {
				log.Printf("directory gossip push failed: %v", err)
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
	trustCandidates := make(map[string]trustCandidate)
	trustVoters := make(map[string]map[string]struct{})
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
		sourceOperator := normalizeSourceOperator(declaredOperator, pubs, peerURL)
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
		}
		attestations, trustErr := s.fetchPeerTrustAttestations(ctx, peerURL, pubs)
		if trustErr != nil {
			lastErr = trustErr
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
		for key, score := range scores {
			role := strings.TrimSpace(score.Role)
			if role == "" {
				role = "exit"
			}
			if role != "exit" || strings.TrimSpace(score.RelayID) == "" {
				continue
			}
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
		for key, att := range attestations {
			role := strings.TrimSpace(att.Role)
			if role == "" {
				role = "exit"
			}
			if role != "exit" || strings.TrimSpace(att.RelayID) == "" {
				continue
			}
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
		return lastErr
	}
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient peer operators")
		}
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
	s.peerMu.Lock()
	s.peerRelays = merged
	s.peerScores = mergedScores
	s.peerTrust = mergedTrust
	s.peerMu.Unlock()
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
	var lastErr error
	nowUnix := time.Now().Unix()
	for _, issuerURL := range s.issuerTrustURLs {
		pubs, declaredOperator, err := s.fetchIssuerPubKeys(ctx, issuerURL)
		if err != nil {
			lastErr = err
			continue
		}
		sourceOperator := normalizeSourceOperator(declaredOperator, pubs, issuerURL)
		attestations, err := s.fetchIssuerTrustAttestations(ctx, issuerURL, pubs)
		if err != nil {
			lastErr = err
			continue
		}
		success++
		successOperators[sourceOperator] = struct{}{}
		for key, att := range attestations {
			role := strings.TrimSpace(att.Role)
			if role == "" {
				role = "exit"
			}
			if role != "exit" || strings.TrimSpace(att.RelayID) == "" {
				continue
			}
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
		return lastErr
	}
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient issuer operators")
		}
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
	s.peerMu.Lock()
	s.issuerTrust = merged
	s.peerMu.Unlock()
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
		if cached, ok := s.cachedIssuerTrust(issuerURL); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("issuer trust feed 304 without cache")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer trust feed status %d", resp.StatusCode)
	}
	var feed proto.RelayTrustAttestationFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}
	if err := verifyIssuerTrustFeedAny(feed, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("issuer trust feed verify failed: %w", err)
	}
	out := make(map[string]proto.RelayTrustAttestation, len(feed.Attestations))
	for _, att := range feed.Attestations {
		role := strings.TrimSpace(att.Role)
		if role == "" {
			role = "exit"
		}
		if role != "exit" || strings.TrimSpace(att.RelayID) == "" {
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
	s.setIssuerTrustCache(issuerURL, resp.Header.Get("ETag"), out)
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
			return cached, nil
		}
		return nil, fmt.Errorf("peer relays 304 without cache")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer relays status %d", resp.StatusCode)
	}

	var out proto.RelayListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	verified := make([]proto.RelayDescriptor, 0, len(out.Relays))
	now := time.Now().UTC()
	for _, desc := range out.Relays {
		if desc.RelayID == "" || (desc.Role != "entry" && desc.Role != "exit") {
			continue
		}
		if err := verifyRelayDescriptorAny(desc, pubs); err != nil {
			return nil, fmt.Errorf("verify peer descriptor relay=%s: %w", desc.RelayID, err)
		}
		if !desc.ValidUntil.IsZero() && now.After(desc.ValidUntil) {
			continue
		}
		desc.Signature = ""
		verified = append(verified, desc)
	}
	s.setPeerRelayCache(peerURL, resp.Header.Get("ETag"), verified)
	return verified, nil
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
		if cached, ok := s.cachedPeerScores(peerURL); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("peer selection feed 304 without cache")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer selection feed status %d", resp.StatusCode)
	}
	var feed proto.RelaySelectionFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}
	if err := verifyRelaySelectionFeedAny(feed, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("peer selection feed verify failed: %w", err)
	}
	out := make(map[string]proto.RelaySelectionScore, len(feed.Scores))
	for _, score := range feed.Scores {
		role := strings.TrimSpace(score.Role)
		if role == "" {
			role = "exit"
		}
		if role != "exit" || strings.TrimSpace(score.RelayID) == "" {
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
	s.setPeerScoreCache(peerURL, resp.Header.Get("ETag"), out)
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
		if cached, ok := s.cachedPeerTrust(peerURL); ok {
			return cached, nil
		}
		return nil, fmt.Errorf("peer trust feed 304 without cache")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer trust feed status %d", resp.StatusCode)
	}
	var feed proto.RelayTrustAttestationFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return nil, err
	}
	if err := verifyRelayTrustFeedAny(feed, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("peer trust feed verify failed: %w", err)
	}
	out := make(map[string]proto.RelayTrustAttestation, len(feed.Attestations))
	for _, att := range feed.Attestations {
		role := strings.TrimSpace(att.Role)
		if role == "" {
			role = "exit"
		}
		if role != "exit" || strings.TrimSpace(att.RelayID) == "" {
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
	s.setPeerTrustCache(peerURL, resp.Header.Get("ETag"), out)
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
		return s.fetchPeerPubKeyLegacy(ctx, peerURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("peer pubkeys status %d", resp.StatusCode)
	}
	var out proto.DirectoryPubKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, "", err
	}
	keys := make([]ed25519.PublicKey, 0, len(out.PubKeys))
	keysB64 := make([]string, 0, len(out.PubKeys))
	for _, key := range dedupeStrings(out.PubKeys) {
		raw, decErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(key))
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid peer pubkey")
		}
		keys = append(keys, ed25519.PublicKey(raw))
		keysB64 = append(keysB64, base64.RawURLEncoding.EncodeToString(raw))
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("peer returned no pubkeys")
	}
	if expected := s.peerHintPubKey(peerURL); expected != "" && !containsString(keysB64, expected) {
		return nil, "", fmt.Errorf("peer pubkey mismatch with signed hint for %s", peerURL)
	}
	if err := s.enforcePeerTrustSet(peerURL, keysB64); err != nil {
		return nil, "", err
	}
	return keys, normalizeOperatorID(out.Operator), nil
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if err != nil {
		return nil, "", err
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if err := verifyDirectoryPeerListAny(out, pubs, time.Now()); err != nil {
		return nil, fmt.Errorf("peer list verify failed: %w", err)
	}
	return normalizePeerHints(out.Peers, out.PeerHints), nil
}

func (s *Service) snapshotSyncPeers(now time.Time) []string {
	peers := append([]string(nil), s.peerURLs...)
	if !s.peerDiscoveryEnabled {
		return normalizePeerURLs(peers)
	}
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
		if s.isDiscoveredPeerCoolingDownLocked(peerURL, now) {
			continue
		}
		peers = append(peers, peerURL)
	}
	s.peerMu.Unlock()
	return normalizePeerURLs(peers)
}

func (s *Service) snapshotKnownPeers(now time.Time) []string {
	peers := s.snapshotSyncPeers(now)
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
		if peerURL == "" || peerURL == self || peerURL == sourceURL {
			continue
		}
		if operator := normalizeOperatorID(hint.Operator); operator != "" {
			s.peerHintOperators[peerURL] = operator
		}
		if key := normalizePeerPubKey(hint.PubKey); key != "" {
			s.peerHintPubKeys[peerURL] = key
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
			s.discoveredPeerVoters[peerURL][sourceOperator] = now
		}
		if s.activeDiscoveredPeerVotesLocked(peerURL) < requiredVotes {
			continue
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

func (s *Service) isConfiguredPeerLocked(peerURL string) bool {
	for _, configured := range s.peerURLs {
		if normalizePeerURL(configured) == peerURL {
			return true
		}
	}
	return false
}

func (s *Service) isDiscoveredPeerCoolingDownLocked(peerURL string, now time.Time) bool {
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
	if peerURL == "" || !s.isDiscoveredPeer(peerURL) {
		return
	}
	s.peerMu.Lock()
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	health := s.discoveredPeerHealth[peerURL]
	health.lastSuccess = now
	health.consecutiveFailures = 0
	health.cooldownUntil = time.Time{}
	health.lastError = ""
	s.discoveredPeerHealth[peerURL] = health
	s.peerMu.Unlock()
}

func (s *Service) recordPeerSyncFailure(peerURL string, now time.Time, err error) {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" || !s.isDiscoveredPeer(peerURL) {
		return
	}
	s.peerMu.Lock()
	if s.discoveredPeerHealth == nil {
		s.discoveredPeerHealth = make(map[string]discoveredPeerHealth)
	}
	health := s.discoveredPeerHealth[peerURL]
	health.lastFailure = now
	health.consecutiveFailures++
	if err != nil {
		msg := strings.TrimSpace(err.Error())
		if len(msg) > 256 {
			msg = msg[:256]
		}
		health.lastError = msg
	}
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
	s.discoveredPeerHealth[peerURL] = health
	s.peerMu.Unlock()
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

func (s *Service) cachedPeerScores(peerURL string) (map[string]proto.RelaySelectionScore, bool) {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	scores, ok := s.peerScoreCache[normalizePeerURL(peerURL)]
	if !ok {
		return nil, false
	}
	return cloneSelectionScores(scores), true
}

func (s *Service) setPeerScoreCache(peerURL string, etag string, scores map[string]proto.RelaySelectionScore) {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerScoreCache == nil {
		s.peerScoreCache = make(map[string]map[string]proto.RelaySelectionScore)
	}
	if s.peerScoreETags == nil {
		s.peerScoreETags = make(map[string]string)
	}
	s.peerScoreCache[peerURL] = cloneSelectionScores(scores)
	if strings.TrimSpace(etag) != "" {
		s.peerScoreETags[peerURL] = strings.TrimSpace(etag)
	}
}

func (s *Service) cachedPeerTrustETag(peerURL string) string {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.peerTrustETags[normalizePeerURL(peerURL)]
}

func (s *Service) cachedPeerTrust(peerURL string) (map[string]proto.RelayTrustAttestation, bool) {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	attestations, ok := s.peerTrustCache[normalizePeerURL(peerURL)]
	if !ok {
		return nil, false
	}
	return cloneTrustAttestations(attestations), true
}

func (s *Service) setPeerTrustCache(peerURL string, etag string, attestations map[string]proto.RelayTrustAttestation) {
	peerURL = normalizePeerURL(peerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerTrustCache == nil {
		s.peerTrustCache = make(map[string]map[string]proto.RelayTrustAttestation)
	}
	if s.peerTrustETags == nil {
		s.peerTrustETags = make(map[string]string)
	}
	s.peerTrustCache[peerURL] = cloneTrustAttestations(attestations)
	if strings.TrimSpace(etag) != "" {
		s.peerTrustETags[peerURL] = strings.TrimSpace(etag)
	}
}

func (s *Service) cachedIssuerTrustETag(issuerURL string) string {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	return s.issuerTrustETags[normalizePeerURL(issuerURL)]
}

func (s *Service) cachedIssuerTrust(issuerURL string) (map[string]proto.RelayTrustAttestation, bool) {
	s.peerMu.RLock()
	defer s.peerMu.RUnlock()
	attestations, ok := s.issuerTrustCache[normalizePeerURL(issuerURL)]
	if !ok {
		return nil, false
	}
	return cloneTrustAttestations(attestations), true
}

func (s *Service) setIssuerTrustCache(issuerURL string, etag string, attestations map[string]proto.RelayTrustAttestation) {
	issuerURL = normalizePeerURL(issuerURL)
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.issuerTrustCache == nil {
		s.issuerTrustCache = make(map[string]map[string]proto.RelayTrustAttestation)
	}
	if s.issuerTrustETags == nil {
		s.issuerTrustETags = make(map[string]string)
	}
	s.issuerTrustCache[issuerURL] = cloneTrustAttestations(attestations)
	if strings.TrimSpace(etag) != "" {
		s.issuerTrustETags[issuerURL] = strings.TrimSpace(etag)
	}
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
	if !s.peerTrustStrict {
		return nil
	}
	peerURL = normalizePeerURL(peerURL)
	s.peerTrustMu.Lock()
	defer s.peerTrustMu.Unlock()

	filtered := dedupeStrings(pubB64Set)
	if len(filtered) == 0 {
		return fmt.Errorf("peer returned no pubkeys")
	}
	trusted, err := loadPeerTrustedKeys(s.peerTrustFile)
	if err != nil {
		return err
	}
	if pinned, ok := trusted[peerURL]; ok {
		for _, key := range filtered {
			if pinned == key {
				return nil
			}
		}
		return fmt.Errorf("peer key mismatch for %s", peerURL)
	}
	if s.peerTrustTOFU {
		if err := appendPeerTrustedKey(s.peerTrustFile, peerURL, filtered[0]); err != nil {
			return err
		}
		log.Printf("directory TOFU pinned peer key for %s to %s", peerURL, s.peerTrustFile)
		return nil
	}
	return fmt.Errorf("peer key is not trusted for %s", peerURL)
}

func (s *Service) loadOrCreateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if s.privateKeyPath == "" {
		return crypto.GenerateEd25519Keypair()
	}
	b, err := os.ReadFile(s.privateKeyPath)
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
	if err := os.MkdirAll(filepath.Dir(s.privateKeyPath), 0o755); err != nil {
		return nil, nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString(priv)
	if err := os.WriteFile(s.privateKeyPath, []byte(enc+"\n"), 0o600); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	peerURL := normalizePeerURL(req.PeerURL)
	if peerURL == "" || !s.isKnownPeer(peerURL) {
		http.Error(w, "unknown peer", http.StatusForbidden)
		return
	}
	pub, err := s.fetchPeerPubKey(r.Context(), peerURL)
	if err != nil {
		http.Error(w, "peer pubkey unavailable", http.StatusBadGateway)
		return
	}
	now := time.Now().UTC()
	validated := make([]proto.RelayDescriptor, 0, len(req.Relays))
	for _, desc := range req.Relays {
		if strings.TrimSpace(desc.RelayID) == "" {
			continue
		}
		if desc.Role != "entry" && desc.Role != "exit" {
			continue
		}
		if err := crypto.VerifyRelayDescriptor(desc, pub); err != nil {
			continue
		}
		if !desc.ValidUntil.IsZero() && now.After(desc.ValidUntil) {
			continue
		}
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
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
	s.upsertProviderRelay(desc)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.ProviderRelayUpsertResponse{Accepted: true, Relay: desc})
}

func providerTokenFromRequest(r *http.Request, bodyToken string) string {
	if token := parseBearerToken(r.Header.Get("Authorization")); token != "" {
		return token
	}
	return strings.TrimSpace(bodyToken)
}

func parseBearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(raw) > len(prefix) && strings.EqualFold(raw[:len(prefix)], prefix) {
		return strings.TrimSpace(raw[len(prefix):])
	}
	return ""
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

	var lastErr error
	for _, issuerURL := range issuerURLs {
		pubs, declaredIssuer, err := s.fetchIssuerPubKeys(ctx, issuerURL)
		if err != nil {
			lastErr = err
			continue
		}
		for _, pub := range pubs {
			claims, verifyErr := crypto.VerifyClaims(token, pub)
			if verifyErr != nil {
				lastErr = verifyErr
				continue
			}
			if declaredIssuer != "" && strings.TrimSpace(claims.Issuer) != "" && strings.TrimSpace(claims.Issuer) != declaredIssuer {
				lastErr = fmt.Errorf("provider token issuer mismatch")
				continue
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

func (s *Service) buildProviderRelayDescriptor(req proto.ProviderRelayUpsertRequest, claims crypto.CapabilityClaims, now time.Time) (proto.RelayDescriptor, error) {
	role := strings.TrimSpace(strings.ToLower(req.Role))
	if role != "entry" && role != "exit" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider relay role must be entry or exit")
	}
	relayID := strings.TrimSpace(req.RelayID)
	if relayID == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider relay_id is required")
	}
	pubKey := normalizePeerPubKey(req.PubKey)
	if pubKey == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider pub_key invalid")
	}
	endpoint := strings.TrimSpace(req.Endpoint)
	if endpoint == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider endpoint is required")
	}
	controlURL := normalizeHTTPURL(req.ControlURL)
	if controlURL == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("provider control_url is required")
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
		ValidUntil:     now.Add(ttl),
	}
	if role == "exit" {
		desc.Reputation = clampScore(req.Reputation)
		desc.Uptime = clampScore(req.Uptime)
		desc.Capacity = clampScore(req.Capacity)
		desc.AbusePenalty = clampScore(req.AbusePenalty)
		desc.BondScore = clampScore(req.BondScore)
		desc.StakeScore = clampScore(req.StakeScore)
	}
	return desc, nil
}

func (s *Service) upsertProviderRelay(desc proto.RelayDescriptor) {
	key := relayKey(desc.RelayID, desc.Role)
	desc.Signature = ""
	s.providerMu.Lock()
	if s.providerRelays == nil {
		s.providerRelays = make(map[string]proto.RelayDescriptor)
	}
	prev, ok := s.providerRelays[key]
	if ok && prev.ValidUntil.After(desc.ValidUntil) {
		desc.ValidUntil = prev.ValidUntil
	}
	s.providerRelays[key] = desc
	s.providerMu.Unlock()
}

func (s *Service) isKnownPeer(peerURL string) bool {
	peerURL = normalizePeerURL(peerURL)
	if peerURL == "" {
		return false
	}
	for _, known := range s.snapshotSyncPeers(time.Now()) {
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
	return merged
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
		role := strings.TrimSpace(score.Role)
		if role == "" {
			role = "exit"
		}
		if role != "exit" || strings.TrimSpace(score.RelayID) == "" {
			return
		}
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
		if relayDesc.Role != "exit" {
			continue
		}
		add(proto.RelaySelectionScore{
			RelayID:      relayDesc.RelayID,
			Role:         relayDesc.Role,
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
		appealVotes  int
		appealOps    map[string]struct{}
		appealUntil  []int64
		appealMeta   map[adjudicationMetadataPair]int
	}
	agg := make(map[string]trustAgg)
	nowUnix := time.Now().Unix()
	metaMinVotes := maxInt(1, s.adjudicationMetaMin)
	disputeMinVotes := s.effectiveFinalDisputeMinVotes()
	appealMinVotes := s.effectiveFinalAppealMinVotes()
	adjudicationMinOperators := s.effectiveFinalAdjudicationMinOperators()
	adjudicationMinRatio := s.effectiveFinalAdjudicationMinRatio()
	add := func(att proto.RelayTrustAttestation) {
		role := strings.TrimSpace(att.Role)
		if role == "" {
			role = "exit"
		}
		if role != "exit" || strings.TrimSpace(att.RelayID) == "" {
			return
		}
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
			a.appealUntil = append(a.appealUntil, appealUntil)
			recordMetadataPairVote(&a.appealMeta, att.AppealCase, att.AppealRef)
		}
		agg[key] = a
	}

	for _, relayDesc := range relays {
		if relayDesc.Role != "exit" {
			continue
		}
		add(proto.RelayTrustAttestation{
			RelayID:      relayDesc.RelayID,
			Role:         relayDesc.Role,
			OperatorID:   relayDesc.OperatorID,
			Reputation:   relayDesc.Reputation,
			Uptime:       relayDesc.Uptime,
			Capacity:     relayDesc.Capacity,
			AbusePenalty: relayDesc.AbusePenalty,
			BondScore:    relayDesc.BondScore,
			StakeScore:   relayDesc.StakeScore,
			Confidence:   1,
		})
	}
	for _, att := range s.snapshotPeerTrust() {
		add(att)
	}
	for _, att := range s.snapshotIssuerTrust() {
		add(att)
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
			len(a.disputeOps) >= adjudicationMinOperators {
			if tierCap, ok := pickConsensusTier(a.disputeCaps); ok {
				att.TierCap = tierCap
				att.DisputeUntil = pickMedianUnix(a.disputeUntil)
				att.DisputeCase, att.DisputeRef = pickVotedMetadataPair(a.disputeMeta, metaMinVotes)
			}
		}
		if meetsAdjudicationQuorum(a.appealVotes, a.count, appealMinVotes, adjudicationMinRatio) &&
			len(a.appealOps) >= adjudicationMinOperators {
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
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return v
	}
	return "http://" + v
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
	caps := append([]string(nil), clone.Capabilities...)
	sort.Strings(caps)
	clone.Capabilities = caps
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
	b, err := os.ReadFile(path)
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
	peerURL = normalizePeerURL(peerURL)
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(peerURL + " " + key + "\n")
	return err
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
		if count > bestVotes || (count == bestVotes && tier > bestTier) {
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

func (s *Service) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.TrimSpace(r.Header.Get("X-Admin-Token")) != s.adminToken {
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
	if strings.TrimSpace(r.Header.Get("X-Admin-Token")) != s.adminToken {
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
	if strings.TrimSpace(r.Header.Get("X-Admin-Token")) != s.adminToken {
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
	if strings.TrimSpace(r.Header.Get("X-Admin-Token")) != s.adminToken {
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
		if status.Discovered {
			status.CoolingDown = s.isDiscoveredPeerCoolingDownLocked(url, now)
		}
		status.Eligible = status.Configured || (status.Discovered && !status.CoolingDown)
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
		role := strings.TrimSpace(desc.Role)
		if role == "" {
			role = "exit"
		}
		if strings.TrimSpace(desc.RelayID) == "" {
			continue
		}
		if operator := normalizeOperatorID(desc.OperatorID); operator != "" {
			relayOperators[relayKey(desc.RelayID, role)] = operator
		}
	}
	for _, att := range aggregated {
		role := strings.TrimSpace(att.Role)
		if role == "" {
			role = "exit"
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
		role := strings.TrimSpace(att.Role)
		if role == "" {
			role = "exit"
		}
		if role != "exit" || strings.TrimSpace(att.RelayID) == "" {
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
		role := strings.TrimSpace(att.Role)
		if role == "" {
			role = "exit"
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
	return os.WriteFile(s.privateKeyPath, []byte(enc+"\n"), 0o600)
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
	return os.WriteFile(path, []byte(data), 0o644)
}

func loadPreviousPubKeys(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
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
