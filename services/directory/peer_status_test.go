package directory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestSnapshotSyncPeersSkipsCoolingDownDiscoveredPeer(t *testing.T) {
	now := time.Now().UTC()
	discoveredURL := "http://peer-down.local"
	s := &Service{
		peerURLs:             []string{"http://seed.local"},
		peerDiscoveryEnabled: true,
		discoveredPeers: map[string]time.Time{
			discoveredURL: now,
		},
		discoveredPeerVoters: map[string]map[string]time.Time{
			discoveredURL: {
				"op-seed": now,
			},
		},
		discoveredPeerHealth: map[string]discoveredPeerHealth{
			discoveredURL: {
				consecutiveFailures: 3,
				cooldownUntil:       now.Add(2 * time.Minute),
				lastError:           "dial timeout",
			},
		},
	}

	peers := s.snapshotSyncPeers(now.Add(30 * time.Second))
	if containsString(peers, discoveredURL) {
		t.Fatalf("expected cooling-down discovered peer to be excluded from sync set")
	}
	if !containsString(peers, "http://seed.local") {
		t.Fatalf("expected configured seed peer to remain in sync set")
	}

	peers = s.snapshotSyncPeers(now.Add(3 * time.Minute))
	if !containsString(peers, discoveredURL) {
		t.Fatalf("expected discovered peer to return after cooldown expiry")
	}
}

func TestRecordPeerSyncFailureAndSuccessManageCooldown(t *testing.T) {
	now := time.Now().UTC()
	discoveredURL := "http://peer-flaky.local"
	s := &Service{
		peerDiscoveryEnabled:    true,
		peerDiscoveryFailN:      2,
		peerDiscoveryBackoff:    20 * time.Second,
		peerDiscoveryBackoffMax: 2 * time.Minute,
		discoveredPeers: map[string]time.Time{
			discoveredURL: now,
		},
		discoveredPeerVoters: map[string]map[string]time.Time{
			discoveredURL: {
				"op-seed": now,
			},
		},
		discoveredPeerHealth: make(map[string]discoveredPeerHealth),
	}

	s.recordPeerSyncFailure(discoveredURL, now, errors.New("dial timeout"))
	health := s.discoveredPeerHealth[discoveredURL]
	if health.consecutiveFailures != 1 {
		t.Fatalf("expected one consecutive failure, got %d", health.consecutiveFailures)
	}
	if !health.cooldownUntil.IsZero() {
		t.Fatalf("expected no cooldown before threshold")
	}

	s.recordPeerSyncFailure(discoveredURL, now.Add(time.Second), errors.New("tls failure"))
	health = s.discoveredPeerHealth[discoveredURL]
	if health.consecutiveFailures != 2 {
		t.Fatalf("expected two consecutive failures, got %d", health.consecutiveFailures)
	}
	if health.cooldownUntil.Before(now.Add(20 * time.Second)) {
		t.Fatalf("expected cooldown to be applied after threshold")
	}
	if health.lastError == "" {
		t.Fatalf("expected last error recorded")
	}

	peers := s.snapshotSyncPeers(now.Add(2 * time.Second))
	if containsString(peers, discoveredURL) {
		t.Fatalf("expected peer excluded while in cooldown")
	}

	s.recordPeerSyncSuccess(discoveredURL, now.Add(30*time.Second))
	health = s.discoveredPeerHealth[discoveredURL]
	if health.consecutiveFailures != 0 {
		t.Fatalf("expected failure counter reset after success, got %d", health.consecutiveFailures)
	}
	if !health.cooldownUntil.IsZero() {
		t.Fatalf("expected cooldown cleared after success")
	}
	if health.lastError != "" {
		t.Fatalf("expected last error cleared after success, got %q", health.lastError)
	}

	peers = s.snapshotSyncPeers(now.Add(31 * time.Second))
	if !containsString(peers, discoveredURL) {
		t.Fatalf("expected peer re-enabled after success")
	}
}

func TestSyncPeerRelaysAppliesBackoffToFailingDiscoveredPeer(t *testing.T) {
	urlSeed := "http://seed-a.local"
	urlDiscovered := "http://peer-unreachable.local"
	pubSeed, privSeed, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("seed keygen: %v", err)
	}
	now := time.Now().UTC()
	relaySeed := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-seed",
		Role:       "exit",
		OperatorID: "op-seed",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privSeed)
	peerFeed := proto.DirectoryPeerListResponse{
		Operator:    "op-seed",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(40 * time.Second).Unix(),
		Peers:       []string{urlSeed, urlDiscovered},
		PeerHints: []proto.DirectoryPeerHint{
			{URL: urlSeed, Operator: "op-seed", PubKey: base64.RawURLEncoding.EncodeToString(pubSeed)},
		},
	}
	feedSig, err := signDirectoryPeerList(peerFeed, privSeed)
	if err != nil {
		t.Fatalf("sign peer feed: %v", err)
	}
	peerFeed.Signature = feedSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlSeed + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubSeed)}),
		urlSeed + "/v1/peers":  jsonResp(peerFeed),
		urlSeed + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relaySeed}}),
		// No handlers for discovered peer URL to force sync failures.
	}

	s := &Service{
		operatorID:              "op-local",
		localURL:                "http://local-dir",
		peerURLs:                []string{urlSeed},
		peerDiscoveryEnabled:    true,
		peerDiscoveryTTL:        10 * time.Minute,
		peerDiscoveryMinVotes:   1,
		peerDiscoveryFailN:      1,
		peerDiscoveryBackoff:    60 * time.Second,
		peerDiscoveryBackoffMax: 5 * time.Minute,
		peerRelays:              make(map[string]proto.RelayDescriptor),
		discoveredPeers:         make(map[string]time.Time),
		discoveredPeerVoters:    make(map[string]map[string]time.Time),
		discoveredPeerHealth:    make(map[string]discoveredPeerHealth),
		peerHintPubKeys:         make(map[string]string),
		peerHintOperators:       make(map[string]string),
		peerRelayETags:          make(map[string]string),
		peerRelayCache:          make(map[string][]proto.RelayDescriptor),
		httpClient:              &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays discovery pass: %v", err)
	}
	if !containsString(s.snapshotSyncPeers(time.Now()), urlDiscovered) {
		t.Fatalf("expected discovered peer in sync set before failure")
	}

	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays failure pass: %v", err)
	}
	health := s.discoveredPeerHealth[urlDiscovered]
	if health.consecutiveFailures < 1 {
		t.Fatalf("expected discovered peer failure recorded")
	}
	if health.cooldownUntil.IsZero() {
		t.Fatalf("expected discovered peer cooldown to be applied")
	}
	if containsString(s.snapshotSyncPeers(time.Now()), urlDiscovered) {
		t.Fatalf("expected discovered peer excluded while cooling down")
	}
}

func TestHandlePeerStatusRequiresAdminToken(t *testing.T) {
	s := &Service{adminToken: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/peer-status", nil)
	rr := httptest.NewRecorder()
	s.handlePeerStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandlePeerStatusReturnsConfiguredAndDiscoveredState(t *testing.T) {
	now := time.Now().UTC()
	discoveredURL := "http://peer-managed.local"
	validHintKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	s := &Service{
		adminToken:           "secret",
		peerURLs:             []string{"http://seed.local"},
		peerDiscoveryEnabled: true,
		discoveredPeers: map[string]time.Time{
			discoveredURL: now,
		},
		discoveredPeerVoters: map[string]map[string]time.Time{
			discoveredURL: {
				"op-a": now,
				"op-b": now,
			},
		},
		discoveredPeerHealth: map[string]discoveredPeerHealth{
			discoveredURL: {
				lastSuccess:         now.Add(-2 * time.Minute),
				lastFailure:         now.Add(-10 * time.Second),
				consecutiveFailures: 4,
				cooldownUntil:       now.Add(90 * time.Second),
				lastError:           "dial timeout",
			},
		},
		peerHintOperators: map[string]string{
			discoveredURL: "op-peer",
		},
		peerHintPubKeys: map[string]string{
			discoveredURL: validHintKey,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/peer-status", nil)
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	s.handlePeerStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var out proto.DirectoryPeerStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode peer status response: %v", err)
	}
	if len(out.Peers) != 2 {
		t.Fatalf("expected 2 peers in status response, got %d", len(out.Peers))
	}

	byURL := make(map[string]proto.DirectoryPeerStatus, len(out.Peers))
	for _, peer := range out.Peers {
		byURL[peer.URL] = peer
	}

	seed, ok := byURL["http://seed.local"]
	if !ok {
		t.Fatalf("expected configured seed peer status")
	}
	if !seed.Configured || !seed.Eligible || seed.CoolingDown {
		t.Fatalf("unexpected configured peer status: %+v", seed)
	}

	discovered, ok := byURL[discoveredURL]
	if !ok {
		t.Fatalf("expected discovered peer status")
	}
	if !discovered.Discovered {
		t.Fatalf("expected discovered flag true")
	}
	if discovered.Eligible {
		t.Fatalf("expected discovered peer in cooldown to be ineligible")
	}
	if !discovered.CoolingDown {
		t.Fatalf("expected discovered peer to be cooling down")
	}
	if discovered.VoteOperators != 2 {
		t.Fatalf("expected vote operator count=2, got %d", discovered.VoteOperators)
	}
	if discovered.HintOperator != "op-peer" {
		t.Fatalf("expected hint operator persisted, got %q", discovered.HintOperator)
	}
	if discovered.HintPubKey != validHintKey {
		t.Fatalf("expected hint pubkey persisted")
	}
	if discovered.CooldownUntil == 0 {
		t.Fatalf("expected cooldown timestamp")
	}
}
