package directory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

type mockRoundTripper struct {
	handlers map[string]func(*http.Request) (*http.Response, error)
}

func (m mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if h, ok := m.handlers[req.URL.String()]; ok {
		return h(req)
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

func TestFetchPeerRelaysVerifiesSignature(t *testing.T) {
	peerURL := "http://peer-a.local"
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	desc := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-peer-1",
		Role:       "exit",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		peerURL + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
		peerURL + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{desc}}),
	}

	s := &Service{httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}}}
	got, err := s.fetchPeerRelays(context.Background(), peerURL)
	if err != nil {
		t.Fatalf("fetchPeerRelays: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one relay, got %d", len(got))
	}
	if got[0].RelayID != "exit-peer-1" {
		t.Fatalf("unexpected relay id: %s", got[0].RelayID)
	}
	if got[0].Signature != "" {
		t.Fatalf("expected signature cleared for local re-signing")
	}
}

func TestFetchPeerPubKeyRejectsSignedHintMismatch(t *testing.T) {
	peerURL := "http://peer-a.local"
	actualPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("actual keygen: %v", err)
	}
	hintPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("hint keygen: %v", err)
	}
	handlers := map[string]func(*http.Request) (*http.Response, error){
		peerURL + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(actualPub)}),
	}
	s := &Service{
		peerHintPubKeys: map[string]string{
			peerURL: base64.RawURLEncoding.EncodeToString(hintPub),
		},
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if _, err := s.fetchPeerPubKey(context.Background(), peerURL); err == nil {
		t.Fatalf("expected signed peer hint mismatch rejection")
	}
}

func TestSyncPeerRelaysMergesSources(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	entry := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "entry-a",
		Role:       "entry",
		Endpoint:   "127.0.0.1:51820",
		ValidUntil: time.Now().Add(time.Minute),
	}, privA)
	exit := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-b",
		Role:       "exit",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: time.Now().Add(time.Minute),
	}, privB)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{entry}}),
		urlB + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{exit}}),
	}
	s := &Service{
		peerURLs:     []string{urlA, urlB},
		peerMinVotes: 1,
		peerRelays:   make(map[string]proto.RelayDescriptor),
		httpClient:   &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	peers := s.snapshotPeerRelays()
	if len(peers) != 2 {
		t.Fatalf("expected 2 merged peer relays, got %d", len(peers))
	}
}

func TestBuildRelayDescriptorsIncludesPeerRelay(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s := &Service{
		pubKey:            pub,
		entryEndpoints:    []string{"127.0.0.1:51820"},
		endpointRotateSec: 30,
		peerRelays: map[string]proto.RelayDescriptor{
			relayKey("exit-peer-1", "exit"): {
				RelayID:    "exit-peer-1",
				Role:       "exit",
				Endpoint:   "127.0.0.1:51831",
				ControlURL: "http://127.0.0.1:8184",
				ValidUntil: time.Now().Add(time.Minute),
			},
		},
	}
	relays := s.buildRelayDescriptors(time.Now())
	found := false
	for _, desc := range relays {
		if desc.RelayID == "exit-peer-1" && desc.Role == "exit" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected synced peer relay in published descriptors")
	}
}

func TestSyncPeerRelaysConflictRequiresMinVotes(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	relayFromA := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		Endpoint:   "127.0.0.1:51821",
		ControlURL: "http://exit-a.local",
		ValidUntil: time.Now().Add(time.Minute),
	}, privA)
	relayFromB := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://exit-b.local",
		ValidUntil: time.Now().Add(time.Minute),
	}, privB)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayFromA}}),
		urlB + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayFromB}}),
	}
	s := &Service{
		peerURLs:     []string{urlA, urlB},
		peerMinVotes: 2,
		peerRelays:   make(map[string]proto.RelayDescriptor),
		httpClient:   &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	peers := s.snapshotPeerRelays()
	if len(peers) != 0 {
		t.Fatalf("expected unresolved conflict to be dropped, got %d relays", len(peers))
	}
}

func TestSyncPeerRelaysConflictSelectsQuorumVariant(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	urlC := "http://peer-c.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	pubC, privC, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenC: %v", err)
	}
	agreedA := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:      "exit-shared",
		Role:         "exit",
		Endpoint:     "127.0.0.1:51821",
		ControlURL:   "http://exit-agreed.local",
		OperatorID:   "op-agreed",
		Capabilities: []string{"tiered-policy", "wg"},
		ValidUntil:   time.Now().Add(time.Minute),
	}, privA)
	agreedB := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:      "exit-shared",
		Role:         "exit",
		Endpoint:     "127.0.0.1:51821",
		ControlURL:   "http://exit-agreed.local",
		OperatorID:   "op-agreed",
		Capabilities: []string{"wg", "tiered-policy"},
		ValidUntil:   time.Now().Add(2 * time.Minute),
	}, privB)
	conflicting := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:      "exit-shared",
		Role:         "exit",
		Endpoint:     "127.0.0.1:52821",
		ControlURL:   "http://exit-conflict.local",
		OperatorID:   "op-conflict",
		Capabilities: []string{"wg"},
		ValidUntil:   time.Now().Add(3 * time.Minute),
	}, privC)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{agreedA}}),
		urlB + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{agreedB}}),
		urlC + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubC)}),
		urlC + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{conflicting}}),
	}
	s := &Service{
		peerURLs:     []string{urlA, urlB, urlC},
		peerMinVotes: 2,
		peerRelays:   make(map[string]proto.RelayDescriptor),
		httpClient:   &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	peers := s.snapshotPeerRelays()
	if len(peers) != 1 {
		t.Fatalf("expected one quorum relay, got %d", len(peers))
	}
	got := peers[0]
	if got.Endpoint != "127.0.0.1:51821" || got.ControlURL != "http://exit-agreed.local" {
		t.Fatalf("expected quorum variant selected, got endpoint=%s control=%s", got.Endpoint, got.ControlURL)
	}
}

func TestEnforcePeerTrustTOFUPins(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	file := filepath.Join(t.TempDir(), "peer_trusted_keys.txt")
	s := &Service{
		peerTrustStrict: true,
		peerTrustTOFU:   true,
		peerTrustFile:   file,
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	if err := s.enforcePeerTrust("peer-a.local", pubB64); err != nil {
		t.Fatalf("expected tofu pin success: %v", err)
	}
	loaded, err := loadPeerTrustedKeys(file)
	if err != nil {
		t.Fatalf("load peer trusted keys: %v", err)
	}
	if got := loaded["http://peer-a.local"]; got != pubB64 {
		t.Fatalf("expected pinned key, got %q", got)
	}
}

func TestEnforcePeerTrustRejectsMismatch(t *testing.T) {
	pubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	file := filepath.Join(t.TempDir(), "peer_trusted_keys.txt")
	if err := appendPeerTrustedKey(file, "http://peer-a.local", base64.RawURLEncoding.EncodeToString(pubA)); err != nil {
		t.Fatalf("append trusted key: %v", err)
	}
	s := &Service{
		peerTrustStrict: true,
		peerTrustTOFU:   false,
		peerTrustFile:   file,
	}
	if err := s.enforcePeerTrust("http://peer-a.local", base64.RawURLEncoding.EncodeToString(pubB)); err == nil {
		t.Fatalf("expected peer trust mismatch rejection")
	}
}

func TestPreparePeerDescriptorLoopResistanceAndHopLimit(t *testing.T) {
	s := &Service{operatorID: "op-self", peerMaxHops: 2}
	if _, ok := s.preparePeerDescriptor(proto.RelayDescriptor{OriginOperator: "op-self", HopCount: 0}); ok {
		t.Fatalf("expected looped origin descriptor to be rejected")
	}
	if _, ok := s.preparePeerDescriptor(proto.RelayDescriptor{OriginOperator: "op-peer", HopCount: 2}); ok {
		t.Fatalf("expected descriptor beyond hop limit to be rejected")
	}
	out, ok := s.preparePeerDescriptor(proto.RelayDescriptor{OperatorID: "op-peer", HopCount: 1})
	if !ok {
		t.Fatalf("expected descriptor inside hop limit accepted")
	}
	if out.OriginOperator != "op-peer" || out.HopCount != 2 {
		t.Fatalf("unexpected normalized descriptor origin=%s hop=%d", out.OriginOperator, out.HopCount)
	}
}

func TestFetchPeerRelaysUsesETagCache(t *testing.T) {
	peerURL := "http://peer-a.local"
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	desc := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-peer-1",
		Role:       "exit",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)
	const etag = "\"etag-peer-a\""
	relayCalls := 0
	handlers := map[string]func(*http.Request) (*http.Response, error){
		peerURL + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
		peerURL + "/v1/relays": func(req *http.Request) (*http.Response, error) {
			relayCalls++
			if req.Header.Get("If-None-Match") == etag {
				return &http.Response{
					StatusCode: http.StatusNotModified,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			b, _ := json.Marshal(proto.RelayListResponse{Relays: []proto.RelayDescriptor{desc}})
			h := make(http.Header)
			h.Set("ETag", etag)
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     h,
				Body:       io.NopCloser(bytes.NewReader(b)),
			}, nil
		},
	}
	s := &Service{
		httpClient:     &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		peerRelayETags: make(map[string]string),
		peerRelayCache: make(map[string][]proto.RelayDescriptor),
	}
	first, err := s.fetchPeerRelays(context.Background(), peerURL)
	if err != nil {
		t.Fatalf("first fetchPeerRelays: %v", err)
	}
	second, err := s.fetchPeerRelays(context.Background(), peerURL)
	if err != nil {
		t.Fatalf("second fetchPeerRelays: %v", err)
	}
	if relayCalls != 2 {
		t.Fatalf("expected two relay handler calls, got %d", relayCalls)
	}
	if len(first) != 1 || len(second) != 1 || first[0].RelayID != second[0].RelayID {
		t.Fatalf("expected cached relay response on second fetch")
	}
}

func TestSyncPeerRelaysAggregatesPeerSelectionScores(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now()
	relayA := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		OperatorID: "op-shared",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privA)
	relayB := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		OperatorID: "op-shared",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privB)
	feedA := proto.RelaySelectionFeedResponse{
		Operator:    "op-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Scores: []proto.RelaySelectionScore{
			{RelayID: "exit-shared", Role: "exit", Reputation: 0.9, Uptime: 0.8, Capacity: 0.7, AbusePenalty: 0.1},
		},
	}
	feedASig, err := crypto.SignRelaySelectionFeed(feedA, privA)
	if err != nil {
		t.Fatalf("sign feedA: %v", err)
	}
	feedA.Signature = feedASig
	feedB := proto.RelaySelectionFeedResponse{
		Operator:    "op-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Scores: []proto.RelaySelectionScore{
			{RelayID: "exit-shared", Role: "exit", Reputation: 0.7, Uptime: 0.6, Capacity: 0.5, AbusePenalty: 0.2},
		},
	}
	feedBSig, err := crypto.SignRelaySelectionFeed(feedB, privB)
	if err != nil {
		t.Fatalf("sign feedB: %v", err)
	}
	feedB.Signature = feedBSig
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey":         jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/relays":         jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayA}}),
		urlA + "/v1/selection-feed": jsonResp(feedA),
		urlB + "/v1/pubkey":         jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/relays":         jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayB}}),
		urlB + "/v1/selection-feed": jsonResp(feedB),
	}
	s := &Service{
		operatorID:        "op-local",
		peerURLs:          []string{urlA, urlB},
		peerMinVotes:      1,
		peerScoreMinVotes: 2,
		peerMaxHops:       2,
		peerRelays:        make(map[string]proto.RelayDescriptor),
		peerScores:        make(map[string]proto.RelaySelectionScore),
		peerRelayETags:    make(map[string]string),
		peerRelayCache:    make(map[string][]proto.RelayDescriptor),
		peerScoreETags:    make(map[string]string),
		peerScoreCache:    make(map[string]map[string]proto.RelaySelectionScore),
		httpClient:        &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	scores := s.snapshotPeerScores()
	score, ok := scores[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected aggregated peer score")
	}
	if score.Reputation < 0.79 || score.Reputation > 0.81 {
		t.Fatalf("expected averaged reputation around 0.8, got %f", score.Reputation)
	}
}

func TestSyncPeerRelaysAggregatesPeerTrustAttestations(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now()
	relayA := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		OperatorID: "op-shared",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privA)
	relayB := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		OperatorID: "op-shared",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privB)
	trustA := proto.RelayTrustAttestationFeedResponse{
		Operator:    "op-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-shared",
				Role:         "exit",
				OperatorID:   "op-shared",
				Reputation:   0.8,
				Uptime:       0.7,
				Capacity:     0.6,
				AbusePenalty: 0.1,
				BondScore:    0.5,
				StakeScore:   0.4,
				Confidence:   0.9,
			},
		},
	}
	trustASig, err := crypto.SignRelayTrustAttestationFeed(trustA, privA)
	if err != nil {
		t.Fatalf("sign trustA: %v", err)
	}
	trustA.Signature = trustASig
	trustB := proto.RelayTrustAttestationFeedResponse{
		Operator:    "op-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-shared",
				Role:         "exit",
				OperatorID:   "op-shared",
				Reputation:   0.6,
				Uptime:       0.5,
				Capacity:     0.4,
				AbusePenalty: 0.2,
				BondScore:    0.3,
				StakeScore:   0.2,
				Confidence:   0.8,
			},
		},
	}
	trustBSig, err := crypto.SignRelayTrustAttestationFeed(trustB, privB)
	if err != nil {
		t.Fatalf("sign trustB: %v", err)
	}
	trustB.Signature = trustBSig
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayA}}),
		urlA + "/v1/trust-attestations": jsonResp(trustA),
		urlB + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayB}}),
		urlB + "/v1/trust-attestations": jsonResp(trustB),
	}
	s := &Service{
		operatorID:        "op-local",
		peerURLs:          []string{urlA, urlB},
		peerMinVotes:      1,
		peerTrustMinVotes: 2,
		peerMaxHops:       2,
		peerRelays:        make(map[string]proto.RelayDescriptor),
		peerScores:        make(map[string]proto.RelaySelectionScore),
		peerTrust:         make(map[string]proto.RelayTrustAttestation),
		peerRelayETags:    make(map[string]string),
		peerRelayCache:    make(map[string][]proto.RelayDescriptor),
		peerScoreETags:    make(map[string]string),
		peerScoreCache:    make(map[string]map[string]proto.RelaySelectionScore),
		peerTrustETags:    make(map[string]string),
		peerTrustCache:    make(map[string]map[string]proto.RelayTrustAttestation),
		httpClient:        &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	att := s.snapshotPeerTrust()
	got, ok := att[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected aggregated trust attestation")
	}
	if got.BondScore < 0.39 || got.BondScore > 0.41 {
		t.Fatalf("expected averaged bond score around 0.4, got %f", got.BondScore)
	}
	if got.StakeScore < 0.29 || got.StakeScore > 0.31 {
		t.Fatalf("expected averaged stake score around 0.3, got %f", got.StakeScore)
	}
}

func TestSyncIssuerTrustAggregatesAttestations(t *testing.T) {
	urlA := "http://issuer-a.local"
	urlB := "http://issuer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now()
	trustA := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "exit-shared",
				Role:       "exit",
				OperatorID: "op-shared",
				Reputation: 0.85,
				BondScore:  0.6,
				StakeScore: 0.5,
				Confidence: 0.9,
			},
		},
	}
	trustASig, err := crypto.SignRelayTrustAttestationFeed(trustA, privA)
	if err != nil {
		t.Fatalf("sign trustA: %v", err)
	}
	trustA.Signature = trustASig
	trustB := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "exit-shared",
				Role:       "exit",
				OperatorID: "op-shared",
				Reputation: 0.65,
				BondScore:  0.4,
				StakeScore: 0.3,
				Confidence: 0.8,
			},
		},
	}
	trustBSig, err := crypto.SignRelayTrustAttestationFeed(trustB, privB)
	if err != nil {
		t.Fatalf("sign trustB: %v", err)
	}
	trustB.Signature = trustBSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-a", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubA)}}),
		urlA + "/v1/trust/relays": jsonResp(trustA),
		urlB + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-b", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubB)}}),
		urlB + "/v1/trust/relays": jsonResp(trustB),
	}

	s := &Service{
		issuerTrustURLs:     []string{urlA, urlB},
		issuerSyncSec:       5,
		issuerTrustMinVotes: 2,
		issuerTrust:         make(map[string]proto.RelayTrustAttestation),
		issuerTrustETags:    make(map[string]string),
		issuerTrustCache:    make(map[string]map[string]proto.RelayTrustAttestation),
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	if err := s.syncIssuerTrust(context.Background()); err != nil {
		t.Fatalf("syncIssuerTrust: %v", err)
	}
	gotMap := s.snapshotIssuerTrust()
	got, ok := gotMap[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected aggregated issuer trust attestation")
	}
	if got.Reputation < 0.74 || got.Reputation > 0.76 {
		t.Fatalf("expected averaged reputation around 0.75, got %f", got.Reputation)
	}
	if got.BondScore < 0.49 || got.BondScore > 0.51 {
		t.Fatalf("expected averaged bond score around 0.5, got %f", got.BondScore)
	}
}

func TestSyncIssuerTrustAppliesDisputeVoteThreshold(t *testing.T) {
	urlA := "http://issuer-a.local"
	urlB := "http://issuer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now()
	disputeUntil := now.Add(5 * time.Minute).Unix()
	trustA := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-shared",
				Role:         "exit",
				OperatorID:   "op-shared",
				Reputation:   0.80,
				AbusePenalty: 0.2,
				Confidence:   0.9,
				TierCap:      1,
				DisputeUntil: disputeUntil,
				DisputeCase:  "case-dispute-1",
				DisputeRef:   "evidence://dispute-1",
			},
		},
	}
	sigA, err := crypto.SignRelayTrustAttestationFeed(trustA, privA)
	if err != nil {
		t.Fatalf("sign trustA: %v", err)
	}
	trustA.Signature = sigA
	trustB := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-shared",
				Role:         "exit",
				OperatorID:   "op-shared",
				Reputation:   0.75,
				AbusePenalty: 0.1,
				Confidence:   0.8,
			},
		},
	}
	sigB, err := crypto.SignRelayTrustAttestationFeed(trustB, privB)
	if err != nil {
		t.Fatalf("sign trustB: %v", err)
	}
	trustB.Signature = sigB

	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-a", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubA)}}),
		urlA + "/v1/trust/relays": jsonResp(trustA),
		urlB + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-b", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubB)}}),
		urlB + "/v1/trust/relays": jsonResp(trustB),
	}

	s := &Service{
		issuerTrustURLs:       []string{urlA, urlB},
		issuerSyncSec:         5,
		issuerTrustMinVotes:   1,
		issuerDisputeMinVotes: 2,
		issuerTrust:           make(map[string]proto.RelayTrustAttestation),
		issuerTrustETags:      make(map[string]string),
		issuerTrustCache:      make(map[string]map[string]proto.RelayTrustAttestation),
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	if err := s.syncIssuerTrust(context.Background()); err != nil {
		t.Fatalf("syncIssuerTrust: %v", err)
	}
	gotMap := s.snapshotIssuerTrust()
	got, ok := gotMap[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected aggregated issuer trust attestation")
	}
	if got.TierCap != 0 || got.DisputeUntil != 0 {
		t.Fatalf("expected dispute omitted below vote threshold, got tier_cap=%d dispute_until=%d", got.TierCap, got.DisputeUntil)
	}
	if got.DisputeCase != "" || got.DisputeRef != "" {
		t.Fatalf("expected dispute metadata omitted below vote threshold, got case=%q ref=%q", got.DisputeCase, got.DisputeRef)
	}
}

func TestSyncIssuerTrustAppliesAppealVoteThreshold(t *testing.T) {
	urlA := "http://issuer-a.local"
	urlB := "http://issuer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now()
	appealUntil := now.Add(10 * time.Minute).Unix()
	trustA := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:     "exit-shared",
				Role:        "exit",
				OperatorID:  "op-shared",
				Reputation:  0.80,
				Confidence:  0.9,
				AppealUntil: appealUntil,
				AppealCase:  "case-appeal-1",
				AppealRef:   "evidence://appeal-1",
			},
		},
	}
	sigA, err := crypto.SignRelayTrustAttestationFeed(trustA, privA)
	if err != nil {
		t.Fatalf("sign trustA: %v", err)
	}
	trustA.Signature = sigA
	trustB := proto.RelayTrustAttestationFeedResponse{
		Operator:    "issuer-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "exit-shared",
				Role:       "exit",
				OperatorID: "op-shared",
				Reputation: 0.75,
				Confidence: 0.8,
			},
		},
	}
	sigB, err := crypto.SignRelayTrustAttestationFeed(trustB, privB)
	if err != nil {
		t.Fatalf("sign trustB: %v", err)
	}
	trustB.Signature = sigB
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-a", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubA)}}),
		urlA + "/v1/trust/relays": jsonResp(trustA),
		urlB + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-b", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubB)}}),
		urlB + "/v1/trust/relays": jsonResp(trustB),
	}

	s := &Service{
		issuerTrustURLs:       []string{urlA, urlB},
		issuerSyncSec:         5,
		issuerTrustMinVotes:   1,
		issuerDisputeMinVotes: 2,
		issuerTrust:           make(map[string]proto.RelayTrustAttestation),
		issuerTrustETags:      make(map[string]string),
		issuerTrustCache:      make(map[string]map[string]proto.RelayTrustAttestation),
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncIssuerTrust(context.Background()); err != nil {
		t.Fatalf("syncIssuerTrust: %v", err)
	}
	gotMap := s.snapshotIssuerTrust()
	got, ok := gotMap[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected aggregated issuer trust attestation")
	}
	if got.AppealUntil != 0 {
		t.Fatalf("expected appeal omitted below vote threshold, got appeal_until=%d", got.AppealUntil)
	}
	if got.AppealCase != "" || got.AppealRef != "" {
		t.Fatalf("expected appeal metadata omitted below vote threshold, got case=%q ref=%q", got.AppealCase, got.AppealRef)
	}
}

func TestSyncPeerRelaysAppliesAppealVoteThreshold(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now()
	relayA := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		OperatorID: "op-shared",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privA)
	relayB := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		OperatorID: "op-shared",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privB)
	appealUntil := now.Add(8 * time.Minute).Unix()
	trustA := proto.RelayTrustAttestationFeedResponse{
		Operator:    "op-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:     "exit-shared",
				Role:        "exit",
				OperatorID:  "op-shared",
				Reputation:  0.8,
				Confidence:  0.9,
				AppealUntil: appealUntil,
				AppealCase:  "case-peer-appeal-1",
				AppealRef:   "evidence://peer-appeal-1",
			},
		},
	}
	sigA, err := crypto.SignRelayTrustAttestationFeed(trustA, privA)
	if err != nil {
		t.Fatalf("sign trustA: %v", err)
	}
	trustA.Signature = sigA
	trustB := proto.RelayTrustAttestationFeedResponse{
		Operator:    "op-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "exit-shared",
				Role:       "exit",
				OperatorID: "op-shared",
				Reputation: 0.7,
				Confidence: 0.8,
			},
		},
	}
	sigB, err := crypto.SignRelayTrustAttestationFeed(trustB, privB)
	if err != nil {
		t.Fatalf("sign trustB: %v", err)
	}
	trustB.Signature = sigB

	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayA}}),
		urlA + "/v1/trust-attestations": jsonResp(trustA),
		urlB + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayB}}),
		urlB + "/v1/trust-attestations": jsonResp(trustB),
	}
	s := &Service{
		operatorID:          "op-local",
		peerURLs:            []string{urlA, urlB},
		peerMinVotes:        1,
		peerTrustMinVotes:   1,
		peerDisputeMinVotes: 1,
		peerAppealMinVotes:  2,
		peerRelays:          make(map[string]proto.RelayDescriptor),
		peerTrust:           make(map[string]proto.RelayTrustAttestation),
		peerRelayETags:      make(map[string]string),
		peerRelayCache:      make(map[string][]proto.RelayDescriptor),
		peerTrustETags:      make(map[string]string),
		peerTrustCache:      make(map[string]map[string]proto.RelayTrustAttestation),
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	gotMap := s.snapshotPeerTrust()
	got, ok := gotMap[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected aggregated trust attestation")
	}
	if got.AppealUntil != 0 {
		t.Fatalf("expected appeal omitted below peer appeal threshold, got appeal_until=%d", got.AppealUntil)
	}
	if got.AppealCase != "" || got.AppealRef != "" {
		t.Fatalf("expected appeal metadata omitted below peer appeal threshold, got case=%q ref=%q", got.AppealCase, got.AppealRef)
	}
}

func TestHandlePeersIncludesDiscoveredAndSigns(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().UTC()
	s := &Service{
		operatorID:           "op-local",
		localURL:             "http://self.local",
		pubKey:               pub,
		privKey:              priv,
		peerURLs:             []string{"http://seed-a.local"},
		peerDiscoveryEnabled: true,
		peerDiscoveryTTL:     5 * time.Minute,
		discoveredPeers: map[string]time.Time{
			"http://peer-b.local": now,
		},
		peerHintPubKeys: map[string]string{
			"http://seed-a.local": base64.RawURLEncoding.EncodeToString(pub),
		},
		peerHintOperators: map[string]string{
			"http://seed-a.local": "op-seed",
		},
		peerListTTL: 30 * time.Second,
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/peers", nil)
	rr := httptest.NewRecorder()
	s.handlePeers(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.DirectoryPeerListResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode peers response: %v", err)
	}
	if err := verifyDirectoryPeerList(out, pub, time.Now()); err != nil {
		t.Fatalf("verify peer list: %v", err)
	}
	set := make(map[string]struct{}, len(out.Peers))
	for _, peerURL := range out.Peers {
		set[peerURL] = struct{}{}
	}
	for _, want := range []string{"http://self.local", "http://seed-a.local", "http://peer-b.local"} {
		if _, ok := set[want]; !ok {
			t.Fatalf("expected peer list to include %s", want)
		}
	}
	if len(out.PeerHints) < len(out.Peers) {
		t.Fatalf("expected peer hints for all peers")
	}
	selfHint := proto.DirectoryPeerHint{}
	for _, hint := range out.PeerHints {
		if hint.URL == "http://self.local" {
			selfHint = hint
			break
		}
	}
	if selfHint.URL == "" || selfHint.Operator != "op-local" || strings.TrimSpace(selfHint.PubKey) == "" {
		t.Fatalf("expected self peer hint with operator/pubkey, got %+v", selfHint)
	}
}

func TestSyncPeerRelaysDiscoversNewPeerFromPeerFeed(t *testing.T) {
	urlA := "http://peer-a.local"
	urlB := "http://peer-b.local"
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now().UTC()
	relayA := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-from-a",
		Role:       "exit",
		OperatorID: "op-a",
		Endpoint:   "127.0.0.1:51921",
		ValidUntil: now.Add(time.Minute),
	}, privA)
	relayB := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-from-b",
		Role:       "exit",
		OperatorID: "op-b",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: now.Add(time.Minute),
	}, privB)
	feedB := proto.DirectoryPeerListResponse{
		Operator:    "op-b",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(40 * time.Second).Unix(),
		Peers:       []string{urlB, urlA},
		PeerHints: []proto.DirectoryPeerHint{
			{URL: urlB, Operator: "op-b", PubKey: base64.RawURLEncoding.EncodeToString(pubB)},
			{URL: urlA, Operator: "op-a", PubKey: base64.RawURLEncoding.EncodeToString(pubA)},
		},
	}
	feedBSig, err := signDirectoryPeerList(feedB, privB)
	if err != nil {
		t.Fatalf("sign peer feed b: %v", err)
	}
	feedB.Signature = feedBSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubA)}),
		urlA + "/v1/peers": jsonResp(proto.DirectoryPeerListResponse{
			Operator:    "op-a",
			GeneratedAt: now.Unix(),
			ExpiresAt:   now.Add(40 * time.Second).Unix(),
			Peers:       []string{urlA},
			Signature: func() string {
				resp := proto.DirectoryPeerListResponse{
					Operator:    "op-a",
					GeneratedAt: now.Unix(),
					ExpiresAt:   now.Add(40 * time.Second).Unix(),
					Peers:       []string{urlA},
				}
				sig, _ := signDirectoryPeerList(resp, privA)
				return sig
			}(),
		}),
		urlA + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayA}}),
		urlB + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pubB)}),
		urlB + "/v1/peers":  jsonResp(feedB),
		urlB + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayB}}),
	}

	s := &Service{
		operatorID:           "op-local",
		localURL:             "http://local-dir",
		peerURLs:             []string{urlB},
		peerDiscoveryEnabled: true,
		peerDiscoveryTTL:     10 * time.Minute,
		peerDiscoveryMax:     8,
		peerRelays:           make(map[string]proto.RelayDescriptor),
		discoveredPeers:      make(map[string]time.Time),
		peerRelayETags:       make(map[string]string),
		peerRelayCache:       make(map[string][]proto.RelayDescriptor),
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays first: %v", err)
	}
	syncPeers := s.snapshotSyncPeers(time.Now())
	foundA := false
	for _, peerURL := range syncPeers {
		if peerURL == urlA {
			foundA = true
			break
		}
	}
	if !foundA {
		t.Fatalf("expected discovered peer %s in sync set", urlA)
	}
	if gotHint := s.peerHintPubKey(urlA); gotHint != base64.RawURLEncoding.EncodeToString(pubA) {
		t.Fatalf("expected discovered hint pubkey for %s", urlA)
	}

	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays second: %v", err)
	}
	relays := s.snapshotPeerRelays()
	foundRelayFromA := false
	for _, relayDesc := range relays {
		if relayDesc.RelayID == "exit-from-a" {
			foundRelayFromA = true
			break
		}
	}
	if !foundRelayFromA {
		t.Fatalf("expected relay from discovered peer %s to be imported", urlA)
	}
}

func TestHandleGossipRelaysImportsVerifiedDescriptors(t *testing.T) {
	peerURL := "http://peer-a.local"
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	desc := signedDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-peer-gossip",
		Role:       "exit",
		OperatorID: "op-peer",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		peerURL + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
	}
	s := &Service{
		operatorID:  "op-local",
		peerURLs:    []string{peerURL},
		peerRelays:  make(map[string]proto.RelayDescriptor),
		peerMaxHops: 3,
		httpClient:  &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	body, _ := json.Marshal(proto.RelayGossipPushRequest{
		PeerURL: peerURL,
		Relays:  []proto.RelayDescriptor{desc},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/gossip/relays", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleGossipRelays(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.RelayGossipPushResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode gossip response: %v", err)
	}
	if out.Imported != 1 {
		t.Fatalf("expected one imported relay, got %d", out.Imported)
	}
	relays := s.snapshotPeerRelays()
	if len(relays) != 1 {
		t.Fatalf("expected one relay in peer store, got %d", len(relays))
	}
	if relays[0].HopCount != 1 {
		t.Fatalf("expected hop-count increment to 1, got %d", relays[0].HopCount)
	}
}

func TestSelectionFromTrustAttestationAppealMitigatesDisputePenalty(t *testing.T) {
	nowUnix := time.Now().Unix()
	base := selectionFromTrustAttestation(proto.RelayTrustAttestation{
		RelayID:      "exit-a",
		Role:         "exit",
		TierCap:      1,
		DisputeUntil: nowUnix + 300,
	}, nowUnix)
	withAppeal := selectionFromTrustAttestation(proto.RelayTrustAttestation{
		RelayID:      "exit-a",
		Role:         "exit",
		TierCap:      1,
		DisputeUntil: nowUnix + 300,
		AppealUntil:  nowUnix + 300,
	}, nowUnix)
	if base.AbusePenalty < 0.84 {
		t.Fatalf("expected base dispute penalty near 0.85, got %f", base.AbusePenalty)
	}
	if withAppeal.AbusePenalty >= base.AbusePenalty {
		t.Fatalf("expected appeal to reduce dispute penalty: base=%f appeal=%f", base.AbusePenalty, withAppeal.AbusePenalty)
	}
}

func signedDescriptor(t *testing.T, desc proto.RelayDescriptor, priv ed25519.PrivateKey) proto.RelayDescriptor {
	t.Helper()
	desc.Signature = ""
	payload, err := json.Marshal(desc)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	desc.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return desc
}

func jsonResp(v interface{}) func(*http.Request) (*http.Response, error) {
	return func(_ *http.Request) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(b)),
		}, nil
	}
}
