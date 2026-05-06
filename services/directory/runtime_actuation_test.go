package directory

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestBuildRelayDescriptorsPublishesLocalMiddleRelayWhenEnabled(t *testing.T) {
	t.Setenv("MIDDLE_RELAY_ENABLED", "1")
	t.Setenv("MIDDLE_RELAY_ID", "middle-lab-a")
	t.Setenv("MIDDLE_OPERATOR_ID", "op-middle-a")
	t.Setenv("MIDDLE_ENDPOINT_PUBLIC", "100.64.0.10:51822")
	t.Setenv("MIDDLE_CONTROL_URL_PUBLIC", "http://100.64.0.10:8085")
	t.Setenv("MIDDLE_COUNTRY_CODE", "MX")
	t.Setenv("MIDDLE_REGION", "lab-west")
	t.Setenv("MIDDLE_REPUTATION_SCORE", "0.93")
	t.Setenv("MIDDLE_UPTIME_SCORE", "0.94")
	t.Setenv("MIDDLE_CAPACITY_SCORE", "0.95")
	t.Setenv("MIDDLE_ABUSE_PENALTY", "0.04")
	t.Setenv("MIDDLE_BOND_SCORE", "0.72")
	t.Setenv("MIDDLE_STAKE_SCORE", "0.67")

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	s := &Service{
		operatorID:     "op-a",
		pubKey:         pub,
		privKey:        priv,
		descriptorTTL:  2 * time.Minute,
		providerRelays: make(map[string]proto.RelayDescriptor),
		peerRelays:     make(map[string]proto.RelayDescriptor),
	}

	relays := s.buildRelayDescriptors(now)
	middle, ok := findRelay(relays, "middle-lab-a", "micro-relay")
	if !ok {
		t.Fatalf("expected local middle relay descriptor in published relays")
	}
	if middle.OperatorID != "op-middle-a" || middle.OriginOperator != "op-middle-a" {
		t.Fatalf("unexpected middle operator fields: operator=%q origin=%q", middle.OperatorID, middle.OriginOperator)
	}
	if middle.Endpoint != "100.64.0.10:51822" {
		t.Fatalf("endpoint=%q, want public middle data endpoint", middle.Endpoint)
	}
	if middle.ControlURL != "http://100.64.0.10:8085" {
		t.Fatalf("control_url=%q, want public middle control URL", middle.ControlURL)
	}
	if middle.CountryCode != "MX" || middle.Region != "lab-west" {
		t.Fatalf("unexpected middle locality country=%q region=%q", middle.CountryCode, middle.Region)
	}
	if got, want := base64.RawURLEncoding.EncodeToString(pub), middle.PubKey; got != want {
		t.Fatalf("middle pubkey=%q, want directory current pubkey %q", want, got)
	}
	if len(middle.HopRoles) != 1 || middle.HopRoles[0] != "middle" {
		t.Fatalf("unexpected middle hop_roles: %#v", middle.HopRoles)
	}
	if len(middle.Capabilities) != 1 || middle.Capabilities[0] != "wg" {
		t.Fatalf("unexpected middle capabilities: %#v", middle.Capabilities)
	}
	if middle.Reputation != 0.93 || middle.Uptime != 0.94 || middle.Capacity != 0.95 || middle.AbusePenalty != 0.04 {
		t.Fatalf("unexpected middle quality scores: rep=%v uptime=%v capacity=%v abuse=%v", middle.Reputation, middle.Uptime, middle.Capacity, middle.AbusePenalty)
	}
	if middle.BondScore != 0.72 || middle.StakeScore != 0.67 {
		t.Fatalf("unexpected middle stake scores: bond=%v stake=%v", middle.BondScore, middle.StakeScore)
	}
	if !middle.ValidUntil.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("valid_until=%v, want %v", middle.ValidUntil, now.Add(2*time.Minute))
	}
}

func TestBuildRelayDescriptorsKeepsMicroRelayWhenSignalsAbsent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := &Service{
		operatorID: "op-local",
		providerRelays: map[string]proto.RelayDescriptor{
			relayKey("micro-provider-1", "micro-relay"): {
				RelayID:      "micro-provider-1",
				Role:         "micro-relay",
				OperatorID:   "op-provider",
				Endpoint:     "127.0.0.1:51825",
				ControlURL:   "http://127.0.0.1:18085",
				Reputation:   0.82,
				Uptime:       0.9,
				Capacity:     0.86,
				AbusePenalty: 0.2,
				ValidUntil:   now.Add(time.Minute),
			},
		},
	}

	relays := s.buildRelayDescriptors(now)
	if !hasRelay(relays, "micro-provider-1", "micro-relay") {
		t.Fatalf("expected micro-relay to remain published without runtime signals")
	}
}

func TestBuildRelayDescriptorsDemotesAndRecoversMicroRelayFromQualitySignals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := relayKey("micro-provider-1", "micro-relay")
	s := &Service{
		operatorID: "op-local",
		providerRelays: map[string]proto.RelayDescriptor{
			key: {
				RelayID:      "micro-provider-1",
				Role:         "micro-relay",
				OperatorID:   "op-provider",
				Endpoint:     "127.0.0.1:51825",
				ControlURL:   "http://127.0.0.1:18085",
				Reputation:   0.82,
				Uptime:       0.9,
				Capacity:     0.86,
				AbusePenalty: 0.2,
				ValidUntil:   now.Add(time.Minute),
			},
		},
		peerScores: map[string]proto.RelaySelectionScore{
			key: {
				RelayID:      "micro-provider-1",
				Role:         "micro-relay",
				Reputation:   0.2,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
			},
		},
	}

	relays := s.buildRelayDescriptors(now)
	if hasRelay(relays, "micro-provider-1", "micro-relay") {
		t.Fatalf("expected unhealthy micro-relay quality signals to demote descriptor")
	}

	s.peerScores[key] = proto.RelaySelectionScore{
		RelayID:      "micro-provider-1",
		Role:         "micro-relay",
		Reputation:   0.9,
		Uptime:       0.95,
		Capacity:     0.92,
		AbusePenalty: 0.1,
	}
	relays = s.buildRelayDescriptors(now)
	if !hasRelay(relays, "micro-provider-1", "micro-relay") {
		t.Fatalf("expected healthy micro-relay quality signals to re-promote descriptor")
	}
}

func TestBuildRelayDescriptorsDemotesAndRecoversMicroExitFromQualitySignals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := relayKey("micro-exit-provider-1", "micro-exit")
	s := &Service{
		operatorID:           "op-local",
		microExitBetaAllowed: true,
		providerRelays: map[string]proto.RelayDescriptor{
			key: {
				RelayID:      "micro-exit-provider-1",
				Role:         "micro-exit",
				OperatorID:   "op-provider",
				Endpoint:     "127.0.0.1:51826",
				ControlURL:   "http://127.0.0.1:18086",
				Reputation:   0.86,
				Uptime:       0.91,
				Capacity:     0.88,
				AbusePenalty: 0.12,
				ValidUntil:   now.Add(time.Minute),
			},
		},
		peerScores: map[string]proto.RelaySelectionScore{
			key: {
				RelayID:      "micro-exit-provider-1",
				Role:         "micro-exit",
				Reputation:   0.2,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
			},
		},
	}

	relays := s.buildRelayDescriptors(now)
	if hasRelay(relays, "micro-exit-provider-1", "micro-exit") {
		t.Fatalf("expected unhealthy micro-exit quality signals to demote descriptor")
	}

	s.peerScores[key] = proto.RelaySelectionScore{
		RelayID:      "micro-exit-provider-1",
		Role:         "micro-exit",
		Reputation:   0.9,
		Uptime:       0.95,
		Capacity:     0.92,
		AbusePenalty: 0.1,
	}
	relays = s.buildRelayDescriptors(now)
	if !hasRelay(relays, "micro-exit-provider-1", "micro-exit") {
		t.Fatalf("expected healthy micro-exit quality signals to re-promote descriptor")
	}
}

func TestBuildRelayDescriptorsHidesMicroExitWhenBetaDisabled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := &Service{
		operatorID: "op-local",
		providerRelays: map[string]proto.RelayDescriptor{
			relayKey("micro-exit-provider-1", "micro-exit"): {
				RelayID:      "micro-exit-provider-1",
				Role:         "micro-exit",
				OperatorID:   "op-provider",
				Endpoint:     "127.0.0.1:51826",
				ControlURL:   "http://127.0.0.1:18086",
				Reputation:   0.86,
				Uptime:       0.91,
				Capacity:     0.88,
				AbusePenalty: 0.12,
				ValidUntil:   now.Add(time.Minute),
			},
			relayKey("micro-relay-provider-1", "micro-relay"): {
				RelayID:      "micro-relay-provider-1",
				Role:         "micro-relay",
				OperatorID:   "op-provider",
				Endpoint:     "127.0.0.1:51825",
				ControlURL:   "http://127.0.0.1:18085",
				Reputation:   0.82,
				Uptime:       0.9,
				Capacity:     0.86,
				AbusePenalty: 0.2,
				ValidUntil:   now.Add(time.Minute),
			},
		},
		peerRelays: map[string]proto.RelayDescriptor{
			relayKey("micro-exit-peer-1", "micro-exit"): {
				RelayID:      "micro-exit-peer-1",
				Role:         "micro-exit",
				OperatorID:   "op-peer",
				Endpoint:     "127.0.0.1:51827",
				ControlURL:   "http://127.0.0.1:18087",
				Reputation:   0.86,
				Uptime:       0.91,
				Capacity:     0.88,
				AbusePenalty: 0.12,
				ValidUntil:   now.Add(time.Minute),
			},
		},
	}

	relays := s.buildRelayDescriptors(now)
	if hasRelay(relays, "micro-exit-provider-1", "micro-exit") {
		t.Fatalf("expected provider micro-exit to be hidden while beta is disabled")
	}
	if hasRelay(relays, "micro-exit-peer-1", "micro-exit") {
		t.Fatalf("expected peer micro-exit to be hidden while beta is disabled")
	}
	if !hasRelay(relays, "micro-relay-provider-1", "micro-relay") {
		t.Fatalf("expected micro-relay publication to remain enabled")
	}
}

func TestBuildRelayDescriptorsDemotesAndRecoversMicroRelayFromTrustSignals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := relayKey("micro-provider-1", "micro-relay")
	s := &Service{
		operatorID: "op-local",
		providerRelays: map[string]proto.RelayDescriptor{
			key: {
				RelayID:      "micro-provider-1",
				Role:         "micro-relay",
				OperatorID:   "op-provider",
				Endpoint:     "127.0.0.1:51825",
				ControlURL:   "http://127.0.0.1:18085",
				Reputation:   0.82,
				Uptime:       0.9,
				Capacity:     0.86,
				AbusePenalty: 0.2,
				ValidUntil:   now.Add(time.Minute),
			},
		},
		peerTrust: map[string]proto.RelayTrustAttestation{
			key: {
				RelayID:      "micro-provider-1",
				Role:         "micro-relay",
				OperatorID:   "op-peer",
				TierCap:      1,
				DisputeUntil: now.Add(5 * time.Minute).Unix(),
			},
		},
	}

	relays := s.buildRelayDescriptors(now)
	if hasRelay(relays, "micro-provider-1", "micro-relay") {
		t.Fatalf("expected disputed micro-relay trust signal to demote descriptor")
	}

	s.peerTrust[key] = proto.RelayTrustAttestation{
		RelayID:      "micro-provider-1",
		Role:         "micro-relay",
		OperatorID:   "op-peer",
		TierCap:      1,
		DisputeUntil: now.Add(-time.Minute).Unix(),
	}
	relays = s.buildRelayDescriptors(now)
	if !hasRelay(relays, "micro-provider-1", "micro-relay") {
		t.Fatalf("expected cleared micro-relay trust dispute to re-promote descriptor")
	}
}

func TestFetchPeerSignalFeedsIncludeMicroRelayRoles(t *testing.T) {
	peerURL := "http://peer-signals.local"
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().UTC()

	selectionFeed := proto.RelaySelectionFeedResponse{
		Operator:    "op-peer",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(time.Minute).Unix(),
		Scores: []proto.RelaySelectionScore{
			{
				RelayID:      "micro-peer-1",
				Role:         "relay",
				Reputation:   0.9,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
			},
		},
	}
	sig, err := crypto.SignRelaySelectionFeed(selectionFeed, priv)
	if err != nil {
		t.Fatalf("sign selection feed: %v", err)
	}
	selectionFeed.Signature = sig

	trustFeed := proto.RelayTrustAttestationFeedResponse{
		Operator:    "op-peer",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(time.Minute).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "micro-peer-1",
				Role:       "middle",
				OperatorID: "op-peer",
				Confidence: 0.9,
			},
		},
	}
	trustSig, err := crypto.SignRelayTrustAttestationFeed(trustFeed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	trustFeed.Signature = trustSig

	s := &Service{
		httpClient: &http.Client{Transport: actuationRoundTripper{
			handlers: map[string]func(*http.Request) (*http.Response, error){
				peerURL + "/v1/selection-feed":     actuationJSONResp(selectionFeed),
				peerURL + "/v1/trust-attestations": actuationJSONResp(trustFeed),
			},
		}},
	}

	scores, err := s.fetchPeerSelectionScores(context.Background(), peerURL, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("fetchPeerSelectionScores: %v", err)
	}
	score, ok := scores[relayKey("micro-peer-1", "micro-relay")]
	if !ok {
		t.Fatalf("expected canonical micro-relay score signal from peer selection feed")
	}
	if score.Role != "micro-relay" {
		t.Fatalf("expected canonical micro-relay score role, got %q", score.Role)
	}

	attestations, err := s.fetchPeerTrustAttestations(context.Background(), peerURL, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("fetchPeerTrustAttestations: %v", err)
	}
	att, ok := attestations[relayKey("micro-peer-1", "micro-relay")]
	if !ok {
		t.Fatalf("expected canonical micro-relay trust signal from peer trust feed")
	}
	if att.Role != "micro-relay" {
		t.Fatalf("expected canonical micro-relay trust role, got %q", att.Role)
	}
}

func TestFetchIssuerTrustFeedIncludesMicroRelayRoles(t *testing.T) {
	issuerURL := "http://issuer-signals.local"
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().UTC()

	trustFeed := proto.RelayTrustAttestationFeedResponse{
		Operator:    "op-issuer",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(time.Minute).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:    "micro-issuer-1",
				Role:       "transit",
				OperatorID: "op-issuer",
				Confidence: 0.9,
			},
		},
	}
	trustSig, err := crypto.SignRelayTrustAttestationFeed(trustFeed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	trustFeed.Signature = trustSig

	s := &Service{
		httpClient: &http.Client{Transport: actuationRoundTripper{
			handlers: map[string]func(*http.Request) (*http.Response, error){
				issuerURL + "/v1/trust/relays": actuationJSONResp(trustFeed),
			},
		}},
	}
	attestations, err := s.fetchIssuerTrustAttestations(context.Background(), issuerURL, []ed25519.PublicKey{pub})
	if err != nil {
		t.Fatalf("fetchIssuerTrustAttestations: %v", err)
	}
	att, ok := attestations[relayKey("micro-issuer-1", "micro-relay")]
	if !ok {
		t.Fatalf("expected canonical micro-relay trust signal from issuer trust feed")
	}
	if att.Role != "micro-relay" {
		t.Fatalf("expected canonical micro-relay issuer trust role, got %q", att.Role)
	}
}

type actuationRoundTripper struct {
	handlers map[string]func(*http.Request) (*http.Response, error)
}

func (m actuationRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if h, ok := m.handlers[req.URL.String()]; ok {
		return h(req)
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("not found")),
	}, nil
}

func actuationJSONResp(payload any) func(*http.Request) (*http.Response, error) {
	return func(_ *http.Request) (*http.Response, error) {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(string(b))),
		}, nil
	}
}

func hasRelay(relays []proto.RelayDescriptor, relayID string, role string) bool {
	_, ok := findRelay(relays, relayID, role)
	return ok
}

func findRelay(relays []proto.RelayDescriptor, relayID string, role string) (proto.RelayDescriptor, bool) {
	for _, desc := range relays {
		if desc.RelayID == relayID && desc.Role == role {
			return desc, true
		}
	}
	return proto.RelayDescriptor{}, false
}
