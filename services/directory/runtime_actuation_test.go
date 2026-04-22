package directory

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestBuildRelayDescriptorsKeepsMicroRelayWhenSignalsAbsent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	s := &Service{
		operatorID: "op-local",
		providerRelays: map[string]proto.RelayDescriptor{
			relayKey("micro-provider-1", "micro-relay"): {
				RelayID:    "micro-provider-1",
				Role:       "micro-relay",
				OperatorID: "op-provider",
				Endpoint:   "127.0.0.1:51825",
				ControlURL: "http://127.0.0.1:18085",
				ValidUntil: now.Add(time.Minute),
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
				RelayID:    "micro-provider-1",
				Role:       "micro-relay",
				OperatorID: "op-provider",
				Endpoint:   "127.0.0.1:51825",
				ControlURL: "http://127.0.0.1:18085",
				ValidUntil: now.Add(time.Minute),
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

func TestBuildRelayDescriptorsDemotesAndRecoversMicroRelayFromTrustSignals(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	key := relayKey("micro-provider-1", "micro-relay")
	s := &Service{
		operatorID: "op-local",
		providerRelays: map[string]proto.RelayDescriptor{
			key: {
				RelayID:    "micro-provider-1",
				Role:       "micro-relay",
				OperatorID: "op-provider",
				Endpoint:   "127.0.0.1:51825",
				ControlURL: "http://127.0.0.1:18085",
				ValidUntil: now.Add(time.Minute),
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
	for _, desc := range relays {
		if desc.RelayID == relayID && desc.Role == role {
			return true
		}
	}
	return false
}
