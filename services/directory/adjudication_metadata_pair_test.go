package directory

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestBuildTrustAttestationsKeepsMetadataPairIntegrity(t *testing.T) {
	now := time.Now()
	until := now.Add(5 * time.Minute).Unix()
	s := &Service{
		finalDisputeMinVotes: 1,
		finalAppealMinVotes:  1,
		finalAdjudicationOps: 1,
		finalAdjudicationMin: 0,
		peerTrust: map[string]proto.RelayTrustAttestation{
			relayKey("exit-shared", "exit"): {
				RelayID:      "exit-shared",
				Role:         "exit",
				OperatorID:   "op-peer",
				Reputation:   0.8,
				Confidence:   0.9,
				TierCap:      1,
				DisputeUntil: until,
				DisputeCase:  "case-a",
				DisputeRef:   "evidence://z",
			},
		},
		issuerTrust: map[string]proto.RelayTrustAttestation{
			relayKey("exit-shared", "exit"): {
				RelayID:      "exit-shared",
				Role:         "exit",
				OperatorID:   "op-issuer",
				Reputation:   0.7,
				Confidence:   0.8,
				TierCap:      1,
				DisputeUntil: until,
				DisputeCase:  "case-b",
				DisputeRef:   "evidence://a",
			},
		},
	}

	out := s.buildTrustAttestations(nil)
	if len(out) != 1 {
		t.Fatalf("expected one attestation, got %d", len(out))
	}
	got := out[0]
	if got.DisputeCase != "case-a" || got.DisputeRef != "evidence://z" {
		t.Fatalf("expected consistent metadata pair from a single vote source, got case=%q ref=%q", got.DisputeCase, got.DisputeRef)
	}
}

func TestSyncPeerRelaysKeepsMetadataPairIntegrity(t *testing.T) {
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
	disputeUntil := now.Add(6 * time.Minute).Unix()
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
	trustA := signedTrustFeed(t, privA, "operator-a", now, []proto.RelayTrustAttestation{
		{
			RelayID:      "exit-shared",
			Role:         "exit",
			OperatorID:   "op-shared",
			Reputation:   0.8,
			Confidence:   0.9,
			TierCap:      1,
			DisputeUntil: disputeUntil,
			DisputeCase:  "case-a",
			DisputeRef:   "evidence://z",
		},
	})
	trustB := signedTrustFeed(t, privB, "operator-b", now, []proto.RelayTrustAttestation{
		{
			RelayID:      "exit-shared",
			Role:         "exit",
			OperatorID:   "op-shared",
			Reputation:   0.7,
			Confidence:   0.8,
			TierCap:      1,
			DisputeUntil: disputeUntil,
			DisputeCase:  "case-b",
			DisputeRef:   "evidence://a",
		},
	})
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			Operator: "operator-a",
			PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pubA)},
		}),
		urlA + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayA}}),
		urlA + "/v1/trust-attestations": jsonResp(trustA),
		urlB + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			Operator: "operator-b",
			PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pubB)},
		}),
		urlB + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relayB}}),
		urlB + "/v1/trust-attestations": jsonResp(trustB),
	}
	s := &Service{
		peerURLs:            []string{urlA, urlB},
		peerMinVotes:        1,
		peerTrustMinVotes:   1,
		peerDisputeMinVotes: 1,
		adjudicationMetaMin: 1,
		peerRelays:          make(map[string]proto.RelayDescriptor),
		peerTrust:           make(map[string]proto.RelayTrustAttestation),
		peerRelayETags:      make(map[string]string),
		peerRelayCache:      make(map[string][]proto.RelayDescriptor),
		peerTrustETags:      make(map[string]string),
		peerTrustCache:      make(map[string]map[string]proto.RelayTrustAttestation),
		peerHintPubKeys:     make(map[string]string),
		peerHintOperators:   make(map[string]string),
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if err := s.syncPeerRelays(context.Background()); err != nil {
		t.Fatalf("syncPeerRelays: %v", err)
	}
	gotMap := s.snapshotPeerTrust()
	got, ok := gotMap[relayKey("exit-shared", "exit")]
	if !ok {
		t.Fatalf("expected merged peer trust attestation")
	}
	if got.DisputeCase != "case-a" || got.DisputeRef != "evidence://z" {
		t.Fatalf("expected consistent dispute metadata pair, got case=%q ref=%q", got.DisputeCase, got.DisputeRef)
	}
}

func TestSyncIssuerTrustKeepsMetadataPairIntegrity(t *testing.T) {
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
	disputeUntil := now.Add(6 * time.Minute).Unix()
	trustA := signedTrustFeed(t, privA, "issuer-a", now, []proto.RelayTrustAttestation{
		{
			RelayID:      "exit-shared",
			Role:         "exit",
			OperatorID:   "op-shared",
			Reputation:   0.8,
			Confidence:   0.9,
			TierCap:      1,
			DisputeUntil: disputeUntil,
			DisputeCase:  "case-a",
			DisputeRef:   "evidence://z",
		},
	})
	trustB := signedTrustFeed(t, privB, "issuer-b", now, []proto.RelayTrustAttestation{
		{
			RelayID:      "exit-shared",
			Role:         "exit",
			OperatorID:   "op-shared",
			Reputation:   0.7,
			Confidence:   0.8,
			TierCap:      1,
			DisputeUntil: disputeUntil,
			DisputeCase:  "case-b",
			DisputeRef:   "evidence://a",
		},
	})
	handlers := map[string]func(*http.Request) (*http.Response, error){
		urlA + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-a", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubA)}}),
		urlA + "/v1/trust/relays": jsonResp(trustA),
		urlB + "/v1/pubkeys":      jsonResp(proto.IssuerPubKeysResponse{Issuer: "issuer-b", PubKeys: []string{base64.RawURLEncoding.EncodeToString(pubB)}}),
		urlB + "/v1/trust/relays": jsonResp(trustB),
	}
	s := &Service{
		issuerTrustURLs:       []string{urlA, urlB},
		issuerTrustMinVotes:   1,
		issuerDisputeMinVotes: 1,
		adjudicationMetaMin:   1,
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
		t.Fatalf("expected merged issuer trust attestation")
	}
	if got.DisputeCase != "case-a" || got.DisputeRef != "evidence://z" {
		t.Fatalf("expected consistent dispute metadata pair, got case=%q ref=%q", got.DisputeCase, got.DisputeRef)
	}
}

func signedTrustFeed(t *testing.T, priv ed25519.PrivateKey, operator string, now time.Time, attestations []proto.RelayTrustAttestation) proto.RelayTrustAttestationFeedResponse {
	t.Helper()
	feed := proto.RelayTrustAttestationFeedResponse{
		Operator:     operator,
		GeneratedAt:  now.Unix(),
		ExpiresAt:    now.Add(30 * time.Second).Unix(),
		Attestations: attestations,
	}
	sig, err := crypto.SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	feed.Signature = sig
	return feed
}
