package directory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func TestHandleGovernanceStatusRequiresAdminToken(t *testing.T) {
	s := &Service{adminToken: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/governance-status", nil)
	rr := httptest.NewRecorder()
	s.handleGovernanceStatus(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGovernanceStatusReturnsPolicyAndCounts(t *testing.T) {
	nowUnix := time.Now().Unix()
	s := &Service{
		adminToken:           "secret",
		adjudicationMetaMin:  2,
		finalDisputeMinVotes: 2,
		finalAppealMinVotes:  2,
		finalAdjudicationOps: 2,
		finalAdjudicationMin: 0.6,
		peerTrust:            map[string]proto.RelayTrustAttestation{},
		issuerTrust:          map[string]proto.RelayTrustAttestation{},
		peerScores:           map[string]proto.RelaySelectionScore{},
		peerRelays:           map[string]proto.RelayDescriptor{},
		providerRelays:       map[string]proto.RelayDescriptor{},
		discoveredPeers:      map[string]time.Time{},
		discoveredPeerVoters: map[string]map[string]time.Time{},
		peerHintPubKeys:      map[string]string{},
		peerHintOperators:    map[string]string{},
		peerRelayETags:       map[string]string{},
		peerRelayCache:       map[string][]proto.RelayDescriptor{},
		peerScoreETags:       map[string]string{},
		peerScoreCache:       map[string]map[string]proto.RelaySelectionScore{},
		peerTrustETags:       map[string]string{},
		peerTrustCache:       map[string]map[string]proto.RelayTrustAttestation{},
		issuerTrustETags:     map[string]string{},
		issuerTrustCache:     map[string]map[string]proto.RelayTrustAttestation{},
	}
	s.peerTrust[relayKey("exit-local-1", "exit")] = proto.RelayTrustAttestation{
		RelayID:      "exit-local-1",
		Role:         "exit",
		OperatorID:   "op-a",
		Reputation:   0.8,
		Confidence:   0.9,
		TierCap:      1,
		DisputeUntil: nowUnix + 300,
	}
	s.issuerTrust[relayKey("exit-local-1", "exit")] = proto.RelayTrustAttestation{
		RelayID:    "exit-local-1",
		Role:       "exit",
		OperatorID: "op-a",
		Reputation: 0.85,
		Confidence: 0.95,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/governance-status", nil)
	req.Header.Set("X-Admin-Token", "secret")
	rr := httptest.NewRecorder()
	s.handleGovernanceStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var out proto.DirectoryGovernanceStatusResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode governance status: %v", err)
	}
	if out.Policy.MetaMinVotes != 2 || out.Policy.FinalDisputeMin != 2 || out.Policy.FinalAppealMin != 2 {
		t.Fatalf("unexpected policy mins: %+v", out.Policy)
	}
	if out.Policy.FinalMinOperators != 2 {
		t.Fatalf("unexpected operator policy: %+v", out.Policy)
	}
	if out.Policy.FinalDisputeRatio != 0.6 {
		t.Fatalf("unexpected ratio policy: %+v", out.Policy)
	}
	if out.PeerTrustCandidates != 1 || out.IssuerTrustCandidates != 1 {
		t.Fatalf("unexpected candidate counts: peer=%d issuer=%d", out.PeerTrustCandidates, out.IssuerTrustCandidates)
	}
	if out.AggregatedTrustAttestations == 0 {
		t.Fatalf("expected aggregated trust attestations")
	}
	if out.AggregatedDisputeSignals != 1 {
		t.Fatalf("expected one dispute signal candidate, got %d", out.AggregatedDisputeSignals)
	}
	if out.DisputeSignalOperators != 1 {
		t.Fatalf("expected one dispute signal operator, got %d", out.DisputeSignalOperators)
	}
	if len(out.DisputeSignalOperatorIDs) != 1 || out.DisputeSignalOperatorIDs[0] != "op-a" {
		t.Fatalf("expected dispute signal operator ids [op-a], got %+v", out.DisputeSignalOperatorIDs)
	}
	if out.AggregatedDisputed != 0 {
		t.Fatalf("expected disputed count suppressed by quorum, got %d", out.AggregatedDisputed)
	}
	if out.AggregatedDisputedOperators != 0 {
		t.Fatalf("expected disputed operator count suppressed by quorum, got %d", out.AggregatedDisputedOperators)
	}
	if len(out.AggregatedDisputedOperatorIDs) != 0 {
		t.Fatalf("expected no aggregated disputed operator ids, got %+v", out.AggregatedDisputedOperatorIDs)
	}
	if out.SuppressedDisputed != 1 {
		t.Fatalf("expected one suppressed disputed signal, got %d", out.SuppressedDisputed)
	}
	if out.SuppressedDisputeOperators != 1 {
		t.Fatalf("expected one suppressed disputed operator, got %d", out.SuppressedDisputeOperators)
	}
	if len(out.SuppressedDisputeOperatorIDs) != 1 || out.SuppressedDisputeOperatorIDs[0] != "op-a" {
		t.Fatalf("expected suppressed dispute operator ids [op-a], got %+v", out.SuppressedDisputeOperatorIDs)
	}
	if len(out.Relays) == 0 {
		t.Fatalf("expected per-relay governance status entries")
	}
	var relayStatus proto.DirectoryGovernanceRelayStatus
	foundRelay := false
	for _, relay := range out.Relays {
		if relay.RelayID == "exit-local-1" && relay.Role == "exit" {
			relayStatus = relay
			foundRelay = true
			break
		}
	}
	if !foundRelay {
		t.Fatalf("expected governance relay status for exit-local-1")
	}
	if !relayStatus.UpstreamDisputeSignal {
		t.Fatalf("expected upstream dispute signal in relay status")
	}
	if relayStatus.PublishedDisputed {
		t.Fatalf("expected published disputed=false due quorum suppression")
	}
	if !relayStatus.SuppressedDisputed {
		t.Fatalf("expected suppressed disputed=true in relay status")
	}
	if len(relayStatus.UpstreamDisputeOperatorIDs) != 1 || relayStatus.UpstreamDisputeOperatorIDs[0] != "op-a" {
		t.Fatalf("expected relay upstream dispute operators [op-a], got %+v", relayStatus.UpstreamDisputeOperatorIDs)
	}
	if len(relayStatus.SuppressedDisputeOperatorIDs) != 1 || relayStatus.SuppressedDisputeOperatorIDs[0] != "op-a" {
		t.Fatalf("expected relay suppressed dispute operators [op-a], got %+v", relayStatus.SuppressedDisputeOperatorIDs)
	}
}
