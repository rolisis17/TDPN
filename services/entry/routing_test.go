package entry

import (
	"strings"
	"testing"

	"privacynode/pkg/relay"
)

func TestRoutePacketTargetClientToExit(t *testing.T) {
	state := sessionState{exitDataAddr: "127.0.0.1:51821"}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40000", 100, 0)
	if !ok {
		t.Fatalf("expected packet to route")
	}
	if target != "127.0.0.1:51821" {
		t.Fatalf("expected exit target, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client addr learned, got %s", next.clientDataAddr)
	}
	if next.clientLastSeen != 100 {
		t.Fatalf("expected client last seen tracked, got %d", next.clientLastSeen)
	}
}

func TestRoutePacketTargetExitToClient(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:51821", 120, 0)
	if !ok {
		t.Fatalf("expected packet to route")
	}
	if target != "127.0.0.1:40000" {
		t.Fatalf("expected client target, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client addr unchanged, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetExitWithoutClient(t *testing.T) {
	state := sessionState{exitDataAddr: "127.0.0.1:51821"}
	_, target, ok := routePacketTarget(state, "127.0.0.1:51821", 100, 0)
	if ok {
		t.Fatalf("expected packet drop before client is known")
	}
	if target != "" {
		t.Fatalf("expected empty target when client unknown, got %s", target)
	}
}

func TestRoutePacketTargetRejectsUnknownClientSourceByDefault(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
		clientLastSeen: 100,
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40001", 101, 0)
	if ok {
		t.Fatalf("expected unknown client source to be dropped")
	}
	if target != "" {
		t.Fatalf("expected no target for dropped packet, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client binding unchanged, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetAllowsClientRebindAfterThreshold(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
		clientLastSeen: 100,
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40001", 111, 10)
	if !ok {
		t.Fatalf("expected client rebind to be allowed after inactivity")
	}
	if target != "127.0.0.1:51821" {
		t.Fatalf("expected rebind packet to route to exit, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40001" {
		t.Fatalf("expected client address rebound, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetRejectsClientRebindBeforeThreshold(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
		clientLastSeen: 100,
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40001", 105, 10)
	if ok {
		t.Fatalf("expected client rebind rejected before inactivity threshold")
	}
	if target != "" {
		t.Fatalf("expected no target for rejected rebind, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client address unchanged, got %s", next.clientDataAddr)
	}
}

func TestSameUDPAddrLocalhostEquivalent(t *testing.T) {
	if !sameUDPAddr("localhost:1234", "127.0.0.1:1234") {
		t.Fatalf("expected localhost and 127.0.0.1 to match")
	}
	if sameUDPAddr("127.0.0.1:1234", "127.0.0.1:1235") {
		t.Fatalf("expected different ports to not match")
	}
}

func TestNormalizePathTransportFallback(t *testing.T) {
	if got := normalizePathTransport("", "wireguard-udp"); got != "wireguard-udp" {
		t.Fatalf("expected request fallback, got %q", got)
	}
	if got := normalizePathTransport("", ""); got != "policy-json" {
		t.Fatalf("expected policy-json default, got %q", got)
	}
}

func TestAllowForwardPayloadLiveModeAllowsPlausibleWireGuard(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 4
	payload := relay.BuildOpaquePayload(1, raw)
	ok, reason := allowForwardPayload("wireguard-udp", payload, true)
	if !ok {
		t.Fatalf("expected payload allowed, reason=%s", reason)
	}
}

func TestAllowForwardPayloadLiveModeRejectsNonWireGuard(t *testing.T) {
	payload := relay.BuildOpaquePayload(1, []byte("not-wireguard"))
	ok, reason := allowForwardPayload("wireguard-udp", payload, true)
	if ok {
		t.Fatalf("expected payload rejected")
	}
	if reason != "non-wireguard-live" {
		t.Fatalf("expected non-wireguard-live reason, got %q", reason)
	}
}

func TestAllowForwardPayloadLiveModeRejectsMalformedOpaque(t *testing.T) {
	ok, reason := allowForwardPayload("wireguard-udp", []byte{1, 2, 3}, true)
	if ok {
		t.Fatalf("expected malformed opaque rejected")
	}
	if reason != "invalid-opaque-live" {
		t.Fatalf("expected invalid-opaque-live reason, got %q", reason)
	}
}

func TestAllowForwardPayloadLiveModeRejectsNonWireGuardTransport(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 4
	payload := relay.BuildOpaquePayload(1, raw)
	ok, reason := allowForwardPayload("policy-json", payload, true)
	if ok {
		t.Fatalf("expected live mode to reject non-wireguard transport")
	}
	if reason != "transport-must-be-wireguard-live" {
		t.Fatalf("expected transport-must-be-wireguard-live reason, got %q", reason)
	}
}

func TestValidateRuntimeConfigBetaStrict(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
		directoryURLs:         []string{"http://127.0.0.1:8081"},
		directoryMinSources:   1,
		directoryMinOperators: 1,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDefaultPuzzleSecret(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-default",
		puzzleDifficulty:      1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "non-default ENTRY_PUZZLE_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsEmptyPuzzleSecret(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "",
		puzzleDifficulty:      1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "non-default ENTRY_PUZZLE_SECRET") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsShortPuzzleSecret(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "too-short",
		puzzleDifficulty:      1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_PUZZLE_SECRET length>=16") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsZeroPuzzleDifficulty(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      0,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_PUZZLE_DIFFICULTY>0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsNonLive(t *testing.T) {
	s := &Service{
		betaStrict:           true,
		liveWGMode:           false,
		directoryTrustStrict: true,
		puzzleSecret:         "entry-secret-012345",
		puzzleDifficulty:     1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_LIVE_WG_MODE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingDistinctExitOperator(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: false,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiDirectoryWithoutSourceQuorum(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
		directoryURLs:         []string{"http://127.0.0.1:8081", "http://127.0.0.1:8085"},
		directoryMinSources:   1,
		directoryMinOperators: 2,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_DIRECTORY_MIN_SOURCES>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiDirectoryWithoutOperatorQuorum(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
		directoryURLs:         []string{"http://127.0.0.1:8081", "http://127.0.0.1:8085"},
		directoryMinSources:   2,
		directoryMinOperators: 1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_DIRECTORY_MIN_OPERATORS>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiDirectoryWithoutRelayVoteQuorum(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
		directoryURLs:         []string{"http://127.0.0.1:8081", "http://127.0.0.1:8085"},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_DIRECTORY_MIN_RELAY_VOTES>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictAllowsMultiDirectoryWithRelayVoteQuorum(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
		directoryURLs:         []string{"http://127.0.0.1:8081", "http://127.0.0.1:8085"},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     2,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigRejectsDistinctOperatorWithoutEntryOperatorID(t *testing.T) {
	s := &Service{
		betaStrict:            false,
		liveWGMode:            false,
		directoryTrustStrict:  false,
		requireDistinctExitOp: true,
		operatorID:            "",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "ENTRY_OPERATOR_ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigWGOnlyRequiresLiveMode(t *testing.T) {
	s := &Service{
		wgOnlyMode: true,
		liveWGMode: false,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected wg-only validation error")
	}
	if !strings.Contains(err.Error(), "WG_ONLY_MODE requires ENTRY_LIVE_WG_MODE=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigWGOnlyAcceptsLiveMode(t *testing.T) {
	s := &Service{
		wgOnlyMode: true,
		liveWGMode: true,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected wg-only config valid, got %v", err)
	}
}

func TestNewProdStrictEnablesWGOnly(t *testing.T) {
	t.Setenv("PROD_STRICT_MODE", "1")
	t.Setenv("ENTRY_PROD_STRICT", "0")
	s := New()
	if !s.wgOnlyMode {
		t.Fatalf("expected prod strict mode to enable wg-only mode")
	}
}
