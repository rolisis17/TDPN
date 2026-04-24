package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestSelectEntryExitPrefersHealthyPair(t *testing.T) {
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://entry-unhealthy.local/v1/health": statusResp(http.StatusServiceUnavailable),
		"http://entry-healthy.local/v1/health":   statusResp(http.StatusOK),
		"http://exit-unhealthy.local/v1/health":  statusResp(http.StatusServiceUnavailable),
		"http://exit-healthy.local/v1/health":    statusResp(http.StatusOK),
	}
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: true,
		healthCheckTimeout: 0,
		healthCacheTTL:     0,
		healthCache:        map[string]healthProbeState{},
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-unhealthy", Role: "entry", ControlURL: "http://entry-unhealthy.local", Region: "us"},
		{RelayID: "entry-healthy", Role: "entry", ControlURL: "http://entry-healthy.local", Region: "us"},
		{RelayID: "exit-unhealthy", Role: "exit", ControlURL: "http://exit-unhealthy.local", Region: "us"},
		{RelayID: "exit-healthy", Role: "exit", ControlURL: "http://exit-healthy.local", Region: "us"},
	}
	entry, exit, ok := c.selectEntryExit(context.Background(), relays)
	if !ok {
		t.Fatalf("expected selection success")
	}
	if entry.RelayID != "entry-healthy" {
		t.Fatalf("expected healthy entry, got %s", entry.RelayID)
	}
	if exit.RelayID != "exit-healthy" {
		t.Fatalf("expected healthy exit, got %s", exit.RelayID)
	}
}

func TestSelectEntryExitPrefersSameRegion(t *testing.T) {
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://entry-us.local/v1/health": statusResp(http.StatusOK),
		"http://entry-eu.local/v1/health": statusResp(http.StatusOK),
		"http://exit-eu.local/v1/health":  statusResp(http.StatusOK),
		"http://exit-us.local/v1/health":  statusResp(http.StatusOK),
	}
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: true,
		healthCacheTTL:     0,
		healthCache:        map[string]healthProbeState{},
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-us", Role: "entry", ControlURL: "http://entry-us.local", Region: "us"},
		{RelayID: "entry-eu", Role: "entry", ControlURL: "http://entry-eu.local", Region: "eu"},
		{RelayID: "exit-eu", Role: "exit", ControlURL: "http://exit-eu.local", Region: "eu"},
		{RelayID: "exit-us", Role: "exit", ControlURL: "http://exit-us.local", Region: "us"},
	}
	entry, exit, ok := c.selectEntryExit(context.Background(), relays)
	if !ok {
		t.Fatalf("expected selection success")
	}
	if entry.Region != exit.Region {
		t.Fatalf("expected same region pair, got entry=%s exit=%s", entry.Region, exit.Region)
	}
	if entry.RelayID != "entry-us" || exit.RelayID != "exit-us" {
		t.Fatalf("unexpected pair: entry=%s exit=%s", entry.RelayID, exit.RelayID)
	}
}

func TestSelectEntryExitFallbackWhenAllUnhealthy(t *testing.T) {
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://entry-a.local/v1/health": statusResp(http.StatusServiceUnavailable),
		"http://exit-a.local/v1/health":  statusResp(http.StatusServiceUnavailable),
	}
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: true,
		healthCacheTTL:     0,
		healthCache:        map[string]healthProbeState{},
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "http://entry-a.local"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "http://entry-b.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "http://exit-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "http://exit-b.local"},
	}
	entry, exit, ok := c.selectEntryExit(context.Background(), relays)
	if !ok {
		t.Fatalf("expected selection success")
	}
	if entry.RelayID != "entry-a" || exit.RelayID != "exit-a" {
		t.Fatalf("expected first relays fallback, got entry=%s exit=%s", entry.RelayID, exit.RelayID)
	}
}

func TestSelectEntryExitStrictModeFailClosedWhenAllUnhealthy(t *testing.T) {
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://entry-a.local/v1/health": statusResp(http.StatusServiceUnavailable),
		"http://entry-b.local/v1/health": statusResp(http.StatusServiceUnavailable),
		"http://exit-a.local/v1/health":  statusResp(http.StatusServiceUnavailable),
		"http://exit-b.local/v1/health":  statusResp(http.StatusServiceUnavailable),
	}
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: true,
		healthCacheTTL:     0,
		healthCache:        map[string]healthProbeState{},
		httpClient:         &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		betaStrict:         true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "http://entry-a.local"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "http://entry-b.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "http://exit-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "http://exit-b.local"},
	}
	_, _, ok := c.selectEntryExit(context.Background(), relays)
	if ok {
		t.Fatalf("expected strict mode to fail closed when all relay health probes fail")
	}
}

func TestSelectEntryExitHealthDisabled(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "exit-a.local"},
	}
	entry, exit, ok := c.selectEntryExit(context.Background(), relays)
	if !ok {
		t.Fatalf("expected selection success")
	}
	if entry.RelayID != "entry-a" || exit.RelayID != "exit-a" {
		t.Fatalf("expected direct first-match selection, got entry=%s exit=%s", entry.RelayID, exit.RelayID)
	}
}

func TestSelectEntryExitPreferredCountry(t *testing.T) {
	c := &Client{
		entryURL:             "http://fallback-entry.local",
		exitControlURL:       "http://fallback-exit.local",
		healthCheckEnabled:   false,
		preferredExitCountry: "DE",
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local", Region: "eu"},
		{RelayID: "exit-us", Role: "exit", ControlURL: "exit-us.local", Region: "us-east", CountryCode: "US"},
		{RelayID: "exit-de", Role: "exit", ControlURL: "exit-de.local", Region: "eu-west", CountryCode: "DE"},
	}
	entry, exit, ok := c.selectEntryExit(context.Background(), relays)
	if !ok {
		t.Fatalf("expected selection success")
	}
	if entry.RelayID != "entry-a" {
		t.Fatalf("unexpected entry selected: %s", entry.RelayID)
	}
	if exit.RelayID != "exit-de" {
		t.Fatalf("expected country-preferred exit-de, got %s", exit.RelayID)
	}
}

func TestSelectEntryExitPreferredRegionFallback(t *testing.T) {
	c := &Client{
		entryURL:             "http://fallback-entry.local",
		exitControlURL:       "http://fallback-exit.local",
		healthCheckEnabled:   false,
		preferredExitCountry: "JP",
		preferredExitRegion:  "eu-west",
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local", Region: "eu-west"},
		{RelayID: "exit-us", Role: "exit", ControlURL: "exit-us.local", Region: "us-east", CountryCode: "US"},
		{RelayID: "exit-eu", Role: "exit", ControlURL: "exit-eu.local", Region: "eu-west", CountryCode: "FR"},
	}
	_, exit, ok := c.selectEntryExit(context.Background(), relays)
	if !ok {
		t.Fatalf("expected selection success")
	}
	if exit.RelayID != "exit-eu" {
		t.Fatalf("expected region fallback exit-eu, got %s", exit.RelayID)
	}
}

func TestSelectEntryExitStrictLocalityNoMatch(t *testing.T) {
	c := &Client{
		entryURL:             "http://fallback-entry.local",
		exitControlURL:       "http://fallback-exit.local",
		healthCheckEnabled:   false,
		preferredExitCountry: "JP",
		strictExitLocality:   true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local", Region: "eu-west"},
		{RelayID: "exit-us", Role: "exit", ControlURL: "exit-us.local", Region: "us-east", CountryCode: "US"},
	}
	_, _, ok := c.selectEntryExit(context.Background(), relays)
	if ok {
		t.Fatalf("expected no selection under strict locality when no country match")
	}
}

func TestRankRelayPairsCapsCandidates(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		maxPairCandidates:  2,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "entry-b.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "exit-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "exit-b.local"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) != 2 {
		t.Fatalf("expected capped pairs length=2, got %d", len(pairs))
	}
}

func TestAttemptPairsRetriesUntilSuccess(t *testing.T) {
	pairs := []relayPair{
		{entry: proto.RelayDescriptor{RelayID: "e1"}, exit: proto.RelayDescriptor{RelayID: "x1"}},
		{entry: proto.RelayDescriptor{RelayID: "e2"}, exit: proto.RelayDescriptor{RelayID: "x2"}},
	}
	calls := 0
	got, err := attemptPairs(pairs, 2, func(p relayPair) error {
		calls++
		if p.entry.RelayID == "e1" {
			return errors.New("first failed")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success on second pair, got %v", err)
	}
	if got.entry.RelayID != "e2" || got.exit.RelayID != "x2" {
		t.Fatalf("unexpected winning pair: %+v", got)
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls, got %d", calls)
	}
}

func TestAttemptPairsFailsAfterLimit(t *testing.T) {
	pairs := []relayPair{
		{entry: proto.RelayDescriptor{RelayID: "e1"}, exit: proto.RelayDescriptor{RelayID: "x1"}},
		{entry: proto.RelayDescriptor{RelayID: "e2"}, exit: proto.RelayDescriptor{RelayID: "x2"}},
		{entry: proto.RelayDescriptor{RelayID: "e3"}, exit: proto.RelayDescriptor{RelayID: "x3"}},
	}
	calls := 0
	_, err := attemptPairs(pairs, 2, func(relayPair) error {
		calls++
		return errors.New("nope")
	})
	if err == nil {
		t.Fatalf("expected failure after attempts exhausted")
	}
	if calls != 2 {
		t.Fatalf("expected attempt limit respected, got %d calls", calls)
	}
}

func TestBootstrapUnknownExitFallbackFlagOffStrict(t *testing.T) {
	result := runBootstrapUnknownExitFallbackScenario(t, false)
	if result.err == nil {
		t.Fatalf("expected bootstrap failure when unknown-exit fallback is disabled")
	}
	if !strings.Contains(result.err.Error(), "path open denied: unknown-exit") {
		t.Fatalf("expected unknown-exit denial, got %v", result.err)
	}
	if result.pathOpenCalls != 1 {
		t.Fatalf("expected strict mode to stop after first unknown-exit, got %d attempts", result.pathOpenCalls)
	}
	if len(result.pathOpenExitIDs) != 1 {
		t.Fatalf("expected only one attempted exit, got %v", result.pathOpenExitIDs)
	}
}

func TestBootstrapUnknownExitFallbackFlagOnRetriesNextPair(t *testing.T) {
	result := runBootstrapUnknownExitFallbackScenario(t, true)
	if result.err != nil {
		t.Fatalf("expected bootstrap success with unknown-exit fallback enabled, got %v", result.err)
	}
	if result.pathOpenCalls != 2 {
		t.Fatalf("expected fallback retry to second pair, got %d attempts", result.pathOpenCalls)
	}
	if len(result.pathOpenExitIDs) != 2 {
		t.Fatalf("expected two attempted exits, got %v", result.pathOpenExitIDs)
	}
	if result.pathOpenExitIDs[0] == result.pathOpenExitIDs[1] {
		t.Fatalf("expected fallback to move to a different pair, got attempts %v", result.pathOpenExitIDs)
	}
	if result.selectedExit != result.pathOpenExitIDs[1] {
		t.Fatalf("expected fallback to select second attempted exit, selected=%s attempts=%v", result.selectedExit, result.pathOpenExitIDs)
	}
}

func TestBootstrapStrictPreferMiddleReportsMiddleRequirement(t *testing.T) {
	directoryURL := "http://d1.local"
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	entry := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "entry-a",
		Role:       "entry",
		ControlURL: "http://entry-a.local",
		OperatorID: "op-a",
		Endpoint:   "127.0.0.1:51820",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)
	exit := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-a",
		Role:       "exit",
		ControlURL: "http://exit-a.local",
		OperatorID: "op-b",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)

	handlers := map[string]func(*http.Request) (*http.Response, error){
		directoryURL + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
		directoryURL + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{entry, exit}}),
	}

	c := &Client{
		directoryURLs:         []string{directoryURL},
		directoryMinSources:   1,
		directoryMinOperators: 1,
		directoryMinVotes:     1,
		subject:               "inv-test",
		preferMiddleRelay:     true,
		requireMiddleRelay:    false,
		betaStrict:            true,
		healthCheckEnabled:    false,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	err = c.bootstrap(context.Background())
	if err == nil {
		t.Fatalf("expected bootstrap failure when strict middle-hop policy cannot be satisfied")
	}
	if !strings.Contains(err.Error(), "middle-hop relay requirement not met") {
		t.Fatalf("expected strict middle-hop failure reason, got %v", err)
	}
}

func TestRankRelayPairsAppliesExitOperatorCap(t *testing.T) {
	c := &Client{
		entryURL:            "http://fallback-entry.local",
		exitControlURL:      "http://fallback-exit.local",
		healthCheckEnabled:  false,
		maxExitsPerOperator: 1,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "exit-a1", Role: "exit", ControlURL: "exit-a1.local", OperatorID: "op-a"},
		{RelayID: "exit-a2", Role: "exit", ControlURL: "exit-a2.local", OperatorID: "op-a"},
		{RelayID: "exit-b1", Role: "exit", ControlURL: "exit-b1.local", OperatorID: "op-b"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	seenExits := map[string]struct{}{}
	for _, p := range pairs {
		seenExits[p.exit.RelayID] = struct{}{}
	}
	if len(seenExits) != 2 {
		t.Fatalf("expected one exit per operator after cap, got exits=%v", seenExits)
	}
	if _, ok := seenExits["exit-b1"]; !ok {
		t.Fatalf("expected operator b exit included")
	}
	if _, ok := seenExits["exit-a1"]; !ok {
		if _, ok2 := seenExits["exit-a2"]; !ok2 {
			t.Fatalf("expected one operator a exit included")
		}
	}
}

func TestRankRelayPairsDistinctOperators(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		requireDistinctOps: true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local", OperatorID: "op-a"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "entry-b.local", OperatorID: "op-b"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "exit-a.local", OperatorID: "op-a"},
		{RelayID: "exit-c", Role: "exit", ControlURL: "exit-c.local", OperatorID: "op-c"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) == 0 {
		t.Fatalf("expected non-empty pairs with distinct operators available")
	}
	for _, pair := range pairs {
		if pair.entry.OperatorID == pair.exit.OperatorID {
			t.Fatalf("expected distinct operators, got pair=%s->%s op=%s",
				pair.entry.RelayID, pair.exit.RelayID, pair.entry.OperatorID)
		}
	}
	for _, pair := range pairs {
		if pair.entry.RelayID == "entry-a" && pair.exit.RelayID == "exit-a" {
			t.Fatalf("same-operator pair should be filtered")
		}
	}
}

func TestRankRelayPairsDistinctOperatorsRequiresMetadata(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		requireDistinctOps: true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "exit-b.local", OperatorID: "op-b"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) != 0 {
		t.Fatalf("expected no pairs when operator metadata missing under distinct-operator mode, got %d", len(pairs))
	}
}

func TestRankRelayPairsDistinctCountries(t *testing.T) {
	c := &Client{
		entryURL:                 "http://fallback-entry.local",
		exitControlURL:           "http://fallback-exit.local",
		healthCheckEnabled:       false,
		requireDistinctCountries: true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-us", Role: "entry", ControlURL: "entry-us.local", CountryCode: "US"},
		{RelayID: "entry-de", Role: "entry", ControlURL: "entry-de.local", CountryCode: "DE"},
		{RelayID: "exit-us", Role: "exit", ControlURL: "exit-us.local", CountryCode: "US"},
		{RelayID: "exit-fr", Role: "exit", ControlURL: "exit-fr.local", CountryCode: "FR"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) == 0 {
		t.Fatalf("expected non-empty pairs with distinct countries available")
	}
	for _, pair := range pairs {
		if normalizeCountryCode(pair.entry.CountryCode) == normalizeCountryCode(pair.exit.CountryCode) {
			t.Fatalf("expected distinct countries, got pair=%s->%s country=%s",
				pair.entry.RelayID, pair.exit.RelayID, pair.entry.CountryCode)
		}
	}
	for _, pair := range pairs {
		if pair.entry.RelayID == "entry-us" && pair.exit.RelayID == "exit-us" {
			t.Fatalf("same-country pair should be filtered")
		}
	}
}

func TestRankRelayPairsDistinctCountriesRequiresMetadata(t *testing.T) {
	c := &Client{
		entryURL:                 "http://fallback-entry.local",
		exitControlURL:           "http://fallback-exit.local",
		healthCheckEnabled:       false,
		requireDistinctCountries: true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "exit-us", Role: "exit", ControlURL: "exit-us.local", CountryCode: "US"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) != 0 {
		t.Fatalf("expected no pairs when country metadata missing under distinct-country mode, got %d", len(pairs))
	}
}

func TestRankRelayPairsThreeHopPrefersPairsWithMiddleRelay(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		requireDistinctOps: true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", OperatorID: "op-a"},
		{RelayID: "entry-b", Role: "entry", OperatorID: "op-b"},
		{RelayID: "exit-c", Role: "exit", OperatorID: "op-c"},
		{RelayID: "middle-a", Role: "entry", OperatorID: "op-a", HopRoles: []string{"middle"}},
		{RelayID: "middle-d", Role: "entry", OperatorID: "op-d", HopRoles: []string{"middle"}},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) == 0 {
		t.Fatalf("expected 3hop pairs")
	}
	if !pairs[0].hasMiddle {
		t.Fatalf("expected first ranked pair to include a middle relay")
	}
	if pairs[0].middle.RelayID == "" {
		t.Fatalf("expected selected middle relay id")
	}
	if strings.TrimSpace(pairs[0].middle.OperatorID) == strings.TrimSpace(pairs[0].entry.OperatorID) {
		t.Fatalf("expected middle operator to differ from entry operator for preferred pair")
	}
}

func TestRankRelayPairsThreeHopRequireMiddleRelay(t *testing.T) {
	c := &Client{
		entryURL:                 "http://fallback-entry.local",
		exitControlURL:           "http://fallback-exit.local",
		healthCheckEnabled:       false,
		pathProfile:              "3hop",
		preferMiddleRelay:        true,
		requireMiddleRelay:       true,
		requireDistinctOps:       true,
		requireDistinctCountries: false,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", OperatorID: "op-a"},
		{RelayID: "exit-b", Role: "exit", OperatorID: "op-b"},
		// middle candidate exists but collides with entry operator under distinct-ops
		{RelayID: "middle-a", Role: "entry", OperatorID: "op-a", HopRoles: []string{"middle"}},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) != 0 {
		t.Fatalf("expected no pairs when strict middle relay requirement cannot be met, got %d", len(pairs))
	}
}

func TestRankRelayPairsStrictThreeHopRequiresMiddleRelay(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		requireMiddleRelay: false, // strict mode should still fail closed for 3-hop paths.
		betaStrict:         true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", OperatorID: "op-a"},
		{RelayID: "exit-b", Role: "exit", OperatorID: "op-b"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) != 0 {
		t.Fatalf("expected strict 3hop to reject entry/exit-only candidates, got %d", len(pairs))
	}
}

func TestRankRelayPairsStrictThreeHopAcceptsAliasMiddleRole(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		pathProfile:        "3hop",
		preferMiddleRelay:  true,
		betaStrict:         true,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", OperatorID: "op-a"},
		{RelayID: "exit-b", Role: "exit", OperatorID: "op-b"},
		// Role alias only; no HopRoles/Capabilities.
		{RelayID: "middle-c", Role: "micro-relay", OperatorID: "op-c"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) == 0 {
		t.Fatalf("expected strict 3hop to accept alias middle-role relay")
	}
	if !pairs[0].hasMiddle {
		t.Fatalf("expected first ranked strict 3hop pair to include middle relay")
	}
	if pairs[0].middle.RelayID != "middle-c" {
		t.Fatalf("expected middle-c to be selected, got %q", pairs[0].middle.RelayID)
	}
}

func TestRelaySupportsMiddleHopRoleAliasesWithoutExtraMetadata(t *testing.T) {
	aliases := []string{
		"middle",
		"relay",
		"micro-relay",
		"micro_relay",
		"transit",
		"three-hop-middle",
	}
	for _, alias := range aliases {
		if !relaySupportsMiddleHop(proto.RelayDescriptor{Role: alias}) {
			t.Fatalf("expected alias role %q to be accepted as middle-capable", alias)
		}
	}
}

func TestRankRelayPairsAppliesStickyPairPreference(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		stickyPairSec:      60,
		lastSelectedEntry:  "entry-b",
		lastSelectedExit:   "exit-b",
		lastSelectedAt:     time.Now(),
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "entry-b.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "exit-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "exit-b.local"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) < 2 {
		t.Fatalf("expected multiple pairs, got %d", len(pairs))
	}
	if pairs[0].entry.RelayID != "entry-b" || pairs[0].exit.RelayID != "exit-b" {
		t.Fatalf("expected sticky pair first, got entry=%s exit=%s", pairs[0].entry.RelayID, pairs[0].exit.RelayID)
	}
}

func TestRankRelayPairsStickyPairWithEntryRotationJitter(t *testing.T) {
	c := &Client{
		entryURL:               "http://fallback-entry.local",
		exitControlURL:         "http://fallback-exit.local",
		healthCheckEnabled:     false,
		stickyPairSec:          60,
		entryRotationSec:       30,
		entryRotationJitterPct: 90,
		entryRotationSeed:      7,
		lastSelectedEntry:      "entry-b",
		lastSelectedExit:       "exit-b",
		lastSelectedAt:         time.Now(),
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "entry-b.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "exit-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "exit-b.local"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) < 2 {
		t.Fatalf("expected multiple pairs, got %d", len(pairs))
	}
	if pairs[0].entry.RelayID != "entry-b" || pairs[0].exit.RelayID != "exit-b" {
		t.Fatalf("expected sticky pair first with rotation+jitter enabled, got entry=%s exit=%s", pairs[0].entry.RelayID, pairs[0].exit.RelayID)
	}
}

func TestRankRelayPairsStickyPairExpires(t *testing.T) {
	c := &Client{
		entryURL:           "http://fallback-entry.local",
		exitControlURL:     "http://fallback-exit.local",
		healthCheckEnabled: false,
		stickyPairSec:      1,
		lastSelectedEntry:  "entry-b",
		lastSelectedExit:   "exit-b",
		lastSelectedAt:     time.Now().Add(-3 * time.Second),
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "entry-b", Role: "entry", ControlURL: "entry-b.local"},
		{RelayID: "exit-a", Role: "exit", ControlURL: "exit-a.local"},
		{RelayID: "exit-b", Role: "exit", ControlURL: "exit-b.local"},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) == 0 {
		t.Fatalf("expected non-empty pair list")
	}
	if pairs[0].entry.RelayID != "entry-a" || pairs[0].exit.RelayID != "exit-a" {
		t.Fatalf("expected default first pair when sticky expired, got entry=%s exit=%s", pairs[0].entry.RelayID, pairs[0].exit.RelayID)
	}
	if c.lastSelectedEntry != "" || c.lastSelectedExit != "" {
		t.Fatalf("expected expired sticky pair state cleared")
	}
}

func TestApplyEntryRotationDisabled(t *testing.T) {
	c := &Client{
		entryRotationSec: 0,
	}
	entries := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry"},
		{RelayID: "entry-b", Role: "entry"},
	}
	got := c.applyEntryRotation(entries, time.Unix(120, 0))
	if len(got) != len(entries) {
		t.Fatalf("unexpected rotated length: got=%d want=%d", len(got), len(entries))
	}
	if got[0].RelayID != "entry-a" || got[1].RelayID != "entry-b" {
		t.Fatalf("rotation should be disabled, got order=%s,%s", got[0].RelayID, got[1].RelayID)
	}
}

func TestApplyEntryRotationDeterministic(t *testing.T) {
	c := &Client{
		entryRotationSec:       10,
		entryRotationJitterPct: 0,
		entryRotationSeed:      2,
	}
	entries := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry"},
		{RelayID: "entry-b", Role: "entry"},
		{RelayID: "entry-c", Role: "entry"},
	}
	// now=20s => slot=2, len=3, seed=2 => shift=(2+2)%3=1
	got := c.applyEntryRotation(entries, time.Unix(20, 0))
	if len(got) != 3 {
		t.Fatalf("unexpected rotated length: %d", len(got))
	}
	if got[0].RelayID != "entry-b" || got[1].RelayID != "entry-c" || got[2].RelayID != "entry-a" {
		t.Fatalf("unexpected deterministic rotation order: %s,%s,%s", got[0].RelayID, got[1].RelayID, got[2].RelayID)
	}
}

func TestApplyEntryRotationZeroJitterMatchesLegacy(t *testing.T) {
	legacy := &Client{
		entryRotationSec:  10,
		entryRotationSeed: 2,
	}
	withZeroJitter := &Client{
		entryRotationSec:       10,
		entryRotationJitterPct: 0,
		entryRotationSeed:      2,
	}
	entries := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry"},
		{RelayID: "entry-b", Role: "entry"},
		{RelayID: "entry-c", Role: "entry"},
	}
	now := time.Unix(39, 0)
	gotLegacy := legacy.applyEntryRotation(entries, now)
	gotZeroJitter := withZeroJitter.applyEntryRotation(entries, now)
	if len(gotLegacy) != len(gotZeroJitter) {
		t.Fatalf("unexpected rotated length mismatch: legacy=%d zero_jitter=%d", len(gotLegacy), len(gotZeroJitter))
	}
	for i := range gotLegacy {
		if gotLegacy[i].RelayID != gotZeroJitter[i].RelayID {
			t.Fatalf("expected jitter=0 parity at idx=%d legacy=%s zero_jitter=%s", i, gotLegacy[i].RelayID, gotZeroJitter[i].RelayID)
		}
	}
}

func TestApplyEntryRotationJitterDeterministicShift(t *testing.T) {
	base := &Client{
		entryRotationSec:  10,
		entryRotationSeed: 2,
	}
	jittered := &Client{
		entryRotationSec:       10,
		entryRotationJitterPct: 50,
		entryRotationSeed:      2,
	}
	offset := jittered.entryRotationJitterOffsetSec(10)
	if offset == 0 {
		t.Fatalf("expected non-zero jitter offset for deterministic shift test")
	}

	nowUnix := int64(20)
	if offset > 0 {
		nowUnix = 19
	}
	now := time.Unix(nowUnix, 0)
	entries := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry"},
		{RelayID: "entry-b", Role: "entry"},
		{RelayID: "entry-c", Role: "entry"},
	}
	gotBase := base.applyEntryRotation(entries, now)
	got1 := jittered.applyEntryRotation(entries, now)
	got2 := jittered.applyEntryRotation(entries, now)
	for i := range got1 {
		if got1[i].RelayID != got2[i].RelayID {
			t.Fatalf("expected jittered rotation stable within slot at idx=%d got1=%s got2=%s", i, got1[i].RelayID, got2[i].RelayID)
		}
	}
	sameAsBase := true
	for i := range got1 {
		if got1[i].RelayID != gotBase[i].RelayID {
			sameAsBase = false
			break
		}
	}
	if sameAsBase {
		t.Fatalf("expected jittered rotation to shift slot ordering: offset=%d now=%d", offset, nowUnix)
	}
}

func TestApplyEntryRotationJitterBoundedEdgeValues(t *testing.T) {
	entries := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry"},
		{RelayID: "entry-b", Role: "entry"},
		{RelayID: "entry-c", Role: "entry"},
	}
	cases := []int{-50, 0, 1, 90, 120}
	for _, jitterPct := range cases {
		c := &Client{
			entryRotationSec:       10,
			entryRotationJitterPct: jitterPct,
			entryRotationSeed:      9,
		}
		offset := c.entryRotationJitterOffsetSec(10)
		clamped := clampEntryRotationJitterPct(jitterPct)
		spread := int64((10 * clamped) / 100)
		if offset < -spread || offset > spread {
			t.Fatalf("jitter offset out of bounds for pct=%d offset=%d spread=%d", jitterPct, offset, spread)
		}
		for _, nowUnix := range []int64{0, 9, 10, 11, 99} {
			got := c.applyEntryRotation(entries, time.Unix(nowUnix, 0))
			if len(got) != len(entries) {
				t.Fatalf("unexpected rotated length for pct=%d now=%d got=%d want=%d", jitterPct, nowUnix, len(got), len(entries))
			}
		}
	}
}

func TestCapExitsPerOperatorFallbackRelayID(t *testing.T) {
	exits := []proto.RelayDescriptor{
		{RelayID: "x1", Role: "exit"},
		{RelayID: "x2", Role: "exit"},
	}
	capped := capExitsPerOperator(exits, 1)
	// No shared operator id, so each relay should be treated independently.
	if len(capped) != 2 {
		t.Fatalf("expected both exits kept without operator_id collision, got %d", len(capped))
	}
}

func TestOrderExitsForSelectionNoSignalsPreservesOrder(t *testing.T) {
	c := &Client{
		exitExplorationPct: 50,
		exitSelectionSeed:  7,
	}
	exits := []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit"},
		{RelayID: "exit-b", Role: "exit"},
		{RelayID: "exit-c", Role: "exit"},
	}
	ordered, mode := c.orderExitsForSelection(exits)
	if mode != "" {
		t.Fatalf("expected weighted ordering disabled without scores, got mode=%s", mode)
	}
	for i := range exits {
		if ordered[i].RelayID != exits[i].RelayID {
			t.Fatalf("expected stable order at index %d: got=%s want=%s", i, ordered[i].RelayID, exits[i].RelayID)
		}
	}
}

func TestScoreExitsIncludesBondStakeSignals(t *testing.T) {
	exits := []proto.RelayDescriptor{
		{RelayID: "exit-base", Role: "exit", Reputation: 0.7, Uptime: 0.7, Capacity: 0.7, AbusePenalty: 0.1, BondScore: 0.0, StakeScore: 0.0},
		{RelayID: "exit-bonded", Role: "exit", Reputation: 0.7, Uptime: 0.7, Capacity: 0.7, AbusePenalty: 0.1, BondScore: 1.0, StakeScore: 1.0},
	}
	scored, enabled := scoreExits(exits)
	if !enabled {
		t.Fatalf("expected weighted scoring enabled")
	}
	if len(scored) != 2 {
		t.Fatalf("expected two scored exits, got %d", len(scored))
	}
	weights := map[string]float64{}
	for _, s := range scored {
		weights[s.desc.RelayID] = s.weight
	}
	if weights["exit-bonded"] <= weights["exit-base"] {
		t.Fatalf("expected bond/stake-enhanced exit weight higher, base=%.3f bonded=%.3f", weights["exit-base"], weights["exit-bonded"])
	}
}

func TestRankRelayPairsWeightedExplorationFloor(t *testing.T) {
	c := &Client{
		entryURL:            "http://fallback-entry.local",
		exitControlURL:      "http://fallback-exit.local",
		healthCheckEnabled:  false,
		exitExplorationPct:  50,
		exitSelectionSeed:   11,
		maxPairCandidates:   0,
		maxExitsPerOperator: 0,
	}
	relays := []proto.RelayDescriptor{
		{RelayID: "entry-a", Role: "entry", ControlURL: "entry-a.local"},
		{RelayID: "exit-high-a", Role: "exit", ControlURL: "exit-high-a.local", Reputation: 1.0, Uptime: 0.95, Capacity: 0.9},
		{RelayID: "exit-high-b", Role: "exit", ControlURL: "exit-high-b.local", Reputation: 0.92, Uptime: 0.9, Capacity: 0.88},
		{RelayID: "exit-low-a", Role: "exit", ControlURL: "exit-low-a.local", Reputation: 0.15, Uptime: 0.2, Capacity: 0.25, AbusePenalty: 0.3},
		{RelayID: "exit-low-b", Role: "exit", ControlURL: "exit-low-b.local", Reputation: 0.1, Uptime: 0.18, Capacity: 0.2, AbusePenalty: 0.35},
	}
	pairs := c.rankRelayPairs(context.Background(), relays)
	if len(pairs) != 4 {
		t.Fatalf("expected 4 pairs for single-entry ranking, got %d", len(pairs))
	}
	firstTwo := []string{pairs[0].exit.RelayID, pairs[1].exit.RelayID}
	hasLow := false
	for _, id := range firstTwo {
		if strings.HasPrefix(id, "exit-low-") {
			hasLow = true
			break
		}
	}
	if !hasLow {
		t.Fatalf("expected exploration floor to include low-score exit in first attempts, got %v", firstTwo)
	}
}

func TestSelectPreferredExitsRespectsGeoConfidence(t *testing.T) {
	c := &Client{
		preferredExitCountry:  "US",
		minGeoConfidence:      0.8,
		localityFallbackOrder: parseLocalityFallbackOrder("country,global"),
		strictExitLocality:    true,
	}
	exits := []proto.RelayDescriptor{
		{RelayID: "exit-us-low", Role: "exit", CountryCode: "US", GeoConfidence: 0.3, Region: "us-east"},
		{RelayID: "exit-de-high", Role: "exit", CountryCode: "DE", GeoConfidence: 0.95, Region: "eu-west"},
	}
	selected, mode := c.selectPreferredExits(exits)
	if len(selected) != 0 {
		t.Fatalf("expected strict locality failure with low-confidence country data")
	}
	if mode != "strict-locality-no-match" {
		t.Fatalf("expected strict no match mode, got %s", mode)
	}
}

func TestSelectPreferredExitsRegionPrefixFallback(t *testing.T) {
	c := &Client{
		preferredExitRegion:   "us-west",
		minGeoConfidence:      0.5,
		localityFallbackOrder: parseLocalityFallbackOrder("region,region-prefix,global"),
	}
	exits := []proto.RelayDescriptor{
		{RelayID: "exit-us-east", Role: "exit", Region: "us-east", GeoConfidence: 0.9},
		{RelayID: "exit-eu", Role: "exit", Region: "eu-west", GeoConfidence: 0.9},
	}
	selected, mode := c.selectPreferredExits(exits)
	if mode != "region-prefix" {
		t.Fatalf("expected region-prefix fallback mode, got %s", mode)
	}
	if len(selected) != 1 || selected[0].RelayID != "exit-us-east" {
		t.Fatalf("expected region-prefix fallback exit selected, got %+v", selected)
	}
}

func TestSelectPreferredExitsSoftLocalityBiasKeepsGlobalPool(t *testing.T) {
	c := &Client{
		preferredExitCountry:  "US",
		localitySoftBias:      true,
		localityFallbackOrder: parseLocalityFallbackOrder("country,global"),
		strictExitLocality:    false,
	}
	exits := []proto.RelayDescriptor{
		{RelayID: "exit-us", Role: "exit", CountryCode: "US", Region: "us-east", GeoConfidence: 0.9},
		{RelayID: "exit-fr", Role: "exit", CountryCode: "FR", Region: "eu-west", GeoConfidence: 0.9},
	}
	selected, mode := c.selectPreferredExits(exits)
	if mode != "soft-country" {
		t.Fatalf("expected soft-country mode, got %s", mode)
	}
	if len(selected) != len(exits) {
		t.Fatalf("expected soft locality to keep global exit pool, got=%d want=%d", len(selected), len(exits))
	}
}

func TestOrderExitsForSelectionSoftLocalityBiasWithoutScores(t *testing.T) {
	c := &Client{
		preferredExitCountry:     "US",
		localitySoftBias:         true,
		localityCountryBias:      3.0,
		localityRegionBias:       1.5,
		localityRegionPrefixBias: 1.2,
		exitExplorationPct:       0,
		exitSelectionSeed:        17,
	}
	exits := []proto.RelayDescriptor{
		{RelayID: "exit-fr", Role: "exit", CountryCode: "FR", Region: "eu-west", GeoConfidence: 0.9},
		{RelayID: "exit-us", Role: "exit", CountryCode: "US", Region: "us-east", GeoConfidence: 0.9},
	}
	ordered, mode := c.orderExitsForSelection(exits)
	if mode != "weighted-random-locality-bias" {
		t.Fatalf("expected locality-bias weighting mode, got %s", mode)
	}
	if len(ordered) != len(exits) {
		t.Fatalf("expected same exit count, got=%d want=%d", len(ordered), len(exits))
	}
	base := []scoredExit{
		{desc: exits[0], weight: 1.0},
		{desc: exits[1], weight: 1.0},
	}
	biased, applied := c.applyLocalityBias(base)
	if !applied {
		t.Fatalf("expected locality bias to apply")
	}
	weights := map[string]float64{}
	for _, item := range biased {
		weights[item.desc.RelayID] = item.weight
	}
	if weights["exit-us"] <= weights["exit-fr"] {
		t.Fatalf("expected US locality-biased weight > FR weight, us=%.2f fr=%.2f", weights["exit-us"], weights["exit-fr"])
	}
}

func TestParseLocalityFallbackOrder(t *testing.T) {
	got := parseLocalityFallbackOrder("country,region-prefix,global,invalid,global")
	if len(got) != 3 {
		t.Fatalf("expected three valid unique modes, got %v", got)
	}
	if got[0] != "country" || got[1] != "region-prefix" || got[2] != "global" {
		t.Fatalf("unexpected parsed order: %v", got)
	}
}

type unknownExitFallbackScenarioResult struct {
	err             error
	pathOpenCalls   int
	pathOpenExitIDs []string
	selectedExit    string
}

func runBootstrapUnknownExitFallbackScenario(t *testing.T, allowUnknownFallback bool) unknownExitFallbackScenarioResult {
	t.Helper()

	directoryURL := "http://d1.local"
	issuerURL := "http://issuer.local"
	entryURL := "http://entry.local"

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	entry := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "entry-a",
		Role:       "entry",
		ControlURL: entryURL,
		OperatorID: "op-a",
		Endpoint:   "127.0.0.1:51820",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)
	exitUnknown := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-unknown",
		Role:       "exit",
		ControlURL: "http://exit-unknown.local",
		OperatorID: "op-b",
		Endpoint:   "127.0.0.1:51821",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)
	exitGood := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-good",
		Role:       "exit",
		ControlURL: "http://exit-good.local",
		OperatorID: "op-c",
		Endpoint:   "127.0.0.1:51822",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv)

	pathOpenCalls := 0
	pathOpenExitIDs := make([]string, 0, 2)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		directoryURL + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
		directoryURL + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{entry, exitUnknown, exitGood}}),
		issuerURL + "/v1/token": func(req *http.Request) (*http.Response, error) {
			var in proto.IssueTokenRequest
			if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			if len(in.ExitScope) != 1 {
				t.Fatalf("expected single exit scope, got %+v", in.ExitScope)
			}
			return jsonResp(proto.IssueTokenResponse{
				Token:   "tok-" + in.ExitScope[0],
				Expires: time.Now().Add(time.Minute).Unix(),
			})(req)
		},
		entryURL + "/v1/path/open": func(req *http.Request) (*http.Response, error) {
			pathOpenCalls++
			var in proto.PathOpenRequest
			if err := json.NewDecoder(req.Body).Decode(&in); err != nil {
				t.Fatalf("decode path open request: %v", err)
			}
			pathOpenExitIDs = append(pathOpenExitIDs, strings.TrimSpace(in.ExitID))
			if pathOpenCalls == 1 {
				return jsonResp(proto.PathOpenResponse{Accepted: false, Reason: "unknown-exit"})(req)
			}
			return jsonResp(proto.PathOpenResponse{
				Accepted:      true,
				SessionID:     "sess-" + strings.TrimSpace(in.ExitID),
				SessionExp:    time.Now().Add(time.Minute).Unix(),
				EntryDataAddr: entry.Endpoint,
				Transport:     "policy-json",
			})(req)
		},
		entryURL + "/v1/path/close": jsonResp(proto.PathCloseResponse{Closed: true}),
	}

	c := &Client{
		directoryURLs:            []string{directoryURL},
		directoryMinSources:      1,
		directoryMinOperators:    1,
		directoryMinVotes:        1,
		issuerURL:                issuerURL,
		subject:                  "inv-test",
		entryURL:                 entryURL,
		dataMode:                 "json",
		clientWGPub:              mustRandomWGPublicKeyLike(t),
		pathOpenMaxAttempts:      2,
		maxPairCandidates:        2,
		healthCheckEnabled:       false,
		allowUnknownExitFallback: allowUnknownFallback,
		allowDirectExitFallback:  false,
		httpClient:               &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	err = c.bootstrap(context.Background())
	return unknownExitFallbackScenarioResult{
		err:             err,
		pathOpenCalls:   pathOpenCalls,
		pathOpenExitIDs: append([]string(nil), pathOpenExitIDs...),
		selectedExit:    c.lastSelectedExit,
	}
}

func statusResp(status int) func(*http.Request) (*http.Response, error) {
	return func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
		}, nil
	}
}
