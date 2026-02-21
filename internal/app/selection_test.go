package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

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

func TestParseLocalityFallbackOrder(t *testing.T) {
	got := parseLocalityFallbackOrder("country,region-prefix,global,invalid,global")
	if len(got) != 3 {
		t.Fatalf("expected three valid unique modes, got %v", got)
	}
	if got[0] != "country" || got[1] != "region-prefix" || got[2] != "global" {
		t.Fatalf("unexpected parsed order: %v", got)
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
