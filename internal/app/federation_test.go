package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/http"
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
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("not found"))}, nil
}

func TestFetchRelaysFederatedQuorum(t *testing.T) {
	url1 := "http://d1.local"
	url2 := "http://d2.local"

	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	pub2, priv2, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url2 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub2)}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "entry-a", "entry", priv1)}}),
		url2 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "exit-a", "exit", priv2)}}),
	}

	c := &Client{
		directoryURLs:       []string{url1, url2},
		directoryMinSources: 2,
		directoryMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		trustStrict:         false,
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) < 2 {
		t.Fatalf("expected merged relays from both sources, got %d", len(relays))
	}
}

func TestFetchRelaysFederatedQuorumFailure(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "entry-a", "entry", priv1)}}),
	}

	c := &Client{
		directoryURLs:       []string{url1, "http://missing.local"},
		directoryMinSources: 2,
		directoryMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		trustStrict:         false,
	}

	if _, err := c.fetchRelaysFederated(context.Background()); err == nil {
		t.Fatalf("expected quorum failure")
	}
}

func TestFetchRelaysFederatedOperatorQuorumFailure(t *testing.T) {
	url1 := "http://d1.local"
	url2 := "http://d2.local"

	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	pub2, priv2, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			Operator: "operator-a",
			PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pub1)},
		}),
		url2 + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			Operator: "operator-a",
			PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pub2)},
		}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "entry-a", "entry", priv1)}}),
		url2 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "exit-a", "exit", priv2)}}),
	}

	c := &Client{
		directoryURLs:         []string{url1, url2},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     1,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		trustStrict:           false,
	}
	if _, err := c.fetchRelaysFederated(context.Background()); err == nil {
		t.Fatalf("expected operator quorum failure")
	}
}

func TestFetchRelaysFederatedRelayVoteThreshold(t *testing.T) {
	url1 := "http://d1.local"
	url2 := "http://d2.local"

	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	pub2, priv2, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}

	sharedEntry1 := signedDesc(t, "entry-shared", "entry", priv1)
	sharedEntry2 := signedDesc(t, "entry-shared", "entry", priv2)
	uniqueExit := signedDesc(t, "exit-unique", "exit", priv2)

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url2 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub2)}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{sharedEntry1}}),
		url2 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{sharedEntry2, uniqueExit}}),
	}

	c := &Client{
		directoryURLs:       []string{url1, url2},
		directoryMinSources: 2,
		directoryMinVotes:   2,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		trustStrict:         false,
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected only shared relay to pass vote threshold, got %d", len(relays))
	}
	if relays[0].RelayID != "entry-shared" {
		t.Fatalf("unexpected relay selected: %+v", relays[0])
	}
}

func TestFetchRelaysFederatedRelayVotesDedupByOperator(t *testing.T) {
	url1 := "http://d1.local"
	url2 := "http://d2.local"

	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	pub2, priv2, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}

	shared1 := signedDesc(t, "exit-shared", "exit", priv1)
	shared2 := signedDesc(t, "exit-shared", "exit", priv2)

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			Operator: "operator-a",
			PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pub1)},
		}),
		url2 + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			Operator: "operator-a",
			PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pub2)},
		}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{shared1}}),
		url2 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{shared2}}),
	}

	c := &Client{
		directoryURLs:         []string{url1, url2},
		directoryMinSources:   2,
		directoryMinOperators: 1,
		directoryMinVotes:     2,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		trustStrict:           false,
	}

	if _, err := c.fetchRelaysFederated(context.Background()); err == nil {
		t.Fatalf("expected relay vote threshold failure with operator-deduped votes")
	}
}

func TestFetchRelaysFederatedAppliesSignedSelectionFeed(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	exit := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-a",
		Role:       "exit",
		Endpoint:   "127.0.0.1:1",
		ValidUntil: time.Now().Add(time.Minute),
	}, priv1)
	feed := proto.RelaySelectionFeedResponse{
		Operator:    "operator-a",
		GeneratedAt: time.Now().Unix(),
		ExpiresAt:   time.Now().Add(30 * time.Second).Unix(),
		Scores: []proto.RelaySelectionScore{
			{
				RelayID:      "exit-a",
				Role:         "exit",
				Reputation:   0.91,
				Uptime:       0.88,
				Capacity:     0.77,
				AbusePenalty: 0.09,
			},
		},
	}
	feedSig, err := crypto.SignRelaySelectionFeed(feed, priv1)
	if err != nil {
		t.Fatalf("sign selection feed: %v", err)
	}
	feed.Signature = feedSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey":         jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays":         jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{exit}}),
		url1 + "/v1/selection-feed": jsonResp(feed),
	}
	c := &Client{
		directoryURLs:       []string{url1},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected one relay, got %d", len(relays))
	}
	got := relays[0]
	if got.RelayID != "exit-a" {
		t.Fatalf("unexpected relay id: %s", got.RelayID)
	}
	if math.Abs(got.Reputation-0.91) > 0.0001 || math.Abs(got.Uptime-0.88) > 0.0001 || math.Abs(got.Capacity-0.77) > 0.0001 || math.Abs(got.AbusePenalty-0.09) > 0.0001 {
		t.Fatalf("expected selection feed scores applied, got rep=%.3f uptime=%.3f cap=%.3f abuse=%.3f", got.Reputation, got.Uptime, got.Capacity, got.AbusePenalty)
	}
}

func TestFetchRelaysFederatedSelectionFeedRequiredUnavailable(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "exit-a", "exit", priv1)}}),
	}
	c := &Client{
		directoryURLs:        []string{url1},
		directoryMinSources:  1,
		directoryMinVotes:    1,
		selectionFeedRequire: true,
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if _, err := c.fetchRelaysFederated(context.Background()); err == nil {
		t.Fatalf("expected selection feed requirement failure")
	}
}

func TestFetchRelaysFederatedSelectionFeedInvalidIgnoredWhenOptional(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	_, otherPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}
	exit := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:     "exit-a",
		Role:        "exit",
		Endpoint:    "127.0.0.1:1",
		Reputation:  0.42,
		ValidUntil:  time.Now().Add(time.Minute),
		ControlURL:  "http://exit-a.local",
		CountryCode: "US",
	}, priv1)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: time.Now().Unix(),
		ExpiresAt:   time.Now().Add(30 * time.Second).Unix(),
		Scores: []proto.RelaySelectionScore{
			{RelayID: "exit-a", Role: "exit", Reputation: 0.99},
		},
	}
	invalidSig, err := crypto.SignRelaySelectionFeed(feed, otherPriv)
	if err != nil {
		t.Fatalf("sign selection feed invalid key: %v", err)
	}
	feed.Signature = invalidSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey":         jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays":         jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{exit}}),
		url1 + "/v1/selection-feed": jsonResp(feed),
	}
	c := &Client{
		directoryURLs:       []string{url1},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected one relay, got %d", len(relays))
	}
	if math.Abs(relays[0].Reputation-0.42) > 0.0001 {
		t.Fatalf("expected descriptor score retained when feed invalid, got %.3f", relays[0].Reputation)
	}
}

func TestFetchRelaysFederatedSelectionFeedMinVotes(t *testing.T) {
	url1 := "http://d1.local"
	url2 := "http://d2.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	pub2, priv2, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}
	shared1 := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		Endpoint:   "127.0.0.1:1",
		ValidUntil: time.Now().Add(time.Minute),
		Reputation: 0.30,
	}, priv1)
	shared2 := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-shared",
		Role:       "exit",
		Endpoint:   "127.0.0.1:1",
		ValidUntil: time.Now().Add(time.Minute),
		Reputation: 0.30,
	}, priv2)
	feed := proto.RelaySelectionFeedResponse{
		GeneratedAt: time.Now().Unix(),
		ExpiresAt:   time.Now().Add(30 * time.Second).Unix(),
		Scores: []proto.RelaySelectionScore{
			{RelayID: "exit-shared", Role: "exit", Reputation: 0.95},
		},
	}
	feedSig, err := crypto.SignRelaySelectionFeed(feed, priv1)
	if err != nil {
		t.Fatalf("sign selection feed: %v", err)
	}
	feed.Signature = feedSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey":         jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url2 + "/v1/pubkey":         jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub2)}),
		url1 + "/v1/relays":         jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{shared1}}),
		url2 + "/v1/relays":         jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{shared2}}),
		url1 + "/v1/selection-feed": jsonResp(feed),
	}
	c := &Client{
		directoryURLs:         []string{url1, url2},
		directoryMinSources:   2,
		directoryMinVotes:     2,
		selectionFeedMinVotes: 2,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected one shared relay, got %d", len(relays))
	}
	if math.Abs(relays[0].Reputation-0.30) > 0.0001 {
		t.Fatalf("expected descriptor score retained when feed votes below threshold, got %.3f", relays[0].Reputation)
	}
}

func TestFetchRelaysFederatedAppliesSignedTrustFeed(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	exit := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:    "exit-a",
		Role:       "exit",
		Endpoint:   "127.0.0.1:1",
		Reputation: 0.2,
		ValidUntil: time.Now().Add(time.Minute),
	}, priv1)
	trust := proto.RelayTrustAttestationFeedResponse{
		Operator:    "operator-a",
		GeneratedAt: time.Now().Unix(),
		ExpiresAt:   time.Now().Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-a",
				Role:         "exit",
				Reputation:   0.9,
				Uptime:       0.8,
				Capacity:     0.7,
				AbusePenalty: 0.1,
				BondScore:    0.85,
				StakeScore:   0.75,
				Confidence:   1.0,
			},
		},
	}
	trustSig, err := crypto.SignRelayTrustAttestationFeed(trust, priv1)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	trust.Signature = trustSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{exit}}),
		url1 + "/v1/trust-attestations": jsonResp(trust),
	}
	c := &Client{
		directoryURLs:       []string{url1},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected one relay, got %d", len(relays))
	}
	got := relays[0]
	if got.Reputation < 0.89 || got.Reputation > 0.91 {
		t.Fatalf("expected trust-adjusted reputation around 0.9, got %.3f", got.Reputation)
	}
	if got.BondScore < 0.84 || got.BondScore > 0.86 {
		t.Fatalf("expected trust-adjusted bond score around 0.85, got %.3f", got.BondScore)
	}
	if got.StakeScore < 0.74 || got.StakeScore > 0.76 {
		t.Fatalf("expected trust-adjusted stake score around 0.75, got %.3f", got.StakeScore)
	}
}

func TestFetchRelaysFederatedTrustFeedRequiredUnavailable(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{signedDesc(t, "exit-a", "exit", priv1)}}),
	}
	c := &Client{
		directoryURLs:       []string{url1},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		trustFeedRequire:    true,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if _, err := c.fetchRelaysFederated(context.Background()); err == nil {
		t.Fatalf("expected trust feed requirement failure")
	}
}

func TestFetchRelaysFederatedAppliesTrustDisputePenalty(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	exit := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:      "exit-a",
		Role:         "exit",
		Endpoint:     "127.0.0.1:1",
		Reputation:   0.95,
		Capacity:     0.92,
		AbusePenalty: 0.05,
		ValidUntil:   time.Now().Add(time.Minute),
	}, priv1)
	trust := proto.RelayTrustAttestationFeedResponse{
		Operator:    "operator-a",
		GeneratedAt: time.Now().Unix(),
		ExpiresAt:   time.Now().Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-a",
				Role:         "exit",
				Reputation:   0.95,
				Capacity:     0.90,
				AbusePenalty: 0.15,
				Confidence:   0.9,
				TierCap:      1,
				DisputeUntil: time.Now().Add(5 * time.Minute).Unix(),
			},
		},
	}
	trustSig, err := crypto.SignRelayTrustAttestationFeed(trust, priv1)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	trust.Signature = trustSig

	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{exit}}),
		url1 + "/v1/trust-attestations": jsonResp(trust),
	}
	c := &Client{
		directoryURLs:       []string{url1},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		trustFeedMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected one relay, got %d", len(relays))
	}
	got := relays[0]
	if got.AbusePenalty < 0.84 {
		t.Fatalf("expected elevated abuse penalty from dispute, got %.3f", got.AbusePenalty)
	}
	if got.Reputation > 0.70 {
		t.Fatalf("expected dispute-dampened reputation, got %.3f", got.Reputation)
	}
}

func TestFetchRelaysFederatedAppealMitigatesDisputePenalty(t *testing.T) {
	url1 := "http://d1.local"
	pub1, priv1, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen1: %v", err)
	}
	exit := signedDescFrom(t, proto.RelayDescriptor{
		RelayID:      "exit-a",
		Role:         "exit",
		Endpoint:     "127.0.0.1:1",
		Reputation:   0.95,
		Capacity:     0.92,
		AbusePenalty: 0.05,
		ValidUntil:   time.Now().Add(time.Minute),
	}, priv1)
	now := time.Now()
	withAppeal := proto.RelayTrustAttestationFeedResponse{
		Operator:    "operator-a",
		GeneratedAt: now.Unix(),
		ExpiresAt:   now.Add(30 * time.Second).Unix(),
		Attestations: []proto.RelayTrustAttestation{
			{
				RelayID:      "exit-a",
				Role:         "exit",
				Reputation:   0.95,
				Capacity:     0.90,
				AbusePenalty: 0.15,
				Confidence:   0.9,
				TierCap:      1,
				DisputeUntil: now.Add(5 * time.Minute).Unix(),
				AppealUntil:  now.Add(4 * time.Minute).Unix(),
			},
		},
	}
	sig, err := crypto.SignRelayTrustAttestationFeed(withAppeal, priv1)
	if err != nil {
		t.Fatalf("sign trust feed: %v", err)
	}
	withAppeal.Signature = sig
	handlers := map[string]func(*http.Request) (*http.Response, error){
		url1 + "/v1/pubkey":             jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub1)}),
		url1 + "/v1/relays":             jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{exit}}),
		url1 + "/v1/trust-attestations": jsonResp(withAppeal),
	}
	c := &Client{
		directoryURLs:       []string{url1},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		trustFeedMinVotes:   1,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	relays, err := c.fetchRelaysFederated(context.Background())
	if err != nil {
		t.Fatalf("fetch federated failed: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected one relay, got %d", len(relays))
	}
	got := relays[0]
	if got.AbusePenalty < 0.58 || got.AbusePenalty > 0.61 {
		t.Fatalf("expected appeal-mitigated dispute penalty near 0.595, got %.3f", got.AbusePenalty)
	}
}

func signedDesc(t *testing.T, relayID, role string, priv ed25519.PrivateKey) proto.RelayDescriptor {
	t.Helper()
	d := proto.RelayDescriptor{RelayID: relayID, Role: role, Endpoint: "127.0.0.1:1", ValidUntil: time.Now().Add(time.Minute)}
	return signedDescFrom(t, d, priv)
}

func signedDescFrom(t *testing.T, d proto.RelayDescriptor, priv ed25519.PrivateKey) proto.RelayDescriptor {
	t.Helper()
	d.Signature = ""
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	d.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, b))
	return d
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
