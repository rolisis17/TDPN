package entry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nodecrypto "privacynode/pkg/crypto"
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

func TestResolveExitRouteFromDirectory(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "https://10.0.0.20:8084"},
	})

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	route, err := s.resolveExitRoute(context.Background(), "exit-a")
	if err != nil {
		t.Fatalf("resolve route failed: %v", err)
	}
	if route.controlURL != "https://10.0.0.20:8084" {
		t.Fatalf("unexpected control url: %s", route.controlURL)
	}
	if route.dataAddr != "10.0.0.20:51821" {
		t.Fatalf("unexpected data addr: %s", route.dataAddr)
	}
}

func TestResolveExitRouteFallback(t *testing.T) {
	s := &Service{
		exitControlURL: "127.0.0.1:8084",
		exitDataAddr:   "127.0.0.1:51821",
		routeTTL:       time.Minute,
		exitRouteCache: map[string]exitRoute{},
	}
	route, err := s.resolveExitRoute(context.Background(), "")
	if err != nil {
		t.Fatalf("resolve fallback failed: %v", err)
	}
	if route.controlURL != "http://127.0.0.1:8084" {
		t.Fatalf("unexpected fallback control url: %s", route.controlURL)
	}
	if route.dataAddr != "127.0.0.1:51821" {
		t.Fatalf("unexpected fallback data addr: %s", route.dataAddr)
	}
}

func TestResolveExitRouteFallbackStrictRejectsEmptyExitID(t *testing.T) {
	s := &Service{
		betaStrict:     true,
		exitControlURL: "127.0.0.1:8084",
		exitDataAddr:   "127.0.0.1:51821",
		routeTTL:       time.Minute,
		exitRouteCache: map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), ""); err == nil {
		t.Fatalf("expected strict mode to reject empty exit id fallback")
	}
}

func TestResolveExitRouteCached(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "10.0.0.20:8084"},
	})

	calls := 0
	origRelays := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		calls++
		return origRelays(req)
	}

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err != nil {
		t.Fatalf("first resolve failed: %v", err)
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err != nil {
		t.Fatalf("second resolve failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one directory relays fetch due to cache, got %d", calls)
	}
}

func TestResolveExitRouteStrictCacheHitStillValidatesRoute(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "198.51.100.20:51821", ControlURL: "https://198.51.100.20:8084"},
	})

	calls := 0
	origRelays := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		calls++
		return origRelays(req)
	}

	s := &Service{
		betaStrict:          true,
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache: map[string]exitRoute{
			"exit-a": {
				controlURL: "http://127.0.0.1:8084",
				dataAddr:   "127.0.0.1:51821",
				fetchedAt:  time.Now(),
			},
		},
	}

	route, err := s.resolveExitRoute(context.Background(), "exit-a")
	if err != nil {
		t.Fatalf("resolve route failed: %v", err)
	}
	if route.controlURL != "https://198.51.100.20:8084" {
		t.Fatalf("expected strict mode to ignore invalid cached route, got control url: %s", route.controlURL)
	}
	if route.dataAddr != "198.51.100.20:51821" {
		t.Fatalf("unexpected data addr: %s", route.dataAddr)
	}
	if calls != 1 {
		t.Fatalf("expected strict mode to re-fetch route when cached route is invalid, got %d relays calls", calls)
	}
}

func TestResolveExitRouteStrictBypassesCachedOperatorMetadata(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-a",
			Role:       "exit",
			Endpoint:   "198.51.100.20:51821",
			ControlURL: "https://198.51.100.20:8084",
			OperatorID: "op-fresh",
		},
	})

	calls := 0
	origRelays := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		calls++
		return origRelays(req)
	}

	s := &Service{
		betaStrict:          true,
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache: map[string]exitRoute{
			"exit-a": {
				controlURL: "https://198.51.100.20:8084",
				dataAddr:   "198.51.100.20:51821",
				operatorID: "op-stale",
				fetchedAt:  time.Now(),
				validUntil: time.Now().Add(time.Minute),
			},
		},
	}

	route, err := s.resolveExitRoute(context.Background(), "exit-a")
	if err != nil {
		t.Fatalf("resolve route failed: %v", err)
	}
	if route.operatorID != "op-fresh" {
		t.Fatalf("expected strict mode to bypass stale cached operator metadata, got %q", route.operatorID)
	}
	if calls != 1 {
		t.Fatalf("expected strict mode to bypass cache read and fetch relays, got %d relays calls", calls)
	}
}

func TestResolveExitRouteDistinctModeBypassesCachedOperatorMetadata(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-a",
			Role:       "exit",
			Endpoint:   "198.51.100.21:51821",
			ControlURL: "https://198.51.100.21:8084",
			OperatorID: "op-fresh",
		},
	})

	calls := 0
	origRelays := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		calls++
		return origRelays(req)
	}

	s := &Service{
		requireDistinctExitOp: true,
		exitControlURL:        "http://127.0.0.1:8084",
		exitDataAddr:          "127.0.0.1:51821",
		directoryURLs:         []string{durl},
		directoryMinSources:   1,
		directoryMinVotes:     1,
		routeTTL:              time.Minute,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache: map[string]exitRoute{
			"exit-a": {
				controlURL: "https://198.51.100.21:8084",
				dataAddr:   "198.51.100.21:51821",
				operatorID: "op-stale",
				fetchedAt:  time.Now(),
				validUntil: time.Now().Add(time.Minute),
			},
		},
	}

	route, err := s.resolveExitRoute(context.Background(), "exit-a")
	if err != nil {
		t.Fatalf("resolve route failed: %v", err)
	}
	if route.operatorID != "op-fresh" {
		t.Fatalf("expected distinct mode to bypass stale cached operator metadata, got %q", route.operatorID)
	}
	if calls != 1 {
		t.Fatalf("expected distinct mode to bypass cache read and fetch relays, got %d relays calls", calls)
	}
}

func TestResolveExitRouteCacheBypassesExpiredDescriptor(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "203.0.113.20:51821", ControlURL: "https://203.0.113.20:8084"},
	})

	calls := 0
	origRelays := handlers[durl+"/v1/relays"]
	handlers[durl+"/v1/relays"] = func(req *http.Request) (*http.Response, error) {
		calls++
		return origRelays(req)
	}

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache: map[string]exitRoute{
			"exit-a": {
				controlURL: "https://198.51.100.10:8084",
				dataAddr:   "198.51.100.10:51821",
				operatorID: "op-stale",
				fetchedAt:  time.Now(),
				validUntil: time.Now().Add(-1 * time.Minute),
			},
		},
	}

	route, err := s.resolveExitRoute(context.Background(), "exit-a")
	if err != nil {
		t.Fatalf("resolve route failed: %v", err)
	}
	if route.controlURL != "https://203.0.113.20:8084" {
		t.Fatalf("expected expired cache bypass, got control url: %s", route.controlURL)
	}
	if route.dataAddr != "203.0.113.20:51821" {
		t.Fatalf("unexpected data addr: %s", route.dataAddr)
	}
	if calls != 1 {
		t.Fatalf("expected one relays fetch after expired cache bypass, got %d", calls)
	}
}

func TestResolveExitRouteRejectsExpiredDirectoryDescriptor(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:    "exit-a",
			Role:       "exit",
			Endpoint:   "203.0.113.20:51821",
			ControlURL: "https://203.0.113.20:8084",
			ValidUntil: time.Now().Add(-1 * time.Minute),
		},
	})

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected expired directory descriptor to be rejected")
	}
}

func TestFetchDirectoryPubKeysStrictRejectsLegacyFallback(t *testing.T) {
	durl := "http://directory.local"
	pub, _, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	handlers := map[string]func(*http.Request) (*http.Response, error){
		durl + "/v1/pubkeys": func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("not found")),
			}, nil
		},
		durl + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
	}

	s := &Service{
		betaStrict: true,
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	if _, _, err := s.fetchDirectoryPubKeys(context.Background(), durl); err == nil {
		t.Fatalf("expected strict mode to reject legacy /v1/pubkey fallback")
	}
}

func TestResolveExitRouteUnknown(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{})

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "missing"); err == nil {
		t.Fatalf("expected unknown exit error")
	}
}

func TestResolveExitRouteQuorumFailure(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, d1, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "https://10.0.0.20:8084"},
	})
	// d2 intentionally missing to simulate failed source.

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{d1, d2},
		directoryMinSources: 2,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected source quorum failure")
	}
}

func TestResolveExitRouteOperatorQuorumFailure(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	pub, priv, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	relay := signDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-a",
		Role:       "exit",
		Endpoint:   "10.0.0.20:51821",
		ControlURL: "https://10.0.0.20:8084",
	}, priv)
	handlers[d1+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: "operator-a",
		PubKeys:  []string{pubB64},
	})
	handlers[d2+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: "operator-a",
		PubKeys:  []string{pubB64},
	})
	handlers[d1+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relay}})
	handlers[d2+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relay}})

	s := &Service{
		exitControlURL:        "http://127.0.0.1:8084",
		exitDataAddr:          "127.0.0.1:51821",
		directoryURLs:         []string{d1, d2},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     1,
		routeTTL:              time.Minute,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:        map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected operator quorum failure")
	}
}

func TestResolveExitRouteOperatorQuorumRejectsDeclaredOperatorAliasSpoofing(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))

	pub, priv, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	relay := signDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-a",
		Role:       "exit",
		Endpoint:   "198.51.100.20:51821",
		ControlURL: "https://198.51.100.20:8084",
		OperatorID: "exit-op",
	}, priv)

	handlers[d1+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: "spoofed-operator-a",
		PubKeys:  []string{pubB64},
	})
	handlers[d2+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: "spoofed-operator-b",
		PubKeys:  []string{pubB64},
	})
	handlers[d1+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relay}})
	handlers[d2+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relay}})

	s := &Service{
		exitControlURL:        "http://127.0.0.1:8084",
		exitDataAddr:          "127.0.0.1:51821",
		directoryURLs:         []string{d1, d2},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     1,
		routeTTL:              time.Minute,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:        map[string]exitRoute{},
	}

	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected operator quorum failure when multiple sources share one signing key")
	}
}

func TestResolveExitRouteVoteThreshold(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, d1, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "https://10.0.0.20:8084"},
	})
	addDirectoryFixture(t, handlers, d2, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.21:51821", ControlURL: "https://10.0.0.21:8084"},
	})

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{d1, d2},
		directoryMinSources: 2,
		directoryMinVotes:   2,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected vote-threshold failure for conflicting routes")
	}
}

func TestResolveExitRouteVoteThresholdDedupByOperator(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	pub, priv, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	relay := signDescriptor(t, proto.RelayDescriptor{
		RelayID:    "exit-a",
		Role:       "exit",
		Endpoint:   "10.0.0.20:51821",
		ControlURL: "https://10.0.0.20:8084",
	}, priv)
	handlers[d1+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: "operator-a",
		PubKeys:  []string{pubB64},
	})
	handlers[d2+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: "operator-a",
		PubKeys:  []string{pubB64},
	})
	handlers[d1+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relay}})
	handlers[d2+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{relay}})

	s := &Service{
		exitControlURL:        "http://127.0.0.1:8084",
		exitDataAddr:          "127.0.0.1:51821",
		directoryURLs:         []string{d1, d2},
		directoryMinSources:   2,
		directoryMinOperators: 1,
		directoryMinVotes:     2,
		routeTTL:              time.Minute,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:        map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected vote-threshold failure with operator-deduped votes")
	}
}

func TestResolveRelayDescriptorPrefersMiddleCapableVariantWhenRelayIDShared(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	sharedExit := proto.RelayDescriptor{
		RelayID:    "relay-shared",
		Role:       "exit",
		Endpoint:   "10.0.0.20:51821",
		ControlURL: "https://10.0.0.20:8084",
		OperatorID: "op-exit",
	}
	sharedMiddle := proto.RelayDescriptor{
		RelayID:      "relay-shared",
		Role:         "micro-relay",
		Endpoint:     "10.0.0.21:51822",
		ControlURL:   "https://10.0.0.21:8084",
		OperatorID:   "op-middle",
		Capabilities: []string{"relay"},
		HopRoles:     []string{"middle"},
	}
	addDirectoryFixtureWithOperator(t, handlers, d1, "operator-a", []proto.RelayDescriptor{sharedExit, sharedMiddle})
	addDirectoryFixtureWithOperator(t, handlers, d2, "operator-b", []proto.RelayDescriptor{sharedExit, sharedMiddle})

	s := &Service{
		directoryURLs:         []string{d1, d2},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     2,
		routeTTL:              time.Minute,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		relayDescCache:        map[string]cachedRelayDescriptor{},
	}

	desc, err := s.resolveRelayDescriptor(context.Background(), "relay-shared")
	if err != nil {
		t.Fatalf("resolve relay descriptor: %v", err)
	}
	if !relaySupportsMiddleDescriptor(desc) {
		t.Fatalf("expected middle-capable descriptor, got role=%q hop_roles=%v capabilities=%v", desc.Role, desc.HopRoles, desc.Capabilities)
	}
	if desc.Role != "micro-relay" {
		t.Fatalf("expected micro-relay variant selected, got %q", desc.Role)
	}
}

func TestResolveRelayDescriptorMergesMiddleAliasVotesForQuorum(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	sharedExit := proto.RelayDescriptor{
		RelayID:    "relay-shared",
		Role:       "exit",
		Endpoint:   "10.0.0.20:51821",
		ControlURL: "https://10.0.0.20:8084",
		OperatorID: "op-exit",
	}
	sharedMiddleAliasA := proto.RelayDescriptor{
		RelayID:      "relay-shared",
		Role:         "relay",
		Endpoint:     "10.0.0.21:51822",
		ControlURL:   "https://10.0.0.21:8084",
		OperatorID:   "op-middle",
		Capabilities: []string{"relay"},
		HopRoles:     []string{"relay"},
	}
	sharedMiddleAliasB := proto.RelayDescriptor{
		RelayID:      "relay-shared",
		Role:         "micro_relay",
		Endpoint:     "10.0.0.21:51822",
		ControlURL:   "https://10.0.0.21:8084",
		OperatorID:   "op-middle",
		Capabilities: []string{"micro_relay"},
		HopRoles:     []string{"middle"},
	}
	addDirectoryFixtureWithOperator(t, handlers, d1, "operator-a", []proto.RelayDescriptor{sharedExit, sharedMiddleAliasA})
	addDirectoryFixtureWithOperator(t, handlers, d2, "operator-b", []proto.RelayDescriptor{sharedExit, sharedMiddleAliasB})

	s := &Service{
		directoryURLs:         []string{d1, d2},
		directoryMinSources:   2,
		directoryMinOperators: 2,
		directoryMinVotes:     2,
		routeTTL:              time.Minute,
		httpClient:            &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		relayDescCache:        map[string]cachedRelayDescriptor{},
	}

	desc, err := s.resolveRelayDescriptor(context.Background(), "relay-shared")
	if err != nil {
		t.Fatalf("resolve relay descriptor: %v", err)
	}
	if !relaySupportsMiddleDescriptor(desc) {
		t.Fatalf("expected middle-capable descriptor, got role=%q hop_roles=%v capabilities=%v", desc.Role, desc.HopRoles, desc.Capabilities)
	}
	if desc.Role != "relay" && desc.Role != "micro_relay" && desc.Role != "micro-relay" {
		t.Fatalf("expected one of middle alias descriptors selected, got role=%q", desc.Role)
	}
}

func TestResolveRelayDescriptorRejectsExpiredDirectoryDescriptor(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:      "relay-expired",
			Role:         "micro-relay",
			Endpoint:     "203.0.113.21:51822",
			ControlURL:   "https://203.0.113.21:8084",
			OperatorID:   "op-middle",
			HopRoles:     []string{"middle"},
			Capabilities: []string{"relay"},
			ValidUntil:   time.Now().Add(-1 * time.Minute),
		},
	})

	s := &Service{
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		relayDescCache:      map[string]cachedRelayDescriptor{},
	}

	if _, err := s.resolveRelayDescriptor(context.Background(), "relay-expired"); err == nil {
		t.Fatalf("expected expired relay descriptor to be rejected")
	}
}

func TestFetchRelaysVerifiedFiltersExpiredDescriptors(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{
			RelayID:      "relay-valid",
			Role:         "micro-relay",
			Endpoint:     "203.0.113.22:51822",
			ControlURL:   "https://203.0.113.22:8084",
			OperatorID:   "op-middle",
			HopRoles:     []string{"middle"},
			Capabilities: []string{"relay"},
			ValidUntil:   time.Now().Add(1 * time.Minute),
		},
		{
			RelayID:      "relay-expired",
			Role:         "micro-relay",
			Endpoint:     "203.0.113.23:51822",
			ControlURL:   "https://203.0.113.23:8084",
			OperatorID:   "op-middle",
			HopRoles:     []string{"middle"},
			Capabilities: []string{"relay"},
			ValidUntil:   time.Now().Add(-1 * time.Minute),
		},
	})

	s := &Service{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	pubs, _, err := s.fetchDirectoryPubKeys(context.Background(), durl)
	if err != nil {
		t.Fatalf("fetchDirectoryPubKeys: %v", err)
	}
	relays, err := s.fetchRelaysVerified(context.Background(), durl, pubs)
	if err != nil {
		t.Fatalf("fetchRelaysVerified: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected only unexpired relays, got %d", len(relays))
	}
	if relays[0].RelayID != "relay-valid" {
		t.Fatalf("expected relay-valid, got %q", relays[0].RelayID)
	}
}

func TestFetchRelaysVerifiedRejectsDescriptorsWithoutValidUntil(t *testing.T) {
	durl := "http://directory.local"
	pub, priv, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signRaw := func(desc proto.RelayDescriptor) proto.RelayDescriptor {
		desc.Signature = ""
		payload, err := json.Marshal(desc)
		if err != nil {
			t.Fatalf("marshal descriptor: %v", err)
		}
		desc.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
		return desc
	}
	missingValidUntil := signRaw(proto.RelayDescriptor{
		RelayID:      "relay-missing-valid-until",
		Role:         "micro-relay",
		Endpoint:     "203.0.113.24:51822",
		ControlURL:   "https://203.0.113.24:8084",
		OperatorID:   "op-middle",
		HopRoles:     []string{"middle"},
		Capabilities: []string{"relay"},
	})
	live := signRaw(proto.RelayDescriptor{
		RelayID:      "relay-live",
		Role:         "micro-relay",
		Endpoint:     "203.0.113.25:51822",
		ControlURL:   "https://203.0.113.25:8084",
		OperatorID:   "op-middle",
		HopRoles:     []string{"middle"},
		Capabilities: []string{"relay"},
		ValidUntil:   time.Now().Add(1 * time.Minute),
	})

	handlers := map[string]func(*http.Request) (*http.Response, error){
		durl + "/v1/pubkey": jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)}),
		durl + "/v1/pubkeys": jsonResp(proto.DirectoryPubKeysResponse{
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(pub)},
		}),
		durl + "/v1/relays": jsonResp(proto.RelayListResponse{Relays: []proto.RelayDescriptor{missingValidUntil, live}}),
	}

	s := &Service{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}

	pubs, _, err := s.fetchDirectoryPubKeys(context.Background(), durl)
	if err != nil {
		t.Fatalf("fetchDirectoryPubKeys: %v", err)
	}
	relays, err := s.fetchRelaysVerified(context.Background(), durl, pubs)
	if err != nil {
		t.Fatalf("fetchRelaysVerified: %v", err)
	}
	if len(relays) != 1 {
		t.Fatalf("expected only descriptors with non-zero valid_until, got %d", len(relays))
	}
	if relays[0].RelayID != "relay-live" {
		t.Fatalf("expected relay-live, got %q", relays[0].RelayID)
	}
}

func TestResolveExitRouteStrictTrustRejectsUnknownKey(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "https://10.0.0.20:8084"},
	})

	trustFile := filepath.Join(t.TempDir(), "trusted_keys.txt")
	otherPub, _, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := os.WriteFile(trustFile, []byte(base64.RawURLEncoding.EncodeToString(otherPub)+"\n"), 0o644); err != nil {
		t.Fatalf("write trust file: %v", err)
	}

	s := &Service{
		exitControlURL:       "http://127.0.0.1:8084",
		exitDataAddr:         "127.0.0.1:51821",
		directoryURLs:        []string{durl},
		directoryMinSources:  1,
		directoryMinVotes:    1,
		directoryTrustStrict: true,
		directoryTrustTOFU:   false,
		directoryTrustFile:   trustFile,
		routeTTL:             time.Minute,
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:       map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected strict trust rejection")
	}
}

func TestResolveExitRouteStrictRejectsLoopbackControlURL(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "127.0.0.1:51821", ControlURL: "http://127.0.0.1:8084"},
	})

	s := &Service{
		exitControlURL:      "http://127.0.0.1:8084",
		exitDataAddr:        "127.0.0.1:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		betaStrict:          true,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected strict mode to reject loopback exit control_url")
	}
}

func TestResolveExitRouteStrictRejectsControlURLPathPrefix(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "8.8.8.8:51821", ControlURL: "https://8.8.8.8:8084/internal"},
	})

	s := &Service{
		exitControlURL:      "https://8.8.8.8:8084",
		exitDataAddr:        "8.8.8.8:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		betaStrict:          true,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected strict mode to reject exit control_url path prefixes")
	}
}

func TestResolveExitRouteStrictRejectsMissingDescriptorRouteFields(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "", ControlURL: ""},
	})

	s := &Service{
		exitControlURL:      "https://198.51.100.10:8084",
		exitDataAddr:        "198.51.100.10:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		betaStrict:          true,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	if _, err := s.resolveExitRoute(context.Background(), "exit-a"); err == nil {
		t.Fatalf("expected strict mode to reject descriptors missing control_url/endpoint instead of using local fallback route")
	}
}

func TestResolveExitRouteRejectsMissingDescriptorRouteFieldsNonStrict(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "", ControlURL: ""},
	})

	s := &Service{
		exitControlURL:      "https://198.51.100.10:8084",
		exitDataAddr:        "198.51.100.10:51821",
		directoryURLs:       []string{durl},
		directoryMinSources: 1,
		directoryMinVotes:   1,
		routeTTL:            time.Minute,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		exitRouteCache:      map[string]exitRoute{},
	}
	_, err := s.resolveExitRoute(context.Background(), "exit-a")
	if err == nil {
		t.Fatalf("expected non-strict mode to reject descriptors missing control_url/endpoint")
	}
	if !strings.Contains(err.Error(), "missing control_url or endpoint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnforceDirectoryTrustSetRejectsAdditionalUntrustedKeys(t *testing.T) {
	keyA, _, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	keyB, _, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}
	keyAB64 := base64.RawURLEncoding.EncodeToString(keyA)
	keyBB64 := base64.RawURLEncoding.EncodeToString(keyB)
	trustFile := filepath.Join(t.TempDir(), "trusted_keys.txt")
	if err := os.WriteFile(trustFile, []byte(keyAB64+"\n"), 0o644); err != nil {
		t.Fatalf("write trust file: %v", err)
	}
	s := &Service{
		directoryTrustStrict: true,
		directoryTrustTOFU:   false,
		directoryTrustFile:   trustFile,
	}
	if err := s.enforceDirectoryTrustSet([]string{keyAB64, keyBB64}); err == nil {
		t.Fatalf("expected strict trust to reject additional untrusted key")
	}
	trusted, err := loadTrustedKeys(trustFile)
	if err != nil {
		t.Fatalf("load trusted keys: %v", err)
	}
	if _, ok := trusted[keyAB64]; !ok {
		t.Fatalf("expected original trusted key to remain present")
	}
	if _, ok := trusted[keyBB64]; ok {
		t.Fatalf("expected additional key to remain untrusted")
	}
}

func TestEnforceDirectoryTrustSetTOFUBootstrapRejectsMultipleKeys(t *testing.T) {
	keyA, _, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen A: %v", err)
	}
	keyB, _, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen B: %v", err)
	}
	keyAB64 := base64.RawURLEncoding.EncodeToString(keyA)
	keyBB64 := base64.RawURLEncoding.EncodeToString(keyB)
	trustFile := filepath.Join(t.TempDir(), "trusted_keys.txt")

	s := &Service{
		directoryTrustStrict: true,
		directoryTrustTOFU:   true,
		directoryTrustFile:   trustFile,
	}
	err = s.enforceDirectoryTrustSet([]string{keyAB64, keyBB64})
	if err == nil {
		t.Fatalf("expected TOFU bootstrap to reject multiple pubkeys")
	}
	if !strings.Contains(err.Error(), "TOFU bootstrap requires exactly 1 pubkey") {
		t.Fatalf("unexpected error: %v", err)
	}
	trusted, err := loadTrustedKeys(trustFile)
	if err != nil {
		t.Fatalf("load trusted keys: %v", err)
	}
	if len(trusted) != 0 {
		t.Fatalf("expected no keys pinned when TOFU bootstrap rejects, got %d", len(trusted))
	}
}

func addDirectoryFixture(t *testing.T, handlers map[string]func(*http.Request) (*http.Response, error), durl string, relays []proto.RelayDescriptor) {
	addDirectoryFixtureWithOperator(t, handlers, durl, "", relays)
}

func addDirectoryFixtureWithOperator(t *testing.T, handlers map[string]func(*http.Request) (*http.Response, error), durl string, operator string, relays []proto.RelayDescriptor) {
	t.Helper()
	pub, priv, err := nodecrypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signed := make([]proto.RelayDescriptor, 0, len(relays))
	for _, d := range relays {
		signed = append(signed, signDescriptor(t, d, priv))
	}
	handlers[durl+"/v1/pubkey"] = jsonResp(map[string]string{"pub_key": base64.RawURLEncoding.EncodeToString(pub)})
	handlers[durl+"/v1/pubkeys"] = jsonResp(proto.DirectoryPubKeysResponse{
		Operator: operator,
		PubKeys:  []string{base64.RawURLEncoding.EncodeToString(pub)},
	})
	handlers[durl+"/v1/relays"] = jsonResp(proto.RelayListResponse{Relays: signed})
}

func signDescriptor(t *testing.T, d proto.RelayDescriptor, priv ed25519.PrivateKey) proto.RelayDescriptor {
	t.Helper()
	if d.ValidUntil.IsZero() {
		d.ValidUntil = time.Now().Add(time.Minute)
	}
	d.Signature = ""
	payload, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	d.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
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
