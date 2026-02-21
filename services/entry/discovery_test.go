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
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
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
	if route.controlURL != "http://10.0.0.20:8084" {
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
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
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
	addDirectoryFixtureWithOperator(t, handlers, d1, "operator-a", []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
	})
	addDirectoryFixtureWithOperator(t, handlers, d2, "operator-a", []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
	})

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

func TestResolveExitRouteVoteThreshold(t *testing.T) {
	d1 := "http://d1.local"
	d2 := "http://d2.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, d1, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
	})
	addDirectoryFixture(t, handlers, d2, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.21:51821", ControlURL: "http://10.0.0.21:8084"},
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
	addDirectoryFixtureWithOperator(t, handlers, d1, "operator-a", []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
	})
	addDirectoryFixtureWithOperator(t, handlers, d2, "operator-a", []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
	})

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

func TestResolveExitRouteStrictTrustRejectsUnknownKey(t *testing.T) {
	durl := "http://directory.local"
	handlers := make(map[string]func(*http.Request) (*http.Response, error))
	addDirectoryFixture(t, handlers, durl, []proto.RelayDescriptor{
		{RelayID: "exit-a", Role: "exit", Endpoint: "10.0.0.20:51821", ControlURL: "http://10.0.0.20:8084"},
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
