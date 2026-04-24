package directory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestVerifyProviderTokenCachesIssuerPubKeysOnRepeatedFailures(t *testing.T) {
	issuerPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	issuerURL := "http://127.0.0.1:8082"
	pubkeysHandler := jsonResp(proto.IssuerPubKeysResponse{
		Issuer:  "issuer-local",
		PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
	})
	fetchCount := 0
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": func(r *http.Request) (*http.Response, error) {
			fetchCount++
			return pubkeysHandler(r)
		},
	}
	s := &Service{
		httpClient:                &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		providerIssuerURLs:        []string{issuerURL},
		providerIssuerPubCacheTTL: time.Minute,
		providerIssuerPubCache:    make(map[string]providerIssuerPubCacheEntry),
	}
	nowUnix := time.Now().Unix()
	if _, err := s.verifyProviderToken(context.Background(), "invalid-token-1", nowUnix); err == nil {
		t.Fatalf("expected invalid provider token to fail")
	}
	if _, err := s.verifyProviderToken(context.Background(), "invalid-token-2", nowUnix); err == nil {
		t.Fatalf("expected repeated invalid provider token to fail")
	}
	if fetchCount != 1 {
		t.Fatalf("expected provider issuer pubkeys fetched once, got %d", fetchCount)
	}
}

func TestVerifyProviderTokenRejectsMissingIssuerWhenIssuerDeclared(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	issuerURL := "http://127.0.0.1:8082"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:                &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		providerIssuerURLs:        []string{issuerURL},
		providerIssuerPubCacheTTL: time.Minute,
		providerIssuerPubCache:    make(map[string]providerIssuerPubCacheEntry),
	}
	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Audience:   "provider",
		Subject:    "provider-op-issuerless",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-issuerless",
	})

	_, err = s.verifyProviderToken(context.Background(), token, time.Now().Unix())
	if err == nil {
		t.Fatalf("expected provider token missing issuer to be rejected")
	}
	if !strings.Contains(err.Error(), "provider token issuer missing") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleProviderRelayUpsertAcceptsProviderToken(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-1",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-1",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:       "exit-provider-1",
		Role:          "exit",
		PubKey:        base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:      "127.0.0.1:52821",
		ControlURL:    "http://127.0.0.1:9284",
		CountryCode:   "US",
		GeoConfidence: 0.9,
		Region:        "us-east",
		Capabilities:  []string{"wg", "tiered-policy"},
		Reputation:    0.8,
		Uptime:        0.9,
		Capacity:      0.7,
		AbusePenalty:  0.1,
		ValidForSec:   120,
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.ProviderRelayUpsertResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !out.Accepted {
		t.Fatalf("expected accepted response")
	}
	if out.Relay.OperatorID != "provider-op-1" {
		t.Fatalf("expected operator from token subject, got %s", out.Relay.OperatorID)
	}

	relaysReq := httptest.NewRequest(http.MethodGet, "/v1/relays", nil)
	relaysRR := httptest.NewRecorder()
	s.handleRelays(relaysRR, relaysReq)
	if relaysRR.Code != http.StatusOK {
		t.Fatalf("relays expected 200, got %d", relaysRR.Code)
	}
	var relaysOut proto.RelayListResponse
	if err := json.NewDecoder(relaysRR.Body).Decode(&relaysOut); err != nil {
		t.Fatalf("decode relays response: %v", err)
	}
	found := false
	for _, desc := range relaysOut.Relays {
		if desc.RelayID == "exit-provider-1" && desc.Role == "exit" {
			found = true
			if desc.OperatorID != "provider-op-1" {
				t.Fatalf("expected relays operator from provider token subject, got %s", desc.OperatorID)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected provider relay in directory relays list")
	}
}

func TestHandleProviderRelayUpsertStoresScoresForMicroRelayRole(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-micro",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-micro",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:       "middle-provider-1",
		Role:          "micro_relay",
		PubKey:        base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:      "127.0.0.1:52822",
		ControlURL:    "http://127.0.0.1:9285",
		Reputation:    0.82,
		Uptime:        0.93,
		Capacity:      0.74,
		AbusePenalty:  0.08,
		BondScore:     0.61,
		StakeScore:    0.52,
		Capabilities:  []string{"wg", "relay"},
		GeoConfidence: 0.95,
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for micro-relay upsert, got %d body=%s", rr.Code, rr.Body.String())
	}
	stored, ok := s.providerRelays[relayKey("middle-provider-1", "micro-relay")]
	if !ok {
		t.Fatalf("expected canonicalized micro-relay descriptor stored")
	}
	if stored.Role != "micro-relay" {
		t.Fatalf("expected canonical role micro-relay, got %q", stored.Role)
	}
	if stored.Reputation != 0.82 || stored.Uptime != 0.93 || stored.Capacity != 0.74 {
		t.Fatalf("expected quality scores persisted for micro-relay role, got rep=%.2f up=%.2f cap=%.2f", stored.Reputation, stored.Uptime, stored.Capacity)
	}
	if stored.AbusePenalty != 0.08 || stored.BondScore != 0.61 || stored.StakeScore != 0.52 {
		t.Fatalf("expected abuse/bond/stake scores persisted for micro-relay role, got abuse=%.2f bond=%.2f stake=%.2f", stored.AbusePenalty, stored.BondScore, stored.StakeScore)
	}
}

func TestBuildRelayDescriptorsSkipsMicroRelayWithoutOperatorID(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().UTC()
	s := &Service{
		operatorID: "op-local",
		pubKey:     pub,
		privKey:    priv,
		providerRelays: map[string]proto.RelayDescriptor{
			relayKey("middle-missing-operator", "micro-relay"): {
				RelayID:      "middle-missing-operator",
				Role:         "micro-relay",
				OperatorID:   "",
				Endpoint:     "127.0.0.1:52850",
				ControlURL:   "http://127.0.0.1:9285",
				Reputation:   0.9,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
				ValidUntil:   now.Add(5 * time.Minute),
			},
			relayKey("middle-valid-operator", "micro-relay"): {
				RelayID:      "middle-valid-operator",
				Role:         "micro-relay",
				OperatorID:   "provider-op-1",
				Endpoint:     "127.0.0.1:52851",
				ControlURL:   "http://127.0.0.1:9286",
				Reputation:   0.9,
				Uptime:       0.9,
				Capacity:     0.9,
				AbusePenalty: 0.1,
				ValidUntil:   now.Add(5 * time.Minute),
			},
		},
		peerRelays:  make(map[string]proto.RelayDescriptor),
		peerScores:  make(map[string]proto.RelaySelectionScore),
		peerTrust:   make(map[string]proto.RelayTrustAttestation),
		issuerTrust: make(map[string]proto.RelayTrustAttestation),
	}

	relays := s.buildRelayDescriptors(now)
	var sawMissingOperator bool
	var sawValidOperator bool
	for _, desc := range relays {
		if desc.RelayID == "middle-missing-operator" && desc.Role == "micro-relay" {
			sawMissingOperator = true
		}
		if desc.RelayID == "middle-valid-operator" && desc.Role == "micro-relay" {
			sawValidOperator = true
		}
	}
	if sawMissingOperator {
		t.Fatalf("expected micro-relay without operator id to be suppressed from publication")
	}
	if !sawValidOperator {
		t.Fatalf("expected micro-relay with operator id to remain eligible for publication")
	}
}

func TestHandleProviderRelayUpsertRejectsUnanchoredProviderIssuerKey(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	anchorPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("anchor keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{anchorPub},
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-1",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-unanchored",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-unanchored",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when provider issuer keys are not trust-anchored, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsUnanchoredNonLocalIssuerURL(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "https://issuer.example.com"
	issuerID := "issuer-example"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-unpinned-nonlocal",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-unpinned-nonlocal",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-unpinned-nonlocal",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52823",
		ControlURL: "http://127.0.0.1:9286",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when non-local provider issuer URL is unanchored, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertAcceptsAnchoredProviderIssuerKey(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{issuerPub},
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-anchored",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-anchored",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-anchored",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52822",
		ControlURL: "http://127.0.0.1:9285",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with anchored provider issuer key, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertStrictModeRejectsLoopbackControlURL(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{issuerPub},
		betaStrict:          true,
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-1",
		TokenType:  crypto.TokenTypeProviderRole,
		CNFEd25519: base64.RawURLEncoding.EncodeToString(relayPub),
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-strict-loopback",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-1",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected strict mode to reject loopback control_url, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertStrictModeRejectsUnanchoredLocalIssuerURL(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	relayPubB64 := base64.RawURLEncoding.EncodeToString(relayPub)
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		betaStrict:          true,
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-1",
		TokenType:  crypto.TokenTypeProviderRole,
		CNFEd25519: relayPubB64,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-strict-unanchored-local",
		AllowPorts: nil,
		DenyPorts:  nil,
		ExitScope:  nil,
		ConnRate:   0,
		MaxConns:   0,
		AnonCredID: "",
		KeyEpoch:   0,
		BWKbps:     0,
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-strict-unanchored",
		Role:       "exit",
		PubKey:     relayPubB64,
		Endpoint:   "relay-provider.example:52821",
		ControlURL: "https://relay-provider.example:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected strict mode to reject unanchored local issuer URL, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsMismatchedCNFBinding(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	tokenBoundPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("bound relay keygen: %v", err)
	}
	requestRelayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("request relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-mismatch",
		TokenType:  crypto.TokenTypeProviderRole,
		CNFEd25519: base64.RawURLEncoding.EncodeToString(tokenBoundPub),
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-cnf-mismatch",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-cnf-mismatch",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(requestRelayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for mismatched provider token cnf binding, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "cnf_ed25519") {
		t.Fatalf("expected cnf binding error, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRequiresCNFByDefault(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{issuerPub},
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-missing-cnf",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-missing-cnf",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-missing-cnf",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing provider token cnf_ed25519, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "cnf_ed25519 missing") {
		t.Fatalf("expected missing cnf error, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertDangerousOverrideAllowsMissingCNFAndProof(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{issuerPub},
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-dangerous-bypass",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-dangerous-bypass",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-dangerous-bypass",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected dangerous override to allow missing cnf/proof, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertStrictIgnoresDangerousBypassOverride(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "https://issuer.example"
	issuerID := "issuer-public"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		betaStrict:          true,
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{issuerPub},
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-strict-bypass",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-strict-bypass",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-strict-bypass",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "8.8.8.8:52821",
		ControlURL: "https://8.8.8.8:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected strict mode to reject missing cnf/proof despite dangerous bypass env, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "cnf_ed25519 missing") {
		t.Fatalf("expected missing cnf error in strict mode, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRequiresProofWhenCNFPresent(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
		issuerTrustedKeys:   []ed25519.PublicKey{issuerPub},
	}

	claims := crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-proof-required",
		TokenType:  crypto.TokenTypeProviderRole,
		CNFEd25519: base64.RawURLEncoding.EncodeToString(relayPub),
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-proof-required",
	}
	token := signProviderTestToken(t, issuerPriv, claims)

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-proof-required",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing provider token proof, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "token proof") {
		t.Fatalf("expected token proof requirement error, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertAcceptsProofAndRejectsNonceReplay(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, relayPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:             "op-local",
		pubKey:                 dirPub,
		privKey:                dirPriv,
		httpClient:             &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:         []string{"127.0.0.1:51820"},
		endpointRotateSec:      30,
		providerIssuerURLs:     []string{issuerURL},
		providerRelayMaxTTL:    3 * time.Minute,
		providerRelays:         make(map[string]proto.RelayDescriptor),
		providerTokenProofSeen: make(map[string]time.Time),
		issuerTrustedKeys:      []ed25519.PublicKey{issuerPub},
	}

	claims := crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-proof-ok",
		TokenType:  crypto.TokenTypeProviderRole,
		CNFEd25519: base64.RawURLEncoding.EncodeToString(relayPub),
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-proof-ok",
	}
	token := signProviderTestToken(t, issuerPriv, claims)

	in := proto.ProviderRelayUpsertRequest{
		RelayID:         "exit-provider-proof-ok",
		Role:            "exit",
		PubKey:          base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:        "127.0.0.1:52831",
		ControlURL:      "http://127.0.0.1:9291",
		TokenProofNonce: "nonce-proof-ok-1",
	}
	in.TokenProof = signProviderUpsertProof(t, relayPriv, claims, in, in.TokenProofNonce)

	firstBody, _ := json.Marshal(in)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(firstBody))
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first proof-bearing upsert accepted, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}

	secondBody, _ := json.Marshal(in)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(secondBody))
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(secondRR, secondReq)
	if secondRR.Code != http.StatusBadRequest {
		t.Fatalf("expected replayed nonce rejection, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}
	if !strings.Contains(secondRR.Body.String(), "nonce replayed") {
		t.Fatalf("expected nonce replay error, got %q", secondRR.Body.String())
	}
}

func TestMarkProviderTokenProofReplayCapsEntries(t *testing.T) {
	s := &Service{
		providerTokenProofSeen: make(map[string]time.Time),
	}
	now := time.Now()
	total := providerRelayUpsertProofReplayMaxPerToken
	for i := 0; i < total; i++ {
		nonce := fmt.Sprintf("nonce-%d", i)
		if err := s.markProviderTokenProofReplay("provider-token-cap", nonce, now.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatalf("nonce %d should pass: %v", i, err)
		}
	}
	if err := s.markProviderTokenProofReplay("provider-token-cap", "nonce-overflow", now.Add(time.Duration(total)*time.Millisecond)); err != nil {
		t.Fatalf("expected overflow nonce to evict oldest and pass: %v", err)
	}

	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	if got := len(s.providerTokenProofSeen); got != providerRelayUpsertProofReplayMaxPerToken {
		t.Fatalf("expected %d replay entries retained, got %d", providerRelayUpsertProofReplayMaxPerToken, got)
	}
	if _, ok := s.providerTokenProofSeen["provider-token-cap:nonce-0"]; ok {
		t.Fatalf("expected oldest nonce to be evicted")
	}
	if _, ok := s.providerTokenProofSeen["provider-token-cap:nonce-overflow"]; !ok {
		t.Fatalf("expected overflow nonce retained after eviction")
	}
}

func TestMarkProviderTokenProofReplayCapsGlobalEntries(t *testing.T) {
	s := &Service{
		providerTokenProofSeen: make(map[string]time.Time),
	}
	now := time.Now()
	total := providerRelayUpsertProofReplayMaxEntries + 1
	for i := 0; i < total; i++ {
		tokenID := fmt.Sprintf("provider-token-%d", i)
		nonce := fmt.Sprintf("nonce-%d", i)
		if err := s.markProviderTokenProofReplay(tokenID, nonce, now.Add(time.Duration(i)*time.Millisecond)); err != nil {
			t.Fatalf("entry %d should pass: %v", i, err)
		}
	}
	s.providerMu.RLock()
	defer s.providerMu.RUnlock()
	if got := len(s.providerTokenProofSeen); got != providerRelayUpsertProofReplayMaxEntries {
		t.Fatalf("expected global replay entries capped at %d, got %d", providerRelayUpsertProofReplayMaxEntries, got)
	}
	if _, ok := s.providerTokenProofSeen["provider-token-0:nonce-0"]; ok {
		t.Fatalf("expected oldest global entry evicted")
	}
	if _, ok := s.providerTokenProofSeen[fmt.Sprintf("provider-token-%d:nonce-%d", total-1, total-1)]; !ok {
		t.Fatalf("expected newest global entry retained")
	}
}

func TestParseBearerTokenRequiresSingleCredential(t *testing.T) {
	if got := parseBearerToken("Bearer token extra"); got != "" {
		t.Fatalf("expected malformed bearer header to be rejected, got %q", got)
	}
	if got := parseBearerToken("Bearer token"); got != "token" {
		t.Fatalf("expected bearer token extraction, got %q", got)
	}
}

func TestHandleProviderRelayUpsertRejectsBodyTokenWithoutAuthorizationHeader(t *testing.T) {
	dirPub, dirPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("directory keygen: %v", err)
	}
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	issuerID := "issuer-local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  issuerID,
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		operatorID:          "op-local",
		pubKey:              dirPub,
		privKey:             dirPriv,
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "provider",
		Subject:    "provider-op-1",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-body-only",
	})

	in := proto.ProviderRelayUpsertRequest{
		Token:         token,
		RelayID:       "exit-provider-1",
		Role:          "exit",
		PubKey:        base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:      "127.0.0.1:52821",
		ControlURL:    "http://127.0.0.1:9284",
		CountryCode:   "US",
		GeoConfidence: 0.9,
		Region:        "us-east",
		Capabilities:  []string{"wg", "tiered-policy"},
		ValidForSec:   120,
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when only body token is provided, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsUnknownFieldJSON(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewBufferString(`{"relay_id":"relay-1","role":"exit","pub_key":"pub","endpoint":"127.0.0.1:51820","control_url":"http://127.0.0.1:9284","unexpected":"value"}`))
	rr := httptest.NewRecorder()

	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown json field, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected invalid json message, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsTrailingJSON(t *testing.T) {
	s := &Service{}
	body := `{"relay_id":"relay-1","role":"exit","pub_key":"pub","endpoint":"127.0.0.1:51820","control_url":"http://127.0.0.1:9284"}{"extra":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()

	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for trailing json payload, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected invalid json message, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsOversizedJSON(t *testing.T) {
	s := &Service{}
	oversizedRelayID := strings.Repeat("a", int(providerRelayUpsertMaxBodyBytes))
	body := `{"relay_id":"` + oversizedRelayID + `","role":"exit","pub_key":"pub","endpoint":"127.0.0.1:51820","control_url":"http://127.0.0.1:9284"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewBufferString(body))
	rr := httptest.NewRecorder()

	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized json payload, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid json") {
		t.Fatalf("expected invalid json message, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsClientAccessToken(t *testing.T) {
	_, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	s := &Service{
		httpClient:        &http.Client{Transport: mockRoundTripper{handlers: map[string]func(*http.Request) (*http.Response, error){}}},
		entryEndpoints:    []string{"127.0.0.1:51820"},
		endpointRotateSec: 30,
		providerIssuerURLs: []string{
			"http://issuer.local",
		},
	}

	// no fetch path here; short-circuit by providing invalid token class after successful key fetch
	issuerPub := issuerPriv.Public().(ed25519.PublicKey)
	handlers := map[string]func(*http.Request) (*http.Response, error){
		"http://issuer.local/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s.httpClient = &http.Client{Transport: mockRoundTripper{handlers: handlers}}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		Subject:    "client-user-1",
		TokenType:  crypto.TokenTypeClientAccess,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "client-token-1",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-1",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(issuerPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for client_access token, got %d", rr.Code)
	}
}

func TestHandleProviderRelayUpsertRejectsLowTierExitProvider(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:       []string{"127.0.0.1:51820"},
		endpointRotateSec:    30,
		providerIssuerURLs:   []string{issuerURL},
		providerRelayMaxTTL:  3 * time.Minute,
		providerMinEntryTier: 1,
		providerMinExitTier:  2,
		providerRelays:       make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-low",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-low",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "exit-provider-low",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for low-tier exit provider token, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertAllowsTier1EntryProvider(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:       []string{"127.0.0.1:51820"},
		endpointRotateSec:    30,
		providerIssuerURLs:   []string{issuerURL},
		providerRelayMaxTTL:  3 * time.Minute,
		providerMinEntryTier: 1,
		providerMinExitTier:  2,
		providerRelays:       make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-entry",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-entry",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:      "entry-provider-tier1",
		Role:         "entry",
		PubKey:       base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:     "127.0.0.1:52820",
		ControlURL:   "http://127.0.0.1:9283",
		Capabilities: []string{"wg", "tiered-policy"},
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for tier1 entry provider token, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertAllowsTier1MicroRelayProvider(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:       []string{"127.0.0.1:51820"},
		endpointRotateSec:    30,
		providerIssuerURLs:   []string{issuerURL},
		providerRelayMaxTTL:  3 * time.Minute,
		providerMinEntryTier: 1,
		providerMinExitTier:  2,
		providerRelays:       make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-micro",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-micro",
	})

	in := proto.ProviderRelayUpsertRequest{
		RelayID:      "micro-provider-tier1",
		Role:         "micro-relay",
		PubKey:       base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:     "127.0.0.1:52820",
		ControlURL:   "http://127.0.0.1:9283",
		Capabilities: []string{"wg"},
		Reputation:   0.8,
		Uptime:       0.85,
		Capacity:     0.75,
		AbusePenalty: 0.2,
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.handleProviderRelayUpsert(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for tier1 micro-relay provider token, got %d body=%s", rr.Code, rr.Body.String())
	}

	var out proto.ProviderRelayUpsertResponse
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Relay.Role != "micro-relay" {
		t.Fatalf("expected canonical micro-relay role, got %q", out.Relay.Role)
	}
	if _, ok := s.providerRelays[relayKey("micro-provider-tier1", "micro-relay")]; !ok {
		t.Fatalf("expected micro-relay stored under canonical role key")
	}
}

func TestHandleProviderRelayUpsertCanonicalizesMicroRelayAliases(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:       []string{"127.0.0.1:51820"},
		endpointRotateSec:    30,
		providerIssuerURLs:   []string{issuerURL},
		providerRelayMaxTTL:  3 * time.Minute,
		providerMinEntryTier: 1,
		providerMinExitTier:  2,
		providerRelays:       make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-alias",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-alias",
	})

	aliases := []string{"micro_relay", "middle", "relay", "transit", "three-hop-middle"}
	for idx, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			relayPub, _, err := crypto.GenerateEd25519Keypair()
			if err != nil {
				t.Fatalf("relay keygen: %v", err)
			}
			in := proto.ProviderRelayUpsertRequest{
				RelayID:      fmt.Sprintf("micro-alias-provider-%d", idx),
				Role:         alias,
				PubKey:       base64.RawURLEncoding.EncodeToString(relayPub),
				Endpoint:     fmt.Sprintf("127.0.0.1:%d", 52830+idx),
				ControlURL:   fmt.Sprintf("http://127.0.0.1:%d", 9290+idx),
				Capabilities: []string{"wg"},
				Reputation:   0.83,
				Uptime:       0.88,
				Capacity:     0.79,
				AbusePenalty: 0.21,
			}
			body, _ := json.Marshal(in)
			req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()
			s.handleProviderRelayUpsert(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200 for alias role %q, got %d body=%s", alias, rr.Code, rr.Body.String())
			}

			var out proto.ProviderRelayUpsertResponse
			if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if out.Relay.Role != "micro-relay" {
				t.Fatalf("expected canonical micro-relay role for alias %q, got %q", alias, out.Relay.Role)
			}
			if _, ok := s.providerRelays[relayKey(in.RelayID, "micro-relay")]; !ok {
				t.Fatalf("expected alias role %q stored under canonical micro-relay key", alias)
			}
		})
	}
}

func TestHandleProviderRelayUpsertRejectsUnknownRole(t *testing.T) {
	relayPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay keygen: %v", err)
	}

	in := proto.ProviderRelayUpsertRequest{
		RelayID:    "provider-unknown-role",
		Role:       "unknown-role",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPub),
		Endpoint:   "127.0.0.1:52820",
		ControlURL: "http://127.0.0.1:9283",
	}
	body, _ := json.Marshal(in)
	req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	s := &Service{}
	s.handleProviderRelayUpsert(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown provider relay role, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "provider relay role must be entry, exit, or micro-relay") {
		t.Fatalf("expected clear unknown role validation message, got %q", rr.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsInvalidMicroRelayScores(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}

	s := &Service{
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:       []string{"127.0.0.1:51820"},
		endpointRotateSec:    30,
		providerIssuerURLs:   []string{issuerURL},
		providerRelayMaxTTL:  3 * time.Minute,
		providerMinEntryTier: 1,
		providerMinExitTier:  2,
		providerRelays:       make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-micro-invalid-scores",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       1,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-micro-invalid-scores",
	})

	tests := []struct {
		name        string
		mutateBody  func(body map[string]any)
		wantErrPart string
	}{
		{
			name: "missing scores",
			mutateBody: func(body map[string]any) {
				// Intentionally omit score fields.
			},
			wantErrPart: "provider micro-relay reputation score",
		},
		{
			name: "zero scores explicit",
			mutateBody: func(body map[string]any) {
				body["reputation_score"] = 0.0
				body["uptime_score"] = 0.0
				body["capacity_score"] = 0.0
				body["abuse_penalty"] = 0.0
			},
			wantErrPart: "provider micro-relay reputation score",
		},
		{
			name: "under-threshold reputation",
			mutateBody: func(body map[string]any) {
				body["reputation_score"] = 0.49
				body["uptime_score"] = 0.9
				body["capacity_score"] = 0.9
				body["abuse_penalty"] = 0.1
			},
			wantErrPart: "provider micro-relay reputation score",
		},
		{
			name: "abuse penalty above max",
			mutateBody: func(body map[string]any) {
				body["reputation_score"] = 0.9
				body["uptime_score"] = 0.9
				body["capacity_score"] = 0.9
				body["abuse_penalty"] = 0.51
			},
			wantErrPart: "provider micro-relay abuse penalty",
		},
	}

	for i, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			relayPub, _, err := crypto.GenerateEd25519Keypair()
			if err != nil {
				t.Fatalf("relay keygen: %v", err)
			}
			body := map[string]any{
				"relay_id":     fmt.Sprintf("micro-invalid-score-%d", i),
				"role":         "micro-relay",
				"pub_key":      base64.RawURLEncoding.EncodeToString(relayPub),
				"endpoint":     fmt.Sprintf("127.0.0.1:%d", 52860+i),
				"control_url":  fmt.Sprintf("http://127.0.0.1:%d", 9380+i),
				"capabilities": []string{"wg"},
			}
			tc.mutateBody(body)

			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+token)
			rr := httptest.NewRecorder()

			s.handleProviderRelayUpsert(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for invalid micro-relay scores, got %d body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantErrPart) {
				t.Fatalf("expected error containing %q, got %q", tc.wantErrPart, rr.Body.String())
			}
		})
	}
}

func TestHandleProviderRelayUpsertRejectsOverOperatorRelayLimit(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay A keygen: %v", err)
	}
	relayPubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay B keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:             &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:         []string{"127.0.0.1:51820"},
		endpointRotateSec:      30,
		providerIssuerURLs:     []string{issuerURL},
		providerRelayMaxTTL:    3 * time.Minute,
		providerMinEntryTier:   1,
		providerMinExitTier:    1,
		providerMaxPerOperator: 1,
		providerRelays:         make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-cap",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-cap",
	})

	first := proto.ProviderRelayUpsertRequest{
		RelayID:      "provider-cap-entry-1",
		Role:         "entry",
		PubKey:       base64.RawURLEncoding.EncodeToString(relayPubA),
		Endpoint:     "127.0.0.1:52820",
		ControlURL:   "http://127.0.0.1:9283",
		Capabilities: []string{"wg", "tiered-policy"},
	}
	firstBody, _ := json.Marshal(first)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(firstBody))
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first relay upsert accepted, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}

	second := proto.ProviderRelayUpsertRequest{
		RelayID:      "provider-cap-exit-2",
		Role:         "exit",
		PubKey:       base64.RawURLEncoding.EncodeToString(relayPubB),
		Endpoint:     "127.0.0.1:52821",
		ControlURL:   "http://127.0.0.1:9284",
		Capabilities: []string{"wg", "tiered-policy"},
	}
	secondBody, _ := json.Marshal(second)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(secondBody))
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(secondRR, secondReq)
	if secondRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once operator relay cap reached, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsDualRoleWhenSplitRolesEnabled(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay A keygen: %v", err)
	}
	relayPubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay B keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:           &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:       []string{"127.0.0.1:51820"},
		endpointRotateSec:    30,
		providerIssuerURLs:   []string{issuerURL},
		providerRelayMaxTTL:  3 * time.Minute,
		providerMinEntryTier: 1,
		providerMinExitTier:  1,
		providerSplitRoles:   true,
		providerRelays:       make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-op-split",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-split",
	})

	first := proto.ProviderRelayUpsertRequest{
		RelayID:      "provider-split-entry",
		Role:         "entry",
		PubKey:       base64.RawURLEncoding.EncodeToString(relayPubA),
		Endpoint:     "127.0.0.1:52820",
		ControlURL:   "http://127.0.0.1:9283",
		Capabilities: []string{"wg", "two-hop"},
	}
	firstBody, _ := json.Marshal(first)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(firstBody))
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first relay upsert accepted, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}

	second := proto.ProviderRelayUpsertRequest{
		RelayID:      "provider-split-exit",
		Role:         "exit",
		PubKey:       base64.RawURLEncoding.EncodeToString(relayPubB),
		Endpoint:     "127.0.0.1:52821",
		ControlURL:   "http://127.0.0.1:9284",
		Capabilities: []string{"wg", "tiered-policy"},
	}
	secondBody, _ := json.Marshal(second)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(secondBody))
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(secondRR, secondReq)
	if secondRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for split-role violation, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}
	if !bytes.Contains(secondRR.Body.Bytes(), []byte("split-role")) {
		t.Fatalf("expected split-role policy message, got %q", secondRR.Body.String())
	}
}

func TestHandleProviderRelayUpsertRejectsTakeoverByDifferentOperator(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay A keygen: %v", err)
	}
	relayPubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay B keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:          &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:      []string{"127.0.0.1:51820"},
		endpointRotateSec:   30,
		providerIssuerURLs:  []string{issuerURL},
		providerRelayMaxTTL: 3 * time.Minute,
		providerRelays:      make(map[string]proto.RelayDescriptor),
	}

	tokenA := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-owner-a",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-owner-a",
	})
	tokenB := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-owner-b",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-owner-b",
	})

	first := proto.ProviderRelayUpsertRequest{
		RelayID:    "provider-owned-relay",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPubA),
		Endpoint:   "127.0.0.1:52820",
		ControlURL: "http://127.0.0.1:9283",
	}
	firstBody, _ := json.Marshal(first)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(firstBody))
	firstReq.Header.Set("Authorization", "Bearer "+tokenA)
	firstRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first relay upsert accepted, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}

	second := proto.ProviderRelayUpsertRequest{
		RelayID:    "provider-owned-relay",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPubB),
		Endpoint:   "127.0.0.1:52821",
		ControlURL: "http://127.0.0.1:9284",
	}
	secondBody, _ := json.Marshal(second)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(secondBody))
	secondReq.Header.Set("Authorization", "Bearer "+tokenB)
	secondRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(secondRR, secondReq)
	if secondRR.Code != http.StatusConflict {
		t.Fatalf("expected 409 for relay ownership takeover attempt, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}
	if !strings.Contains(secondRR.Body.String(), "owned by different operator") {
		t.Fatalf("expected ownership conflict message, got %q", secondRR.Body.String())
	}

	stored, ok := s.providerRelays[relayKey("provider-owned-relay", "exit")]
	if !ok {
		t.Fatalf("expected original relay to remain stored")
	}
	if stored.OperatorID != "provider-owner-a" {
		t.Fatalf("expected relay owner to remain provider-owner-a, got %s", stored.OperatorID)
	}
}

func TestHandleProviderRelayUpsertAllowsSameOwnerUpdate(t *testing.T) {
	t.Setenv(allowDangerousProviderTokenBypass, "1")

	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	relayPubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay A keygen: %v", err)
	}
	relayPubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("relay B keygen: %v", err)
	}
	issuerURL := "http://issuer.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		issuerURL + "/v1/pubkeys": jsonResp(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(issuerPub)},
		}),
	}
	s := &Service{
		httpClient:             &http.Client{Transport: mockRoundTripper{handlers: handlers}},
		entryEndpoints:         []string{"127.0.0.1:51820"},
		endpointRotateSec:      30,
		providerIssuerURLs:     []string{issuerURL},
		providerRelayMaxTTL:    3 * time.Minute,
		providerMaxPerOperator: 1,
		providerRelays:         make(map[string]proto.RelayDescriptor),
	}

	token := signProviderTestToken(t, issuerPriv, crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "provider",
		Subject:    "provider-owner-stable",
		TokenType:  crypto.TokenTypeProviderRole,
		Tier:       2,
		ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		TokenID:    "provider-token-owner-stable",
	})

	first := proto.ProviderRelayUpsertRequest{
		RelayID:    "provider-update-relay",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPubA),
		Endpoint:   "127.0.0.1:52920",
		ControlURL: "http://127.0.0.1:9383",
	}
	firstBody, _ := json.Marshal(first)
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(firstBody))
	firstReq.Header.Set("Authorization", "Bearer "+token)
	firstRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first relay upsert accepted, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}

	second := proto.ProviderRelayUpsertRequest{
		RelayID:    "provider-update-relay",
		Role:       "exit",
		PubKey:     base64.RawURLEncoding.EncodeToString(relayPubB),
		Endpoint:   "127.0.0.1:52921",
		ControlURL: "http://127.0.0.1:9384",
	}
	secondBody, _ := json.Marshal(second)
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/provider/relay/upsert", bytes.NewReader(secondBody))
	secondReq.Header.Set("Authorization", "Bearer "+token)
	secondRR := httptest.NewRecorder()
	s.handleProviderRelayUpsert(secondRR, secondReq)
	if secondRR.Code != http.StatusOK {
		t.Fatalf("expected same-owner update accepted, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}

	stored, ok := s.providerRelays[relayKey("provider-update-relay", "exit")]
	if !ok {
		t.Fatalf("expected updated relay to remain stored")
	}
	if stored.OperatorID != "provider-owner-stable" {
		t.Fatalf("expected relay owner provider-owner-stable, got %s", stored.OperatorID)
	}
	if stored.Endpoint != "127.0.0.1:52921" {
		t.Fatalf("expected endpoint updated by same owner, got %s", stored.Endpoint)
	}
	if stored.ControlURL != "http://127.0.0.1:9384" {
		t.Fatalf("expected control_url updated by same owner, got %s", stored.ControlURL)
	}
}

func TestUpsertProviderRelayRuntimeAdmissionMicroRelayRoleDescriptors(t *testing.T) {
	baseDesc := proto.RelayDescriptor{
		RelayID:      "runtime-admission-relay",
		Role:         "micro-relay",
		OperatorID:   "provider-op-runtime",
		Endpoint:     "127.0.0.1:52890",
		ControlURL:   "http://127.0.0.1:9389",
		Capabilities: []string{"wg"},
		HopRoles:     []string{"middle"},
		Reputation:   0.82,
		Uptime:       0.9,
		Capacity:     0.86,
		AbusePenalty: 0.2,
		ValidUntil:   time.Now().Add(5 * time.Minute),
	}
	tests := []struct {
		name        string
		desc        proto.RelayDescriptor
		wantErrPart string
		wantStored  bool
	}{
		{
			name:       "approved canonical micro-relay descriptor",
			desc:       baseDesc,
			wantStored: true,
		},
		{
			name: "approved alias micro-relay descriptor",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-alias"
				d.Role = "middle"
				return d
			}(),
			wantStored: true,
		},
		{
			name: "unapproved role descriptor",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-bad-role"
				d.Role = "bogus-role"
				return d
			}(),
			wantErrPart: "provider relay role must be entry, exit, or micro-relay",
		},
		{
			name: "malformed micro descriptor with non-middle hop role",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-bad-hop"
				d.HopRoles = []string{"entry"}
				return d
			}(),
			wantErrPart: "provider micro-relay hop_roles must only include middle",
		},
		{
			name: "malformed micro descriptor with role-conflicting capability",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-bad-cap"
				d.Capabilities = []string{"wg", "tiered-policy"}
				return d
			}(),
			wantErrPart: "provider micro-relay capability \"tiered-policy\" is not allowed",
		},
		{
			name: "malformed micro descriptor with missing operator",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-missing-op"
				d.OperatorID = ""
				return d
			}(),
			wantErrPart: "provider micro-relay operator id invalid",
		},
		{
			name: "malformed micro descriptor with missing quality scores",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-missing-scores"
				d.Reputation = 0
				d.Uptime = 0
				d.Capacity = 0
				d.AbusePenalty = 0
				return d
			}(),
			wantErrPart: "provider micro-relay reputation score",
		},
		{
			name: "malformed micro descriptor with under-threshold quality score",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-under-reputation"
				d.Reputation = 0.49
				return d
			}(),
			wantErrPart: "provider micro-relay reputation score",
		},
		{
			name: "malformed micro descriptor with high abuse penalty",
			desc: func() proto.RelayDescriptor {
				d := baseDesc
				d.RelayID = "runtime-admission-relay-high-abuse"
				d.AbusePenalty = 0.51
				return d
			}(),
			wantErrPart: "provider micro-relay abuse penalty",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{
				providerRelays: make(map[string]proto.RelayDescriptor),
			}
			err := s.upsertProviderRelay(tc.desc)
			if tc.wantErrPart == "" && err != nil {
				t.Fatalf("expected success, got err=%v", err)
			}
			if tc.wantErrPart != "" {
				if err == nil {
					t.Fatalf("expected error containing %q", tc.wantErrPart)
				}
				if !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrPart, err.Error())
				}
			}

			if tc.wantStored {
				stored, ok := s.providerRelays[relayKey(tc.desc.RelayID, "micro-relay")]
				if !ok {
					t.Fatalf("expected descriptor stored under canonical micro-relay key")
				}
				if stored.Role != "micro-relay" {
					t.Fatalf("expected stored canonical role micro-relay, got %q", stored.Role)
				}
			}
		})
	}
}

func TestUpsertProviderRelayRuntimeAdmissionNonMicroBackwardCompatible(t *testing.T) {
	tests := []struct {
		name string
		desc proto.RelayDescriptor
	}{
		{
			name: "entry descriptor remains accepted",
			desc: proto.RelayDescriptor{
				RelayID:      "runtime-admission-entry",
				Role:         "entry",
				OperatorID:   "provider-op-entry",
				Endpoint:     "127.0.0.1:52910",
				ControlURL:   "http://127.0.0.1:9391",
				Capabilities: []string{"wg", "two-hop"},
				ValidUntil:   time.Now().Add(5 * time.Minute),
			},
		},
		{
			name: "exit descriptor remains accepted",
			desc: proto.RelayDescriptor{
				RelayID:      "runtime-admission-exit",
				Role:         "exit",
				OperatorID:   "provider-op-exit",
				Endpoint:     "127.0.0.1:52911",
				ControlURL:   "http://127.0.0.1:9392",
				Capabilities: []string{"wg", "tiered-policy"},
				ValidUntil:   time.Now().Add(5 * time.Minute),
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{
				providerRelays: make(map[string]proto.RelayDescriptor),
			}
			if err := s.upsertProviderRelay(tc.desc); err != nil {
				t.Fatalf("expected non-micro descriptor accepted, got err=%v", err)
			}
			stored, ok := s.providerRelays[relayKey(tc.desc.RelayID, tc.desc.Role)]
			if !ok {
				t.Fatalf("expected descriptor stored for role=%s", tc.desc.Role)
			}
			if stored.Role != tc.desc.Role {
				t.Fatalf("expected stored role %q, got %q", tc.desc.Role, stored.Role)
			}
		})
	}
}

func signProviderTestToken(t *testing.T, priv ed25519.PrivateKey, claims crypto.CapabilityClaims) string {
	t.Helper()
	tok, err := crypto.SignClaims(claims, priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func signProviderUpsertProof(
	t *testing.T,
	proofPriv ed25519.PrivateKey,
	claims crypto.CapabilityClaims,
	req proto.ProviderRelayUpsertRequest,
	nonce string,
) string {
	t.Helper()
	controlURL := normalizeHTTPURL(req.ControlURL)
	message, err := providerRelayUpsertProofMessage(
		claims.TokenID,
		claims.Subject,
		req.RelayID,
		req.Role,
		req.PubKey,
		req.Endpoint,
		controlURL,
		nonce,
	)
	if err != nil {
		t.Fatalf("provider proof message: %v", err)
	}
	signature := ed25519.Sign(proofPriv, message)
	return base64.RawURLEncoding.EncodeToString(signature)
}
