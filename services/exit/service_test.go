package exit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/policy"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
)

func TestAuthorizePacketReplayDenied(t *testing.T) {
	s := &Service{enforcer: policy.NewEnforcer(), sessions: map[string]sessionInfo{}}
	s.sessions["s1"] = sessionInfo{
		claims: crypto.CapabilityClaims{
			Tier:       1,
			ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		},
		seenNonces: map[uint64]struct{}{},
	}

	pkt := proto.InnerPacket{DestinationPort: 443, Nonce: 42, Payload: "x"}
	if _, err := s.authorizePacket("s1", pkt, time.Now()); err != nil {
		t.Fatalf("first packet should pass: %v", err)
	}
	if _, err := s.authorizePacket("s1", pkt, time.Now()); err == nil {
		t.Fatalf("expected replay to be denied")
	}
}

func TestAuthorizePacketExpiredDenied(t *testing.T) {
	s := &Service{enforcer: policy.NewEnforcer(), sessions: map[string]sessionInfo{}}
	s.sessions["s1"] = sessionInfo{
		claims: crypto.CapabilityClaims{
			Tier:       1,
			ExpiryUnix: time.Now().Add(-time.Minute).Unix(),
		},
		seenNonces: map[uint64]struct{}{},
	}

	pkt := proto.InnerPacket{DestinationPort: 443, Nonce: 1, Payload: "x"}
	if _, err := s.authorizePacket("s1", pkt, time.Now()); err == nil {
		t.Fatalf("expected expired session to be denied")
	}
}

func TestValidatePathOpenClaims(t *testing.T) {
	now := time.Now().Unix()
	good := crypto.CapabilityClaims{
		Audience:   "exit",
		Subject:    "client-a",
		Tier:       2,
		ExpiryUnix: now + 60,
		TokenID:    "jti-1",
	}
	if err := validatePathOpenClaims(good, now); err != nil {
		t.Fatalf("expected valid claims, got err=%v", err)
	}

	cases := []struct {
		name   string
		claims crypto.CapabilityClaims
	}{
		{
			name: "bad audience",
			claims: crypto.CapabilityClaims{
				Audience:   "entry",
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
		{
			name: "bad tier",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				Subject:    "client-a",
				Tier:       0,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
		{
			name: "missing token id",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now + 60,
			},
		},
		{
			name: "expired",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now - 1,
				TokenID:    "jti-1",
			},
		},
		{
			name: "tier2 missing subject",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				Tier:       2,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePathOpenClaims(tc.claims, now); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestApplyRevocationFeedSigned(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:      "issuer-local",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "jti-1", Until: now + 120}},
	}
	feed.Signature = mustSignFeed(t, feed, priv)

	s := &Service{
		issuerPub:  pub,
		revokedJTI: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err != nil {
		t.Fatalf("expected signed feed to apply: %v", err)
	}
	if !s.isRevoked(issuerKeyID(pub), "jti-1", now) {
		t.Fatalf("expected jti-1 to be revoked")
	}
}

func TestApplyRevocationFeedRejectsBadSignature(t *testing.T) {
	_, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub2, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:      "issuer-local",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "jti-2", Until: now + 120}},
	}
	feed.Signature = mustSignFeed(t, feed, priv)

	s := &Service{
		issuerPub:  pub2,
		revokedJTI: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err == nil {
		t.Fatalf("expected bad signature to be rejected")
	}
}

func TestVerifyTokenAcceptsAnyTrustedIssuer(t *testing.T) {
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	claimsA := crypto.CapabilityClaims{
		Issuer:     "issuer-a",
		Audience:   "exit",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "jti-a",
	}
	claimsB := crypto.CapabilityClaims{
		Issuer:     "issuer-b",
		Audience:   "exit",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "jti-b",
	}
	tokenA, err := crypto.SignClaims(claimsA, privA)
	if err != nil {
		t.Fatalf("signA: %v", err)
	}
	tokenB, err := crypto.SignClaims(claimsB, privB)
	if err != nil {
		t.Fatalf("signB: %v", err)
	}
	s := &Service{
		issuerPubs: map[string]ed25519.PublicKey{
			issuerKeyID(pubA): pubA,
			issuerKeyID(pubB): pubB,
		},
	}
	if out, keyID, err := s.verifyToken(tokenA); err != nil {
		t.Fatalf("verify tokenA: %v", err)
	} else {
		if out.TokenID != "jti-a" || keyID != issuerKeyID(pubA) {
			t.Fatalf("unexpected tokenA verify result token=%s key=%s", out.TokenID, keyID)
		}
	}
	if out, keyID, err := s.verifyToken(tokenB); err != nil {
		t.Fatalf("verify tokenB: %v", err)
	} else {
		if out.TokenID != "jti-b" || keyID != issuerKeyID(pubB) {
			t.Fatalf("unexpected tokenB verify result token=%s key=%s", out.TokenID, keyID)
		}
	}
}

func TestVerifyTokenRejectsIssuerMismatchWhenMapped(t *testing.T) {
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-spoofed",
		Audience:   "exit",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "jti-spoof",
	}
	token, err := crypto.SignClaims(claims, privA)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	keyID := issuerKeyID(pubA)
	s := &Service{
		issuerPubs:      map[string]ed25519.PublicKey{keyID: pubA},
		issuerKeyIssuer: map[string]string{keyID: "issuer-a"},
	}
	if _, _, err := s.verifyToken(token); err == nil {
		t.Fatalf("expected issuer mismatch rejection")
	}
}

func TestRevocationScopedByIssuerKey(t *testing.T) {
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now().Unix()
	feedA := proto.RevocationListResponse{
		Issuer:      "issuer-a",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "shared-jti", Until: now + 120}},
	}
	feedA.Signature = mustSignFeed(t, feedA, privA)
	feedB := proto.RevocationListResponse{
		Issuer:      "issuer-b",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{},
	}
	feedB.Signature = mustSignFeed(t, feedB, privB)

	s := &Service{
		issuerPubs: map[string]ed25519.PublicKey{
			issuerKeyID(pubA): pubA,
			issuerKeyID(pubB): pubB,
		},
		revokedJTI: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feedA, now); err != nil {
		t.Fatalf("apply feedA: %v", err)
	}
	if err := s.applyRevocationFeed(feedB, now); err != nil {
		t.Fatalf("apply feedB: %v", err)
	}
	if !s.isRevoked(issuerKeyID(pubA), "shared-jti", now) {
		t.Fatalf("expected issuer A token revoked")
	}
	if s.isRevoked(issuerKeyID(pubB), "shared-jti", now) {
		t.Fatalf("did not expect issuer B token revoked")
	}
}

func mustSignFeed(t *testing.T, feed proto.RevocationListResponse, priv ed25519.PrivateKey) string {
	t.Helper()
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

func TestNewCommandBackendDisablesOpaqueEchoByDefault(t *testing.T) {
	t.Setenv("WG_BACKEND", "command")
	t.Setenv("EXIT_OPAQUE_ECHO", "")
	t.Setenv("EXIT_LIVE_WG_MODE", "0")

	s := New()
	if s.opaqueEcho {
		t.Fatalf("expected opaque echo disabled by default in command backend")
	}
}

func TestNewCommandBackendAllowsOpaqueEchoOverride(t *testing.T) {
	t.Setenv("WG_BACKEND", "command")
	t.Setenv("EXIT_OPAQUE_ECHO", "1")

	s := New()
	if !s.opaqueEcho {
		t.Fatalf("expected opaque echo enabled when explicitly overridden")
	}
}

func TestValidateRuntimeConfigLiveModeRequiresSink(t *testing.T) {
	s := &Service{
		dataMode:         "opaque",
		wgBackend:        "command",
		wgPrivateKey:     "/tmp/wg-exit.key",
		liveWGMode:       true,
		opaqueEcho:       false,
		opaqueSinkAddr:   "",
		opaqueSourceAddr: "127.0.0.1:53010",
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected live mode validation error without EXIT_OPAQUE_SINK_ADDR")
	}
}

func TestValidateRuntimeConfigLiveModeRequiresSource(t *testing.T) {
	s := &Service{
		dataMode:         "opaque",
		wgBackend:        "command",
		wgPrivateKey:     "/tmp/wg-exit.key",
		liveWGMode:       true,
		opaqueEcho:       false,
		opaqueSinkAddr:   "127.0.0.1:53011",
		opaqueSourceAddr: "",
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected live mode validation error without EXIT_OPAQUE_SOURCE_ADDR")
	}
}

func TestValidateRuntimeConfigCommandModeRequiresOpaque(t *testing.T) {
	s := &Service{
		dataMode:     "json",
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-exit.key",
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected command backend validation error for non-opaque data mode")
	}
}

func TestApplyRevocationFeedSetsMinTokenEpoch(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:        "issuer-epoch",
		KeyEpoch:      7,
		MinTokenEpoch: 6,
		Version:       2,
		GeneratedAt:   now,
		ExpiresAt:     now + 30,
	}
	feed.Signature = mustSignFeed(t, feed, priv)
	s := &Service{
		issuerPubs:        map[string]ed25519.PublicKey{issuerKeyID(pub): pub},
		revokedJTI:        map[string]int64{},
		minTokenEpoch:     map[string]int64{},
		revocationVersion: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err != nil {
		t.Fatalf("apply feed: %v", err)
	}
	if got := s.minTokenEpoch["issuer-epoch"]; got != 6 {
		t.Fatalf("expected min epoch 6, got %d", got)
	}
	if got := s.revocationVersion["issuer-epoch"]; got != 2 {
		t.Fatalf("expected revocation version 2, got %d", got)
	}
}

func TestParseOpaqueDownlinkPacketFramed(t *testing.T) {
	s := &Service{sessions: map[string]sessionInfo{}}
	frame := relay.BuildDatagram("sid-1", []byte("hello-downlink"))
	sid, payload, ok := s.parseOpaqueDownlinkPacket(frame, time.Now())
	if !ok {
		t.Fatalf("expected framed downlink parse success")
	}
	if sid != "sid-1" || string(payload) != "hello-downlink" {
		t.Fatalf("unexpected parsed result sid=%s payload=%q", sid, string(payload))
	}
}

func TestParseOpaqueDownlinkPacketSingleSessionFallback(t *testing.T) {
	now := time.Now()
	s := &Service{
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				sessionKeyID: "k1",
			},
		},
	}
	sid, payload, ok := s.parseOpaqueDownlinkPacket([]byte("raw-from-kernel"), now)
	if !ok {
		t.Fatalf("expected fallback parse success")
	}
	if sid != "sid-1" || string(payload) != "raw-from-kernel" {
		t.Fatalf("unexpected fallback result sid=%s payload=%q", sid, string(payload))
	}
}

func TestParseOpaqueDownlinkPacketLiveModeRequiresFraming(t *testing.T) {
	now := time.Now()
	s := &Service{
		liveWGMode: true,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				sessionKeyID: "k1",
			},
		},
	}
	if sid, payload, ok := s.parseOpaqueDownlinkPacket([]byte("raw-from-kernel"), now); ok {
		t.Fatalf("expected live mode raw downlink drop, got sid=%s payload_len=%d", sid, len(payload))
	}
}

func TestApplyRevocationFeedRejectsVersionRollback(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	base := proto.RevocationListResponse{
		Issuer:      "issuer-epoch",
		Version:     5,
		GeneratedAt: now,
		ExpiresAt:   now + 30,
	}
	base.Signature = mustSignFeed(t, base, priv)
	s := &Service{
		issuerPubs:        map[string]ed25519.PublicKey{issuerKeyID(pub): pub},
		revokedJTI:        map[string]int64{},
		revocationVersion: map[string]int64{},
		minTokenEpoch:     map[string]int64{},
	}
	if err := s.applyRevocationFeed(base, now); err != nil {
		t.Fatalf("apply base feed: %v", err)
	}
	stale := proto.RevocationListResponse{
		Issuer:      "issuer-epoch",
		Version:     4,
		GeneratedAt: now,
		ExpiresAt:   now + 30,
	}
	stale.Signature = mustSignFeed(t, stale, priv)
	if err := s.applyRevocationFeed(stale, now); err == nil {
		t.Fatalf("expected rollback version rejection")
	}
}

func TestAcceptsTokenKeyEpoch(t *testing.T) {
	s := &Service{
		minTokenEpoch:   map[string]int64{"issuer-a": 4},
		issuerKeyIssuer: map[string]string{"kid-a": "issuer-a"},
	}
	if !s.acceptsTokenKeyEpoch(crypto.CapabilityClaims{Issuer: "issuer-a", KeyEpoch: 4}, "kid-a") {
		t.Fatalf("expected token at epoch threshold accepted")
	}
	if s.acceptsTokenKeyEpoch(crypto.CapabilityClaims{Issuer: "issuer-a", KeyEpoch: 3}, "kid-a") {
		t.Fatalf("expected stale key epoch token rejected")
	}
	if !s.acceptsTokenKeyEpoch(crypto.CapabilityClaims{Issuer: "issuer-b", KeyEpoch: 1}, "kid-b") {
		t.Fatalf("expected untracked issuer epoch accepted")
	}
}

func TestFlushAccountingSnapshotWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acct.json")
	s := &Service{
		accountingFile: path,
		sessions: map[string]sessionInfo{
			"s1": {},
		},
		metrics: exitMetrics{
			AcceptedPackets: 10,
			DroppedPackets:  2,
		},
	}
	if err := s.flushAccountingSnapshot(time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("flush accounting: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read accounting file: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "\"accepted_packets\": 10") {
		t.Fatalf("expected accepted packet metric in accounting output: %s", text)
	}
	if !strings.Contains(text, "\"active_sessions\": 1") {
		t.Fatalf("expected active session count in accounting output: %s", text)
	}
}

func TestBuildEgressSetupCommandsContainsHardeningRules(t *testing.T) {
	cmds := buildEgressSetupCommands("CHAINX", "10.90.0.0/24", "eth9")
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "sysctl -w net.ipv4.ip_forward=1") {
		t.Fatalf("expected ip_forward setup command")
	}
	if !strings.Contains(joined, "iptables -t nat -A CHAINX -s 10.90.0.0/24 -o eth9 -j MASQUERADE") {
		t.Fatalf("expected dedicated nat chain masquerade command")
	}
	if !strings.Contains(joined, "conntrack --ctstate ESTABLISHED,RELATED") {
		t.Fatalf("expected established conntrack forward rule")
	}
}
