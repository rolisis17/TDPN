package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	TokenTypeClientAccess = "client_access"
	TokenTypeProviderRole = "provider_role"

	pathOpenProofContext = "path_open_v1"

	maxSignedTokenChars     = 16 * 1024
	maxTokenPayloadB64Chars = 12 * 1024
	maxTokenSigB64Chars     = 512
	maxPathOpenProofChars   = 1024
	maxKeyB64Chars          = 256

	maxProofIDChars     = 256
	maxProofNonceChars  = 1024
	maxProofPubKeyChars = 1024
	maxProofTokenChars  = maxSignedTokenChars
	maxProofRegionChars = 128
	maxProofTransport   = 64
	maxProofProfile     = 32
)

type CapabilityClaims struct {
	Issuer     string   `json:"iss"`
	Audience   string   `json:"aud"`
	Subject    string   `json:"sub,omitempty"`
	AnonCredID string   `json:"anon_cred_id,omitempty"`
	KeyEpoch   int64    `json:"key_epoch,omitempty"`
	TokenType  string   `json:"token_type,omitempty"`
	CNFEd25519 string   `json:"cnf_ed25519,omitempty"`
	Transport  string   `json:"transport,omitempty"`
	Tier       int      `json:"tier"`
	ExpiryUnix int64    `json:"exp"`
	TokenID    string   `json:"jti"`
	AllowPorts []int    `json:"allow_ports,omitempty"`
	DenyPorts  []int    `json:"deny_ports,omitempty"`
	BWKbps     int      `json:"bw_kbps"`
	ConnRate   int      `json:"conn_rate"`
	MaxConns   int      `json:"max_conns"`
	ExitScope  []string `json:"exit_scope,omitempty"`
}

type PathOpenProofInput struct {
	Token                string
	ExitID               string
	MiddleRelayID        string
	PathProfile          string
	SessionID            string
	TokenProofNonce      string
	ReservationID        string
	ReservationSessionID string
	ReservationSubjectID string
	ClientInnerPub       string
	Transport            string
	RequestedMTU         int
	RequestedRegion      string
	ClientRoute          PathRouteAssertionInput
}

type PathRouteAssertionInput struct {
	PathProfile          string
	EntryRelayID         string
	MiddleRelayID        string
	ExitRelayID          string
	SessionID            string
	TokenProofNonce      string
	ReservationID        string
	ReservationSessionID string
	ReservationSubjectID string
	ClientInnerPub       string
	Transport            string
	RequestedMTU         int
	RequestedRegion      string
	TokenSHA256          string
	TokenProofSHA256     string
	SignerPubKey         string
	Signature            string
}

func NormalizeTokenType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", TokenTypeClientAccess:
		return TokenTypeClientAccess
	case TokenTypeProviderRole:
		return TokenTypeProviderRole
	default:
		return ""
	}
}

func EncodeEd25519PublicKey(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(pub)
}

func ParseEd25519PublicKey(pubB64 string) (ed25519.PublicKey, error) {
	pubB64 = strings.TrimSpace(pubB64)
	if len(pubB64) > maxKeyB64Chars {
		return nil, fmt.Errorf("public key exceeds max encoded size")
	}
	raw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key encoding: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	return ed25519.PublicKey(raw), nil
}

func NormalizeEd25519PublicKey(pubB64 string) (string, error) {
	pub, err := ParseEd25519PublicKey(pubB64)
	if err != nil {
		return "", err
	}
	return EncodeEd25519PublicKey(pub), nil
}

func GenerateEd25519Keypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func SignClaims(claims CapabilityClaims, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyClaims(token string, pub ed25519.PublicKey) (CapabilityClaims, error) {
	var claims CapabilityClaims

	token = strings.TrimSpace(token)
	if len(token) > maxSignedTokenChars {
		return claims, fmt.Errorf("token exceeds max size")
	}
	payloadB64, sigB64, ok := strings.Cut(token, ".")
	if !ok || payloadB64 == "" || sigB64 == "" {
		return claims, fmt.Errorf("invalid token format")
	}
	if len(payloadB64) > maxTokenPayloadB64Chars {
		return claims, fmt.Errorf("token payload exceeds max size")
	}
	if len(sigB64) > maxTokenSigB64Chars {
		return claims, fmt.Errorf("token signature exceeds max size")
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return claims, fmt.Errorf("invalid payload encoding: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return claims, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return claims, fmt.Errorf("invalid signature size")
	}

	if !ed25519.Verify(pub, payload, sig) {
		return claims, fmt.Errorf("signature verification failed")
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("invalid claims json: %w", err)
	}
	return claims, nil
}

func SignPathOpenProof(priv ed25519.PrivateKey, input PathOpenProofInput) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size")
	}
	msg, err := pathOpenProofMessage(input)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyPathOpenProof(proof string, pub ed25519.PublicKey, input PathOpenProofInput) error {
	return verifyPathOpenProof(proof, pub, input, false)
}

// VerifyPathOpenProofCompat verifies a proof and accepts legacy payload variants.
// Use this only during controlled migration windows.
func VerifyPathOpenProofCompat(proof string, pub ed25519.PublicKey, input PathOpenProofInput) error {
	return verifyPathOpenProof(proof, pub, input, true)
}

// VerifyPathOpenProofStrict verifies only the canonical path-open proof payload.
// It rejects legacy proof variants that omit fields such as middle_relay_id.
func VerifyPathOpenProofStrict(proof string, pub ed25519.PublicKey, input PathOpenProofInput) error {
	return verifyPathOpenProof(proof, pub, input, false)
}

func verifyPathOpenProof(proof string, pub ed25519.PublicKey, input PathOpenProofInput, allowLegacyVariants bool) error {
	proof = strings.TrimSpace(proof)
	if proof == "" {
		return fmt.Errorf("missing token proof")
	}
	if len(proof) > maxPathOpenProofChars {
		return fmt.Errorf("token proof exceeds max size")
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof)
	if err != nil {
		return fmt.Errorf("invalid token proof encoding: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid token proof size")
	}
	var msgs [][]byte
	if allowLegacyVariants {
		msgs, err = pathOpenProofMessagesForVerification(input)
	} else {
		msg, err := pathOpenProofMessage(input)
		if err != nil {
			return err
		}
		msgs = [][]byte{msg}
	}
	if err != nil {
		return err
	}
	for _, msg := range msgs {
		if ed25519.Verify(pub, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("invalid token proof signature")
}

func pathOpenProofMessage(input PathOpenProofInput) ([]byte, error) {
	return pathOpenProofMessageVariant(input, true, true, true, true, true)
}

func pathOpenProofMessagesForVerification(input PathOpenProofInput) ([][]byte, error) {
	normalized := normalizePathOpenProofInput(input)
	routeAssertionRequired := !pathOpenProofRouteAssertionEmpty(normalized.ClientRoute)
	variants := []struct {
		includeMiddleRelayID   bool
		includeTransport       bool
		includeRequestedMTU    bool
		includeRequestedRegion bool
		includeRouteAssertion  bool
	}{
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: true, includeRouteAssertion: true},
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: true, includeRouteAssertion: false},
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: false, includeRouteAssertion: false},
		{includeMiddleRelayID: false, includeTransport: true, includeRequestedMTU: true, includeRequestedRegion: false, includeRouteAssertion: false},
		{includeMiddleRelayID: true, includeTransport: true, includeRequestedMTU: false, includeRequestedRegion: false, includeRouteAssertion: false},
		{includeMiddleRelayID: false, includeTransport: true, includeRequestedMTU: false, includeRequestedRegion: false, includeRouteAssertion: false},
		{includeMiddleRelayID: true, includeTransport: false, includeRequestedMTU: false, includeRequestedRegion: false, includeRouteAssertion: false},
		{includeMiddleRelayID: false, includeTransport: false, includeRequestedMTU: false, includeRequestedRegion: false, includeRouteAssertion: false},
	}
	out := make([][]byte, 0, len(variants))
	seen := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		if routeAssertionRequired && !variant.includeRouteAssertion {
			continue
		}
		msg, err := pathOpenProofMessageVariant(
			normalized,
			variant.includeMiddleRelayID,
			variant.includeTransport,
			variant.includeRequestedMTU,
			variant.includeRequestedRegion,
			variant.includeRouteAssertion,
		)
		if err != nil {
			return nil, err
		}
		key := string(msg)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, msg)
	}
	return out, nil
}

func pathOpenProofMessageVariant(input PathOpenProofInput, includeMiddleRelayID bool, includeTransport bool, includeRequestedMTU bool, includeRequestedRegion bool, includeRouteAssertion bool) ([]byte, error) {
	normalized := normalizePathOpenProofInput(input)
	if len(normalized.Token) > maxProofTokenChars {
		return nil, fmt.Errorf("token exceeds max size")
	}
	if len(normalized.ExitID) > maxProofIDChars {
		return nil, fmt.Errorf("exit id exceeds max size")
	}
	if len(normalized.MiddleRelayID) > maxProofIDChars {
		return nil, fmt.Errorf("middle relay id exceeds max size")
	}
	if len(normalized.PathProfile) > maxProofProfile {
		return nil, fmt.Errorf("path profile exceeds max size")
	}
	if len(normalized.SessionID) > maxProofIDChars {
		return nil, fmt.Errorf("session id exceeds max size")
	}
	if len(normalized.TokenProofNonce) > maxProofNonceChars {
		return nil, fmt.Errorf("token proof nonce exceeds max size")
	}
	if len(normalized.ReservationID) > maxProofIDChars {
		return nil, fmt.Errorf("reservation id exceeds max size")
	}
	if len(normalized.ReservationSessionID) > maxProofIDChars {
		return nil, fmt.Errorf("reservation session id exceeds max size")
	}
	if len(normalized.ReservationSubjectID) > maxProofIDChars {
		return nil, fmt.Errorf("reservation subject id exceeds max size")
	}
	if len(normalized.ClientInnerPub) > maxProofPubKeyChars {
		return nil, fmt.Errorf("client inner pub exceeds max size")
	}
	if len(normalized.Transport) > maxProofTransport {
		return nil, fmt.Errorf("transport exceeds max size")
	}
	if len(normalized.RequestedRegion) > maxProofRegionChars {
		return nil, fmt.Errorf("requested region exceeds max size")
	}
	if err := validatePathOpenProofRouteAssertion(normalized.ClientRoute); err != nil {
		return nil, err
	}
	middleRelayID := normalized.MiddleRelayID
	pathProfile := normalized.PathProfile
	transport := normalized.Transport
	requestedMTU := normalized.RequestedMTU
	requestedRegion := normalized.RequestedRegion

	payload := struct {
		Context              string  `json:"ctx"`
		Token                string  `json:"token"`
		ExitID               string  `json:"exit_id"`
		MiddleRelayID        *string `json:"middle_relay_id,omitempty"`
		PathProfile          *string `json:"path_profile,omitempty"`
		SessionID            string  `json:"session_id,omitempty"`
		TokenProofNonce      string  `json:"token_proof_nonce"`
		ReservationID        string  `json:"reservation_id,omitempty"`
		ReservationSessionID string  `json:"reservation_session_id,omitempty"`
		ReservationSubjectID string  `json:"reservation_subject_id,omitempty"`
		ClientInnerPub       string  `json:"client_inner_pub"`
		Transport            *string `json:"transport,omitempty"`
		RequestedMTU         *int    `json:"requested_mtu,omitempty"`
		RequestedRegion      *string `json:"requested_region,omitempty"`
		ClientRoute          *struct {
			PathProfile          string `json:"path_profile,omitempty"`
			EntryRelayID         string `json:"entry_relay_id,omitempty"`
			MiddleRelayID        string `json:"middle_relay_id,omitempty"`
			ExitRelayID          string `json:"exit_relay_id,omitempty"`
			SessionID            string `json:"session_id,omitempty"`
			TokenProofNonce      string `json:"token_proof_nonce,omitempty"`
			ReservationID        string `json:"reservation_id,omitempty"`
			ReservationSessionID string `json:"reservation_session_id,omitempty"`
			ReservationSubjectID string `json:"reservation_subject_id,omitempty"`
			ClientInnerPub       string `json:"client_inner_pub,omitempty"`
			Transport            string `json:"transport,omitempty"`
			RequestedMTU         int    `json:"requested_mtu,omitempty"`
			RequestedRegion      string `json:"requested_region,omitempty"`
			TokenSHA256          string `json:"token_sha256,omitempty"`
			TokenProofSHA256     string `json:"token_proof_sha256,omitempty"`
			SignerPubKey         string `json:"signer_pub_key,omitempty"`
			Signature            string `json:"signature,omitempty"`
		} `json:"client_route_assertion,omitempty"`
	}{
		Context:              pathOpenProofContext,
		Token:                normalized.Token,
		ExitID:               normalized.ExitID,
		SessionID:            normalized.SessionID,
		TokenProofNonce:      normalized.TokenProofNonce,
		ReservationID:        normalized.ReservationID,
		ReservationSessionID: normalized.ReservationSessionID,
		ReservationSubjectID: normalized.ReservationSubjectID,
		ClientInnerPub:       normalized.ClientInnerPub,
	}
	if includeMiddleRelayID {
		payload.MiddleRelayID = &middleRelayID
	}
	if includeRouteAssertion && pathProfile != "" {
		payload.PathProfile = &pathProfile
	}
	if includeRouteAssertion && !pathOpenProofRouteAssertionEmpty(normalized.ClientRoute) {
		payload.ClientRoute = &struct {
			PathProfile          string `json:"path_profile,omitempty"`
			EntryRelayID         string `json:"entry_relay_id,omitempty"`
			MiddleRelayID        string `json:"middle_relay_id,omitempty"`
			ExitRelayID          string `json:"exit_relay_id,omitempty"`
			SessionID            string `json:"session_id,omitempty"`
			TokenProofNonce      string `json:"token_proof_nonce,omitempty"`
			ReservationID        string `json:"reservation_id,omitempty"`
			ReservationSessionID string `json:"reservation_session_id,omitempty"`
			ReservationSubjectID string `json:"reservation_subject_id,omitempty"`
			ClientInnerPub       string `json:"client_inner_pub,omitempty"`
			Transport            string `json:"transport,omitempty"`
			RequestedMTU         int    `json:"requested_mtu,omitempty"`
			RequestedRegion      string `json:"requested_region,omitempty"`
			TokenSHA256          string `json:"token_sha256,omitempty"`
			TokenProofSHA256     string `json:"token_proof_sha256,omitempty"`
			SignerPubKey         string `json:"signer_pub_key,omitempty"`
			Signature            string `json:"signature,omitempty"`
		}{
			PathProfile:          normalized.ClientRoute.PathProfile,
			EntryRelayID:         normalized.ClientRoute.EntryRelayID,
			MiddleRelayID:        normalized.ClientRoute.MiddleRelayID,
			ExitRelayID:          normalized.ClientRoute.ExitRelayID,
			SessionID:            normalized.ClientRoute.SessionID,
			TokenProofNonce:      normalized.ClientRoute.TokenProofNonce,
			ReservationID:        normalized.ClientRoute.ReservationID,
			ReservationSessionID: normalized.ClientRoute.ReservationSessionID,
			ReservationSubjectID: normalized.ClientRoute.ReservationSubjectID,
			ClientInnerPub:       normalized.ClientRoute.ClientInnerPub,
			Transport:            normalized.ClientRoute.Transport,
			RequestedMTU:         normalized.ClientRoute.RequestedMTU,
			RequestedRegion:      normalized.ClientRoute.RequestedRegion,
			TokenSHA256:          normalized.ClientRoute.TokenSHA256,
			TokenProofSHA256:     normalized.ClientRoute.TokenProofSHA256,
			SignerPubKey:         normalized.ClientRoute.SignerPubKey,
			Signature:            normalized.ClientRoute.Signature,
		}
	}
	if includeTransport {
		payload.Transport = &transport
	}
	if includeRequestedMTU {
		payload.RequestedMTU = &requestedMTU
	}
	if includeRequestedRegion {
		payload.RequestedRegion = &requestedRegion
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal path-open proof payload: %w", err)
	}
	return msg, nil
}

func normalizePathOpenProofInput(input PathOpenProofInput) PathOpenProofInput {
	input.Token = strings.TrimSpace(input.Token)
	input.ExitID = strings.TrimSpace(input.ExitID)
	input.MiddleRelayID = strings.TrimSpace(input.MiddleRelayID)
	input.PathProfile = strings.ToLower(strings.TrimSpace(input.PathProfile))
	input.SessionID = strings.TrimSpace(input.SessionID)
	input.TokenProofNonce = strings.TrimSpace(input.TokenProofNonce)
	input.ReservationID = strings.TrimSpace(input.ReservationID)
	input.ReservationSessionID = strings.TrimSpace(input.ReservationSessionID)
	input.ReservationSubjectID = strings.TrimSpace(input.ReservationSubjectID)
	input.ClientInnerPub = strings.TrimSpace(input.ClientInnerPub)
	input.Transport = strings.TrimSpace(input.Transport)
	input.RequestedRegion = strings.TrimSpace(input.RequestedRegion)
	input.ClientRoute.PathProfile = strings.ToLower(strings.TrimSpace(input.ClientRoute.PathProfile))
	input.ClientRoute.EntryRelayID = strings.TrimSpace(input.ClientRoute.EntryRelayID)
	input.ClientRoute.MiddleRelayID = strings.TrimSpace(input.ClientRoute.MiddleRelayID)
	input.ClientRoute.ExitRelayID = strings.TrimSpace(input.ClientRoute.ExitRelayID)
	input.ClientRoute.SessionID = strings.TrimSpace(input.ClientRoute.SessionID)
	input.ClientRoute.TokenProofNonce = strings.TrimSpace(input.ClientRoute.TokenProofNonce)
	input.ClientRoute.ReservationID = strings.TrimSpace(input.ClientRoute.ReservationID)
	input.ClientRoute.ReservationSessionID = strings.TrimSpace(input.ClientRoute.ReservationSessionID)
	input.ClientRoute.ReservationSubjectID = strings.TrimSpace(input.ClientRoute.ReservationSubjectID)
	input.ClientRoute.ClientInnerPub = strings.TrimSpace(input.ClientRoute.ClientInnerPub)
	input.ClientRoute.Transport = strings.TrimSpace(input.ClientRoute.Transport)
	input.ClientRoute.RequestedRegion = strings.TrimSpace(input.ClientRoute.RequestedRegion)
	input.ClientRoute.TokenSHA256 = strings.TrimSpace(input.ClientRoute.TokenSHA256)
	input.ClientRoute.TokenProofSHA256 = strings.TrimSpace(input.ClientRoute.TokenProofSHA256)
	input.ClientRoute.SignerPubKey = strings.TrimSpace(input.ClientRoute.SignerPubKey)
	input.ClientRoute.Signature = strings.TrimSpace(input.ClientRoute.Signature)
	return input
}

func validatePathOpenProofRouteAssertion(assertion PathRouteAssertionInput) error {
	if len(assertion.PathProfile) > maxProofProfile {
		return fmt.Errorf("client route assertion path profile exceeds max size")
	}
	if len(assertion.EntryRelayID) > maxProofIDChars {
		return fmt.Errorf("client route assertion entry relay id exceeds max size")
	}
	if len(assertion.MiddleRelayID) > maxProofIDChars {
		return fmt.Errorf("client route assertion middle relay id exceeds max size")
	}
	if len(assertion.ExitRelayID) > maxProofIDChars {
		return fmt.Errorf("client route assertion exit relay id exceeds max size")
	}
	if len(assertion.SessionID) > maxProofIDChars {
		return fmt.Errorf("client route assertion session id exceeds max size")
	}
	if len(assertion.TokenProofNonce) > maxProofNonceChars {
		return fmt.Errorf("client route assertion nonce exceeds max size")
	}
	if len(assertion.ReservationID) > maxProofIDChars {
		return fmt.Errorf("client route assertion reservation id exceeds max size")
	}
	if len(assertion.ReservationSessionID) > maxProofIDChars {
		return fmt.Errorf("client route assertion reservation session id exceeds max size")
	}
	if len(assertion.ReservationSubjectID) > maxProofIDChars {
		return fmt.Errorf("client route assertion reservation subject id exceeds max size")
	}
	if len(assertion.ClientInnerPub) > maxProofPubKeyChars {
		return fmt.Errorf("client route assertion public key exceeds max size")
	}
	if len(assertion.Transport) > maxProofTransport {
		return fmt.Errorf("client route assertion transport exceeds max size")
	}
	if len(assertion.RequestedRegion) > maxProofRegionChars {
		return fmt.Errorf("client route assertion region exceeds max size")
	}
	if len(assertion.TokenSHA256) > maxKeyB64Chars {
		return fmt.Errorf("client route assertion token hash exceeds max size")
	}
	if len(assertion.TokenProofSHA256) > maxKeyB64Chars {
		return fmt.Errorf("client route assertion proof hash exceeds max size")
	}
	if len(assertion.SignerPubKey) > maxKeyB64Chars {
		return fmt.Errorf("client route assertion signer public key exceeds max size")
	}
	if len(assertion.Signature) > maxTokenSigB64Chars {
		return fmt.Errorf("client route assertion signature exceeds max size")
	}
	return nil
}

func pathOpenProofRouteAssertionEmpty(assertion PathRouteAssertionInput) bool {
	return assertion.PathProfile == "" &&
		assertion.EntryRelayID == "" &&
		assertion.MiddleRelayID == "" &&
		assertion.ExitRelayID == "" &&
		assertion.SessionID == "" &&
		assertion.TokenProofNonce == "" &&
		assertion.ReservationID == "" &&
		assertion.ReservationSessionID == "" &&
		assertion.ReservationSubjectID == "" &&
		assertion.ClientInnerPub == "" &&
		assertion.Transport == "" &&
		assertion.RequestedMTU == 0 &&
		assertion.RequestedRegion == "" &&
		assertion.TokenSHA256 == "" &&
		assertion.TokenProofSHA256 == "" &&
		assertion.SignerPubKey == "" &&
		assertion.Signature == ""
}
