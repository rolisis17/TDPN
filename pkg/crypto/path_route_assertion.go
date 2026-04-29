package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"privacynode/pkg/proto"
)

const pathRouteAssertionContext = "path_route_assertion_v1"

// SignPathRouteAssertion signs a route assertion with the entry relay key.
// The signer public key is embedded so exits can match it against a trusted set.
func SignPathRouteAssertion(priv ed25519.PrivateKey, assertion proto.PathRouteAssertion) (proto.PathRouteAssertion, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return proto.PathRouteAssertion{}, fmt.Errorf("invalid private key size")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return proto.PathRouteAssertion{}, fmt.Errorf("invalid public key size")
	}
	assertion.SignerPubKey = EncodeEd25519PublicKey(pub)
	assertion.Signature = ""
	payload, err := pathRouteAssertionPayload(assertion)
	if err != nil {
		return proto.PathRouteAssertion{}, err
	}
	assertion.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
	return assertion, nil
}

func VerifyPathRouteAssertionSignature(assertion proto.PathRouteAssertion, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size")
	}
	signerPubKey := strings.TrimSpace(assertion.SignerPubKey)
	if signerPubKey == "" {
		return fmt.Errorf("route assertion signer public key required")
	}
	if signerPubKey != EncodeEd25519PublicKey(pub) {
		return fmt.Errorf("route assertion signer public key mismatch")
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(assertion.Signature))
	if err != nil {
		return fmt.Errorf("decode route assertion signature: %w", err)
	}
	if len(sigRaw) != ed25519.SignatureSize {
		return fmt.Errorf("invalid route assertion signature size")
	}
	unsigned := assertion
	unsigned.Signature = ""
	payload, err := pathRouteAssertionPayload(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sigRaw) {
		return fmt.Errorf("route assertion signature invalid")
	}
	return nil
}

func PathRouteAssertionBindingHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pathRouteAssertionPayload(assertion proto.PathRouteAssertion) ([]byte, error) {
	payload := struct {
		Context              string `json:"ctx"`
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
	}{
		Context:              pathRouteAssertionContext,
		PathProfile:          strings.ToLower(strings.TrimSpace(assertion.PathProfile)),
		EntryRelayID:         strings.TrimSpace(assertion.EntryRelayID),
		MiddleRelayID:        strings.TrimSpace(assertion.MiddleRelayID),
		ExitRelayID:          strings.TrimSpace(assertion.ExitRelayID),
		SessionID:            strings.TrimSpace(assertion.SessionID),
		TokenProofNonce:      strings.TrimSpace(assertion.TokenProofNonce),
		ReservationID:        strings.TrimSpace(assertion.ReservationID),
		ReservationSessionID: strings.TrimSpace(assertion.ReservationSessionID),
		ReservationSubjectID: strings.TrimSpace(assertion.ReservationSubjectID),
		ClientInnerPub:       strings.TrimSpace(assertion.ClientInnerPub),
		Transport:            strings.TrimSpace(assertion.Transport),
		RequestedMTU:         assertion.RequestedMTU,
		RequestedRegion:      strings.TrimSpace(assertion.RequestedRegion),
		TokenSHA256:          strings.TrimSpace(assertion.TokenSHA256),
		TokenProofSHA256:     strings.TrimSpace(assertion.TokenProofSHA256),
		SignerPubKey:         strings.TrimSpace(assertion.SignerPubKey),
	}
	return json.Marshal(payload)
}
