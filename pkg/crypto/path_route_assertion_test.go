package crypto

import (
	"testing"

	"privacynode/pkg/proto"
)

func TestPathRouteAssertionSignatureBindsRoute(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	assertion, err := SignPathRouteAssertion(priv, proto.PathRouteAssertion{
		PathProfile:   "3hop",
		EntryRelayID:  "entry-a",
		MiddleRelayID: "middle-a",
		ExitRelayID:   "exit-a",
	})
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	if err := VerifyPathRouteAssertionSignature(assertion, pub); err != nil {
		t.Fatalf("verify assertion: %v", err)
	}

	assertion.MiddleRelayID = "middle-b"
	if err := VerifyPathRouteAssertionSignature(assertion, pub); err == nil {
		t.Fatalf("expected mutated route assertion to fail verification")
	}
}

func TestPathRouteAssertionSignatureBindsRequestFields(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	assertion, err := SignPathRouteAssertion(priv, proto.PathRouteAssertion{
		PathProfile:          "3hop",
		EntryRelayID:         "entry-a",
		MiddleRelayID:        "middle-a",
		ExitRelayID:          "exit-a",
		SessionID:            "sid-a",
		ReservationID:        "res-a",
		ReservationSessionID: "sid-a",
		ReservationSubjectID: "cosmos1subject",
		TokenProofNonce:      "nonce-a",
		ClientInnerPub:       "client-pub-a",
		Transport:            "wireguard-udp",
		RequestedMTU:         1280,
		RequestedRegion:      "us",
		TokenSHA256:          PathRouteAssertionBindingHash("token-a"),
		TokenProofSHA256:     PathRouteAssertionBindingHash("proof-a"),
	})
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	if err := VerifyPathRouteAssertionSignature(assertion, pub); err != nil {
		t.Fatalf("verify assertion: %v", err)
	}

	assertion.TokenProofNonce = "nonce-b"
	if err := VerifyPathRouteAssertionSignature(assertion, pub); err == nil {
		t.Fatalf("expected mutated request binding to fail verification")
	}

	assertion.TokenProofNonce = "nonce-a"
	assertion.ReservationID = "res-b"
	if err := VerifyPathRouteAssertionSignature(assertion, pub); err == nil {
		t.Fatalf("expected mutated reservation id to fail verification")
	}

	assertion.ReservationID = "res-a"
	assertion.ReservationSubjectID = "cosmos1other"
	if err := VerifyPathRouteAssertionSignature(assertion, pub); err == nil {
		t.Fatalf("expected mutated reservation subject id to fail verification")
	}
}
