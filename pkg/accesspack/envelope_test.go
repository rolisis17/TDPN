package accesspack

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTextEnvelopeRoundTrip(t *testing.T) {
	payload, err := json.Marshal(testPack())
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	text, err := EncodeTextEnvelope(EnvelopeKindPack, payload)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	if !strings.HasPrefix(text, TextEnvelopePrefix+".") {
		t.Fatalf("missing envelope prefix: %q", text)
	}
	envelope, decoded, err := DecodeTextEnvelope(text)
	if err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.Kind != EnvelopeKindPack {
		t.Fatalf("kind mismatch: %q", envelope.Kind)
	}
	var pack Pack
	if err := json.Unmarshal(decoded, &pack); err != nil {
		t.Fatalf("decoded payload is not pack json: %v", err)
	}
	if pack.PackID != testPack().PackID {
		t.Fatalf("pack id mismatch: %q", pack.PackID)
	}
}

func TestTextEnvelopeBridgeInviteRoundTrip(t *testing.T) {
	payload, err := json.Marshal(testBridgeInvite())
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	text, err := EncodeTextEnvelope(EnvelopeKindBridge, payload)
	if err != nil {
		t.Fatalf("encode bridge envelope: %v", err)
	}
	envelope, decoded, err := DecodeTextEnvelope(text)
	if err != nil {
		t.Fatalf("decode bridge envelope: %v", err)
	}
	if envelope.Kind != EnvelopeKindBridge {
		t.Fatalf("kind mismatch: %q", envelope.Kind)
	}
	var invite BridgeInvite
	if err := json.Unmarshal(decoded, &invite); err != nil {
		t.Fatalf("decoded payload is not bridge invite json: %v", err)
	}
	if invite.InviteID != testBridgeInvite().InviteID {
		t.Fatalf("invite id mismatch: %q", invite.InviteID)
	}
}

func TestTextEnvelopeBridgeHelperRegistryRoundTrip(t *testing.T) {
	payload, err := json.Marshal(testBridgeHelperRegistry())
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	text, err := EncodeTextEnvelope(EnvelopeKindBridgeHelperRegistry, payload)
	if err != nil {
		t.Fatalf("encode bridge helper registry envelope: %v", err)
	}
	envelope, decoded, err := DecodeTextEnvelope(text)
	if err != nil {
		t.Fatalf("decode bridge helper registry envelope: %v", err)
	}
	if envelope.Kind != EnvelopeKindBridgeHelperRegistry {
		t.Fatalf("kind mismatch: %q", envelope.Kind)
	}
	var registry BridgeHelperRegistry
	if err := json.Unmarshal(decoded, &registry); err != nil {
		t.Fatalf("decoded payload is not bridge helper registry json: %v", err)
	}
	if len(registry.Helpers) != 1 || registry.Helpers[0].HelperID != "helper-1" {
		t.Fatalf("registry mismatch: %+v", registry)
	}
}

func TestTextEnvelopeRejectsUnknownKind(t *testing.T) {
	_, err := EncodeTextEnvelope("unknown", []byte(`{"ok":true}`))
	if err == nil {
		t.Fatal("expected unknown kind to fail")
	}
}

func TestTextEnvelopeRejectsMalformedText(t *testing.T) {
	_, _, err := DecodeTextEnvelope("GPMREC1.not-base64")
	if err == nil {
		t.Fatal("expected malformed text to fail")
	}
}
