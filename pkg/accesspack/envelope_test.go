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
