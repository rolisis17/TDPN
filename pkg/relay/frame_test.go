package relay

import "testing"

func TestBuildParseDatagram(t *testing.T) {
	frame := BuildDatagram("abc", []byte("payload"))
	sid, payload, err := ParseDatagram(frame)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if sid != "abc" {
		t.Fatalf("unexpected session id: %s", sid)
	}
	if string(payload) != "payload" {
		t.Fatalf("unexpected payload: %q", string(payload))
	}
}

func TestParseDatagramRejectsInvalid(t *testing.T) {
	if _, _, err := ParseDatagram([]byte("no-separator")); err == nil {
		t.Fatalf("expected invalid frame error")
	}
}
