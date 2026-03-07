package adminauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	ts := int64(1700000000)
	nonce := "nonce-1"
	path := "/v1/admin/subject/upsert?x=1"
	sig, err := Sign(priv, "POST", path, body, ts, nonce)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(pub, sig, "POST", path, body, ts, nonce); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsWrongBody(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sig, err := Sign(priv, "POST", "/v1/admin/revoke-token", []byte(`{"a":1}`), 1700000000, "n")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(pub, sig, "POST", "/v1/admin/revoke-token", []byte(`{"a":2}`), 1700000000, "n"); err == nil {
		t.Fatalf("expected verify failure")
	}
}

func TestReadBodyPreserve(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/admin/test", strings.NewReader(`{"x":1}`))
	body, err := ReadBodyPreserve(req)
	if err != nil {
		t.Fatalf("ReadBodyPreserve: %v", err)
	}
	if string(body) != `{"x":1}` {
		t.Fatalf("unexpected body: %s", string(body))
	}
	body2, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll preserved body: %v", err)
	}
	if string(body2) != `{"x":1}` {
		t.Fatalf("unexpected preserved body: %s", string(body2))
	}
}
