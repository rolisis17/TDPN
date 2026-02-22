package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"privacynode/pkg/crypto"
)

func main() {
	if len(os.Args) < 2 {
		exitf("usage: tokenpop <gen|sign> [flags]")
	}
	switch os.Args[1] {
	case "gen":
		runGen()
	case "sign":
		runSign(os.Args[2:])
	default:
		exitf("unknown subcommand %q", os.Args[1])
	}
}

func runGen() {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		exitf("keygen failed: %v", err)
	}
	out := map[string]string{
		"public_key":  crypto.EncodeEd25519PublicKey(pub),
		"private_key": base64.RawURLEncoding.EncodeToString(priv),
	}
	writeJSON(out)
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	privateKey := fs.String("private-key", "", "base64url-encoded ed25519 private key")
	token := fs.String("token", "", "signed token string")
	exitID := fs.String("exit-id", "", "requested exit id")
	tokenProofNonce := fs.String("proof-nonce", "", "token proof nonce")
	clientInnerPub := fs.String("client-inner-pub", "", "client inner pubkey")
	transport := fs.String("transport", "policy-json", "transport type")
	requestedMTU := fs.Int("requested-mtu", 1280, "requested mtu")
	requestedRegion := fs.String("requested-region", "local", "requested region")
	if err := fs.Parse(args); err != nil {
		exitf("parse flags failed: %v", err)
	}

	if *privateKey == "" || *token == "" || *exitID == "" {
		exitf("required flags: --private-key --token --exit-id")
	}
	priv, err := parsePrivateKey(*privateKey)
	if err != nil {
		exitf("invalid private key: %v", err)
	}
	proof, err := crypto.SignPathOpenProof(priv, crypto.PathOpenProofInput{
		Token:           *token,
		ExitID:          *exitID,
		TokenProofNonce: *tokenProofNonce,
		ClientInnerPub:  *clientInnerPub,
		Transport:       *transport,
		RequestedMTU:    *requestedMTU,
		RequestedRegion: *requestedRegion,
	})
	if err != nil {
		exitf("sign proof failed: %v", err)
	}
	writeJSON(map[string]string{"proof": proof})
}

func parsePrivateKey(v string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid size")
	}
	return ed25519.PrivateKey(raw), nil
}

func writeJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		exitf("encode json failed: %v", err)
	}
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
