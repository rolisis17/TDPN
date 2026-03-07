package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privacynode/pkg/adminauth"
)

type signOutput struct {
	KeyID     string            `json:"key_id"`
	Timestamp int64             `json:"timestamp"`
	Nonce     string            `json:"nonce"`
	Signature string            `json:"signature"`
	Headers   map[string]string `json:"headers"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "gen":
		if err := runGen(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "inspect":
		if err := runInspect(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "sign":
		if err := runSign(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`Usage:
  go run ./cmd/adminsig gen [--private-key-out FILE] [--public-key-out FILE] [--key-id-out FILE]
  go run ./cmd/adminsig inspect --private-key-file FILE
  go run ./cmd/adminsig sign --private-key-file FILE --method METHOD --url URL [--body-file FILE|--body STRING] [--key-id ID] [--timestamp UNIX] [--nonce NONCE]

Outputs are JSON for script-friendly usage.`)
}

func runGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	privateOut := fs.String("private-key-out", "", "path to write private key (base64url, 0600)")
	publicOut := fs.String("public-key-out", "", "path to write public key (base64url)")
	keyIDOut := fs.String("key-id-out", "", "path to write key id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	privB64 := base64.RawURLEncoding.EncodeToString(priv)
	pubB64 := adminauth.EncodePublicKey(pub)
	keyID := adminauth.KeyIDFromPublicKey(pub)

	if *privateOut != "" {
		if err := writeFileWithMode(*privateOut, []byte(privB64+"\n"), 0o600); err != nil {
			return err
		}
	}
	if *publicOut != "" {
		if err := writeFileWithMode(*publicOut, []byte(pubB64+"\n"), 0o644); err != nil {
			return err
		}
	}
	if *keyIDOut != "" {
		if err := writeFileWithMode(*keyIDOut, []byte(keyID+"\n"), 0o644); err != nil {
			return err
		}
	}
	out := map[string]string{
		"private_key": privB64,
		"public_key":  pubB64,
		"key_id":      keyID,
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	privateFile := fs.String("private-key-file", "", "path to private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*privateFile) == "" {
		return fmt.Errorf("inspect requires --private-key-file")
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	out := map[string]string{
		"public_key": adminauth.EncodePublicKey(pub),
		"key_id":     adminauth.KeyIDFromPublicKey(pub),
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	privateFile := fs.String("private-key-file", "", "path to private key file")
	method := fs.String("method", "POST", "http method")
	rawURL := fs.String("url", "", "request URL")
	bodyFile := fs.String("body-file", "", "request body file")
	bodyInline := fs.String("body", "", "request body inline")
	keyID := fs.String("key-id", "", "explicit key id (optional)")
	timestamp := fs.Int64("timestamp", 0, "unix timestamp (optional)")
	nonce := fs.String("nonce", "", "request nonce (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*privateFile) == "" {
		return fmt.Errorf("sign requires --private-key-file")
	}
	if strings.TrimSpace(*rawURL) == "" {
		return fmt.Errorf("sign requires --url")
	}
	if *bodyFile != "" && *bodyInline != "" {
		return fmt.Errorf("sign accepts only one of --body-file or --body")
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(*rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	body := []byte(*bodyInline)
	if *bodyFile != "" {
		b, readErr := os.ReadFile(*bodyFile)
		if readErr != nil {
			return fmt.Errorf("read body file: %w", readErr)
		}
		body = b
	}
	ts := *timestamp
	if ts <= 0 {
		ts = time.Now().Unix()
	}
	n := strings.TrimSpace(*nonce)
	if n == "" {
		n = randomNonce(16)
	}
	kid := strings.TrimSpace(*keyID)
	if kid == "" {
		pub := priv.Public().(ed25519.PublicKey)
		kid = adminauth.KeyIDFromPublicKey(pub)
	}
	sig, err := adminauth.Sign(priv, *method, adminauth.PathWithQuery(parsed), body, ts, n)
	if err != nil {
		return err
	}
	out := signOutput{
		KeyID:     kid,
		Timestamp: ts,
		Nonce:     n,
		Signature: sig,
		Headers: map[string]string{
			adminauth.HeaderKeyID:     kid,
			adminauth.HeaderTimestamp: fmt.Sprintf("%d", ts),
			adminauth.HeaderNonce:     n,
			adminauth.HeaderSignature: sig,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func readPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}
	return ed25519.PrivateKey(raw), nil
}

func randomNonce(n int) string {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeFileWithMode(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
