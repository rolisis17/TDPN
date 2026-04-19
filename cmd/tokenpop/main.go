package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"privacynode/internal/fileperm"
	"privacynode/pkg/crypto"
)

func main() {
	if len(os.Args) < 2 {
		exitf("usage: tokenpop <gen|sign> [flags]")
	}
	switch os.Args[1] {
	case "gen":
		runGen(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	default:
		exitf("unknown subcommand %q", os.Args[1])
	}
}

func runGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	showPrivateKey := fs.Bool("show-private-key", false, "include private key in stdout output (dangerous)")
	if err := fs.Parse(args); err != nil {
		exitf("parse flags failed: %v", err)
	}
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		exitf("keygen failed: %v", err)
	}
	out := map[string]string{
		"public_key": crypto.EncodeEd25519PublicKey(pub),
	}
	if *showPrivateKey {
		out["private_key"] = base64.RawURLEncoding.EncodeToString(priv)
	}
	writeJSON(out)
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	privateKey := fs.String("private-key", "", "base64url-encoded ed25519 private key")
	privateKeyFile := fs.String("private-key-file", "", "path to file containing base64url-encoded ed25519 private key")
	token := fs.String("token", "", "signed token string")
	tokenFile := fs.String("token-file", "", "path to file containing signed token string")
	exitID := fs.String("exit-id", "", "requested exit id")
	tokenProofNonce := fs.String("proof-nonce", "", "token proof nonce")
	clientInnerPub := fs.String("client-inner-pub", "", "client inner pubkey")
	transport := fs.String("transport", "policy-json", "transport type")
	requestedMTU := fs.Int("requested-mtu", 1280, "requested mtu")
	requestedRegion := fs.String("requested-region", "local", "requested region")
	if err := fs.Parse(args); err != nil {
		exitf("parse flags failed: %v", err)
	}

	tokenValue := strings.TrimSpace(*token)
	if tokenValue != "" {
		exitf("inline --token is not allowed; use --token-file")
	}
	if strings.TrimSpace(*tokenFile) == "" {
		exitf("required flags: --token-file, --exit-id, --proof-nonce, and --private-key-file")
	}
	rawToken, readErr := readTokenMaterialFile(strings.TrimSpace(*tokenFile))
	if readErr != nil {
		exitf("read --token-file failed: %v", readErr)
	}
	tokenValue = strings.TrimSpace(string(rawToken))
	if tokenValue == "" || strings.TrimSpace(*exitID) == "" {
		exitf("required flags: non-empty --token-file value, --exit-id, --proof-nonce, and --private-key-file")
	}
	if strings.TrimSpace(*tokenProofNonce) == "" {
		exitf("required flags: --proof-nonce must be non-empty")
	}
	if strings.TrimSpace(*privateKey) != "" {
		exitf("inline --private-key is not allowed; use --private-key-file")
	}
	if strings.TrimSpace(*privateKeyFile) == "" {
		exitf("required flags: --private-key-file")
	}
	rawPrivateKey, readErr := readPrivateKeyMaterialFile(strings.TrimSpace(*privateKeyFile))
	if readErr != nil {
		exitf("read --private-key-file failed: %v", readErr)
	}
	privateKeyValue := strings.TrimSpace(string(rawPrivateKey))
	priv, err := parsePrivateKey(privateKeyValue)
	if err != nil {
		exitf("invalid private key: %v", err)
	}
	proof, err := crypto.SignPathOpenProof(priv, crypto.PathOpenProofInput{
		Token:           tokenValue,
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

func readPrivateKeyMaterialFile(path string) ([]byte, error) {
	return readSensitiveMaterialFile(path, "private key", true, 8*1024)
}

func readTokenMaterialFile(path string) ([]byte, error) {
	return readSensitiveMaterialFile(path, "token", true, 64*1024)
}

func readSensitiveMaterialFile(path string, label string, ownerOnly bool, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("%s file is required", label)
	}
	linfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s file: %w", label, err)
	}
	if linfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s file %q must not be a symlink", label, path)
	}
	if !linfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%s file %q must be a regular file", label, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s file: %w", label, err)
	}
	defer f.Close()
	finfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open %s file: %w", label, err)
	}
	if !os.SameFile(linfo, finfo) {
		return nil, fmt.Errorf("%s file %q changed during open", label, path)
	}
	if ownerOnly {
		if err := fileperm.ValidateOwnerOnly(path, finfo); err != nil {
			return nil, fmt.Errorf("%s file: %w", label, err)
		}
	}
	if maxBytes > 0 && finfo.Size() > maxBytes {
		return nil, fmt.Errorf("%s file %q exceeds max size %d bytes", label, path, maxBytes)
	}
	reader := io.Reader(f)
	if maxBytes > 0 {
		reader = io.LimitReader(f, maxBytes+1)
	}
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%s file %q exceeds max size %d bytes", label, path, maxBytes)
	}
	return b, nil
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
