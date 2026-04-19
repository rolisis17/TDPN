package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privacynode/internal/fileperm"
	"privacynode/pkg/adminauth"
)

type signOutput struct {
	KeyID     string            `json:"key_id"`
	Timestamp int64             `json:"timestamp"`
	Nonce     string            `json:"nonce"`
	Signature string            `json:"signature"`
	Headers   map[string]string `json:"headers"`
}

const maxPrivateKeyFileBytes int64 = 8 * 1024

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
	showPrivateKey := fs.Bool("show-private-key", false, "include private key in stdout output (dangerous)")
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
		"public_key": pubB64,
		"key_id":     keyID,
	}
	if *showPrivateKey {
		out["private_key"] = privB64
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
		b, readErr := readInputFileStrict(*bodyFile, "body", 2*1024*1024)
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
		n, err = randomNonce(16)
		if err != nil {
			return fmt.Errorf("generate nonce: %w", err)
		}
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
	b, err := readSecretFileStrict(path, "private key")
	if err != nil {
		return nil, err
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

func readSecretFileStrict(path string, label string) ([]byte, error) {
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
	if err := fileperm.ValidateOwnerOnly(path, finfo); err != nil {
		return nil, fmt.Errorf("%s file: %w", label, err)
	}
	if finfo.Size() > maxPrivateKeyFileBytes {
		return nil, fmt.Errorf("%s file %q exceeds max size %d bytes", label, path, maxPrivateKeyFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPrivateKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	if int64(len(b)) > maxPrivateKeyFileBytes {
		return nil, fmt.Errorf("%s file %q exceeds max size %d bytes", label, path, maxPrivateKeyFileBytes)
	}
	return b, nil
}

func readInputFileStrict(path string, label string, maxBytes int64) ([]byte, error) {
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

func randomNonce(n int) (string, error) {
	if n <= 0 {
		n = 16
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeFileWithMode(path string, body []byte, mode os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("write path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir for %s: %w", path, err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write symlink path %s", path)
		}
		if info.IsDir() {
			return fmt.Errorf("write path %s is a directory", path)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("lstat %s: %w", path, err)
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", path, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmpFile.Write(body); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp for %s: %w", path, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp for %s: %w", path, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp for %s: %w", path, err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp for %s: %w", path, err)
	}
	return nil
}
