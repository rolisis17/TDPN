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
	"os"
	"path/filepath"
	"strings"

	"privacynode/internal/fileperm"
	"privacynode/pkg/adminauth"
)

const (
	maxManifestFileBytes int64 = 2 * 1024 * 1024
	maxKeyFileBytes      int64 = 8 * 1024
)

type keyOutput struct {
	PublicKey  string `json:"public_key"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key,omitempty"`
}

type signOutput struct {
	Alg       string            `json:"alg"`
	KeyID     string            `json:"key_id"`
	Signature string            `json:"signature"`
	Headers   map[string]string `json:"headers"`
}

type verifyOutput struct {
	Status string `json:"status"`
	KeyID  string `json:"key_id,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gen":
		err = runGen(os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Usage:
  go run ./cmd/gpmmanifest gen [--private-key-out FILE] [--public-key-out FILE]
  go run ./cmd/gpmmanifest inspect --private-key-file FILE
  go run ./cmd/gpmmanifest sign --manifest FILE --private-key-file FILE [--key-id ID]
  go run ./cmd/gpmmanifest verify --manifest FILE --public-key-file FILE --signature SIG [--key-id ID]

The signature is Ed25519 over the exact manifest bytes. Serve it in the
X-GPM-Signature-Ed25519 header for the local API manifest verifier.`)
}

func runGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	privateOut := fs.String("private-key-out", "", "path to write private key (base64url, owner-only)")
	publicOut := fs.String("public-key-out", "", "path to write public key (base64url)")
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
	out := keyOutput{PublicKey: pubB64, KeyID: keyID}
	if *showPrivateKey {
		if !allowStdoutPrivateKeys() {
			return errors.New("--show-private-key requires GPM_ALLOW_STDOUT_PRIVATE_KEYS=1")
		}
		out.PrivateKey = privB64
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	privateFile := fs.String("private-key-file", "", "path to private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return json.NewEncoder(os.Stdout).Encode(keyOutput{
		PublicKey: adminauth.EncodePublicKey(pub),
		KeyID:     adminauth.KeyIDFromPublicKey(pub),
	})
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	manifestFile := fs.String("manifest", "", "path to manifest JSON file")
	privateFile := fs.String("private-key-file", "", "path to private key file")
	keyID := fs.String("key-id", "", "explicit key id (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	body, err := readInputFileStrict(*manifestFile, "manifest", maxManifestFileBytes)
	if err != nil {
		return err
	}
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, body))
	kid := strings.TrimSpace(*keyID)
	if kid == "" {
		kid = adminauth.KeyIDFromPublicKey(priv.Public().(ed25519.PublicKey))
	}
	out := signOutput{
		Alg:       "ed25519",
		KeyID:     kid,
		Signature: sig,
		Headers: map[string]string{
			"X-GPM-Signature-Ed25519": sig,
		},
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	manifestFile := fs.String("manifest", "", "path to manifest JSON file")
	publicFile := fs.String("public-key-file", "", "path to public key file")
	signature := fs.String("signature", "", "base64url Ed25519 signature")
	keyID := fs.String("key-id", "", "expected key id (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := readPublicKeyFile(*publicFile)
	if err != nil {
		return err
	}
	body, err := readInputFileStrict(*manifestFile, "manifest", maxManifestFileBytes)
	if err != nil {
		return err
	}
	sigRaw, err := decodeBase64URLFixed(*signature, ed25519.SignatureSize, "signature")
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, sigRaw) {
		return errors.New("manifest signature verification failed")
	}
	actualKeyID := adminauth.KeyIDFromPublicKey(pub)
	if expected := strings.TrimSpace(*keyID); expected != "" && expected != actualKeyID {
		return fmt.Errorf("manifest key id mismatch: got %q, expected %q", actualKeyID, expected)
	}
	return json.NewEncoder(os.Stdout).Encode(verifyOutput{Status: "ok", KeyID: actualKeyID})
}

func allowStdoutPrivateKeys() bool {
	for _, name := range []string{"GPM_ALLOW_STDOUT_PRIVATE_KEYS", "GPM_TEST_ALLOW_STDOUT_PRIVATE_KEYS", "TDPN_ALLOW_STDOUT_PRIVATE_KEYS"} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func readPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--private-key-file is required")
	}
	b, err := readSecretFileStrict(path, "private key")
	if err != nil {
		return nil, err
	}
	raw, err := decodeBase64URLFixed(string(b), ed25519.PrivateKeySize, "private key")
	if err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(raw), nil
}

func readPublicKeyFile(path string) (ed25519.PublicKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("--public-key-file is required")
	}
	b, err := readInputFileStrict(path, "public key", maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	raw, err := decodeBase64URLFixed(string(b), ed25519.PublicKeySize, "public key")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func decodeBase64URLFixed(raw string, expectedLen int, label string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("%s is required", label)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("%s must be base64url: %w", label, err)
	}
	if len(decoded) != expectedLen {
		return nil, fmt.Errorf("%s length %d, want %d", label, len(decoded), expectedLen)
	}
	return decoded, nil
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
	if finfo.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("%s file %q exceeds max size %d bytes", label, path, maxKeyFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	if int64(len(b)) > maxKeyFileBytes {
		return nil, fmt.Errorf("%s file %q exceeds max size %d bytes", label, path, maxKeyFileBytes)
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

func writeFileWithMode(path string, body []byte, mode os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("write path is required")
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
	ownerOnly := mode.Perm()&0o077 == 0
	if ownerOnly {
		if err := fileperm.RestrictOwnerOnly(tmpPath); err != nil {
			_ = tmpFile.Close()
			return err
		}
	}
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
	if ownerOnly {
		if err := fileperm.RestrictOwnerOnly(path); err != nil {
			return err
		}
	}
	return nil
}
