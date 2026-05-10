package main

import (
	"context"
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
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"privacynode/internal/fileperm"
	"privacynode/pkg/accesspack"
	"privacynode/pkg/adminauth"
)

const (
	maxPackFileBytes  int64 = 2 * 1024 * 1024
	maxKeyFileBytes   int64 = 8 * 1024
	maxTrustFileBytes int64 = 512 * 1024
)

type keyOutput struct {
	PublicKey  string `json:"public_key"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key,omitempty"`
}

type verifyOutput struct {
	Status             string                  `json:"status"`
	KeyID              string                  `json:"key_id"`
	Trusted            bool                    `json:"trusted"`
	TrustedOrgID       string                  `json:"trusted_org_id,omitempty"`
	TrustedOrgName     string                  `json:"trusted_org_name,omitempty"`
	PackID             string                  `json:"pack_id"`
	OrganizationID     string                  `json:"organization_id"`
	OrganizationName   string                  `json:"organization_name"`
	ExpiresAtUTC       string                  `json:"expires_at_utc"`
	CanonicalBodySize  int                     `json:"canonical_body_size"`
	SourcesCount       int                     `json:"sources_count"`
	AccessPathsCount   int                     `json:"access_paths_count"`
	TrustedAccessPaths []accesspack.AccessPath `json:"trusted_access_paths,omitempty"`
}

type bridgeVerifyOutput struct {
	Status             string                  `json:"status"`
	KeyID              string                  `json:"key_id"`
	Trusted            bool                    `json:"trusted"`
	TrustedOrgID       string                  `json:"trusted_org_id,omitempty"`
	TrustedOrgName     string                  `json:"trusted_org_name,omitempty"`
	InviteID           string                  `json:"invite_id"`
	OrganizationID     string                  `json:"organization_id"`
	OrganizationName   string                  `json:"organization_name"`
	HelperID           string                  `json:"helper_id"`
	HelperName         string                  `json:"helper_name"`
	ExpiresAtUTC       string                  `json:"expires_at_utc"`
	CanonicalBodySize  int                     `json:"canonical_body_size"`
	AccessPathsCount   int                     `json:"access_paths_count"`
	TrustedAccessPaths []accesspack.AccessPath `json:"trusted_access_paths,omitempty"`
}

type trustAddOutput struct {
	Status     string `json:"status"`
	TrustStore string `json:"trust_store"`
	OrgID      string `json:"org_id"`
	OrgName    string `json:"org_name"`
	KeyID      string `json:"key_id"`
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
	case "inspect-key":
		err = runInspectKey(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "bridge-sign":
		err = runBridgeSign(os.Args[2:])
	case "bridge-verify":
		err = runBridgeVerify(os.Args[2:])
	case "trust-add":
		err = runTrustAdd(os.Args[2:])
	case "trust-list":
		err = runTrustList(os.Args[2:])
	case "trust-remove":
		err = runTrustRemove(os.Args[2:])
	case "text-export":
		err = runTextExport(os.Args[2:])
	case "text-import":
		err = runTextImport(os.Args[2:])
	case "qr-png":
		err = runQRPNG(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "check":
		err = runCheck(os.Args[2:])
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
  go run ./cmd/gpmrecover gen [--private-key-out FILE] [--public-key-out FILE]
  go run ./cmd/gpmrecover inspect-key --private-key-file FILE
  go run ./cmd/gpmrecover sign --pack FILE --private-key-file FILE --out FILE [--key-id ID]
  go run ./cmd/gpmrecover bridge-sign --invite FILE --private-key-file FILE --out FILE [--key-id ID]
  go run ./cmd/gpmrecover bridge-verify --invite FILE (--trust-store FILE | --public-key-file FILE) [--show-paths 1]
  go run ./cmd/gpmrecover trust-add --trust-store FILE --org-id ID --org-name NAME --public-key-file FILE
  go run ./cmd/gpmrecover trust-list --trust-store FILE
  go run ./cmd/gpmrecover trust-remove --trust-store FILE --org-id ID --key-id ID
  go run ./cmd/gpmrecover text-export --kind access-pack|bridge-invite|trust-store|trusted-key --in FILE [--out FILE]
  go run ./cmd/gpmrecover text-import --text TEXT --out FILE [--expect-kind KIND]
  go run ./cmd/gpmrecover qr-png --text TEXT --out FILE [--size 768]
  go run ./cmd/gpmrecover verify --pack FILE (--trust-store FILE | --public-key-file FILE) [--show-paths 1]
  go run ./cmd/gpmrecover check --pack FILE (--trust-store FILE | --public-key-file FILE) [--timeout-sec 8]

This verifies signed access recovery packs. It does not tunnel traffic.`)
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

func runInspectKey(args []string) error {
	fs := flag.NewFlagSet("inspect-key", flag.ContinueOnError)
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
	packFile := fs.String("pack", "", "path to unsigned access pack JSON")
	privateFile := fs.String("private-key-file", "", "path to private key file")
	outFile := fs.String("out", "", "path to write signed access pack JSON")
	keyID := fs.String("key-id", "", "explicit key id (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outFile) == "" {
		return errors.New("sign requires --out")
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	body, err := readInputFileStrict(*packFile, "access pack", maxPackFileBytes)
	if err != nil {
		return err
	}
	pack, err := accesspack.Parse(body)
	if err != nil {
		return err
	}
	signed, err := accesspack.Sign(pack, priv, *keyID)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileWithMode(*outFile, append(out, '\n'), 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"status": "ok",
		"out":    strings.TrimSpace(*outFile),
		"key_id": signed.Signature.KeyID,
	})
}

func runBridgeSign(args []string) error {
	fs := flag.NewFlagSet("bridge-sign", flag.ContinueOnError)
	inviteFile := fs.String("invite", "", "path to unsigned bridge invite JSON")
	privateFile := fs.String("private-key-file", "", "path to private key file")
	outFile := fs.String("out", "", "path to write signed bridge invite JSON")
	keyID := fs.String("key-id", "", "explicit key id (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outFile) == "" {
		return errors.New("bridge-sign requires --out")
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	body, err := readInputFileStrict(*inviteFile, "bridge invite", maxPackFileBytes)
	if err != nil {
		return err
	}
	invite, err := accesspack.ParseBridgeInvite(body)
	if err != nil {
		return err
	}
	signed, err := accesspack.SignBridgeInvite(invite, priv, *keyID)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileWithMode(*outFile, append(out, '\n'), 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"status":    "ok",
		"out":       strings.TrimSpace(*outFile),
		"invite_id": signed.InviteID,
		"key_id":    signed.Signature.KeyID,
	})
}

func runTrustAdd(args []string) error {
	fs := flag.NewFlagSet("trust-add", flag.ContinueOnError)
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	orgID := fs.String("org-id", "", "trusted organization id")
	orgName := fs.String("org-name", "", "trusted organization display name")
	publicFile := fs.String("public-key-file", "", "path to public key file")
	expiresAt := fs.String("expires-at-utc", "", "optional trusted-key expiry in RFC3339 UTC")
	source := fs.String("source", "", "optional note about where this key came from")
	notes := fs.String("notes", "", "optional operator notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := readPublicKeyFile(*publicFile)
	if err != nil {
		return err
	}
	store, err := loadTrustStoreFile(*trustStoreFile)
	if err != nil {
		return err
	}
	entry := accesspack.TrustedKey{
		OrgID:        *orgID,
		OrgName:      *orgName,
		PublicKey:    adminauth.EncodePublicKey(pub),
		ExpiresAtUTC: *expiresAt,
		Source:       *source,
	}
	if strings.TrimSpace(*notes) != "" {
		entry.Notes = []string{*notes}
	}
	store, entry, err = accesspack.AddTrustedKey(store, entry, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := writeTrustStoreFile(*trustStoreFile, store); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(trustAddOutput{
		Status:     "ok",
		TrustStore: strings.TrimSpace(*trustStoreFile),
		OrgID:      entry.OrgID,
		OrgName:    entry.OrgName,
		KeyID:      entry.KeyID,
	})
}

func runTrustList(args []string) error {
	fs := flag.NewFlagSet("trust-list", flag.ContinueOnError)
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := loadTrustStoreFile(*trustStoreFile)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(store)
}

func runTrustRemove(args []string) error {
	fs := flag.NewFlagSet("trust-remove", flag.ContinueOnError)
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	orgID := fs.String("org-id", "", "trusted organization id")
	keyID := fs.String("key-id", "", "trusted key id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*orgID) == "" {
		return errors.New("--org-id is required")
	}
	if strings.TrimSpace(*keyID) == "" {
		return errors.New("--key-id is required")
	}
	store, err := loadTrustStoreFile(*trustStoreFile)
	if err != nil {
		return err
	}
	store, removed := accesspack.RemoveTrustedKey(store, *orgID, *keyID)
	if !removed {
		return fmt.Errorf("trusted key not found for org_id=%q key_id=%q", strings.TrimSpace(*orgID), strings.TrimSpace(*keyID))
	}
	if err := writeTrustStoreFile(*trustStoreFile, store); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{
		"status":      "ok",
		"trust_store": strings.TrimSpace(*trustStoreFile),
		"org_id":      strings.TrimSpace(*orgID),
		"key_id":      strings.TrimSpace(*keyID),
	})
}

func runTextExport(args []string) error {
	fs := flag.NewFlagSet("text-export", flag.ContinueOnError)
	kind := fs.String("kind", "", "envelope kind: access-pack, trust-store, or trusted-key")
	inFile := fs.String("in", "", "path to JSON payload file")
	outFile := fs.String("out", "", "optional path to write text envelope")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*inFile, "envelope input", maxPackFileBytes)
	if err != nil {
		return err
	}
	text, err := accesspack.EncodeTextEnvelope(*kind, body)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outFile) != "" {
		if err := writeFileWithMode(*outFile, []byte(text+"\n"), 0o644); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "ok",
		"kind":   strings.TrimSpace(*kind),
		"text":   text,
		"out":    strings.TrimSpace(*outFile),
	})
}

func runTextImport(args []string) error {
	fs := flag.NewFlagSet("text-import", flag.ContinueOnError)
	text := fs.String("text", "", "GPMREC1 text envelope")
	textFile := fs.String("text-file", "", "path to file containing GPMREC1 text envelope")
	expectKind := fs.String("expect-kind", "", "optional expected kind")
	outFile := fs.String("out", "", "path to write decoded JSON payload")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rawText := strings.TrimSpace(*text)
	if rawText == "" || strings.TrimSpace(*textFile) != "" {
		var err error
		rawText, err = readTextEnvelopeInput(*text, *textFile)
		if err != nil {
			return err
		}
	}
	envelope, payload, err := accesspack.DecodeTextEnvelope(rawText)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*expectKind) != "" && strings.TrimSpace(*expectKind) != envelope.Kind {
		return fmt.Errorf("envelope kind %q does not match expected %q", envelope.Kind, strings.TrimSpace(*expectKind))
	}
	if strings.TrimSpace(*outFile) != "" {
		if err := writeFileWithMode(*outFile, append(payload, '\n'), 0o644); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "ok",
		"kind":   envelope.Kind,
		"out":    strings.TrimSpace(*outFile),
		"bytes":  len(payload),
	})
}

func runQRPNG(args []string) error {
	fs := flag.NewFlagSet("qr-png", flag.ContinueOnError)
	text := fs.String("text", "", "GPMREC1 text envelope")
	textFile := fs.String("text-file", "", "path to file containing GPMREC1 text envelope")
	outFile := fs.String("out", "", "path to write QR PNG")
	size := fs.Int("size", 768, "QR image size in pixels")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rawText, err := readTextEnvelopeInput(*text, *textFile)
	if err != nil {
		return err
	}
	envelope, _, err := accesspack.DecodeTextEnvelope(rawText)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outFile) == "" {
		return errors.New("qr-png requires --out")
	}
	qrSize := *size
	if qrSize < 128 {
		qrSize = 128
	}
	if qrSize > 4096 {
		qrSize = 4096
	}
	body, err := qrcode.Encode(rawText, qrcode.Medium, qrSize)
	if err != nil {
		return fmt.Errorf("encode qr png: %w", err)
	}
	if err := writeFileWithMode(*outFile, body, 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "ok",
		"kind":   envelope.Kind,
		"out":    strings.TrimSpace(*outFile),
		"size":   qrSize,
		"bytes":  len(body),
	})
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	packFile := fs.String("pack", "", "path to signed access pack JSON")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	showPaths := fs.Bool("show-paths", false, "include trusted paths in JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*packFile, "access pack", maxPackFileBytes)
	if err != nil {
		return err
	}
	pack, err := accesspack.Parse(body)
	if err != nil {
		return err
	}
	pub, trustedKey, err := resolveVerificationKey(pack, *publicFile, *trustStoreFile)
	if err != nil {
		return err
	}
	verified, err := accesspack.Verify(pack, pub, time.Now().UTC())
	if err != nil {
		return err
	}
	out := verifyOutput{
		Status:            "ok",
		KeyID:             verified.KeyID,
		Trusted:           trustedKey != nil,
		PackID:            verified.Pack.PackID,
		OrganizationID:    verified.Pack.Organization.OrgID,
		OrganizationName:  verified.Pack.Organization.Name,
		ExpiresAtUTC:      verified.ExpiresAt.Format(time.RFC3339),
		CanonicalBodySize: verified.CanonicalBodySize,
		SourcesCount:      len(verified.Pack.Sources),
		AccessPathsCount:  len(verified.Pack.AccessPaths),
	}
	if trustedKey != nil {
		out.TrustedOrgID = trustedKey.OrgID
		out.TrustedOrgName = trustedKey.OrgName
	}
	if *showPaths {
		out.TrustedAccessPaths = verified.Pack.AccessPaths
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runBridgeVerify(args []string) error {
	fs := flag.NewFlagSet("bridge-verify", flag.ContinueOnError)
	inviteFile := fs.String("invite", "", "path to signed bridge invite JSON")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	showPaths := fs.Bool("show-paths", false, "include trusted paths in JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*inviteFile, "bridge invite", maxPackFileBytes)
	if err != nil {
		return err
	}
	invite, err := accesspack.ParseBridgeInvite(body)
	if err != nil {
		return err
	}
	pub, trustedKey, err := resolveBridgeVerificationKey(invite, *publicFile, *trustStoreFile)
	if err != nil {
		return err
	}
	verified, err := accesspack.VerifyBridgeInvite(invite, pub, time.Now().UTC())
	if err != nil {
		return err
	}
	out := bridgeVerifyOutput{
		Status:            "ok",
		KeyID:             verified.KeyID,
		Trusted:           trustedKey != nil,
		InviteID:          verified.Invite.InviteID,
		OrganizationID:    verified.Invite.Organization.OrgID,
		OrganizationName:  verified.Invite.Organization.Name,
		HelperID:          verified.Invite.Helper.HelperID,
		HelperName:        verified.Invite.Helper.DisplayName,
		ExpiresAtUTC:      verified.ExpiresAt.Format(time.RFC3339),
		CanonicalBodySize: verified.CanonicalBodySize,
		AccessPathsCount:  len(verified.Invite.AccessPaths),
	}
	if trustedKey != nil {
		out.TrustedOrgID = trustedKey.OrgID
		out.TrustedOrgName = trustedKey.OrgName
	}
	if *showPaths {
		out.TrustedAccessPaths = verified.Invite.AccessPaths
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	packFile := fs.String("pack", "", "path to signed access pack JSON")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	timeoutSec := fs.Int("timeout-sec", 8, "per-request timeout in seconds")
	probeExternal := fs.Bool("probe-external", false, "probe paths marked requires_external_app")
	allowOnionProbe := fs.Bool("allow-onion-http-probe", false, "allow direct HTTP probing of .onion hosts")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*packFile, "access pack", maxPackFileBytes)
	if err != nil {
		return err
	}
	pack, err := accesspack.Parse(body)
	if err != nil {
		return err
	}
	pub, _, err := resolveVerificationKey(pack, *publicFile, *trustStoreFile)
	if err != nil {
		return err
	}
	verified, err := accesspack.Verify(pack, pub, time.Now().UTC())
	if err != nil {
		return err
	}
	timeout := time.Duration(*timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(verified.Pack.Sources)+len(verified.Pack.AccessPaths)+1))
	defer cancel()
	report := accesspack.CheckReachability(ctx, verified, accesspack.ReachabilityOptions{
		Timeout:         timeout,
		ProbeExternal:   *probeExternal,
		AllowOnionProbe: *allowOnionProbe,
	})
	return json.NewEncoder(os.Stdout).Encode(report)
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

func resolveVerificationKey(pack accesspack.Pack, publicFile string, trustStoreFile string) (ed25519.PublicKey, *accesspack.TrustedKey, error) {
	publicFile = strings.TrimSpace(publicFile)
	trustStoreFile = strings.TrimSpace(trustStoreFile)
	if trustStoreFile != "" {
		store, err := loadTrustStoreFile(trustStoreFile)
		if err != nil {
			return nil, nil, err
		}
		pub, entry, err := accesspack.ResolveTrustedPublicKey(store, pack, time.Now().UTC())
		if err != nil {
			return nil, nil, err
		}
		return pub, &entry, nil
	}
	if publicFile != "" {
		pub, err := readPublicKeyFile(publicFile)
		return pub, nil, err
	}
	return nil, nil, errors.New("verification requires --trust-store or --public-key-file")
}

func resolveBridgeVerificationKey(invite accesspack.BridgeInvite, publicFile string, trustStoreFile string) (ed25519.PublicKey, *accesspack.TrustedKey, error) {
	publicFile = strings.TrimSpace(publicFile)
	trustStoreFile = strings.TrimSpace(trustStoreFile)
	if trustStoreFile != "" {
		store, err := loadTrustStoreFile(trustStoreFile)
		if err != nil {
			return nil, nil, err
		}
		pub, entry, err := accesspack.ResolveTrustedBridgeInvitePublicKey(store, invite, time.Now().UTC())
		if err != nil {
			return nil, nil, err
		}
		return pub, &entry, nil
	}
	if publicFile != "" {
		pub, err := readPublicKeyFile(publicFile)
		return pub, nil, err
	}
	return nil, nil, errors.New("bridge verification requires --trust-store or --public-key-file")
}

func readTextEnvelopeInput(text string, textFile string) (string, error) {
	rawText := strings.TrimSpace(text)
	if rawText == "" && strings.TrimSpace(textFile) != "" {
		body, err := readInputFileStrict(textFile, "text envelope", maxPackFileBytes)
		if err != nil {
			return "", err
		}
		rawText = strings.TrimSpace(string(body))
	}
	if rawText == "" {
		return "", errors.New("text envelope requires --text or --text-file")
	}
	return rawText, nil
}

func loadTrustStoreFile(path string) (accesspack.TrustStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return accesspack.TrustStore{}, errors.New("--trust-store is required")
	}
	body, err := readInputFileStrict(path, "trust store", maxTrustFileBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "cannot find the file") {
			return accesspack.EmptyTrustStore(), nil
		}
		return accesspack.TrustStore{}, err
	}
	return accesspack.ParseTrustStore(body)
}

func writeTrustStoreFile(path string, store accesspack.TrustStore) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("--trust-store is required")
	}
	body, err := accesspack.MarshalTrustStore(store)
	if err != nil {
		return err
	}
	return writeFileWithMode(path, body, 0o644)
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
