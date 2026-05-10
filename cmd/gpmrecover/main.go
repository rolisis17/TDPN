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
	maxPackFileBytes           int64 = 2 * 1024 * 1024
	maxKeyFileBytes            int64 = 8 * 1024
	maxTrustFileBytes          int64 = 512 * 1024
	maxBridgeRegistryFileBytes int64 = 512 * 1024
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

type bridgePolicyOutput struct {
	Status   string                              `json:"status"`
	Verified bool                                `json:"verified"`
	Trusted  bool                                `json:"trusted"`
	KeyID    string                              `json:"key_id"`
	Policy   accesspack.BridgeInvitePolicyReport `json:"policy"`
}

type bridgeRegistrySetStatusOutput struct {
	Status       string                                            `json:"status"`
	RegistryFile string                                            `json:"registry_file"`
	OutputFile   string                                            `json:"output_file"`
	Update       accesspack.BridgeHelperRegistryStatusUpdateReport `json:"update"`
}

type bridgeRegistryUpsertHelperOutput struct {
	Status       string                                      `json:"status"`
	RegistryFile string                                      `json:"registry_file"`
	OutputFile   string                                      `json:"output_file"`
	Upsert       accesspack.BridgeHelperRegistryUpsertReport `json:"upsert"`
}

type bridgeRegistryVerifyOutput struct {
	Status            string                           `json:"status"`
	KeyID             string                           `json:"key_id"`
	Trusted           bool                             `json:"trusted"`
	TrustedOrgID      string                           `json:"trusted_org_id,omitempty"`
	TrustedOrgName    string                           `json:"trusted_org_name,omitempty"`
	RegistryID        string                           `json:"registry_id"`
	OrganizationID    string                           `json:"organization_id"`
	OrganizationName  string                           `json:"organization_name"`
	ExpiresAtUTC      string                           `json:"expires_at_utc"`
	CanonicalBodySize int                              `json:"canonical_body_size"`
	HelpersCount      int                              `json:"helpers_count"`
	Registry          *accesspack.BridgeHelperRegistry `json:"registry,omitempty"`
	OutputRegistry    string                           `json:"output_registry,omitempty"`
}

type trustAddOutput struct {
	Status     string `json:"status"`
	TrustStore string `json:"trust_store"`
	OrgID      string `json:"org_id"`
	OrgName    string `json:"org_name"`
	KeyID      string `json:"key_id"`
}

type demoBundleOutput struct {
	Status         string                              `json:"status"`
	GeneratedAtUTC string                              `json:"generated_at_utc"`
	OutDir         string                              `json:"out_dir"`
	OrgID          string                              `json:"org_id"`
	OrgName        string                              `json:"org_name"`
	KeyID          string                              `json:"key_id"`
	Files          map[string]string                   `json:"files"`
	BridgePolicy   accesspack.BridgeInvitePolicyReport `json:"bridge_policy"`
	NextSteps      []string                            `json:"next_steps"`
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
	case "bridge-policy":
		err = runBridgePolicy(os.Args[2:])
	case "bridge-registry-sign":
		err = runBridgeRegistrySign(os.Args[2:])
	case "bridge-registry-verify":
		err = runBridgeRegistryVerify(os.Args[2:])
	case "bridge-registry-check":
		err = runBridgeRegistryCheck(os.Args[2:])
	case "bridge-registry-upsert-helper":
		err = runBridgeRegistryUpsertHelper(os.Args[2:])
	case "bridge-registry-set-status":
		err = runBridgeRegistrySetStatus(os.Args[2:])
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
	case "demo-bundle":
		err = runDemoBundle(os.Args[2:])
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
  go run ./cmd/gpmrecover bridge-policy --invite FILE (--trust-store FILE | --public-key-file FILE) [--helper-registry FILE | --signed-helper-registry FILE] [--require-helper-registry 1]
  go run ./cmd/gpmrecover bridge-registry-sign --helper-registry FILE --org-id ID --org-name NAME --private-key-file FILE --out FILE [--registry-id ID] [--lifetime-hours HOURS]
  go run ./cmd/gpmrecover bridge-registry-verify --signed-registry FILE (--trust-store FILE | --public-key-file FILE) [--out-registry FILE] [--show-registry 1]
  go run ./cmd/gpmrecover bridge-registry-check --helper-registry FILE [--helper-id ID] [--org-id ID] [--require-active 1]
  go run ./cmd/gpmrecover bridge-registry-upsert-helper --helper-registry FILE --helper-id ID --org-ids ORG[,ORG...] [--display-name NAME] [--contact-url URL] [--status active|quarantined|disabled] [--reason TEXT] [--out FILE]
  go run ./cmd/gpmrecover bridge-registry-set-status --helper-registry FILE --helper-id ID --status active|quarantined|disabled [--reason TEXT] [--out FILE]
  go run ./cmd/gpmrecover trust-add --trust-store FILE --org-id ID --org-name NAME --public-key-file FILE
  go run ./cmd/gpmrecover trust-list --trust-store FILE
  go run ./cmd/gpmrecover trust-remove --trust-store FILE --org-id ID --key-id ID
  go run ./cmd/gpmrecover text-export --kind access-pack|bridge-invite|trust-store|trusted-key|bridge-helper-registry|bridge-helper-registry-signed --in FILE [--out FILE]
  go run ./cmd/gpmrecover text-import (--text TEXT | --text-file FILE) --out FILE [--expect-kind KIND]
  go run ./cmd/gpmrecover qr-png --text TEXT --out FILE [--size 768]
  go run ./cmd/gpmrecover verify --pack FILE (--trust-store FILE | --public-key-file FILE) [--show-paths 1]
  go run ./cmd/gpmrecover check --pack FILE (--trust-store FILE | --public-key-file FILE) [--timeout-sec 8]
  go run ./cmd/gpmrecover demo-bundle [--out-dir DIR] [--org-id ID] [--org-name NAME] [--base-url URL]

This verifies signed access recovery artifacts. It does not tunnel traffic.`)
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
	kind := fs.String("kind", "", "envelope kind: access-pack, bridge-invite, trust-store, trusted-key, bridge-helper-registry, or bridge-helper-registry-signed")
	inFile := fs.String("in", "", "path to JSON payload file")
	outFile := fs.String("out", "", "optional path to write text envelope")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*inFile, "envelope input", maxPackFileBytes)
	if err != nil {
		return err
	}
	if err := validateTextEnvelopePayload(*kind, body); err != nil {
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
	if err := validateTextEnvelopePayload(envelope.Kind, payload); err != nil {
		return err
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

func validateTextEnvelopePayload(kind string, body []byte) error {
	kind = strings.TrimSpace(kind)
	now := time.Now().UTC()
	switch kind {
	case accesspack.EnvelopeKindPack:
		pack, err := accesspack.Parse(body)
		if err != nil {
			return err
		}
		if pack.Signature == nil {
			return errors.New("access-pack envelope payload must include a signature")
		}
		if err := validateEnvelopeSignature(pack.Signature, "access-pack"); err != nil {
			return err
		}
		pack.Signature = nil
		return accesspack.Validate(pack, now)
	case accesspack.EnvelopeKindBridge:
		invite, err := accesspack.ParseBridgeInvite(body)
		if err != nil {
			return err
		}
		if invite.Signature == nil {
			return errors.New("bridge-invite envelope payload must include a signature")
		}
		if err := validateEnvelopeSignature(invite.Signature, "bridge-invite"); err != nil {
			return err
		}
		invite.Signature = nil
		return accesspack.ValidateBridgeInvite(invite, now)
	case accesspack.EnvelopeKindStore:
		_, err := accesspack.ParseTrustStore(body)
		return err
	case accesspack.EnvelopeKindKey:
		var entry accesspack.TrustedKey
		if err := json.Unmarshal(body, &entry); err != nil {
			return fmt.Errorf("invalid trusted-key json: %w", err)
		}
		if entry.Disabled {
			return errors.New("trusted-key envelope payload must not be disabled")
		}
		_, _, err := accesspack.AddTrustedKey(accesspack.EmptyTrustStore(), entry, time.Now().UTC())
		return err
	case accesspack.EnvelopeKindBridgeHelperRegistry:
		_, err := accesspack.ParseBridgeHelperRegistry(body)
		return err
	case accesspack.EnvelopeKindBridgeHelperRegistrySigned:
		artifact, err := accesspack.ParseBridgeHelperRegistryArtifact(body)
		if err != nil {
			return err
		}
		if artifact.Signature == nil {
			return errors.New("bridge-helper-registry-signed envelope payload must include a signature")
		}
		if err := validateEnvelopeSignature(artifact.Signature, "bridge-helper-registry-signed"); err != nil {
			return err
		}
		artifact.Signature = nil
		return accesspack.ValidateBridgeHelperRegistryArtifact(artifact, now)
	default:
		return accesspack.ValidateEnvelopeKind(kind)
	}
}

func validateEnvelopeSignature(signature *accesspack.Signature, label string) error {
	if signature == nil {
		return fmt.Errorf("%s envelope payload must include a signature", label)
	}
	if strings.TrimSpace(signature.Alg) != "ed25519" {
		return fmt.Errorf("%s envelope signature algorithm must be ed25519", label)
	}
	if strings.TrimSpace(signature.KeyID) == "" {
		return fmt.Errorf("%s envelope signature key id is required", label)
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature.Sig))
	if err != nil {
		return fmt.Errorf("%s envelope signature must be base64url: %w", label, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%s envelope signature has invalid size %d", label, len(sig))
	}
	return nil
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
	envelope, payload, err := accesspack.DecodeTextEnvelope(rawText)
	if err != nil {
		return err
	}
	if err := validateTextEnvelopePayload(envelope.Kind, payload); err != nil {
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

func runBridgePolicy(args []string) error {
	fs := flag.NewFlagSet("bridge-policy", flag.ContinueOnError)
	inviteFile := fs.String("invite", "", "path to signed bridge invite JSON")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	helperRegistryFile := fs.String("helper-registry", "", "optional bridge helper registry JSON for active/quarantine policy")
	signedHelperRegistryFile := fs.String("signed-helper-registry", "", "optional signed bridge helper registry artifact JSON for active/quarantine policy")
	requireHelperRegistry := fs.Bool("require-helper-registry", false, "fail if no bridge helper registry is provided")
	minPaths := fs.Int("min-paths", 2, "minimum helper access paths")
	minHosts := fs.Int("min-distinct-hosts", 2, "minimum distinct helper/contact hosts")
	maxLifetimeHours := fs.Int("max-lifetime-hours", int(accesspack.MaxBridgeInviteLifetime/time.Hour), "maximum invite lifetime in hours")
	requireContact := fs.Bool("require-contact", true, "require helper contact URL")
	requireManualFallback := fs.Bool("require-manual-fallback", true, "require manual/external-app fallback path")
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
	var helperRegistry *accesspack.BridgeHelperRegistry
	if strings.TrimSpace(*helperRegistryFile) != "" {
		registry, err := loadBridgeHelperRegistryFile(*helperRegistryFile)
		if err != nil {
			return err
		}
		helperRegistry = &registry
	}
	if strings.TrimSpace(*signedHelperRegistryFile) != "" {
		if helperRegistry != nil {
			return errors.New("use either --helper-registry or --signed-helper-registry, not both")
		}
		verifiedRegistry, err := verifyBridgeHelperRegistryArtifactFile(*signedHelperRegistryFile, verified.Invite.Organization.OrgID, *publicFile, *trustStoreFile)
		if err != nil {
			return err
		}
		registry := verifiedRegistry.Artifact.Registry
		helperRegistry = &registry
	}
	maxLifetime := time.Duration(*maxLifetimeHours) * time.Hour
	report := accesspack.CheckBridgeInvitePolicy(verified.Invite, accesspack.BridgeInvitePolicyOptions{
		MinAccessPaths:        *minPaths,
		MinDistinctHosts:      *minHosts,
		MaxLifetime:           maxLifetime,
		RequireHelperContact:  *requireContact,
		RequireManualFallback: *requireManualFallback,
		RequireHelperRegistry: *requireHelperRegistry,
		HelperRegistry:        helperRegistry,
	}, time.Now().UTC())
	out := bridgePolicyOutput{
		Status:   report.Status,
		Verified: true,
		Trusted:  trustedKey != nil,
		KeyID:    verified.KeyID,
		Policy:   report,
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if report.Status != "pass" {
		return errors.New("bridge invite policy failed")
	}
	return nil
}

func runBridgeRegistrySign(args []string) error {
	fs := flag.NewFlagSet("bridge-registry-sign", flag.ContinueOnError)
	helperRegistryFile := fs.String("helper-registry", "", "path to unsigned bridge helper registry JSON")
	privateFile := fs.String("private-key-file", "", "path to private key file")
	outFile := fs.String("out", "", "path to write signed bridge helper registry artifact JSON")
	registryID := fs.String("registry-id", "", "optional registry id; defaults to bridge-registry-YYYYMMDD-HHMMSS")
	orgID := fs.String("org-id", "", "organization id")
	orgName := fs.String("org-name", "", "organization name")
	orgHomeURL := fs.String("org-home-url", "", "optional organization home URL")
	lifetimeHours := fs.Int("lifetime-hours", 7*24, "signed registry lifetime in hours")
	keyID := fs.String("key-id", "", "explicit key id (optional)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outFile) == "" {
		return errors.New("bridge-registry-sign requires --out")
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	registry, err := loadBridgeHelperRegistryFile(*helperRegistryFile)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	id := strings.TrimSpace(*registryID)
	if id == "" {
		id = "bridge-registry-" + now.Format("20060102-150405")
	}
	lifetime := time.Duration(*lifetimeHours) * time.Hour
	artifact := accesspack.BridgeHelperRegistryArtifact{
		SchemaVersion: accesspack.BridgeHelperRegistryArtifactSchemaVersion,
		RegistryID:    id,
		Organization: accesspack.Organization{
			OrgID:   strings.TrimSpace(*orgID),
			Name:    strings.TrimSpace(*orgName),
			HomeURL: strings.TrimSpace(*orgHomeURL),
		},
		IssuedAtUTC:  now.Format(time.RFC3339),
		ExpiresAtUTC: now.Add(lifetime).Format(time.RFC3339),
		Registry:     registry,
	}
	signed, err := accesspack.SignBridgeHelperRegistryArtifact(artifact, priv, *keyID)
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
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":      "ok",
		"out":         strings.TrimSpace(*outFile),
		"registry_id": signed.RegistryID,
		"key_id":      signed.Signature.KeyID,
		"expires_at":  signed.ExpiresAtUTC,
	})
}

func runBridgeRegistryVerify(args []string) error {
	fs := flag.NewFlagSet("bridge-registry-verify", flag.ContinueOnError)
	signedRegistryFile := fs.String("signed-registry", "", "path to signed bridge helper registry artifact JSON")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	outRegistryFile := fs.String("out-registry", "", "optional path to write verified raw helper registry JSON")
	showRegistry := fs.Bool("show-registry", false, "include verified raw helper registry in JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*signedRegistryFile, "signed bridge helper registry", maxBridgeRegistryFileBytes)
	if err != nil {
		return err
	}
	artifact, err := accesspack.ParseBridgeHelperRegistryArtifact(body)
	if err != nil {
		return err
	}
	pub, trustedKey, err := resolveBridgeRegistryVerificationKey(artifact, *publicFile, *trustStoreFile)
	if err != nil {
		return err
	}
	verified, err := accesspack.VerifyBridgeHelperRegistryArtifact(artifact, pub, time.Now().UTC())
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outRegistryFile) != "" {
		if err := writeBridgeHelperRegistryFile(*outRegistryFile, verified.Artifact.Registry); err != nil {
			return err
		}
	}
	out := bridgeRegistryVerifyOutput{
		Status:            "ok",
		KeyID:             verified.KeyID,
		Trusted:           trustedKey != nil,
		RegistryID:        verified.Artifact.RegistryID,
		OrganizationID:    verified.Artifact.Organization.OrgID,
		OrganizationName:  verified.Artifact.Organization.Name,
		ExpiresAtUTC:      verified.ExpiresAt.Format(time.RFC3339),
		CanonicalBodySize: verified.CanonicalBodySize,
		HelpersCount:      len(verified.Artifact.Registry.Helpers),
		OutputRegistry:    strings.TrimSpace(*outRegistryFile),
	}
	if trustedKey != nil {
		out.TrustedOrgID = trustedKey.OrgID
		out.TrustedOrgName = trustedKey.OrgName
	}
	if *showRegistry {
		registry := verified.Artifact.Registry
		out.Registry = &registry
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runBridgeRegistryCheck(args []string) error {
	fs := flag.NewFlagSet("bridge-registry-check", flag.ContinueOnError)
	helperRegistryFile := fs.String("helper-registry", "", "path to bridge helper registry JSON")
	helperID := fs.String("helper-id", "", "optional helper id filter")
	orgID := fs.String("org-id", "", "optional organization id filter")
	requireActive := fs.Bool("require-active", false, "fail if matching helpers are not currently active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	registry, err := loadBridgeHelperRegistryFile(*helperRegistryFile)
	if err != nil {
		return err
	}
	report := accesspack.CheckBridgeHelperRegistry(registry, accesspack.BridgeHelperRegistryCheckOptions{
		HelperID:      *helperID,
		OrgID:         *orgID,
		RequireActive: *requireActive,
	}, time.Now().UTC())
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	if report.Status != "pass" {
		return errors.New("bridge helper registry check failed")
	}
	return nil
}

func runBridgeRegistryUpsertHelper(args []string) error {
	fs := flag.NewFlagSet("bridge-registry-upsert-helper", flag.ContinueOnError)
	helperRegistryFile := fs.String("helper-registry", "", "path to bridge helper registry JSON")
	helperID := fs.String("helper-id", "", "helper id to add or update")
	orgIDs := fs.String("org-ids", "", "comma-separated organization ids this helper may serve")
	displayName := fs.String("display-name", "", "optional helper display name")
	contactURL := fs.String("contact-url", "", "optional helper contact URL")
	status := fs.String("status", "", "helper status: active, quarantined, or disabled; defaults to active for new helpers")
	activeFromUTC := fs.String("active-from-utc", "", "optional helper active window start")
	activeUntilUTC := fs.String("active-until-utc", "", "optional helper active window end")
	reason := fs.String("reason", "", "required reason when adding or updating a quarantined/disabled helper")
	outFile := fs.String("out", "", "path to write updated registry JSON; defaults to --helper-registry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	registry, err := loadBridgeHelperRegistryFile(*helperRegistryFile)
	if err != nil {
		return err
	}
	outputFile := strings.TrimSpace(*outFile)
	if outputFile == "" {
		outputFile = strings.TrimSpace(*helperRegistryFile)
	}
	updatedRegistry, report := accesspack.UpsertBridgeHelperRegistryHelper(registry, accesspack.BridgeHelperRegistryUpsertOptions{
		HelperID:       *helperID,
		DisplayName:    *displayName,
		Status:         *status,
		OrgIDs:         splitCommaValues(*orgIDs),
		ContactURL:     *contactURL,
		ActiveFromUTC:  *activeFromUTC,
		ActiveUntilUTC: *activeUntilUTC,
		Reason:         *reason,
	}, time.Now().UTC())
	out := bridgeRegistryUpsertHelperOutput{
		Status:       report.Status,
		RegistryFile: strings.TrimSpace(*helperRegistryFile),
		OutputFile:   outputFile,
		Upsert:       report,
	}
	if report.Status == "pass" {
		if err := writeBridgeHelperRegistryFile(outputFile, updatedRegistry); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if report.Status != "pass" {
		return errors.New("bridge helper registry helper upsert failed")
	}
	return nil
}

func runBridgeRegistrySetStatus(args []string) error {
	fs := flag.NewFlagSet("bridge-registry-set-status", flag.ContinueOnError)
	helperRegistryFile := fs.String("helper-registry", "", "path to bridge helper registry JSON")
	helperID := fs.String("helper-id", "", "helper id to update")
	status := fs.String("status", "", "new helper status: active, quarantined, or disabled")
	reason := fs.String("reason", "", "required reason when quarantining or disabling a helper")
	outFile := fs.String("out", "", "path to write updated registry JSON; defaults to --helper-registry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	registry, err := loadBridgeHelperRegistryFile(*helperRegistryFile)
	if err != nil {
		return err
	}
	outputFile := strings.TrimSpace(*outFile)
	if outputFile == "" {
		outputFile = strings.TrimSpace(*helperRegistryFile)
	}
	updatedRegistry, report := accesspack.SetBridgeHelperRegistryStatus(registry, accesspack.BridgeHelperRegistryStatusUpdateOptions{
		HelperID: *helperID,
		Status:   *status,
		Reason:   *reason,
	}, time.Now().UTC())
	out := bridgeRegistrySetStatusOutput{
		Status:       report.Status,
		RegistryFile: strings.TrimSpace(*helperRegistryFile),
		OutputFile:   outputFile,
		Update:       report,
	}
	if report.Status == "pass" {
		if err := writeBridgeHelperRegistryFile(outputFile, updatedRegistry); err != nil {
			return err
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if report.Status != "pass" {
		return errors.New("bridge helper registry status update failed")
	}
	return nil
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

func runDemoBundle(args []string) error {
	fs := flag.NewFlagSet("demo-bundle", flag.ContinueOnError)
	outDir := fs.String("out-dir", "", "directory to write the demo bundle")
	orgID := fs.String("org-id", "freenews-demo", "demo organization id")
	orgName := fs.String("org-name", "FreeNews Demo", "demo organization name")
	baseURL := fs.String("base-url", "https://freenews.example", "primary demo access URL")
	helperURL := fs.String("helper-url", "https://helper.example/freenews/bootstrap", "demo bridge helper URL")
	helperContact := fs.String("helper-contact", "mailto:bridge-helper@example.com", "demo helper contact URL")
	qrSize := fs.Int("qr-size", 768, "QR image size in pixels")
	if err := fs.Parse(args); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	dir := strings.TrimSpace(*outDir)
	if dir == "" {
		dir = filepath.Join(".easy-node-logs", "access-recovery-demo-"+now.Format("20060102_150405"))
	}
	if err := ensureDemoOutputDir(dir); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate demo keypair: %w", err)
	}
	pubText := adminauth.EncodePublicKey(pub)
	privText := base64.RawURLEncoding.EncodeToString(priv)
	keyID := adminauth.KeyIDFromPublicKey(pub)

	pack := demoAccessPack(strings.TrimSpace(*orgID), strings.TrimSpace(*orgName), strings.TrimSpace(*baseURL), now)
	signedPack, err := accesspack.Sign(pack, priv, "")
	if err != nil {
		return fmt.Errorf("sign demo access pack: %w", err)
	}
	invite := demoBridgeInvite(strings.TrimSpace(*orgID), strings.TrimSpace(*orgName), strings.TrimSpace(*baseURL), strings.TrimSpace(*helperURL), strings.TrimSpace(*helperContact), now)
	signedInvite, err := accesspack.SignBridgeInvite(invite, priv, "")
	if err != nil {
		return fmt.Errorf("sign demo bridge invite: %w", err)
	}
	store, _, err := accesspack.AddTrustedKey(accesspack.EmptyTrustStore(), accesspack.TrustedKey{
		OrgID:     strings.TrimSpace(*orgID),
		OrgName:   strings.TrimSpace(*orgName),
		PublicKey: pubText,
		Source:    "generated demo bundle",
		Notes:     []string{"Demo key for local access-recovery testing only."},
	}, now)
	if err != nil {
		return fmt.Errorf("create demo trust store: %w", err)
	}
	if _, _, err := accesspack.ResolveTrustedPublicKey(store, signedPack, now); err != nil {
		return fmt.Errorf("verify demo trust store against pack: %w", err)
	}
	if _, _, err := accesspack.ResolveTrustedBridgeInvitePublicKey(store, signedInvite, now); err != nil {
		return fmt.Errorf("verify demo trust store against bridge invite: %w", err)
	}
	if _, err := accesspack.Verify(signedPack, pub, now); err != nil {
		return fmt.Errorf("verify signed demo access pack: %w", err)
	}
	if _, err := accesspack.VerifyBridgeInvite(signedInvite, pub, now); err != nil {
		return fmt.Errorf("verify signed demo bridge invite: %w", err)
	}
	bridgeHelperRegistry := demoBridgeHelperRegistry(strings.TrimSpace(*orgID), strings.TrimSpace(*helperContact), now)
	bridgeHelperRegistryArtifact, err := accesspack.SignBridgeHelperRegistryArtifact(accesspack.BridgeHelperRegistryArtifact{
		SchemaVersion: accesspack.BridgeHelperRegistryArtifactSchemaVersion,
		RegistryID:    "reg-demo-" + now.Format("20060102-150405"),
		Organization: accesspack.Organization{
			OrgID: strings.TrimSpace(*orgID),
			Name:  strings.TrimSpace(*orgName),
		},
		IssuedAtUTC:  now.Format(time.RFC3339),
		ExpiresAtUTC: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Registry:     bridgeHelperRegistry,
	}, priv, "")
	if err != nil {
		return fmt.Errorf("sign demo bridge helper registry: %w", err)
	}
	if _, _, err := accesspack.ResolveTrustedBridgeHelperRegistryPublicKey(store, bridgeHelperRegistryArtifact, now); err != nil {
		return fmt.Errorf("verify demo trust store against helper registry: %w", err)
	}
	if _, err := accesspack.VerifyBridgeHelperRegistryArtifact(bridgeHelperRegistryArtifact, pub, now); err != nil {
		return fmt.Errorf("verify signed demo bridge helper registry: %w", err)
	}
	bridgePolicyOptions := accesspack.DefaultBridgeInvitePolicyOptions()
	bridgePolicyOptions.RequireHelperRegistry = true
	bridgePolicyOptions.HelperRegistry = &bridgeHelperRegistry
	bridgePolicy := accesspack.CheckBridgeInvitePolicy(signedInvite, bridgePolicyOptions, now)
	if bridgePolicy.Status != "pass" {
		return fmt.Errorf("demo bridge invite policy failed: %+v", bridgePolicy.Findings)
	}

	files := map[string]string{}
	addFile := func(key string, name string) string {
		path := filepath.Join(dir, name)
		files[key] = path
		return path
	}
	if err := writeFileWithMode(addFile("private_key", "recovery.key"), []byte(privText+"\n"), 0o600); err != nil {
		return err
	}
	if err := writeFileWithMode(addFile("public_key", "recovery.pub"), []byte(pubText+"\n"), 0o644); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("access_pack_unsigned", "access-pack.unsigned.json"), pack); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("access_pack_signed", "access-pack.signed.json"), signedPack); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("bridge_invite_unsigned", "bridge-invite.unsigned.json"), invite); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("bridge_invite_signed", "bridge-invite.signed.json"), signedInvite); err != nil {
		return err
	}
	if err := writeTrustStoreFile(addFile("trust_store", "recovery-trust.json"), store); err != nil {
		return err
	}
	if err := writeBridgeHelperRegistryFile(addFile("bridge_helper_registry", "bridge-helper-registry.json"), bridgeHelperRegistry); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("bridge_helper_registry_signed", "bridge-helper-registry.signed.json"), bridgeHelperRegistryArtifact); err != nil {
		return err
	}

	if err := writeTextAndQR(addFile("access_pack_text", "access-pack.txt"), addFile("access_pack_qr", "access-pack.qr.png"), accesspack.EnvelopeKindPack, signedPack, *qrSize); err != nil {
		return err
	}
	if err := writeTextAndQR(addFile("bridge_invite_text", "bridge-invite.txt"), addFile("bridge_invite_qr", "bridge-invite.qr.png"), accesspack.EnvelopeKindBridge, signedInvite, *qrSize); err != nil {
		return err
	}
	if err := writeTextAndQR(addFile("bridge_helper_registry_text", "bridge-helper-registry.txt"), addFile("bridge_helper_registry_qr", "bridge-helper-registry.qr.png"), accesspack.EnvelopeKindBridgeHelperRegistry, bridgeHelperRegistry, *qrSize); err != nil {
		return err
	}
	if err := writeTextAndQR(addFile("bridge_helper_registry_signed_text", "bridge-helper-registry.signed.txt"), addFile("bridge_helper_registry_signed_qr", "bridge-helper-registry.signed.qr.png"), accesspack.EnvelopeKindBridgeHelperRegistrySigned, bridgeHelperRegistryArtifact, *qrSize); err != nil {
		return err
	}
	storeBody, err := accesspack.MarshalTrustStore(store)
	if err != nil {
		return err
	}
	storeText, err := accesspack.EncodeTextEnvelope(accesspack.EnvelopeKindStore, storeBody)
	if err != nil {
		return err
	}
	if err := writeFileWithMode(addFile("trust_store_text", "recovery-trust.txt"), []byte(storeText+"\n"), 0o644); err != nil {
		return err
	}

	out := demoBundleOutput{
		Status:         "ok",
		GeneratedAtUTC: now.Format(time.RFC3339),
		OutDir:         dir,
		OrgID:          strings.TrimSpace(*orgID),
		OrgName:        strings.TrimSpace(*orgName),
		KeyID:          keyID,
		Files:          files,
		BridgePolicy:   bridgePolicy,
		NextSteps: []string{
			"Open apps/web/recovery.html in the local preview.",
			"Import recovery-trust.json as the trust store.",
			"Import access-pack.signed.json or bridge-invite.signed.json as the signed artifact.",
			"Import bridge-helper-registry.signed.json, or paste/scan bridge-helper-registry.signed.txt/QR, then click Verify Signed before checking bridge invites.",
			"Or paste/scan the generated GPMREC1 text/QR handoffs.",
			"Run bridge-registry-verify with bridge-helper-registry.signed.json before publishing a registry snapshot.",
			"Run bridge-registry-check with bridge-helper-registry.json when changing helper status.",
			"Use bridge-registry-upsert-helper to add or update helper registry entries without hand-editing JSON.",
			"Use bridge-registry-set-status to quarantine or re-enable helpers without hand-editing registry JSON.",
			"Run bridge-policy with bridge-helper-registry.json before enabling a helper route in a service.",
		},
	}
	manifestPath := addFile("manifest", "demo-manifest.json")
	if err := writeJSONFile(manifestPath, out); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func ensureDemoOutputDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("--out-dir is required")
	}
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("demo output path %q is not a directory", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("read demo output dir: %w", err)
		}
		if len(entries) > 0 {
			return fmt.Errorf("demo output dir %q is not empty", dir)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat demo output dir: %w", err)
	}
	return os.MkdirAll(dir, 0o755)
}

func demoAccessPack(orgID string, orgName string, baseURL string, now time.Time) accesspack.Pack {
	return accesspack.Pack{
		SchemaVersion: accesspack.SchemaVersion,
		PackID:        "arp-demo-" + now.Format("20060102-150405"),
		Organization: accesspack.Organization{
			OrgID:   orgID,
			Name:    orgName,
			HomeURL: baseURL,
		},
		IssuedAtUTC:      now.Format(time.RFC3339),
		ExpiresAtUTC:     now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		IntendedAudience: "Demo users validating the GPM access recovery flow",
		Sources: []accesspack.Source{
			{SourceID: "official", Kind: "official", URL: baseURL + "/.well-known/gpm/access-pack.json", Priority: 10, Description: "Official signed recovery pack"},
			{SourceID: "mirror", Kind: "mirror", URL: baseURL + "/mirror/access-pack.json", Priority: 20, Description: "Demo mirror source"},
		},
		AccessPaths: []accesspack.AccessPath{
			{PathID: "main-site", Kind: "website", URL: baseURL, Priority: 10, Description: "Primary site"},
			{PathID: "mirror-site", Kind: "mirror", URL: baseURL + "/mirror", Priority: 20, Description: "Demo mirror"},
		},
		SafetyNotes: []string{"Verify this pack before using any listed path."},
	}
}

func demoBridgeInvite(orgID string, orgName string, baseURL string, helperURL string, helperContact string, now time.Time) accesspack.BridgeInvite {
	return accesspack.BridgeInvite{
		SchemaVersion: accesspack.SchemaVersion,
		InviteID:      "bri-demo-" + now.Format("20060102-150405"),
		Organization: accesspack.Organization{
			OrgID:   orgID,
			Name:    orgName,
			HomeURL: baseURL,
		},
		IssuedAtUTC:      now.Format(time.RFC3339),
		ExpiresAtUTC:     now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		IntendedAudience: "Demo users validating a signed helper bootstrap route",
		Helper: accesspack.BridgeHelper{
			HelperID:    "helper-demo",
			DisplayName: "Demo bridge helper",
			ContactURL:  helperContact,
			Description: "Temporary helper route for access recovery testing",
		},
		AccessPaths: []accesspack.AccessPath{
			{PathID: "helper-web", Kind: "bridge", URL: helperURL, Priority: 10, Description: "Signed helper bootstrap page"},
			{PathID: "helper-contact", Kind: "instructions", URL: helperContact, Priority: 20, RequiresExternalApp: true, LaunchHint: "Contact the helper with the invite id only", Description: "Manual contact fallback"},
		},
		SafetyNotes: []string{
			"This invite proves the helper route was signed by the organization key.",
			"Never share private keys, wallet seed phrases, or passwords with a helper.",
		},
	}
}

func demoBridgeHelperRegistry(orgID string, helperContact string, now time.Time) accesspack.BridgeHelperRegistry {
	return accesspack.BridgeHelperRegistry{
		Version: accesspack.BridgeHelperRegistryVersion,
		Helpers: []accesspack.BridgeHelperRegistration{
			{
				HelperID:       "helper-demo",
				DisplayName:    "Demo bridge helper",
				Status:         accesspack.BridgeHelperStatusActive,
				OrgIDs:         []string{orgID},
				ContactURL:     helperContact,
				ActiveFromUTC:  now.Add(-1 * time.Hour).Format(time.RFC3339),
				ActiveUntilUTC: now.Add(8 * 24 * time.Hour).Format(time.RFC3339),
				UpdatedAtUTC:   now.Format(time.RFC3339),
			},
		},
	}
}

func writeJSONFile(path string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	return writeFileWithMode(path, append(body, '\n'), 0o644)
}

func writeTextAndQR(textPath string, qrPath string, kind string, payload any, qrSize int) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal %s envelope payload: %w", kind, err)
	}
	text, err := accesspack.EncodeTextEnvelope(kind, body)
	if err != nil {
		return err
	}
	if err := writeFileWithMode(textPath, []byte(text+"\n"), 0o644); err != nil {
		return err
	}
	if qrSize < 128 {
		qrSize = 128
	}
	if qrSize > 4096 {
		qrSize = 4096
	}
	qr, err := qrcode.Encode(text, qrcode.Medium, qrSize)
	if err != nil {
		return fmt.Errorf("encode %s qr png: %w", kind, err)
	}
	return writeFileWithMode(qrPath, qr, 0o644)
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

func resolveBridgeRegistryVerificationKey(artifact accesspack.BridgeHelperRegistryArtifact, publicFile string, trustStoreFile string) (ed25519.PublicKey, *accesspack.TrustedKey, error) {
	publicFile = strings.TrimSpace(publicFile)
	trustStoreFile = strings.TrimSpace(trustStoreFile)
	if trustStoreFile != "" {
		store, err := loadTrustStoreFile(trustStoreFile)
		if err != nil {
			return nil, nil, err
		}
		pub, entry, err := accesspack.ResolveTrustedBridgeHelperRegistryPublicKey(store, artifact, time.Now().UTC())
		if err != nil {
			return nil, nil, err
		}
		return pub, &entry, nil
	}
	if publicFile != "" {
		pub, err := readPublicKeyFile(publicFile)
		return pub, nil, err
	}
	return nil, nil, errors.New("bridge helper registry verification requires --trust-store or --public-key-file")
}

func verifyBridgeHelperRegistryArtifactFile(path string, expectedOrgID string, publicFile string, trustStoreFile string) (accesspack.VerifiedBridgeHelperRegistryArtifact, error) {
	body, err := readInputFileStrict(path, "signed bridge helper registry", maxBridgeRegistryFileBytes)
	if err != nil {
		return accesspack.VerifiedBridgeHelperRegistryArtifact{}, err
	}
	artifact, err := accesspack.ParseBridgeHelperRegistryArtifact(body)
	if err != nil {
		return accesspack.VerifiedBridgeHelperRegistryArtifact{}, err
	}
	artifact = accesspack.NormalizeBridgeHelperRegistryArtifact(artifact)
	if artifact.Organization.OrgID != strings.TrimSpace(expectedOrgID) {
		return accesspack.VerifiedBridgeHelperRegistryArtifact{}, fmt.Errorf("signed helper registry organization %q does not match bridge invite organization %q", artifact.Organization.OrgID, strings.TrimSpace(expectedOrgID))
	}
	pub, _, err := resolveBridgeRegistryVerificationKey(artifact, publicFile, trustStoreFile)
	if err != nil {
		return accesspack.VerifiedBridgeHelperRegistryArtifact{}, err
	}
	return accesspack.VerifyBridgeHelperRegistryArtifact(artifact, pub, time.Now().UTC())
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

func loadBridgeHelperRegistryFile(path string) (accesspack.BridgeHelperRegistry, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return accesspack.BridgeHelperRegistry{}, errors.New("--helper-registry is required")
	}
	body, err := readInputFileStrict(path, "bridge helper registry", maxBridgeRegistryFileBytes)
	if err != nil {
		return accesspack.BridgeHelperRegistry{}, err
	}
	return accesspack.ParseBridgeHelperRegistry(body)
}

func writeBridgeHelperRegistryFile(path string, registry accesspack.BridgeHelperRegistry) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("--helper-registry is required")
	}
	body, err := accesspack.MarshalBridgeHelperRegistry(registry)
	if err != nil {
		return err
	}
	return writeFileWithMode(path, body, 0o644)
}

func splitCommaValues(raw string) []string {
	var values []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	return values
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
