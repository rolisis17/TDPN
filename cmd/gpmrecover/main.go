package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"privacynode/internal/fileperm"
	"privacynode/pkg/accessbridge"
	"privacynode/pkg/accesspack"
	"privacynode/pkg/adminauth"
)

const (
	maxPackFileBytes             int64 = 2 * 1024 * 1024
	maxKeyFileBytes              int64 = 8 * 1024
	maxTrustFileBytes            int64 = 512 * 1024
	maxBridgeRegistryFileBytes   int64 = 512 * 1024
	maxPublicationIndexBytes     int64 = 512 * 1024
	maxPublicationFileBytes      int64 = 2 * 1024 * 1024
	maxEvidenceBundleFileBytes   int64 = 64 * 1024 * 1024
	maxEvidenceProvenanceBytes   int64 = 512 * 1024
	minBridgeAccessCodeLength          = 24
	defaultBridgeAccessCodeBytes       = 24
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
	Status          string                              `json:"status"`
	Verified        bool                                `json:"verified"`
	Trusted         bool                                `json:"trusted"`
	KeyID           string                              `json:"key_id"`
	RegistryTrusted bool                                `json:"registry_trusted"`
	RegistrySource  string                              `json:"registry_source"`
	Policy          accesspack.BridgeInvitePolicyReport `json:"policy"`
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

type recoveryPublicationIndex struct {
	Version        int               `json:"version"`
	GeneratedAtUTC string            `json:"generated_at_utc,omitempty"`
	OrgID          string            `json:"org_id,omitempty"`
	OrgName        string            `json:"org_name,omitempty"`
	KeyID          string            `json:"key_id,omitempty"`
	Files          map[string]string `json:"files"`
	Notes          []string          `json:"notes,omitempty"`
}

type fetchPublicationOutput struct {
	Status        string            `json:"status"`
	IndexURL      string            `json:"index_url"`
	OutDir        string            `json:"out_dir"`
	Files         map[string]string `json:"files"`
	TrustVerified bool              `json:"trust_verified"`
	NextStep      string            `json:"next_step"`
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
	case "bridge-service-config":
		err = runBridgeServiceConfig(os.Args[2:])
	case "bridge-service-check":
		err = runBridgeServiceCheck(os.Args[2:])
	case "bridge-service-serve":
		err = runBridgeServiceServe(os.Args[2:])
	case "bridge-service-code-hash":
		err = runBridgeServiceCodeHash(os.Args[2:])
	case "bridge-service-code-generate":
		err = runBridgeServiceCodeGenerate(os.Args[2:])
	case "bridge-service-deploy-pack":
		err = runBridgeServiceDeployPack(os.Args[2:])
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
	case "trust-export-key":
		err = runTrustExportKey(os.Args[2:])
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
	case "provenance-sign":
		err = runProvenanceSign(os.Args[2:])
	case "provenance-verify":
		err = runProvenanceVerify(os.Args[2:])
	case "fetch-publication":
		err = runFetchPublication(os.Args[2:])
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
  go run ./cmd/gpmrecover bridge-policy --invite FILE (--trust-store FILE | --public-key-file FILE) (--signed-helper-registry FILE | --helper-registry FILE --allow-unsigned-helper-registry | --allow-missing-helper-registry) [--allow-local-access-paths]
  go run ./cmd/gpmrecover bridge-service-config --invite FILE --signed-helper-registry FILE (--trust-store FILE | --public-key-file FILE) [--out FILE] [--allow-local-access-paths]
  go run ./cmd/gpmrecover bridge-service-check --config FILE [--path-id ID | --url URL] [--out FILE]
  go run ./cmd/gpmrecover bridge-service-serve --config FILE --config-sha256 HEX [--addr 127.0.0.1:18980] [--rps 2] [--abuse-log FILE] --access-code-sha256 HEX [--allow-unpinned-local=false] [--allow-unauthenticated-local=false] [--allow-query-access-code=false] [--trust-proxy-headers=false] [--redirect=false]
  go run ./cmd/gpmrecover bridge-service-code-generate (--code-out FILE | --print-code 1) [--hash-out FILE] [--bytes 24]
  go run ./cmd/gpmrecover bridge-service-code-hash (--code TEXT | --code-file FILE) [--out FILE] [--allow-weak-code=false]
  go run ./cmd/gpmrecover bridge-service-deploy-pack --out-dir DIR [--install-dir /etc/gpm/access-bridge] [--service-name gpm-access-bridge] [--public-host recovery-helper.gpm-pilot.net] --config-sha256 HEX --access-code-sha256 HEX [--rps 1..20] [--max-sources 1..100000] [--allow-unpinned-config=false] [--allow-unauthenticated-local=false] [--allow-query-access-code=false] [--trust-proxy-headers=true]
  go run ./cmd/gpmrecover bridge-registry-sign --helper-registry FILE --org-id ID --org-name NAME --private-key-file FILE --out FILE [--registry-id ID] [--lifetime-hours HOURS]
  go run ./cmd/gpmrecover bridge-registry-verify --signed-registry FILE (--trust-store FILE | --public-key-file FILE) [--out-registry FILE] [--show-registry 1]
  go run ./cmd/gpmrecover bridge-registry-check --helper-registry FILE [--helper-id ID] [--org-id ID] [--require-active 1]
  go run ./cmd/gpmrecover bridge-registry-upsert-helper --helper-registry FILE --helper-id ID --org-ids ORG[,ORG...] [--display-name NAME] [--contact-url URL] [--abuse-report-url URL] [--rate-limit-policy TEXT] [--status active|quarantined|disabled] [--reason TEXT] [--out FILE]
  go run ./cmd/gpmrecover bridge-registry-set-status --helper-registry FILE --helper-id ID --status active|quarantined|disabled [--reason TEXT] [--out FILE]
  go run ./cmd/gpmrecover trust-add --trust-store FILE --org-id ID --org-name NAME --public-key-file FILE
  go run ./cmd/gpmrecover trust-list --trust-store FILE
  go run ./cmd/gpmrecover trust-export-key --trust-store FILE --org-id ID --key-id ID [--out FILE] [--text-out FILE]
  go run ./cmd/gpmrecover trust-remove --trust-store FILE --org-id ID --key-id ID
  go run ./cmd/gpmrecover text-export --kind access-pack|bridge-invite|trust-store|trusted-key|bridge-helper-registry|bridge-helper-registry-signed --in FILE [--out FILE]
  go run ./cmd/gpmrecover text-import (--text TEXT | --text-file FILE) --out FILE [--expect-kind KIND]
  go run ./cmd/gpmrecover qr-png --text TEXT --out FILE [--size 768]
  go run ./cmd/gpmrecover verify --pack FILE (--trust-store FILE | --public-key-file FILE) [--show-paths 1]
  go run ./cmd/gpmrecover check --pack FILE (--trust-store FILE | --public-key-file FILE) [--timeout-sec 8]
  go run ./cmd/gpmrecover demo-bundle [--out-dir DIR] [--org-id ID] [--org-name NAME] [--base-url URL] [--helper-id ID] [--helper-name NAME]
  go run ./cmd/gpmrecover provenance-sign --summary-json FILE --bundle-tar FILE --bundle-tar-sha256-file FILE --private-key-file FILE --org-id ID --org-name NAME --out FILE [--lifetime-hours 720] [--key-id ID]
  go run ./cmd/gpmrecover provenance-verify --provenance FILE --summary-json FILE --bundle-tar FILE --bundle-tar-sha256-file FILE (--trust-store FILE | --public-key-file FILE)
  go run ./cmd/gpmrecover fetch-publication --index-url URL --out-dir DIR [--timeout-sec 10]

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

func runTrustExportKey(args []string) error {
	fs := flag.NewFlagSet("trust-export-key", flag.ContinueOnError)
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	orgID := fs.String("org-id", "", "trusted organization id")
	keyID := fs.String("key-id", "", "trusted key id")
	outFile := fs.String("out", "", "optional path to write trusted-key JSON")
	textOutFile := fs.String("text-out", "", "optional path to write trusted-key GPMREC1 text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	orgIDValue := strings.TrimSpace(*orgID)
	keyIDValue := strings.TrimSpace(*keyID)
	if orgIDValue == "" {
		return errors.New("--org-id is required")
	}
	if keyIDValue == "" {
		return errors.New("--key-id is required")
	}
	store, err := loadTrustStoreFile(*trustStoreFile)
	if err != nil {
		return err
	}
	store = accesspack.NormalizeTrustStore(store)
	var found accesspack.TrustedKey
	var matched bool
	for _, entry := range store.TrustedKeys {
		if strings.TrimSpace(entry.OrgID) == orgIDValue && strings.TrimSpace(entry.KeyID) == keyIDValue {
			found = entry
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("trusted key not found for org_id=%q key_id=%q", orgIDValue, keyIDValue)
	}
	if found.Disabled {
		return errors.New("trusted key is disabled")
	}
	_, exported, err := accesspack.AddTrustedKey(accesspack.EmptyTrustStore(), found, time.Now().UTC())
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(exported, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trusted key: %w", err)
	}
	body = append(body, '\n')
	outPath := strings.TrimSpace(*outFile)
	if outPath != "" {
		if err := writeFileWithMode(outPath, body, 0o644); err != nil {
			return err
		}
	}
	textOutPath := strings.TrimSpace(*textOutFile)
	if textOutPath != "" {
		if err := validateTextEnvelopePayload(accesspack.EnvelopeKindKey, body); err != nil {
			return err
		}
		text, err := accesspack.EncodeTextEnvelope(accesspack.EnvelopeKindKey, body)
		if err != nil {
			return err
		}
		if err := writeFileWithMode(textOutPath, []byte(text+"\n"), 0o644); err != nil {
			return err
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":      "ok",
		"trust_store": strings.TrimSpace(*trustStoreFile),
		"org_id":      exported.OrgID,
		"org_name":    exported.OrgName,
		"key_id":      exported.KeyID,
		"out":         outPath,
		"text_out":    textOutPath,
		"trusted_key": exported,
	})
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
	allowUnsignedHelperRegistry := fs.Bool("allow-unsigned-helper-registry", false, "allow raw unsigned helper registry JSON for local diagnostics only")
	allowMissingHelperRegistry := fs.Bool("allow-missing-helper-registry", false, "diagnostic opt-out: allow bridge policy checks without any helper registry")
	requireHelperRegistry := fs.Bool("require-helper-registry", true, "fail if no bridge helper registry is provided")
	allowLocalAccessPaths := fs.Bool("allow-local-access-paths", false, "diagnostic opt-out: allow plain-http/private bridge access paths for local rehearsal only")
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
	registryTrusted := false
	registrySource := "none"
	if strings.TrimSpace(*helperRegistryFile) != "" {
		if !*allowUnsignedHelperRegistry {
			return errors.New("--helper-registry is unsigned diagnostic input; use --signed-helper-registry for trusted policy evidence or pass --allow-unsigned-helper-registry for local testing")
		}
		registry, err := loadBridgeHelperRegistryFile(*helperRegistryFile)
		if err != nil {
			return err
		}
		helperRegistry = &registry
		registrySource = "unsigned"
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
		registryTrusted = true
		registrySource = "signed"
	}
	effectiveRequireHelperRegistry := *requireHelperRegistry
	if *allowMissingHelperRegistry {
		effectiveRequireHelperRegistry = false
	}
	maxLifetime := time.Duration(*maxLifetimeHours) * time.Hour
	defaultPolicy := accesspack.DefaultBridgeInvitePolicyOptions()
	report := accesspack.CheckBridgeInvitePolicy(verified.Invite, accesspack.BridgeInvitePolicyOptions{
		MinAccessPaths:               *minPaths,
		MinDistinctHosts:             *minHosts,
		MaxLifetime:                  maxLifetime,
		RequireHelperContact:         *requireContact,
		RequireManualFallback:        *requireManualFallback,
		RequireHelperRegistry:        effectiveRequireHelperRegistry,
		RequireHelperAbuseReport:     defaultPolicy.RequireHelperAbuseReport,
		RequireHelperRateLimitPolicy: defaultPolicy.RequireHelperRateLimitPolicy,
		AllowLocalAccessPaths:        *allowLocalAccessPaths,
		HelperRegistry:               helperRegistry,
	}, time.Now().UTC())
	out := bridgePolicyOutput{
		Status:          report.Status,
		Verified:        true,
		Trusted:         trustedKey != nil,
		KeyID:           verified.KeyID,
		RegistryTrusted: registryTrusted,
		RegistrySource:  registrySource,
		Policy:          report,
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		return err
	}
	if report.Status != "pass" {
		return errors.New("bridge invite policy failed")
	}
	return nil
}

func runBridgeServiceConfig(args []string) error {
	fs := flag.NewFlagSet("bridge-service-config", flag.ContinueOnError)
	inviteFile := fs.String("invite", "", "path to signed bridge invite JSON")
	signedHelperRegistryFile := fs.String("signed-helper-registry", "", "path to signed bridge helper registry artifact JSON")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	outFile := fs.String("out", "", "optional path to write bridge service config JSON")
	allowLocalAccessPaths := fs.Bool("allow-local-access-paths", false, "diagnostic opt-out: allow plain-http/private bridge access paths for local rehearsal only")
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
	pub, _, err := resolveBridgeVerificationKey(invite, *publicFile, *trustStoreFile)
	if err != nil {
		return err
	}
	verified, err := accesspack.VerifyBridgeInvite(invite, pub, time.Now().UTC())
	if err != nil {
		return err
	}
	verifiedRegistry, err := verifyBridgeHelperRegistryArtifactFile(*signedHelperRegistryFile, verified.Invite.Organization.OrgID, *publicFile, *trustStoreFile)
	if err != nil {
		return err
	}
	config := accesspack.BuildBridgeServiceConfig(verified.Invite, verifiedRegistry.Artifact.Registry, accesspack.BridgeServiceConfigOptions{
		RegistryID:            verifiedRegistry.Artifact.RegistryID,
		RegistryExpiresAtUTC:  verifiedRegistry.Artifact.ExpiresAtUTC,
		InviteKeyID:           verified.KeyID,
		RegistryKeyID:         verifiedRegistry.KeyID,
		SignedRegistry:        true,
		AllowLocalAccessPaths: *allowLocalAccessPaths,
	}, time.Now().UTC())
	body, err = json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bridge service config: %w", err)
	}
	body = append(body, '\n')
	if strings.TrimSpace(*outFile) != "" {
		if err := writeFileWithMode(*outFile, body, 0o644); err != nil {
			return err
		}
	} else {
		if _, err := os.Stdout.Write(body); err != nil {
			return err
		}
	}
	if config.Status != "pass" {
		return errors.New("bridge service config policy failed")
	}
	return nil
}

func runBridgeServiceCheck(args []string) error {
	fs := flag.NewFlagSet("bridge-service-check", flag.ContinueOnError)
	configFile := fs.String("config", "", "path to bridge service config JSON")
	pathID := fs.String("path-id", "", "optional requested access path id")
	rawURL := fs.String("url", "", "optional requested access URL")
	source := fs.String("source", "", "optional caller/source label for logs")
	outFile := fs.String("out", "", "optional path to write decision JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, err := readInputFileStrict(*configFile, "bridge service config", maxPackFileBytes)
	if err != nil {
		return err
	}
	config, err := accesspack.ParseBridgeServiceConfig(body)
	if err != nil {
		return err
	}
	decision := accesspack.EvaluateBridgeServiceRequest(config, accesspack.BridgeServiceRequest{
		PathID: *pathID,
		URL:    *rawURL,
		Source: *source,
	}, time.Now().UTC())
	body, err = json.MarshalIndent(decision, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bridge service decision: %w", err)
	}
	body = append(body, '\n')
	if strings.TrimSpace(*outFile) != "" {
		if err := writeFileWithMode(*outFile, body, 0o644); err != nil {
			return err
		}
	} else {
		if _, err := os.Stdout.Write(body); err != nil {
			return err
		}
	}
	if !decision.Allowed {
		return errors.New("bridge service check failed")
	}
	return nil
}

func runBridgeServiceServe(args []string) error {
	fs := flag.NewFlagSet("bridge-service-serve", flag.ContinueOnError)
	configFile := fs.String("config", "", "path to bridge service config JSON")
	configSHA256 := fs.String("config-sha256", "", "sha256 hex digest of the bridge service config file")
	addr := fs.String("addr", "127.0.0.1:18980", "HTTP listen address")
	rps := fs.Int("rps", 2, "fixed-window requests per second per source; 0 disables")
	maxSources := fs.Int("max-sources", 1024, "maximum tracked sources for rate limiting")
	abuseLog := fs.String("abuse-log", "", "optional JSONL abuse report log path")
	accessCodeSHA256 := fs.String("access-code-sha256", "", "optional sha256 hex digest of an out-of-band bridge access code")
	allowUnpinnedLocal := fs.Bool("allow-unpinned-local", false, "allow missing config hash only for loopback diagnostics")
	allowUnauthenticatedLocal := fs.Bool("allow-unauthenticated-local", false, "allow no access-code gate only for loopback diagnostics")
	allowQueryAccessCode := fs.Bool("allow-query-access-code", false, "allow access code in ?code= query parameter; header is preferred")
	trustProxyHeaders := fs.Bool("trust-proxy-headers", false, "trust X-Forwarded-For only from loopback reverse proxies")
	redirect := fs.Bool("redirect", false, "redirect allowed bridge requests to the signed access URL instead of returning JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*accessCodeSHA256) == "" {
		if !*allowUnauthenticatedLocal {
			return errors.New("bridge-service-serve requires --access-code-sha256 unless --allow-unauthenticated-local is set")
		}
		if !isLoopbackListenAddr(*addr) {
			return errors.New("--allow-unauthenticated-local requires a loopback --addr")
		}
	}
	if strings.TrimSpace(*configSHA256) == "" {
		if !*allowUnpinnedLocal {
			return errors.New("bridge-service-serve requires --config-sha256 unless --allow-unpinned-local is set")
		}
		if !isLoopbackListenAddr(*addr) {
			return errors.New("--allow-unpinned-local requires a loopback --addr")
		}
	}
	if *allowQueryAccessCode && !isLoopbackListenAddr(*addr) {
		return errors.New("--allow-query-access-code requires a loopback --addr")
	}
	if !isLoopbackListenAddr(*addr) {
		if *rps < 1 || *rps > 20 {
			return errors.New("bridge-service-serve requires --rps between 1 and 20 for non-loopback listeners")
		}
		if *maxSources < 1 || *maxSources > 100000 {
			return errors.New("bridge-service-serve requires --max-sources between 1 and 100000 for non-loopback listeners")
		}
	} else if *maxSources < 0 {
		return errors.New("bridge-service-serve requires --max-sources >= 0")
	}
	body, err := readInputFileStrict(*configFile, "bridge service config", maxPackFileBytes)
	if err != nil {
		return err
	}
	if err := verifyOptionalSHA256("bridge service config", body, *configSHA256); err != nil {
		return err
	}
	actualConfigSHA256 := sha256.Sum256(body)
	actualConfigSHA256Hex := hex.EncodeToString(actualConfigSHA256[:])
	config, err := accesspack.ParseBridgeServiceConfig(body)
	if err != nil {
		return err
	}
	service, err := accessbridge.NewService(accessbridge.ServiceConfig{
		BridgeConfig:      config,
		ConfigSHA256:      actualConfigSHA256Hex,
		RPS:               *rps,
		MaxSources:        *maxSources,
		AbuseLogPath:      *abuseLog,
		AccessCodeSHA256:  *accessCodeSHA256,
		AllowQueryCode:    *allowQueryAccessCode,
		TrustProxyHeaders: *trustProxyHeaders,
		Redirect:          *redirect,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "bridge service listening on http://%s\n", strings.TrimSpace(*addr))
	server := &http.Server{
		Addr:              strings.TrimSpace(*addr),
		Handler:           service.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server.ListenAndServe()
}

func runBridgeServiceCodeGenerate(args []string) error {
	fs := flag.NewFlagSet("bridge-service-code-generate", flag.ContinueOnError)
	randomBytes := fs.Int("bytes", defaultBridgeAccessCodeBytes, "random byte count before base64url encoding")
	codeOutFile := fs.String("code-out", "", "optional path to write the plaintext access code with 0600 permissions")
	hashOutFile := fs.String("hash-out", "", "optional path to write the access-code hash JSON with 0600 permissions")
	printCode := fs.Bool("print-code", false, "include the plaintext access code in stdout JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *randomBytes < 16 {
		return errors.New("bridge-service-code-generate requires --bytes >= 16")
	}
	if strings.TrimSpace(*codeOutFile) == "" && !*printCode {
		return errors.New("bridge-service-code-generate requires --code-out or --print-code 1 so the generated code is not lost")
	}
	if sameOutputPath(*codeOutFile, *hashOutFile) {
		return errors.New("bridge-service-code-generate requires different --code-out and --hash-out paths")
	}
	buf := make([]byte, *randomBytes)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("generate bridge access code: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(buf)
	if err := validateBridgeAccessCode(code, false); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(code))
	out := struct {
		Status   string `json:"status"`
		SHA256   string `json:"sha256"`
		Length   int    `json:"length"`
		Bytes    int    `json:"bytes"`
		Code     string `json:"code,omitempty"`
		CodeFile string `json:"code_file,omitempty"`
	}{
		Status:   "ok",
		SHA256:   hex.EncodeToString(sum[:]),
		Length:   len(code),
		Bytes:    *randomBytes,
		CodeFile: strings.TrimSpace(*codeOutFile),
	}
	if *printCode {
		out.Code = code
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if strings.TrimSpace(*codeOutFile) != "" {
		if err := writeFileWithMode(*codeOutFile, []byte(code+"\n"), 0o600); err != nil {
			return err
		}
	}
	if strings.TrimSpace(*hashOutFile) != "" {
		if err := writeFileWithMode(*hashOutFile, body, 0o600); err != nil {
			return err
		}
	}
	_, err = os.Stdout.Write(body)
	return err
}

func runBridgeServiceCodeHash(args []string) error {
	fs := flag.NewFlagSet("bridge-service-code-hash", flag.ContinueOnError)
	code := fs.String("code", "", "access code to hash; prefer --code-file to avoid shell history")
	codeFile := fs.String("code-file", "", "file containing the access code")
	outFile := fs.String("out", "", "optional output JSON path")
	allowWeakCode := fs.Bool("allow-weak-code", false, "allow short or whitespace-containing diagnostic codes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*code) != "" && strings.TrimSpace(*codeFile) != "" {
		return errors.New("bridge-service-code-hash accepts only one of --code or --code-file")
	}
	value := strings.TrimSpace(*code)
	if strings.TrimSpace(*codeFile) != "" {
		body, err := readSecretFileStrict(*codeFile, "bridge access code")
		if err != nil {
			return err
		}
		value = strings.TrimSpace(string(body))
	}
	if value == "" {
		return errors.New("bridge-service-code-hash requires --code or --code-file")
	}
	if err := validateBridgeAccessCode(value, *allowWeakCode); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(value))
	out := struct {
		SHA256 string `json:"sha256"`
	}{
		SHA256: hex.EncodeToString(sum[:]),
	}
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if strings.TrimSpace(*outFile) != "" {
		return writeFileWithMode(*outFile, body, 0o600)
	}
	_, err = os.Stdout.Write(body)
	return err
}

func validateBridgeAccessCode(value string, allowWeak bool) error {
	if allowWeak {
		return nil
	}
	if len(value) < minBridgeAccessCodeLength {
		return fmt.Errorf("bridge access code must be at least %d characters; use bridge-service-code-generate or pass --allow-weak-code only for diagnostics", minBridgeAccessCodeLength)
	}
	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return errors.New("bridge access code must not contain whitespace or control characters")
		}
	}
	return nil
}

func sameOutputPath(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil {
		a = absA
	}
	if errB == nil {
		b = absB
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func verifyOptionalSHA256(label string, body []byte, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return nil
	}
	if err := validateSHA256Hex(label, expected); err != nil {
		return err
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return fmt.Errorf("%s sha256 must be hex: %w", label, err)
	}
	actual := sha256.Sum256(body)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), hex.EncodeToString(expectedBytes)) {
		return fmt.Errorf("%s sha256 mismatch", label)
	}
	return nil
}

func validateSHA256Hex(label string, expected string) error {
	expected = strings.TrimSpace(expected)
	if len(expected) != sha256.Size*2 {
		return fmt.Errorf("%s sha256 must be %d hex characters", label, sha256.Size*2)
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return fmt.Errorf("%s sha256 must be hex: %w", label, err)
	}
	return nil
}

func runBridgeServiceDeployPack(args []string) error {
	fs := flag.NewFlagSet("bridge-service-deploy-pack", flag.ContinueOnError)
	outDir := fs.String("out-dir", "", "directory to write deployment files")
	installDir := fs.String("install-dir", "/etc/gpm/access-bridge", "target install directory used inside generated unit")
	serviceName := fs.String("service-name", "gpm-access-bridge", "systemd service name")
	publicHost := fs.String("public-host", "recovery-helper.gpm-pilot.net", "public HTTPS host used in reverse-proxy examples")
	binary := fs.String("binary", "/usr/local/bin/gpmrecover", "installed gpmrecover binary path")
	configPath := fs.String("config", "/etc/gpm/access-bridge/bridge-service-config.json", "installed bridge service config path")
	configSHA256 := fs.String("config-sha256", "", "sha256 hex digest of the installed bridge service config")
	addr := fs.String("addr", "127.0.0.1:18980", "bridge service listen address")
	rps := fs.Int("rps", 2, "fixed-window requests per second per source; 0 disables")
	maxSources := fs.Int("max-sources", 1024, "maximum tracked sources for rate limiting")
	abuseLog := fs.String("abuse-log", "/var/log/gpm/access-bridge-abuse.jsonl", "JSONL abuse report log path")
	accessCodeSHA256 := fs.String("access-code-sha256", "", "optional sha256 hex digest of an out-of-band bridge access code")
	allowUnpinnedConfig := fs.Bool("allow-unpinned-config", false, "reserved diagnostic flag; deploy packs require config hashes")
	allowUnauthenticatedLocal := fs.Bool("allow-unauthenticated-local", false, "allow deploy pack without an access-code hash only for local diagnostics")
	allowQueryAccessCode := fs.Bool("allow-query-access-code", false, "allow access code in ?code= query parameter; header is preferred")
	trustProxyHeaders := fs.Bool("trust-proxy-headers", true, "trust X-Forwarded-For only from loopback reverse proxies")
	redirect := fs.Bool("redirect", false, "redirect allowed bridge requests to the signed access URL instead of returning JSON")
	user := fs.String("user", "gpm-bridge", "service user")
	group := fs.String("group", "gpm-bridge", "service group")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outDir) == "" {
		return errors.New("bridge-service-deploy-pack requires --out-dir")
	}
	if *redirect {
		return errors.New("bridge-service-deploy-pack redirect mode is not supported by the current smoke/evidence path")
	}
	if *allowUnauthenticatedLocal && !isLoopbackListenAddr(*addr) {
		return errors.New("--allow-unauthenticated-local requires a loopback --addr")
	}
	if *allowQueryAccessCode && !isLoopbackListenAddr(*addr) {
		return errors.New("--allow-query-access-code requires a loopback --addr")
	}
	if strings.TrimSpace(*accessCodeSHA256) == "" && !*allowUnauthenticatedLocal {
		return errors.New("bridge-service-deploy-pack requires --access-code-sha256 unless --allow-unauthenticated-local is set")
	}
	if strings.TrimSpace(*accessCodeSHA256) != "" {
		if err := validateSHA256Hex("bridge service access code", *accessCodeSHA256); err != nil {
			return err
		}
	}
	if *allowUnpinnedConfig {
		return errors.New("--allow-unpinned-config is not supported for deploy packs; pass --config-sha256")
	}
	if strings.TrimSpace(*configSHA256) == "" {
		return errors.New("bridge-service-deploy-pack requires --config-sha256")
	}
	if err := validateSHA256Hex("bridge service config", *configSHA256); err != nil {
		return err
	}
	if *rps < 1 || *rps > 20 {
		return errors.New("bridge-service-deploy-pack requires --rps between 1 and 20 for pilot helper hosts")
	}
	if *maxSources < 1 || *maxSources > 100000 {
		return errors.New("bridge-service-deploy-pack requires --max-sources between 1 and 100000 for pilot helper hosts")
	}
	publicHostValue, err := validateBridgeDeployPublicHost(*publicHost)
	if err != nil {
		return err
	}
	addrValue, err := validateBridgeDeployListenAddr(*addr)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	name := sanitizeSystemdName(*serviceName)
	envName := name + ".env"
	scriptName := "run-" + name + ".sh"
	unitName := name + ".service"
	caddyName := name + ".Caddyfile.example"
	nginxName := name + ".nginx.example.conf"
	envBody := bridgeServiceEnvFile(map[string]string{
		"GPM_BRIDGE_BINARY":              *binary,
		"GPM_BRIDGE_CONFIG":              *configPath,
		"GPM_BRIDGE_CONFIG_SHA256":       *configSHA256,
		"GPM_BRIDGE_ADDR":                addrValue,
		"GPM_BRIDGE_RPS":                 fmt.Sprintf("%d", *rps),
		"GPM_BRIDGE_MAX_SOURCES":         fmt.Sprintf("%d", *maxSources),
		"GPM_BRIDGE_ABUSE_LOG":           *abuseLog,
		"GPM_BRIDGE_ACCESS_CODE_SHA256":  *accessCodeSHA256,
		"GPM_BRIDGE_ALLOW_UNAUTH_LOCAL":  fmt.Sprintf("%t", *allowUnauthenticatedLocal),
		"GPM_BRIDGE_ALLOW_QUERY_CODE":    fmt.Sprintf("%t", *allowQueryAccessCode),
		"GPM_BRIDGE_TRUST_PROXY_HEADERS": fmt.Sprintf("%t", *trustProxyHeaders),
		"GPM_BRIDGE_REDIRECT":            fmt.Sprintf("%t", *redirect),
	})
	scriptBody := `#!/usr/bin/env sh
set -eu

set -- "${GPM_BRIDGE_BINARY}" bridge-service-serve \
  --config "${GPM_BRIDGE_CONFIG}" \
  --addr "${GPM_BRIDGE_ADDR}" \
  --rps "${GPM_BRIDGE_RPS}" \
  --max-sources "${GPM_BRIDGE_MAX_SOURCES}" \
  --allow-unauthenticated-local="${GPM_BRIDGE_ALLOW_UNAUTH_LOCAL}" \
  --allow-query-access-code="${GPM_BRIDGE_ALLOW_QUERY_CODE}" \
  --trust-proxy-headers="${GPM_BRIDGE_TRUST_PROXY_HEADERS}" \
  --redirect="${GPM_BRIDGE_REDIRECT}"

if [ -n "${GPM_BRIDGE_ABUSE_LOG:-}" ]; then
  set -- "$@" --abuse-log "${GPM_BRIDGE_ABUSE_LOG}"
fi
if [ -n "${GPM_BRIDGE_ACCESS_CODE_SHA256:-}" ]; then
  set -- "$@" --access-code-sha256 "${GPM_BRIDGE_ACCESS_CODE_SHA256}"
fi
if [ -n "${GPM_BRIDGE_CONFIG_SHA256:-}" ]; then
  set -- "$@" --config-sha256 "${GPM_BRIDGE_CONFIG_SHA256}"
fi

exec "$@"
`
	unitBody := fmt.Sprintf(`[Unit]
Description=GPM access recovery bridge service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=%s
Group=%s
EnvironmentFile=%s/%s
ExecStart=%s/%s
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log/gpm
LogsDirectory=gpm
ReadOnlyPaths=%s

[Install]
WantedBy=multi-user.target
`, *user, *group, strings.TrimRight(*installDir, "/"), envName, strings.TrimRight(*installDir, "/"), scriptName, strings.TrimRight(*installDir, "/"))
	caddyBody := fmt.Sprintf(`%s {
  encode zstd gzip
  reverse_proxy %s {
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto https
  }
  header {
    Cache-Control "no-store"
    Referrer-Policy "no-referrer"
    X-Content-Type-Options "nosniff"
    Strict-Transport-Security "max-age=31536000; includeSubDomains"
  }
}
`, publicHostValue, addrValue)
	nginxBody := fmt.Sprintf(`server {
  listen 443 ssl http2;
  server_name %s;

  # Configure ssl_certificate and ssl_certificate_key for this host before use.

  location / {
    proxy_pass http://%s;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    add_header Cache-Control "no-store" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  }
}
`, publicHostValue, addrValue)
	readmeBody := fmt.Sprintf(`# GPM Access Bridge Deployment Pack

Generated files:
- %s: environment settings
- %s: command wrapper
- %s: systemd unit
- %s: Caddy HTTPS reverse-proxy example
- %s: nginx HTTPS reverse-proxy example

Install outline:
1. Create the service user/group named %s:%s.
2. Copy these files into %s.
3. Copy bridge-service-config.json into the configured GPM_BRIDGE_CONFIG path.
4. Keep GPM_BRIDGE_CONFIG_SHA256 set to the sha256 of the staged config when available.
5. Install %s as /etc/systemd/system/%s.
6. Run: systemctl daemon-reload && systemctl enable --now %s

Smoke checks:
- curl -fsS http://%s/health
- curl -fsS -H 'X-GPM-Bridge-Code: CODE' http://%s/bridge/helper-web
`, envName, scriptName, unitName, caddyName, nginxName, *user, *group, *installDir, unitName, unitName, unitName, addrValue, addrValue)
	if err := writeFileWithMode(filepath.Join(*outDir, envName), []byte(envBody), 0o600); err != nil {
		return err
	}
	if err := writeFileWithMode(filepath.Join(*outDir, scriptName), []byte(scriptBody), 0o755); err != nil {
		return err
	}
	if err := writeFileWithMode(filepath.Join(*outDir, unitName), []byte(unitBody), 0o644); err != nil {
		return err
	}
	if err := writeFileWithMode(filepath.Join(*outDir, caddyName), []byte(caddyBody), 0o644); err != nil {
		return err
	}
	if err := writeFileWithMode(filepath.Join(*outDir, nginxName), []byte(nginxBody), 0o644); err != nil {
		return err
	}
	if err := writeFileWithMode(filepath.Join(*outDir, "README.md"), []byte(readmeBody), 0o644); err != nil {
		return err
	}
	out := map[string]string{
		"status":       "ok",
		"out_dir":      *outDir,
		"env_file":     filepath.Join(*outDir, envName),
		"script_file":  filepath.Join(*outDir, scriptName),
		"service_file": filepath.Join(*outDir, unitName),
		"caddy_file":   filepath.Join(*outDir, caddyName),
		"nginx_file":   filepath.Join(*outDir, nginxName),
		"readme_file":  filepath.Join(*outDir, "README.md"),
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func sanitizeSystemdName(raw string) string {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-', r == '_', r == '.':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "gpm-access-bridge"
	}
	return b.String()
}

func validateBridgeDeployPublicHost(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" {
		return "", errors.New("bridge-service-deploy-pack requires --public-host")
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/\\") {
		return "", errors.New("--public-host must be a bare DNS name or IPv4 address, not a URL or path")
	}
	if strings.Contains(host, ":") {
		return "", errors.New("--public-host must not include a port or IPv6 literal in generated reverse-proxy examples")
	}
	if hasBridgeDeployConfigMeta(host) {
		return "", errors.New("--public-host contains unsafe reverse-proxy config characters")
	}
	if ip := net.ParseIP(host); ip != nil {
		ipv4 := ip.To4()
		if ipv4 == nil {
			return "", errors.New("--public-host must use DNS or IPv4 for generated reverse-proxy examples")
		}
		if !bridgeDeployIPv4LooksPublic(ipv4) {
			return "", errors.New("--public-host must be public-routable, not private, loopback, link-local, documentation, multicast, or reserved")
		}
		return host, nil
	}
	lowerHost := strings.ToLower(host)
	if len(host) > 253 {
		return "", errors.New("--public-host is too long")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", errors.New("--public-host must be a fully qualified public DNS name or public IPv4 address")
	}
	for _, label := range labels {
		if label == "" {
			return "", errors.New("--public-host contains an empty DNS label")
		}
		if len(label) > 63 {
			return "", errors.New("--public-host DNS labels must be 63 characters or fewer")
		}
		for i, r := range label {
			valid := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-'
			if !valid {
				return "", errors.New("--public-host DNS labels may only contain letters, digits, and hyphens")
			}
			if (i == 0 || i == len(label)-1) && r == '-' {
				return "", errors.New("--public-host DNS labels must not start or end with hyphen")
			}
		}
	}
	if bridgeDeployDNSNameLooksReserved(lowerHost) {
		return "", errors.New("--public-host must use a public DNS name, not localhost or reserved/internal/test domains")
	}
	return host, nil
}

func bridgeDeployIPv4LooksPublic(ip net.IP) bool {
	if len(ip) != net.IPv4len {
		return false
	}
	first, second := ip[0], ip[1]
	switch {
	case first == 0:
	case first == 10:
	case first == 127:
	case first == 169 && second == 254:
	case first == 172 && second >= 16 && second <= 31:
	case first == 192 && second == 168:
	case first == 100 && second >= 64 && second <= 127:
	case first == 192 && second == 0 && (ip[2] == 0 || ip[2] == 2):
	case first == 192 && second == 88 && ip[2] == 99:
	case first == 198 && (second == 18 || second == 19):
	case first == 198 && second == 51 && ip[2] == 100:
	case first == 203 && second == 0 && ip[2] == 113:
	case first >= 224:
	default:
		return true
	}
	return false
}

func bridgeDeployDNSNameLooksReserved(host string) bool {
	if host == "localhost" {
		return true
	}
	if host == "example.com" || host == "example.net" || host == "example.org" {
		return true
	}
	if host == "ts.net" || host == "tailscale.net" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".internal", ".test", ".invalid", ".example", ".example.com", ".example.net", ".example.org", ".ts.net", ".tailscale.net"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func validateBridgeDeployListenAddr(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", errors.New("bridge-service-deploy-pack requires --addr")
	}
	if hasBridgeDeployConfigMeta(addr) {
		return "", errors.New("--addr contains unsafe reverse-proxy config characters")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("--addr must be host:port: %w", err)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("--addr host is required")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", errors.New("--addr port must be an integer from 1 to 65535")
	}
	if !isLoopbackListenAddr(addr) {
		return "", errors.New("--addr must use a loopback host for generated reverse-proxy deploy packs")
	}
	return net.JoinHostPort(host, port), nil
}

func hasBridgeDeployConfigMeta(value string) bool {
	for _, r := range value {
		if r <= ' ' || r == 0x7f {
			return true
		}
		switch r {
		case '{', '}', ';', '"', '\'', '`', '$', '(', ')', '<', '>', '|', '&', '#':
			return true
		}
	}
	return false
}

func isLoopbackListenAddr(raw string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func bridgeServiceEnvFile(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(envQuote(values[key]))
		b.WriteByte('\n')
	}
	return b.String()
}

func envQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	return `"` + value + `"`
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
	abuseReportURL := fs.String("abuse-report-url", "", "abuse report URL for this helper; required for active helpers")
	rateLimitPolicy := fs.String("rate-limit-policy", "", "short rate-limit policy for this helper; required for active helpers")
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
		HelperID:        *helperID,
		DisplayName:     *displayName,
		Status:          *status,
		OrgIDs:          splitCommaValues(*orgIDs),
		ContactURL:      *contactURL,
		AbuseReportURL:  *abuseReportURL,
		RateLimitPolicy: *rateLimitPolicy,
		ActiveFromUTC:   *activeFromUTC,
		ActiveUntilUTC:  *activeUntilUTC,
		Reason:          *reason,
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

func runProvenanceSign(args []string) error {
	fs := flag.NewFlagSet("provenance-sign", flag.ContinueOnError)
	summaryFile := fs.String("summary-json", "", "path to access bridge pilot evidence bundle summary JSON")
	bundleTarFile := fs.String("bundle-tar", "", "path to access bridge pilot evidence bundle tarball")
	sidecarFile := fs.String("bundle-tar-sha256-file", "", "path to bundle tar sha256 sidecar")
	privateFile := fs.String("private-key-file", "", "path to private key file")
	orgID := fs.String("org-id", "", "signing organization id")
	orgName := fs.String("org-name", "", "signing organization name")
	orgHomeURL := fs.String("org-home-url", "", "optional organization home URL")
	outFile := fs.String("out", "", "path to write provenance JSON")
	keyID := fs.String("key-id", "", "optional key id; must match the private key")
	lifetimeHours := fs.Int("lifetime-hours", 30*24, "provenance lifetime in hours")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*outFile) == "" {
		return errors.New("provenance-sign requires --out")
	}
	if *lifetimeHours <= 0 {
		return errors.New("provenance-sign requires --lifetime-hours greater than zero")
	}
	priv, err := readPrivateKeyFile(*privateFile)
	if err != nil {
		return err
	}
	derivedKeyID := adminauth.KeyIDFromPublicKey(priv.Public().(ed25519.PublicKey))
	if strings.TrimSpace(*keyID) != "" && strings.TrimSpace(*keyID) != derivedKeyID {
		return fmt.Errorf("provenance-sign --key-id mismatch: got %q, derived %q from private key", strings.TrimSpace(*keyID), derivedKeyID)
	}
	summaryBytes, err := readInputFileStrict(*summaryFile, "evidence bundle summary", maxEvidenceProvenanceBytes)
	if err != nil {
		return err
	}
	bundleTarBytes, err := readInputFileStrict(*bundleTarFile, "evidence bundle tar", maxEvidenceBundleFileBytes)
	if err != nil {
		return err
	}
	sidecarBytes, err := readInputFileStrict(*sidecarFile, "evidence bundle tar sha256 sidecar", maxKeyFileBytes)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	prov, err := accesspack.SignEvidenceBundleProvenance(accesspack.EvidenceBundleProvenanceInput{
		Organization: accesspack.Organization{
			OrgID:   strings.TrimSpace(*orgID),
			Name:    strings.TrimSpace(*orgName),
			HomeURL: strings.TrimSpace(*orgHomeURL),
		},
		IssuedAtUTC:    now.Format(time.RFC3339),
		ExpiresAtUTC:   now.Add(time.Duration(*lifetimeHours) * time.Hour).Format(time.RFC3339),
		EvidenceScope:  evidenceScopeFromSummary(summaryBytes),
		BundleTarName:  filepath.Base(strings.TrimSpace(*bundleTarFile)),
		SummaryBytes:   summaryBytes,
		BundleTarBytes: bundleTarBytes,
		SidecarBytes:   sidecarBytes,
	}, priv)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal provenance: %w", err)
	}
	if err := writeFileWithMode(*outFile, append(out, '\n'), 0o644); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status":          "ok",
		"out":             strings.TrimSpace(*outFile),
		"organization_id": prov.Organization.OrgID,
		"key_id":          prov.Signature.KeyID,
		"evidence_scope":  prov.Subject.EvidenceScope,
		"bundle_tar_name": prov.Subject.BundleTarName,
		"expires_at":      prov.ExpiresAtUTC,
	})
}

func runProvenanceVerify(args []string) error {
	fs := flag.NewFlagSet("provenance-verify", flag.ContinueOnError)
	provenanceFile := fs.String("provenance", "", "path to evidence bundle provenance JSON")
	summaryFile := fs.String("summary-json", "", "path to access bridge pilot evidence bundle summary JSON")
	bundleTarFile := fs.String("bundle-tar", "", "path to access bridge pilot evidence bundle tarball")
	sidecarFile := fs.String("bundle-tar-sha256-file", "", "path to bundle tar sha256 sidecar")
	publicFile := fs.String("public-key-file", "", "path to public key file for one-off diagnostic verification")
	trustStoreFile := fs.String("trust-store", "", "path to access recovery trust store JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*publicFile) != "" && strings.TrimSpace(*trustStoreFile) != "" {
		return errors.New("provenance-verify accepts only one of --trust-store or --public-key-file")
	}
	if strings.TrimSpace(*publicFile) == "" && strings.TrimSpace(*trustStoreFile) == "" {
		return errors.New("provenance-verify requires --trust-store or --public-key-file")
	}
	body, err := readInputFileStrict(*provenanceFile, "evidence bundle provenance", maxEvidenceProvenanceBytes)
	if err != nil {
		return err
	}
	var prov accesspack.EvidenceBundleProvenance
	if err := json.Unmarshal(body, &prov); err != nil {
		return fmt.Errorf("invalid evidence bundle provenance json: %w", err)
	}
	summaryBytes, err := readInputFileStrict(*summaryFile, "evidence bundle summary", maxEvidenceProvenanceBytes)
	if err != nil {
		return err
	}
	bundleTarBytes, err := readInputFileStrict(*bundleTarFile, "evidence bundle tar", maxEvidenceBundleFileBytes)
	if err != nil {
		return err
	}
	sidecarBytes, err := readInputFileStrict(*sidecarFile, "evidence bundle tar sha256 sidecar", maxKeyFileBytes)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	var (
		verified   accesspack.VerifiedEvidenceBundleProvenance
		trustedKey *accesspack.TrustedKey
		trusted    bool
	)
	if strings.TrimSpace(*trustStoreFile) != "" {
		store, err := loadTrustStoreFile(*trustStoreFile)
		if err != nil {
			return err
		}
		var entry accesspack.TrustedKey
		verified, entry, err = accesspack.VerifyEvidenceBundleProvenanceWithTrustStore(store, prov, summaryBytes, bundleTarBytes, sidecarBytes, now)
		if err != nil {
			return err
		}
		trustedKey = &entry
		trusted = true
	} else {
		pub, err := readPublicKeyFile(*publicFile)
		if err != nil {
			return err
		}
		verified, err = accesspack.VerifyEvidenceBundleProvenance(prov, summaryBytes, bundleTarBytes, sidecarBytes, pub, now)
		if err != nil {
			return err
		}
	}
	out := map[string]any{
		"status":              "ok",
		"trusted":             trusted,
		"key_id":              verified.KeyID,
		"organization_id":     verified.Provenance.Organization.OrgID,
		"organization_name":   verified.Provenance.Organization.Name,
		"evidence_scope":      verified.Provenance.Subject.EvidenceScope,
		"bundle_tar_name":     verified.Provenance.Subject.BundleTarName,
		"expires_at_utc":      verified.ExpiresAt.Format(time.RFC3339),
		"canonical_body_size": verified.CanonicalBodySize,
	}
	if trustedKey != nil {
		out["trusted_org_id"] = trustedKey.OrgID
		out["trusted_org_name"] = trustedKey.OrgName
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func evidenceScopeFromSummary(body []byte) string {
	var summary struct {
		EvidenceScope string `json:"evidence_scope"`
	}
	if err := json.Unmarshal(body, &summary); err != nil {
		return "incomplete"
	}
	scope := strings.TrimSpace(summary.EvidenceScope)
	if scope == "" {
		return "incomplete"
	}
	return scope
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
	baseURL := fs.String("base-url", "https://freenews.gpm-pilot.net", "primary demo access URL")
	helperURL := fs.String("helper-url", "https://helper.gpm-pilot.net/freenews/bootstrap", "demo bridge helper URL")
	helperContact := fs.String("helper-contact", "mailto:bridge-helper@gpm-pilot.net", "demo helper contact URL")
	helperID := fs.String("helper-id", "helper-demo", "demo bridge helper id")
	helperName := fs.String("helper-name", "Demo bridge helper", "demo bridge helper display name")
	packAudience := fs.String("pack-audience", "Demo users validating the GPM access recovery flow", "signed access-pack intended audience")
	inviteAudience := fs.String("invite-audience", "Demo users validating a signed helper bootstrap route", "signed bridge-invite intended audience")
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

	pack := demoAccessPack(strings.TrimSpace(*orgID), strings.TrimSpace(*orgName), strings.TrimSpace(*baseURL), strings.TrimSpace(*packAudience), now)
	signedPack, err := accesspack.Sign(pack, priv, "")
	if err != nil {
		return fmt.Errorf("sign demo access pack: %w", err)
	}
	invite := demoBridgeInvite(
		strings.TrimSpace(*orgID),
		strings.TrimSpace(*orgName),
		strings.TrimSpace(*baseURL),
		strings.TrimSpace(*helperID),
		strings.TrimSpace(*helperName),
		strings.TrimSpace(*helperURL),
		strings.TrimSpace(*helperContact),
		strings.TrimSpace(*inviteAudience),
		now,
	)
	signedInvite, err := accesspack.SignBridgeInvite(invite, priv, "")
	if err != nil {
		return fmt.Errorf("sign demo bridge invite: %w", err)
	}
	store, trustedEntry, err := accesspack.AddTrustedKey(accesspack.EmptyTrustStore(), accesspack.TrustedKey{
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
	bridgeHelperRegistry := demoBridgeHelperRegistry(strings.TrimSpace(*orgID), strings.TrimSpace(*helperID), strings.TrimSpace(*helperName), strings.TrimSpace(*helperContact), now)
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
	bridgePolicyOptions.AllowLocalAccessPaths = bridgeDemoBundleUsesLocalAccessPaths(*baseURL, *helperURL)
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
	if err := writeJSONFile(addFile("trusted_key", "recovery-trusted-key.json"), trustedEntry); err != nil {
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
	if err := writeTextAndQR(addFile("trusted_key_text", "recovery-trusted-key.txt"), addFile("trusted_key_qr", "recovery-trusted-key.qr.png"), accesspack.EnvelopeKindKey, trustedEntry, *qrSize); err != nil {
		return err
	}
	storeBody, err := accesspack.MarshalTrustStore(store)
	if err != nil {
		return err
	}
	if err := validateTextEnvelopePayload(accesspack.EnvelopeKindStore, storeBody); err != nil {
		return err
	}
	storeText, err := accesspack.EncodeTextEnvelope(accesspack.EnvelopeKindStore, storeBody)
	if err != nil {
		return err
	}
	if err := writeFileWithMode(addFile("trust_store_text", "recovery-trust.txt"), []byte(storeText+"\n"), 0o644); err != nil {
		return err
	}

	publishDir := filepath.Join("public", ".well-known", "gpm")
	if err := writeJSONFile(addFile("publish_access_pack", filepath.Join(publishDir, "access-pack.json")), signedPack); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("publish_bridge_invite", filepath.Join(publishDir, "bridge-invite.json")), signedInvite); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("publish_bridge_helper_registry_signed", filepath.Join(publishDir, "bridge-helper-registry.signed.json")), bridgeHelperRegistryArtifact); err != nil {
		return err
	}
	if err := writeJSONFile(addFile("publish_trusted_key", filepath.Join(publishDir, "recovery-trusted-key.json")), trustedEntry); err != nil {
		return err
	}
	publishIndex := recoveryPublicationIndex{
		Version:        1,
		GeneratedAtUTC: now.Format(time.RFC3339),
		OrgID:          strings.TrimSpace(*orgID),
		OrgName:        strings.TrimSpace(*orgName),
		KeyID:          keyID,
		Files: map[string]string{
			"access_pack":                   "access-pack.json",
			"bridge_invite":                 "bridge-invite.json",
			"bridge_helper_registry_signed": "bridge-helper-registry.signed.json",
			"trusted_key":                   "recovery-trusted-key.json",
		},
		Notes: []string{
			"Upload this folder to /.well-known/gpm/ on the organization site or mirror.",
			"Users must still verify signatures and trust keys locally before using any recovery path.",
		},
	}
	if err := writeJSONFile(addFile("publish_index", filepath.Join(publishDir, "recovery-index.json")), publishIndex); err != nil {
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
			"Import recovery-trusted-key.json/text/QR as the first-time trusted organization key, or import recovery-trust.json as the full trust store.",
			"Import access-pack.signed.json or bridge-invite.signed.json as the signed artifact.",
			"Import bridge-helper-registry.signed.json, or paste/scan bridge-helper-registry.signed.txt/QR, then click Verify Signed before checking bridge invites.",
			"Or paste/scan the generated GPMREC1 text/QR handoffs.",
			"Upload public/.well-known/gpm/ to a site or mirror when testing static online publication.",
			"Run bridge-registry-verify with bridge-helper-registry.signed.json before publishing a registry snapshot.",
			"Run bridge-registry-check with bridge-helper-registry.json when changing helper status.",
			"Use bridge-registry-upsert-helper to add or update helper registry entries without hand-editing JSON.",
			"Use bridge-registry-set-status to quarantine or re-enable helpers without hand-editing registry JSON.",
			"Run bridge-policy with bridge-helper-registry.signed.json before enabling a helper route in a service; raw registries are diagnostic-only.",
		},
	}
	manifestPath := addFile("manifest", "demo-manifest.json")
	if err := writeJSONFile(manifestPath, out); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func runFetchPublication(args []string) error {
	fs := flag.NewFlagSet("fetch-publication", flag.ContinueOnError)
	indexURL := fs.String("index-url", "", "URL to /.well-known/gpm/recovery-index.json")
	outDir := fs.String("out-dir", "", "empty directory to write fetched publication artifacts")
	timeoutSec := fs.Int("timeout-sec", 10, "HTTP timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	parsedIndexURL, err := parsePublicationIndexURL(*indexURL)
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(*outDir)
	if err := ensureDemoOutputDir(dir); err != nil {
		return err
	}
	timeout := time.Duration(*timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := newPublicationHTTPClient(parsedIndexURL, timeout)
	indexBody, err := fetchPublicationURL(client, parsedIndexURL.String(), maxPublicationIndexBytes)
	if err != nil {
		return err
	}
	var index recoveryPublicationIndex
	if err := json.Unmarshal(indexBody, &index); err != nil {
		return fmt.Errorf("invalid recovery publication index json: %w", err)
	}
	if err := validateRecoveryPublicationIndex(index); err != nil {
		return err
	}
	written := map[string]string{}
	for _, key := range requiredPublicationFileKeys() {
		rel, err := cleanPublicationRelativePath(index.Files[key])
		if err != nil {
			return fmt.Errorf("publication file %s: %w", key, err)
		}
		fileURL, err := resolvePublicationFileURL(parsedIndexURL, rel)
		if err != nil {
			return fmt.Errorf("publication file %s: %w", key, err)
		}
		body, err := fetchPublicationURL(client, fileURL, maxPublicationFileBytes)
		if err != nil {
			return fmt.Errorf("fetch publication file %s: %w", key, err)
		}
		outPath := filepath.Join(dir, filepath.FromSlash(rel))
		if err := writeFileWithMode(outPath, body, 0o644); err != nil {
			return err
		}
		written[key] = outPath
	}
	out := fetchPublicationOutput{
		Status:        "ok",
		IndexURL:      parsedIndexURL.String(),
		OutDir:        dir,
		Files:         written,
		TrustVerified: false,
		NextStep:      "Verify downloaded artifacts with the local trust store before using any recovery path.",
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

func parsePublicationIndexURL(raw string) (*url.URL, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, errors.New("--index-url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid --index-url: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("--index-url must use https:// or http://")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return nil, errors.New("--index-url must include a host")
	}
	if parsed.Scheme == "http" && !isLoopbackPublicationHost(parsed.Hostname()) {
		return nil, errors.New("--index-url must use https:// for remote publication hosts")
	}
	return parsed, nil
}

func validateRecoveryPublicationIndex(index recoveryPublicationIndex) error {
	if index.Version != 1 {
		return fmt.Errorf("unsupported recovery publication index version %d", index.Version)
	}
	if index.Files == nil {
		return errors.New("recovery publication index files is required")
	}
	for _, key := range requiredPublicationFileKeys() {
		if strings.TrimSpace(index.Files[key]) == "" {
			return fmt.Errorf("recovery publication index files.%s is required", key)
		}
	}
	return nil
}

func requiredPublicationFileKeys() []string {
	return []string{
		"access_pack",
		"bridge_invite",
		"bridge_helper_registry_signed",
		"trusted_key",
	}
}

func cleanPublicationRelativePath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("path is required")
	}
	if strings.Contains(value, "\\") {
		return "", errors.New("path must use forward slashes")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" {
		return "", errors.New("path must be relative to the publication index")
	}
	if strings.TrimSpace(parsed.RawQuery) != "" || strings.TrimSpace(parsed.Fragment) != "" {
		return "", errors.New("path must not include query or fragment")
	}
	clean := pathpkg.Clean(parsed.Path)
	if clean == "." || clean == "/" || pathpkg.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("path must stay inside the publication directory")
	}
	return clean, nil
}

func resolvePublicationFileURL(indexURL *url.URL, rel string) (string, error) {
	if indexURL == nil {
		return "", errors.New("index URL is required")
	}
	relURL, err := url.Parse(rel)
	if err != nil {
		return "", fmt.Errorf("invalid relative URL: %w", err)
	}
	resolved := indexURL.ResolveReference(relURL)
	if resolved.Scheme != indexURL.Scheme || !strings.EqualFold(resolved.Host, indexURL.Host) {
		return "", errors.New("publication file must resolve to the same origin as the index")
	}
	return resolved.String(), nil
}

func newPublicationHTTPClient(indexURL *url.URL, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("publication redirect limit exceeded")
			}
			if indexURL == nil || req == nil || req.URL == nil {
				return errors.New("publication redirect target is invalid")
			}
			if !samePublicationOrigin(indexURL, req.URL) {
				return errors.New("publication redirects must stay on the index origin and scheme")
			}
			return nil
		},
	}
}

func samePublicationOrigin(indexURL *url.URL, candidate *url.URL) bool {
	if indexURL == nil || candidate == nil {
		return false
	}
	return candidate.Scheme == indexURL.Scheme &&
		strings.EqualFold(candidate.Hostname(), indexURL.Hostname()) &&
		publicationURLPort(candidate) == publicationURLPort(indexURL)
}

func publicationURLPort(raw *url.URL) string {
	if raw == nil {
		return ""
	}
	if port := raw.Port(); port != "" {
		return port
	}
	switch raw.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isLoopbackPublicationHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func fetchPublicationURL(client *http.Client, rawURL string, maxBytes int64) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "gpmrecover/0 access-recovery-fetch")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds max size %d bytes", maxBytes)
	}
	return body, nil
}

func bridgeDemoBundleUsesLocalAccessPaths(rawURLs ...string) bool {
	for _, raw := range rawURLs {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if bridgeDemoBundleHostLooksLocal(parsed.Hostname()) {
			return true
		}
	}
	return false
}

func bridgeDemoBundleHostLooksLocal(raw string) bool {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func demoAccessPack(orgID string, orgName string, baseURL string, audience string, now time.Time) accesspack.Pack {
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
		IntendedAudience: audience,
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

func demoBridgeInvite(orgID string, orgName string, baseURL string, helperID string, helperName string, helperURL string, helperContact string, audience string, now time.Time) accesspack.BridgeInvite {
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
		IntendedAudience: audience,
		Helper: accesspack.BridgeHelper{
			HelperID:    helperID,
			DisplayName: helperName,
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

func demoBridgeHelperRegistry(orgID string, helperID string, helperName string, helperContact string, now time.Time) accesspack.BridgeHelperRegistry {
	return accesspack.BridgeHelperRegistry{
		Version: accesspack.BridgeHelperRegistryVersion,
		Helpers: []accesspack.BridgeHelperRegistration{
			{
				HelperID:        helperID,
				DisplayName:     helperName,
				Status:          accesspack.BridgeHelperStatusActive,
				OrgIDs:          []string{orgID},
				ContactURL:      helperContact,
				AbuseReportURL:  strings.TrimRight(helperContact, "/") + "/abuse",
				RateLimitPolicy: "beta cap: per-user and per-source limits enforced",
				ActiveFromUTC:   now.Add(-1 * time.Hour).Format(time.RFC3339),
				ActiveUntilUTC:  now.Add(8 * 24 * time.Hour).Format(time.RFC3339),
				UpdatedAtUTC:    now.Format(time.RFC3339),
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
	if err := validateTextEnvelopePayload(kind, body); err != nil {
		return err
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
	if trustStoreFile != "" && publicFile != "" {
		return nil, nil, errors.New("verification accepts only one of --trust-store or --public-key-file")
	}
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
	if trustStoreFile != "" && publicFile != "" {
		return nil, nil, errors.New("bridge verification accepts only one of --trust-store or --public-key-file")
	}
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
	if trustStoreFile != "" && publicFile != "" {
		return nil, nil, errors.New("bridge helper registry verification accepts only one of --trust-store or --public-key-file")
	}
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
