package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const clientTrustedKeysFileMaxBytes int64 = 256 << 10

func (c *Client) enforceDirectoryTrust(pubB64 string) error {
	return c.enforceDirectoryTrustSet([]string{pubB64})
}

func (c *Client) enforceDirectoryTrustSet(pubKeys []string) error {
	_, _, err := c.selectTrustedDirectoryPubKeys(pubKeys)
	return err
}

func (c *Client) selectTrustedDirectoryPubKeys(pubKeys []string) ([]string, []ed25519.PublicKey, error) {
	canonical, decoded, err := validateDirectoryPubKeySet(pubKeys)
	if err != nil {
		return nil, nil, err
	}
	if len(canonical) == 0 {
		return nil, nil, fmt.Errorf("directory returned no pubkeys")
	}
	if !c.trustStrict {
		return canonical, decoded, nil
	}
	trusted, err := loadTrustedKeys(c.trustFile)
	if err != nil {
		return nil, nil, err
	}
	allowedCanonical := make([]string, 0, len(canonical))
	allowedDecoded := make([]ed25519.PublicKey, 0, len(canonical))
	for i, key := range canonical {
		if _, ok := trusted[key]; !ok {
			continue
		}
		allowedCanonical = append(allowedCanonical, key)
		allowedDecoded = append(allowedDecoded, decoded[i])
	}
	if len(allowedCanonical) > 0 {
		if len(allowedCanonical) != len(canonical) {
			log.Printf("client ignored %d untrusted directory pubkeys in strict mode", len(canonical)-len(allowedCanonical))
		}
		return allowedCanonical, allowedDecoded, nil
	}
	if c.trustTOFU && len(trusted) == 0 {
		for _, key := range canonical {
			if err := appendTrustedKey(c.trustFile, key); err != nil {
				return nil, nil, err
			}
		}
		log.Printf("client TOFU pinned directory key to %s", c.trustFile)
		return canonical, decoded, nil
	}
	return nil, nil, fmt.Errorf("directory key is not trusted")
}

func validateDirectoryPubKey(key string) (string, ed25519.PublicKey, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", nil, fmt.Errorf("invalid directory pubkey")
	}
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("invalid directory pubkey")
	}
	canonical := base64.RawURLEncoding.EncodeToString(raw)
	return canonical, ed25519.PublicKey(raw), nil
}

func validateDirectoryPubKeySet(in []string) ([]string, []ed25519.PublicKey, error) {
	out := make([]string, 0, len(in))
	decoded := make([]ed25519.PublicKey, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, key := range in {
		canonical, raw, err := validateDirectoryPubKey(key)
		if err != nil {
			return nil, nil, err
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
		decoded = append(decoded, raw)
	}
	return out, decoded, nil
}

func loadTrustedKeys(path string) (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	b, err := readAppFileBounded(path, clientTrustedKeysFileMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canonical, _, err := validateDirectoryPubKey(line)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted key entry: %s", line)
		}
		keys[canonical] = struct{}{}
	}
	return keys, nil
}

func appendTrustedKey(path string, key string) error {
	canonical, _, err := validateDirectoryPubKey(key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	existing, err := loadTrustedKeys(path)
	if err != nil {
		return err
	}
	if _, ok := existing[canonical]; ok {
		return nil
	}
	lstatInfo, statErr := os.Lstat(path)
	if statErr != nil {
		if !os.IsNotExist(statErr) {
			return statErr
		}
		f, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if createErr != nil {
			return createErr
		}
		defer f.Close()
		_, createErr = f.WriteString(canonical + "\n")
		return createErr
	}
	if lstatInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("file %s must not be a symlink", path)
	}
	if !lstatInfo.Mode().IsRegular() {
		return fmt.Errorf("file %s must be a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("file %s must be a regular file", path)
	}
	if !os.SameFile(lstatInfo, info) {
		return fmt.Errorf("file %s changed during open", path)
	}
	_, err = f.WriteString(canonical + "\n")
	return err
}
