package app

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func (c *Client) enforceDirectoryTrust(pubB64 string) error {
	return c.enforceDirectoryTrustSet([]string{pubB64})
}

func (c *Client) enforceDirectoryTrustSet(pubKeys []string) error {
	if !c.trustStrict {
		return nil
	}
	filtered := dedupeKeyList(pubKeys)
	if len(filtered) == 0 {
		return fmt.Errorf("directory returned no pubkeys")
	}
	trusted, err := loadTrustedKeys(c.trustFile)
	if err != nil {
		return err
	}
	for _, key := range filtered {
		if _, ok := trusted[key]; ok {
			// Auto-pin additional keys announced by a trusted directory keyset.
			for _, candidate := range filtered {
				if _, known := trusted[candidate]; known {
					continue
				}
				if err := appendTrustedKey(c.trustFile, candidate); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if c.trustTOFU && len(trusted) == 0 {
		if err := appendTrustedKey(c.trustFile, filtered[0]); err != nil {
			return err
		}
		log.Printf("client TOFU pinned directory key to %s", c.trustFile)
		for _, key := range filtered[1:] {
			if err := appendTrustedKey(c.trustFile, key); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("directory key is not trusted")
}

func dedupeKeyList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, k := range in {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func loadTrustedKeys(path string) (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	b, err := os.ReadFile(path)
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
		raw, err := base64.RawURLEncoding.DecodeString(line)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid trusted key entry: %s", line)
		}
		keys[line] = struct{}{}
	}
	return keys, nil
}

func appendTrustedKey(path string, key string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	existing, err := loadTrustedKeys(path)
	if err != nil {
		return err
	}
	if _, ok := existing[key]; ok {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(key + "\n")
	return err
}
