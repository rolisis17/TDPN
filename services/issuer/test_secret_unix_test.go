//go:build !windows

package issuer

import (
	"os"
	"testing"
)

func restrictIssuerTestSecretFile(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("restrict test secret file: %v", err)
	}
}
