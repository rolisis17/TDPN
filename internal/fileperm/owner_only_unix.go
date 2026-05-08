//go:build !windows

package fileperm

import (
	"fmt"
	"os"
)

// ValidateOwnerOnly enforces owner-only filesystem permissions for secret files.
func ValidateOwnerOnly(path string, info os.FileInfo) error {
	if info == nil {
		return fmt.Errorf("file %q metadata is required", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("file %q must not grant group/other permissions", path)
	}
	return nil
}

// RestrictOwnerOnly applies owner-only filesystem permissions for secret files.
func RestrictOwnerOnly(path string) error {
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod owner-only %q: %w", path, err)
	}
	return nil
}
