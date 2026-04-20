//go:build windows

package fileperm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOwnerOnlyWindowsRejectsPathSwap(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.key")
	second := filepath.Join(dir, "second.key")
	if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
		t.Fatalf("write first file: %v", err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
		t.Fatalf("write second file: %v", err)
	}

	f, err := os.Open(first)
	if err != nil {
		t.Fatalf("open first file: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat first file: %v", err)
	}

	err = ValidateOwnerOnly(second, info)
	if err == nil {
		t.Fatalf("expected path swap to be rejected")
	}
	if !strings.Contains(err.Error(), "changed during ACL validation") {
		t.Fatalf("expected change-during-validation error, got %v", err)
	}
}

func TestValidateOwnerOnlyWindowsRejectsEmptyPath(t *testing.T) {
	err := ValidateOwnerOnly(" \t\r\n ", nil)
	if err == nil {
		t.Fatalf("expected empty path error")
	}
	if !strings.Contains(err.Error(), "file path is required") {
		t.Fatalf("expected required path error, got %v", err)
	}
}

func TestDaclAllowACEsFromSDDLFiltersEffectiveAllowEntries(t *testing.T) {
	sddl := "O:SYG:SYD:(A;;FA;;;SY)(A;IO;FR;;;WD)(D;;FA;;;WD)(OA;;FR;;;BA)S:(ML;;NW;;;LW)"
	aces, err := daclAllowACEsFromSDDL(sddl)
	if err != nil {
		t.Fatalf("daclAllowACEsFromSDDL returned error: %v", err)
	}
	if len(aces) != 2 {
		t.Fatalf("expected two effective allow ACEs, got %d", len(aces))
	}
	if got := strings.ToUpper(strings.TrimSpace(aces[0].trustee)); got != "SY" {
		t.Fatalf("first trustee=%q want SY", got)
	}
	if got := strings.ToUpper(strings.TrimSpace(aces[1].trustee)); got != "BA" {
		t.Fatalf("second trustee=%q want BA", got)
	}
}

func TestDaclAllowACEsFromSDDLRejectsMalformedACE(t *testing.T) {
	_, err := daclAllowACEsFromSDDL("D:(A;;FA;;;SY")
	if err == nil {
		t.Fatalf("expected malformed ACE to be rejected")
	}
	if !strings.Contains(err.Error(), "unterminated ACE") {
		t.Fatalf("expected unterminated ACE error, got %v", err)
	}
}

func TestDaclSectionFromSDDLMissingDACL(t *testing.T) {
	_, err := daclSectionFromSDDL("O:SYG:SYS:(ML;;NW;;;LW)")
	if err == nil {
		t.Fatalf("expected missing DACL section error")
	}
	if !strings.Contains(err.Error(), "missing DACL section") {
		t.Fatalf("expected missing DACL error, got %v", err)
	}
}
