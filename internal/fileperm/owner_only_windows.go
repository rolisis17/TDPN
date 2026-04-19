//go:build windows

package fileperm

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

var allowedOwnerOnlyTrustees = map[string]struct{}{
	"BA": {}, // Built-in Administrators
	"CO": {}, // Creator Owner
	"LS": {}, // Local Service
	"NS": {}, // Network Service
	"OW": {}, // Owner Rights
	"SY": {}, // Local System
}

type sddlACE struct {
	aceType string
	flags   string
	trustee string
}

// ValidateOwnerOnly enforces owner-only ACL policy for secret files on Windows.
func ValidateOwnerOnly(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect windows ACL for %q: %w", path, err)
	}
	ownerSID, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read windows owner SID for %q: %w", path, err)
	}
	if ownerSID == nil {
		return fmt.Errorf("read windows owner SID for %q: missing owner", path)
	}
	ownerTrustee := strings.ToUpper(strings.TrimSpace(ownerSID.String()))
	if ownerTrustee == "" {
		return fmt.Errorf("read windows owner SID for %q: empty owner", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read windows DACL for %q: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("file %q has empty DACL and is fully permissive", path)
	}
	allowACEs, err := daclAllowACEsFromSDDL(sd.String())
	if err != nil {
		return fmt.Errorf("parse windows DACL for %q: %w", path, err)
	}
	if len(allowACEs) == 0 {
		return fmt.Errorf("file %q has no effective allow ACE entries", path)
	}
	for _, ace := range allowACEs {
		trustee := strings.ToUpper(strings.TrimSpace(ace.trustee))
		if trustee == "" {
			return fmt.Errorf("file %q has malformed allow ACE with empty trustee", path)
		}
		if trustee == ownerTrustee {
			continue
		}
		if _, ok := allowedOwnerOnlyTrustees[trustee]; ok {
			continue
		}
		return fmt.Errorf("file %q grants access to unexpected trustee %q", path, trustee)
	}
	return nil
}

func daclAllowACEsFromSDDL(sddl string) ([]sddlACE, error) {
	daclSection, err := daclSectionFromSDDL(sddl)
	if err != nil {
		return nil, err
	}
	entries, err := splitSDDLEntries(daclSection)
	if err != nil {
		return nil, err
	}
	allowACEs := make([]sddlACE, 0, len(entries))
	for _, entry := range entries {
		parts := strings.Split(entry, ";")
		if len(parts) < 6 {
			return nil, fmt.Errorf("malformed ACE entry %q", entry)
		}
		aceType := strings.ToUpper(strings.TrimSpace(parts[0]))
		flags := strings.ToUpper(strings.TrimSpace(parts[1]))
		trustee := strings.TrimSpace(parts[len(parts)-1])
		if !isAllowACEType(aceType) {
			continue
		}
		// Inherit-only ACEs do not apply to the current object.
		if strings.Contains(flags, "IO") {
			continue
		}
		allowACEs = append(allowACEs, sddlACE{
			aceType: aceType,
			flags:   flags,
			trustee: trustee,
		})
	}
	return allowACEs, nil
}

func daclSectionFromSDDL(sddl string) (string, error) {
	sddl = strings.TrimSpace(sddl)
	if sddl == "" {
		return "", fmt.Errorf("empty security descriptor")
	}
	idx := strings.Index(sddl, "D:")
	if idx < 0 {
		return "", fmt.Errorf("missing DACL section")
	}
	rest := sddl[idx+2:]
	depth := 0
	for i := 0; i+1 < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		}
		if depth == 0 && rest[i] == 'S' && rest[i+1] == ':' {
			return rest[:i], nil
		}
	}
	return rest, nil
}

func splitSDDLEntries(section string) ([]string, error) {
	out := make([]string, 0, 4)
	depth := 0
	start := -1
	for i := 0; i < len(section); i++ {
		switch section[i] {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			if depth == 0 {
				return nil, fmt.Errorf("unexpected ')' in DACL section")
			}
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, strings.TrimSpace(section[start:i]))
				start = -1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unterminated ACE in DACL section")
	}
	return out, nil
}

func isAllowACEType(aceType string) bool {
	switch aceType {
	case "A", "OA", "XA", "ZA", "XU":
		return true
	default:
		return false
	}
}
