package types

import (
	"strings"
	"unicode"
)

const (
	objectiveSHA256Prefix = "sha256:"
	objectiveObjectPrefix = "obj://"
)

// IsObjectiveEvidenceFormat reports whether value uses the canonical objective evidence format:
// sha256:<64-hex> or obj://<non-empty-no-whitespace>.
func IsObjectiveEvidenceFormat(value string) bool {
	value = strings.TrimSpace(value)

	if strings.HasPrefix(value, objectiveSHA256Prefix) {
		hash := strings.TrimPrefix(value, objectiveSHA256Prefix)
		return isValidObjectiveSHA256Hex(hash)
	}
	if strings.HasPrefix(value, objectiveObjectPrefix) {
		path := strings.TrimPrefix(value, objectiveObjectPrefix)
		if path == "" {
			return false
		}
		for _, r := range path {
			if unicode.IsSpace(r) || unicode.IsControl(r) || r == '\\' {
				return false
			}
		}
		return true
	}
	return false
}

func isValidObjectiveSHA256Hex(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
