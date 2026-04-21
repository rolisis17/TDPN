package app

import (
	"fmt"
	"strings"
)

const (
	clientPathProfileDefault      = "2hop"
	clientPathProfileAllowedHints = "1hop, 2hop, 3hop, speed, speed-1hop, balanced, private (legacy aliases: fast, privacy)"
)

func resolveClientPathProfile(raw string) (string, string, error) {
	return resolvePathProfileValue(raw, "CLIENT_PATH_PROFILE")
}

func resolveConfigV1PathProfile(raw string) (string, string, error) {
	return resolvePathProfileValue(raw, "SIMPLE_CLIENT_PROFILE_DEFAULT")
}

func resolvePathProfileValue(raw string, source string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	if value == "" {
		return clientPathProfileDefault, "", nil
	}
	if strings.ContainsAny(value, ",|/\\") || len(strings.Fields(value)) > 1 {
		return "", "", fmt.Errorf("%s=%q is ambiguous; choose exactly one profile: %s", source, strings.TrimSpace(raw), clientPathProfileAllowedHints)
	}

	token := strings.ToLower(strings.TrimSpace(value))
	switch token {
	case "1", "1hop", "1-hop", "onehop", "hop1", "hop-1":
		return "1hop", fmt.Sprintf("%s=%s uses a compatibility token; migrate to 1hop (or speed-1hop for explicit experimental one-hop naming)", source, token), nil
	case "speed-1hop", "speed1hop", "fast-1hop", "fast1hop":
		return "1hop", fmt.Sprintf("%s=%s maps to canonical 1hop; keep speed-1hop only when you intentionally want explicit experimental one-hop labeling", source, token), nil
	case "2", "2hop", "2-hop", "twohop", "hop2", "hop-2":
		return "2hop", fmt.Sprintf("%s=%s uses a compatibility token; migrate to 2hop", source, token), nil
	case "speed", "balanced":
		return "2hop", "", nil
	case "fast":
		return "2hop", fmt.Sprintf("%s=fast is a legacy TDPN alias; migrate to speed (GPM label) or 2hop", source), nil
	case "3", "3hop", "3-hop", "threehop", "hop3", "hop-3":
		return "3hop", fmt.Sprintf("%s=%s uses a compatibility token; migrate to 3hop", source, token), nil
	case "private":
		return "3hop", "", nil
	case "privacy":
		return "3hop", fmt.Sprintf("%s=privacy is a legacy TDPN alias; migrate to private (GPM label) or 3hop", source), nil
	default:
		return "", "", fmt.Errorf("%s=%q is invalid; use one of: %s", source, strings.TrimSpace(raw), clientPathProfileAllowedHints)
	}
}
