package app

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func applyConfigFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == "" {
			continue
		}
		values[key] = val
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if len(values) == 0 {
		return nil
	}

	if strings.TrimSpace(values["EASY_MODE_CONFIG_VERSION"]) == "1" {
		applyEasyModeConfigV1(values)
		return nil
	}

	for key, val := range values {
		setEnvIfUnset(key, val)
	}
	return nil
}

func applyEasyModeConfigV1(values map[string]string) {
	profile := normalizeConfigV1PathProfile(values["SIMPLE_CLIENT_PROFILE_DEFAULT"])
	applyPathProfileFromConfigV1(values["SIMPLE_CLIENT_PROFILE_DEFAULT"])
	setEnvIfUnset("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", profile)

	iface := strings.TrimSpace(values["SIMPLE_CLIENT_INTERFACE"])
	setEnvIfUnset("CLIENT_WG_INTERFACE", iface)
	setEnvIfUnset("LOCAL_CONTROL_API_CONNECT_INTERFACE", iface)

	setEnvIfUnset(
		"LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT",
		normalizeConfigV1Bool01(values["SIMPLE_CLIENT_RUN_PREFLIGHT"], "1"),
	)
	setEnvIfUnset(
		"LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT",
		normalizeConfigV1ProdProfileDefault(values["SIMPLE_CLIENT_PROD_PROFILE_DEFAULT"]),
	)
}

func applyPathProfileFromConfigV1(raw string) {
	profile := normalizeConfigV1PathProfile(raw)
	setEnvIfUnset("CLIENT_PATH_PROFILE", profile)
	// Easy mode should keep VPN sessions alive by default. Expert flows can still
	// override this explicitly with CLIENT_SESSION_REUSE=0.
	setEnvIfUnset("CLIENT_SESSION_REUSE", "1")
	switch profile {
	case "1hop":
		setEnvIfUnset("CLIENT_REQUIRE_DISTINCT_OPERATORS", "0")
		setEnvIfUnset("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "0")
		setEnvIfUnset("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK", "1")
		setEnvIfUnset("CLIENT_FORCE_DIRECT_EXIT", "1")
		setEnvIfUnset("CLIENT_STICKY_PAIR_SEC", "300")
	case "3hop":
		setEnvIfUnset("CLIENT_REQUIRE_DISTINCT_OPERATORS", "1")
		setEnvIfUnset("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "1")
		setEnvIfUnset("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK", "0")
		setEnvIfUnset("CLIENT_FORCE_DIRECT_EXIT", "0")
	default:
		setEnvIfUnset("CLIENT_REQUIRE_DISTINCT_OPERATORS", "1")
		setEnvIfUnset("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "0")
		setEnvIfUnset("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK", "0")
		setEnvIfUnset("CLIENT_FORCE_DIRECT_EXIT", "0")
	}
}

func normalizeConfigV1PathProfile(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "1", "1hop", "speed-1hop":
		return "1hop"
	case "2", "2hop", "speed", "fast", "balanced":
		return "2hop"
	case "3", "3hop", "private", "privacy":
		return "3hop"
	default:
		return "2hop"
	}
}

func normalizeConfigV1ProdProfileDefault(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "auto":
		return "auto"
	case "1", "true", "yes", "y", "on":
		return "1"
	case "0", "false", "no", "n", "off":
		return "0"
	default:
		return "auto"
	}
}

func normalizeConfigV1Bool01(raw string, fallback string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "1", "true", "yes", "y", "on":
		return "1"
	case "0", "false", "no", "n", "off":
		return "0"
	default:
		fallback = strings.TrimSpace(fallback)
		if fallback == "0" {
			return "0"
		}
		return "1"
	}
}

func setEnvIfUnset(key string, value string) {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return
	}
	if strings.TrimSpace(os.Getenv(key)) != "" {
		return
	}
	_ = os.Setenv(key, value)
}
