package accesspack

import (
	"net"
	"net/url"
	"strings"
)

func bridgeAccessPathIsManualFallback(path AccessPath) bool {
	kind := strings.ToLower(strings.TrimSpace(path.Kind))
	if path.RequiresExternalApp || kind == "instructions" {
		return true
	}
	parsed, err := url.Parse(strings.TrimSpace(path.URL))
	return err == nil && strings.EqualFold(parsed.Scheme, "mailto")
}

func bridgeAccessPathServiceURLIssue(path AccessPath) (string, string, bool) {
	manualFallback := bridgeAccessPathIsManualFallback(path)
	parsed, err := url.Parse(strings.TrimSpace(path.URL))
	if err != nil || parsed.Scheme == "" {
		if manualFallback {
			return "manual_path", "requested access path is a manual or external helper path and cannot be served by the bridge service", true
		}
		return "invalid_url", "requested access path URL is invalid", true
	}
	scheme := strings.ToLower(parsed.Scheme)
	if manualFallback && scheme != "http" && scheme != "https" {
		return "manual_path", "requested access path is a manual or external helper path and cannot be served by the bridge service", true
	}
	if parsed.User != nil {
		return "userinfo", "requested access path URL must not include userinfo", true
	}
	if scheme == "http" {
		return "plain_http", "serviceable bridge access paths must use https", true
	}
	if scheme != "https" {
		return "unserviceable_scheme", "requested access path is not an HTTPS bridge service URL", true
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "missing_host", "requested access path URL host is required", true
	}
	if !bridgeAccessPathHostLooksPublic(host) {
		return "private_host", "serviceable bridge access path host must be public-routable", true
	}
	if manualFallback {
		return "manual_path", "requested access path is a manual or external helper path and cannot be served by the bridge service", true
	}
	return "", "", false
}

func bridgeHelperPublicHTTPSURLIssue(raw string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" {
		return "invalid_url", "helper abuse-report URL is invalid", true
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.User != nil {
		return "userinfo", "helper abuse-report URL must not include userinfo", true
	}
	if scheme == "http" {
		return "plain_http", "helper abuse-report URL must use https", true
	}
	if scheme != "https" {
		return "unserviceable_scheme", "helper abuse-report URL must be an HTTPS URL", true
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "missing_host", "helper abuse-report URL host is required", true
	}
	if !bridgeAccessPathHostLooksPublic(host) {
		return "private_host", "helper abuse-report URL host must be public-routable", true
	}
	return "", "", false
}

func bridgeAccessPathLocalDiagnosticIssueAllowed(code string, path AccessPath) bool {
	switch code {
	case "plain_http", "private_host":
		parsed, err := url.Parse(strings.TrimSpace(path.URL))
		if err != nil {
			return false
		}
		return bridgeAccessPathHostLooksLocalDiagnostic(parsed.Hostname())
	default:
		return false
	}
}

func bridgeAccessPathHostLooksLocalDiagnostic(raw string) bool {
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

func bridgeAccessPathHostLooksPublic(raw string) bool {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			return bridgeAccessPathIPv4LooksPublic(ipv4)
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return false
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			return false
		}
		if ip16[0] == 0x20 && ip16[1] == 0x01 && ip16[2] == 0x0d && ip16[3] == 0xb8 {
			return false
		}
		return true
	}
	return bridgeAccessPathDNSNameLooksPublic(host)
}

func bridgeAccessPathIPv4LooksPublic(ip net.IP) bool {
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

func bridgeAccessPathDNSNameLooksReserved(host string) bool {
	if host == "localhost" {
		return true
	}
	if host == "example.com" || host == "example.net" || host == "example.org" {
		return true
	}
	if host == "home.arpa" || host == "ts.net" || host == "tailscale.net" {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".internal", ".test", ".invalid", ".example", ".example.com", ".example.net", ".example.org", ".home.arpa", ".ts.net", ".tailscale.net"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func bridgeAccessPathDNSNameLooksPublic(host string) bool {
	if bridgeAccessPathDNSNameLooksReserved(host) {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
			if !valid {
				return false
			}
		}
	}
	return true
}
