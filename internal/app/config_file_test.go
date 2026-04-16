package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyConfigFileV1OneHop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "easy_mode_config_v1.conf")
	if err := os.WriteFile(path, []byte(
		"EASY_MODE_CONFIG_VERSION=1\n"+
			"SIMPLE_CLIENT_PROFILE_DEFAULT=1hop\n"+
			"SIMPLE_CLIENT_INTERFACE=wgvpn9\n"+
			"SIMPLE_CLIENT_RUN_PREFLIGHT=0\n"+
			"SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=auto\n",
	), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CLIENT_REQUIRE_DISTINCT_OPERATORS", "")
	t.Setenv("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "")
	t.Setenv("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK", "")
	t.Setenv("CLIENT_FORCE_DIRECT_EXIT", "")
	t.Setenv("CLIENT_SESSION_REUSE", "")
	t.Setenv("CLIENT_STICKY_PAIR_SEC", "")
	t.Setenv("CLIENT_PATH_PROFILE", "")
	t.Setenv("CLIENT_WG_INTERFACE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")

	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("CLIENT_REQUIRE_DISTINCT_OPERATORS"); got != "0" {
		t.Fatalf("CLIENT_REQUIRE_DISTINCT_OPERATORS=%q want 0", got)
	}
	if got := os.Getenv("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK"); got != "1" {
		t.Fatalf("CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=%q want 1", got)
	}
	if got := os.Getenv("CLIENT_FORCE_DIRECT_EXIT"); got != "1" {
		t.Fatalf("CLIENT_FORCE_DIRECT_EXIT=%q want 1", got)
	}
	if got := os.Getenv("CLIENT_SESSION_REUSE"); got != "1" {
		t.Fatalf("CLIENT_SESSION_REUSE=%q want 1", got)
	}
	if got := os.Getenv("CLIENT_STICKY_PAIR_SEC"); got != "300" {
		t.Fatalf("CLIENT_STICKY_PAIR_SEC=%q want 300", got)
	}
	if got := os.Getenv("CLIENT_PATH_PROFILE"); got != "1hop" {
		t.Fatalf("CLIENT_PATH_PROFILE=%q want 1hop", got)
	}
	if got := os.Getenv("CLIENT_WG_INTERFACE"); got != "wgvpn9" {
		t.Fatalf("CLIENT_WG_INTERFACE=%q want wgvpn9", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE"); got != "1hop" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE=%q want 1hop", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_INTERFACE"); got != "wgvpn9" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_INTERFACE=%q want wgvpn9", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT"); got != "0" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT=%q want 0", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT"); got != "auto" {
		t.Fatalf("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT=%q want auto", got)
	}
}

func TestApplyConfigFileV1RespectsExistingEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "easy_mode_config_v1.conf")
	if err := os.WriteFile(path, []byte(
		"EASY_MODE_CONFIG_VERSION=1\n"+
			"SIMPLE_CLIENT_PROFILE_DEFAULT=3hop\n"+
			"SIMPLE_CLIENT_RUN_PREFLIGHT=0\n"+
			"SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=1\n",
	), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY", "0")
	t.Setenv("CLIENT_SESSION_REUSE", "0")
	t.Setenv("CLIENT_PATH_PROFILE", "2hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "2hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "1")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "0")
	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY"); got != "0" {
		t.Fatalf("expected existing env to be preserved, got %q", got)
	}
	if got := os.Getenv("CLIENT_SESSION_REUSE"); got != "0" {
		t.Fatalf("expected existing session reuse env to be preserved, got %q", got)
	}
	if got := os.Getenv("CLIENT_PATH_PROFILE"); got != "2hop" {
		t.Fatalf("expected existing path profile env to be preserved, got %q", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE"); got != "2hop" {
		t.Fatalf("expected existing localapi path env to be preserved, got %q", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT"); got != "1" {
		t.Fatalf("expected existing localapi preflight env to be preserved, got %q", got)
	}
	if got := os.Getenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT"); got != "0" {
		t.Fatalf("expected existing localapi prod env to be preserved, got %q", got)
	}
}

func TestApplyConfigFileGenericEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "generic.env")
	if err := os.WriteFile(path, []byte("FOO=bar\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("FOO", "")
	if err := applyConfigFile(path); err != nil {
		t.Fatalf("applyConfigFile: %v", err)
	}
	if got := os.Getenv("FOO"); got != "bar" {
		t.Fatalf("FOO=%q want bar", got)
	}
}

func TestNormalizeConfigV1PathProfileAliasContract(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "1hop", want: "1hop"},
		{in: "2hop", want: "2hop"},
		{in: "3hop", want: "3hop"},
		{in: "speed-1hop", want: "1hop"},
		{in: "speed", want: "2hop"},
		{in: "fast", want: "2hop"},
		{in: "balanced", want: "2hop"},
		{in: "private", want: "3hop"},
		{in: "privacy", want: "3hop"},
		{in: "unknown", want: "2hop"},
	}
	for _, tc := range tests {
		if got := normalizeConfigV1PathProfile(tc.in); got != tc.want {
			t.Fatalf("normalizeConfigV1PathProfile(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}
