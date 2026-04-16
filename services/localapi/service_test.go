package localapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newFakeService(t *testing.T, allowUpdate bool) (*Service, string) {
	t.Helper()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "easy_node_fake.sh")
	logPath := filepath.Join(tmpDir, "easy_node_calls.log")

	script := `#!/usr/bin/env bash
set -euo pipefail
log_file="${LOCALAPI_TEST_LOG_FILE:?}"
cmd="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi

printf '%s' "$cmd" >>"$log_file"
for arg in "$@"; do
  printf '\t%s' "$arg" >>"$log_file"
done
printf '\n' >>"$log_file"

case "$cmd" in
  client-vpn-preflight)
    if [[ "${LOCALAPI_TEST_PREFLIGHT_FAIL:-0}" == "1" ]]; then
      echo "preflight failed"
      exit 42
    fi
    echo "preflight ok"
    ;;
  client-vpn-up)
    if [[ "${LOCALAPI_TEST_UP_FAIL:-0}" == "1" ]]; then
      echo "connect failed"
      exit 43
    fi
    echo "connect ok"
    ;;
  client-vpn-status)
    if [[ "${LOCALAPI_TEST_STATUS_FAIL:-0}" == "1" ]]; then
      echo "status failed"
      exit 44
    fi
    if [[ "${LOCALAPI_TEST_STATUS_RAW:-0}" == "1" ]]; then
      echo "status-raw"
    else
      echo '{"connected":true,"profile":"2hop"}'
    fi
    ;;
  client-vpn-down)
    if [[ "${LOCALAPI_TEST_DOWN_FAIL:-0}" == "1" ]]; then
      echo "disconnect failed"
      exit 45
    fi
    echo "disconnect ok"
    ;;
  config-v1-set-profile)
    if [[ "${LOCALAPI_TEST_SET_PROFILE_FAIL:-0}" == "1" ]]; then
      echo "set profile failed"
      exit 46
    fi
    echo "set profile ok"
    ;;
  runtime-doctor)
    if [[ "${LOCALAPI_TEST_DIAG_RAW:-0}" == "1" ]]; then
      echo "diagnostics-raw"
    else
      echo '{"runtime":"ok"}'
    fi
    ;;
  self-update)
    if [[ "${LOCALAPI_TEST_UPDATE_FAIL:-0}" == "1" ]]; then
      echo "update failed"
      exit 47
    fi
    echo "update ok"
    ;;
  *)
    echo "ok"
    ;;
esac
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake script: %v", err)
	}
	if err := os.WriteFile(logPath, []byte{}, 0o644); err != nil {
		t.Fatalf("init fake script log: %v", err)
	}
	t.Setenv("LOCALAPI_TEST_LOG_FILE", logPath)

	svc := &Service{
		addr:           "127.0.0.1:0",
		scriptPath:     scriptPath,
		commandTimeout: 5 * time.Second,
		allowUpdate:    allowUpdate,
	}
	return svc, logPath
}

func callJSONHandler(t *testing.T, h http.HandlerFunc, method, path, body string) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	h(rr, req)

	out := map[string]any{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response json (status=%d body=%q): %v", rr.Code, rr.Body.String(), err)
	}
	return rr.Code, out
}

func readCommandLog(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	content := strings.TrimSpace(string(raw))
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	out := make([][]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, strings.Split(line, "\t"))
	}
	return out
}

func commandFlags(parts []string) map[string]string {
	flags := map[string]string{}
	for i := 1; i < len(parts); i++ {
		token := parts[i]
		if !strings.HasPrefix(token, "--") {
			continue
		}
		value := ""
		if i+1 < len(parts) && !strings.HasPrefix(parts[i+1], "--") {
			value = parts[i+1]
			i++
		}
		flags[token] = value
	}
	return flags
}

func mustFlagValue(t *testing.T, parts []string, flag, want string) {
	t.Helper()
	flags := commandFlags(parts)
	got, ok := flags[flag]
	if !ok {
		t.Fatalf("missing flag %s in command %q", flag, strings.Join(parts, " "))
	}
	if got != want {
		t.Fatalf("flag %s=%q want=%q in command %q", flag, got, want, strings.Join(parts, " "))
	}
}

func mustNotHaveFlag(t *testing.T, parts []string, flag string) {
	t.Helper()
	if _, ok := commandFlags(parts)[flag]; ok {
		t.Fatalf("flag %s should not be present in command %q", flag, strings.Join(parts, " "))
	}
}

func TestNormalizePathProfile(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "2hop"},
		{in: "2hop", want: "2hop"},
		{in: "balanced", want: "2hop"},
		{in: "1hop", want: "1hop"},
		{in: "speed", want: "2hop"},
		{in: "speed-1hop", want: "1hop"},
		{in: "3hop", want: "3hop"},
		{in: "private", want: "3hop"},
		{in: " FAST ", want: "2hop"},
		{in: " PRIVACY ", want: "3hop"},
		{in: " 2 ", want: "2hop"},
		{in: "bad", want: ""},
	}
	for _, tc := range tests {
		if got := normalizePathProfile(tc.in); got != tc.want {
			t.Fatalf("normalizePathProfile(%q)=%q want=%q", tc.in, got, tc.want)
		}
	}
}

func TestBoolTo01(t *testing.T) {
	if got := boolTo01(true); got != "1" {
		t.Fatalf("boolTo01(true)=%q", got)
	}
	if got := boolTo01(false); got != "0" {
		t.Fatalf("boolTo01(false)=%q", got)
	}
}

func TestNewDefaultsAndOverrides(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_ADDR", "")
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", "")
		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UPDATE", "")

		s := New()
		if s.addr != defaultAddr {
			t.Fatalf("addr=%q want=%q", s.addr, defaultAddr)
		}
		if s.scriptPath != defaultScriptPath {
			t.Fatalf("scriptPath=%q want=%q", s.scriptPath, defaultScriptPath)
		}
		if s.commandRunner != "" {
			t.Fatalf("commandRunner=%q want empty", s.commandRunner)
		}
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("commandTimeout=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}
		if s.allowUpdate {
			t.Fatalf("allowUpdate=%t want=false", s.allowUpdate)
		}
	})

	t.Run("overrides and timeout validation", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_ADDR", "0.0.0.0:9999")
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", " /tmp/easy_node.sh ")
		t.Setenv("LOCAL_CONTROL_API_RUNNER", " bash ")
		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "240")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UPDATE", "1")

		s := New()
		if s.addr != "0.0.0.0:9999" {
			t.Fatalf("addr=%q", s.addr)
		}
		if s.scriptPath != "/tmp/easy_node.sh" {
			t.Fatalf("scriptPath=%q", s.scriptPath)
		}
		if s.commandRunner != "bash" {
			t.Fatalf("commandRunner=%q", s.commandRunner)
		}
		if s.commandTimeout != 240*time.Second {
			t.Fatalf("commandTimeout=%s", s.commandTimeout)
		}
		if !s.allowUpdate {
			t.Fatalf("allowUpdate=%t want=true", s.allowUpdate)
		}

		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "4")
		s = New()
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("timeout <5 should fall back to default, got=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}

		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "bad")
		s = New()
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("invalid timeout should fall back to default, got=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}
	})
}

func TestBuildEasyNodeCommandWithPlatform(t *testing.T) {
	t.Run("linux defaults to direct script execution", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform("./scripts/easy_node.sh", []string{"client-vpn-status", "--show-json", "1"}, "linux", "")
		if cmdName != "./scripts/easy_node.sh" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{"client-vpn-status", "--show-json", "1"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("explicit runner prefixes script path", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform("./scripts/easy_node.sh", []string{"client-vpn-status"}, "linux", "bash")
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{"./scripts/easy_node.sh", "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows ps1 defaults to powershell", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform(`C:\tdpn\easy_node.ps1`, []string{"client-vpn-status"}, "windows", "")
		if cmdName != "powershell" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		wantPrefix := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", `C:\tdpn\easy_node.ps1`}
		if strings.Join(cmdArgs[:len(wantPrefix)], "\t") != strings.Join(wantPrefix, "\t") {
			t.Fatalf("cmdArgs prefix=%v wantPrefix=%v", cmdArgs, wantPrefix)
		}
		if cmdArgs[len(cmdArgs)-1] != "client-vpn-status" {
			t.Fatalf("cmdArgs tail=%v", cmdArgs)
		}
	})

	t.Run("windows sh defaults to bash", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatform(`C:\tdpn\easy_node.sh`, []string{"client-vpn-status"}, "windows", "")
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})
}

func TestHandleConnectDefaults2Hop(t *testing.T) {
	svc, logPath := newFakeService(t, false)

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"bootstrap_directory":"http://dir.example:8081",
		"invite_key":"inv-test-2hop"
	}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["profile"].(string); got != "2hop" {
		t.Fatalf("profile=%q want=2hop", got)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 3 {
		t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
	}
	if cmds[0][0] != "client-vpn-preflight" || cmds[1][0] != "client-vpn-up" || cmds[2][0] != "client-vpn-status" {
		t.Fatalf("unexpected command order: %v", cmds)
	}

	mustFlagValue(t, cmds[0], "--bootstrap-directory", "http://dir.example:8081")
	mustFlagValue(t, cmds[0], "--discovery-wait-sec", "20")
	mustFlagValue(t, cmds[0], "--prod-profile", "0")
	mustFlagValue(t, cmds[0], "--interface", "wgvpn0")
	mustFlagValue(t, cmds[0], "--operator-floor-check", "1")
	mustFlagValue(t, cmds[0], "--operator-min-operators", "2")
	mustFlagValue(t, cmds[0], "--issuer-quorum-check", "1")
	mustFlagValue(t, cmds[0], "--issuer-min-operators", "2")

	mustFlagValue(t, cmds[1], "--subject", "inv-test-2hop")
	mustFlagValue(t, cmds[1], "--path-profile", "2hop")
	mustFlagValue(t, cmds[1], "--session-reuse", "1")
	mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
	mustFlagValue(t, cmds[1], "--min-operators", "2")
	mustFlagValue(t, cmds[1], "--beta-profile", "1")
	mustFlagValue(t, cmds[1], "--prod-profile", "0")
	mustFlagValue(t, cmds[1], "--install-route", "1")
	mustFlagValue(t, cmds[1], "--ready-timeout-sec", "35")
}

func TestHandleConnectOneHopNormalizationAndOverrides(t *testing.T) {
	t.Run("one-hop defaults from profile alias", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
				"bootstrap_directory":"http://dir.example:8081",
				"invite_key":"inv-test-1hop",
				"path_profile":" speed-1hop "
			}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["profile"].(string); got != "1hop" {
			t.Fatalf("profile=%q want=1hop", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 3 {
			t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
		}
		mustFlagValue(t, cmds[0], "--operator-floor-check", "0")
		mustFlagValue(t, cmds[0], "--operator-min-operators", "1")
		mustFlagValue(t, cmds[0], "--issuer-quorum-check", "0")
		mustFlagValue(t, cmds[0], "--issuer-min-operators", "1")
		mustFlagValue(t, cmds[1], "--path-profile", "1hop")
		mustFlagValue(t, cmds[1], "--session-reuse", "1")
		mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
		mustFlagValue(t, cmds[1], "--min-operators", "1")
		mustFlagValue(t, cmds[1], "--beta-profile", "0")
		mustFlagValue(t, cmds[1], "--prod-profile", "0")
		mustFlagValue(t, cmds[1], "--install-route", "0")
	})

	t.Run("one-hop install_route override and no preflight", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"http://dir.example:8081",
			"invite_key":"inv-test-1hop-up",
			"path_profile":"1hop",
			"run_preflight":false,
			"install_route":true
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-up" || cmds[1][0] != "client-vpn-status" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--session-reuse", "1")
		mustFlagValue(t, cmds[0], "--allow-session-churn", "0")
		mustFlagValue(t, cmds[0], "--install-route", "1")
	})
}

func TestHandleConnectThreeHopProdOverrides(t *testing.T) {
	svc, logPath := newFakeService(t, false)

	code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
		"bootstrap_directory":"http://dir.example:8081",
		"invite_key":"inv-test-3hop",
		"path_profile":"privacy",
		"interface":"wgtest0",
		"discovery_wait_sec":33,
		"ready_timeout_sec":66,
		"prod_profile":true
	}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["profile"].(string); got != "3hop" {
		t.Fatalf("profile=%q want=3hop", got)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 3 {
		t.Fatalf("commands=%d want=3 (%v)", len(cmds), cmds)
	}
	mustFlagValue(t, cmds[0], "--prod-profile", "1")
	mustFlagValue(t, cmds[0], "--interface", "wgtest0")
	mustFlagValue(t, cmds[0], "--discovery-wait-sec", "33")
	mustFlagValue(t, cmds[1], "--path-profile", "3hop")
	mustFlagValue(t, cmds[1], "--session-reuse", "1")
	mustFlagValue(t, cmds[1], "--allow-session-churn", "0")
	mustFlagValue(t, cmds[1], "--prod-profile", "1")
	mustFlagValue(t, cmds[1], "--beta-profile", "1")
	mustFlagValue(t, cmds[1], "--ready-timeout-sec", "66")
	mustFlagValue(t, cmds[1], "--install-route", "1")
}

func TestHandleConnectFailuresAndValidation(t *testing.T) {
	t.Run("validation errors", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, _ := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{"bootstrap_directory":"http://dir.example:8081"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("missing invite key status=%d want=%d", code, http.StatusBadRequest)
		}

		code, _ = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{bad`)
		if code != http.StatusBadRequest {
			t.Fatalf("invalid json status=%d want=%d", code, http.StatusBadRequest)
		}

		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("validation failures should not execute commands, got=%v", cmds)
		}
	})

	t.Run("preflight failure returns conflict and stops", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_PREFLIGHT_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"http://dir.example:8081",
			"invite_key":"inv-preflight-fail"
		}`)
		if code != http.StatusConflict {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["stage"].(string); got != "preflight" {
			t.Fatalf("stage=%q want=preflight", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 1 || cmds[0][0] != "client-vpn-preflight" {
			t.Fatalf("unexpected commands for preflight failure: %v", cmds)
		}
	})

	t.Run("connect failure after preflight returns bad gateway", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_UP_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"http://dir.example:8081",
			"invite_key":"inv-up-fail"
		}`)
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["stage"].(string); got != "connect" {
			t.Fatalf("stage=%q want=connect", got)
		}

		cmds := readCommandLog(t, logPath)
		if len(cmds) != 2 {
			t.Fatalf("commands=%d want=2 (%v)", len(cmds), cmds)
		}
		if cmds[0][0] != "client-vpn-preflight" || cmds[1][0] != "client-vpn-up" {
			t.Fatalf("unexpected command order: %v", cmds)
		}
	})
}

func TestHandleSetProfileNormalizationAndValidation(t *testing.T) {
	svc, logPath := newFakeService(t, false)

	code, payload := callJSONHandler(t, svc.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":" FAST "}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}
	if got, _ := payload["path_profile"].(string); got != "2hop" {
		t.Fatalf("path_profile=%q want=2hop", got)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "config-v1-set-profile" {
		t.Fatalf("unexpected commands for set_profile success: %v", cmds)
	}
	mustFlagValue(t, cmds[0], "--path-profile", "2hop")

	svc2, logPath2 := newFakeService(t, false)
	code, _ = callJSONHandler(t, svc2.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"bad"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid profile status=%d want=%d", code, http.StatusBadRequest)
	}
	if cmds = readCommandLog(t, logPath2); len(cmds) != 0 {
		t.Fatalf("invalid set_profile should not execute commands, got=%v", cmds)
	}
}

func TestHandleUpdateGateAndForwarding(t *testing.T) {
	t.Run("gate disabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"origin",
			"branch":"main",
			"allow_dirty":true
		}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("update disabled should not execute commands, got=%v", cmds)
		}
	})

	t.Run("enabled forwards optional args", func(t *testing.T) {
		svc, logPath := newFakeService(t, true)
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"upstream",
			"branch":"release/v1",
			"allow_dirty":false
		}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		cmds := readCommandLog(t, logPath)
		if len(cmds) != 1 || cmds[0][0] != "self-update" {
			t.Fatalf("unexpected update commands: %v", cmds)
		}
		mustFlagValue(t, cmds[0], "--show-status", "1")
		mustFlagValue(t, cmds[0], "--remote", "upstream")
		mustFlagValue(t, cmds[0], "--branch", "release/v1")
		mustFlagValue(t, cmds[0], "--allow-dirty", "0")
	})
}

func TestHandleStatusVariants(t *testing.T) {
	t.Run("json payload", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		statusMap, ok := payload["status"].(map[string]any)
		if !ok {
			t.Fatalf("status payload missing map: %v", payload)
		}
		if connected, _ := statusMap["connected"].(bool); !connected {
			t.Fatalf("status.connected=%v want=true", statusMap["connected"])
		}
	})

	t.Run("raw payload fallback", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_STATUS_RAW", "1")

		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		statusMap, ok := payload["status"].(map[string]any)
		if !ok {
			t.Fatalf("status payload missing map: %v", payload)
		}
		if raw, _ := statusMap["raw"].(string); raw != "status-raw" {
			t.Fatalf("status.raw=%q want=status-raw", raw)
		}
	})

	t.Run("command failure", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_STATUS_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleStatus, http.MethodGet, "/v1/status", "")
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "status command failed" {
			t.Fatalf("error=%q want=status command failed", got)
		}
	})
}

func TestDiagnosticsAndDisconnectBasicCoverage(t *testing.T) {
	t.Run("diagnostics raw fallback", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_DIAG_RAW", "1")

		code, payload := callJSONHandler(t, svc.handleDiagnostics, http.MethodGet, "/v1/get_diagnostics", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		diagMap, ok := payload["diagnostics"].(map[string]any)
		if !ok {
			t.Fatalf("diagnostics payload missing map: %v", payload)
		}
		if raw, _ := diagMap["raw"].(string); raw != "diagnostics-raw" {
			t.Fatalf("diagnostics.raw=%q want=diagnostics-raw", raw)
		}
	})

	t.Run("disconnect failure mapping", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_DOWN_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "disconnect command failed" {
			t.Fatalf("error=%q want=disconnect command failed", got)
		}
	})
}

func TestMethodGuards(t *testing.T) {
	svc, _ := newFakeService(t, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
	}{
		{name: "health", handler: svc.handleHealth, method: http.MethodPost, target: "/v1/health"},
		{name: "status", handler: svc.handleStatus, method: http.MethodPost, target: "/v1/status"},
		{name: "connect", handler: svc.handleConnect, method: http.MethodGet, target: "/v1/connect"},
		{name: "disconnect", handler: svc.handleDisconnect, method: http.MethodGet, target: "/v1/disconnect"},
		{name: "set_profile", handler: svc.handleSetProfile, method: http.MethodGet, target: "/v1/set_profile"},
		{name: "diagnostics", handler: svc.handleDiagnostics, method: http.MethodPost, target: "/v1/get_diagnostics"},
		{name: "update", handler: svc.handleUpdate, method: http.MethodGet, target: "/v1/update"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, tc.method, tc.target, "")
			if code != http.StatusMethodNotAllowed {
				t.Fatalf("status=%d body=%v", code, payload)
			}
		})
	}
}

func TestUpdateOmitOptionalFlagsWhenUnset(t *testing.T) {
	svc, logPath := newFakeService(t, true)
	code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{}`)
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}

	cmds := readCommandLog(t, logPath)
	if len(cmds) != 1 || cmds[0][0] != "self-update" {
		t.Fatalf("unexpected update commands: %v", cmds)
	}
	mustFlagValue(t, cmds[0], "--show-status", "1")
	mustNotHaveFlag(t, cmds[0], "--remote")
	mustNotHaveFlag(t, cmds[0], "--branch")
	mustNotHaveFlag(t, cmds[0], "--allow-dirty")
}

func TestLoadConnectDefaultsFromEnvFallback(t *testing.T) {
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
	t.Setenv("CLIENT_PATH_PROFILE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
	t.Setenv("CLIENT_WG_INTERFACE", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "")
	t.Setenv("SIMPLE_CLIENT_RUN_PREFLIGHT", "")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")
	t.Setenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT", "")

	got := loadConnectDefaultsFromEnv()
	if got.pathProfile != "2hop" {
		t.Fatalf("pathProfile=%q want 2hop", got.pathProfile)
	}
	if got.interfaceName != "wgvpn0" {
		t.Fatalf("interfaceName=%q want wgvpn0", got.interfaceName)
	}
	if !got.runPreflight {
		t.Fatalf("runPreflight=%t want true", got.runPreflight)
	}
	if got.prodMode != "0" {
		t.Fatalf("prodMode=%q want 0", got.prodMode)
	}
	if defaultProdProfileForMode(got.prodMode, "2hop") {
		t.Fatalf("expected non-prod default when mode is 0")
	}
}

func TestLoadConnectDefaultsFromEnvConfigV1Mapping(t *testing.T) {
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "")
	t.Setenv("CLIENT_PATH_PROFILE", "3hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "")
	t.Setenv("CLIENT_WG_INTERFACE", "wgvpn9")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "0")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "auto")

	got := loadConnectDefaultsFromEnv()
	if got.pathProfile != "3hop" {
		t.Fatalf("pathProfile=%q want 3hop", got.pathProfile)
	}
	if got.interfaceName != "wgvpn9" {
		t.Fatalf("interfaceName=%q want wgvpn9", got.interfaceName)
	}
	if got.runPreflight {
		t.Fatalf("runPreflight=%t want false", got.runPreflight)
	}
	if got.prodMode != "auto" {
		t.Fatalf("prodMode=%q want auto", got.prodMode)
	}
	if !defaultProdProfileForMode(got.prodMode, "3hop") {
		t.Fatalf("expected auto mode to default prod on for 3hop")
	}
	if defaultProdProfileForMode(got.prodMode, "1hop") {
		t.Fatalf("expected auto mode to keep 1hop non-prod")
	}
}

func TestLoadConnectDefaultsFromEnvOverridePriority(t *testing.T) {
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE", "1hop")
	t.Setenv("CLIENT_PATH_PROFILE", "3hop")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_INTERFACE", "wg-localapi")
	t.Setenv("CLIENT_WG_INTERFACE", "wgvpn9")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT", "")
	t.Setenv("SIMPLE_CLIENT_RUN_PREFLIGHT", "0")
	t.Setenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT", "")
	t.Setenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT", "1")

	got := loadConnectDefaultsFromEnv()
	if got.pathProfile != "1hop" {
		t.Fatalf("pathProfile=%q want 1hop", got.pathProfile)
	}
	if got.interfaceName != "wg-localapi" {
		t.Fatalf("interfaceName=%q want wg-localapi", got.interfaceName)
	}
	if got.runPreflight {
		t.Fatalf("runPreflight=%t want false", got.runPreflight)
	}
	if got.prodMode != "1" {
		t.Fatalf("prodMode=%q want 1", got.prodMode)
	}
}

func TestResolveConnectOptionsDefaults(t *testing.T) {
	defaults := connectDefaults{
		pathProfile:   "3hop",
		interfaceName: "wgvpn9",
		runPreflight:  false,
		prodMode:      "auto",
	}
	got := resolveConnectOptions(connectRequest{}, defaults)
	if got.profile != "3hop" {
		t.Fatalf("profile=%q want 3hop", got.profile)
	}
	if got.interfaceName != "wgvpn9" {
		t.Fatalf("interfaceName=%q want wgvpn9", got.interfaceName)
	}
	if got.discoveryWaitSec != defaultDiscoveryWaitSec {
		t.Fatalf("discoveryWaitSec=%d want %d", got.discoveryWaitSec, defaultDiscoveryWaitSec)
	}
	if got.readyTimeoutSec != defaultReadyTimeoutSec {
		t.Fatalf("readyTimeoutSec=%d want %d", got.readyTimeoutSec, defaultReadyTimeoutSec)
	}
	if got.runPreflight {
		t.Fatalf("runPreflight=%t want false", got.runPreflight)
	}
	if !got.prodProfile {
		t.Fatalf("prodProfile=%t want true", got.prodProfile)
	}
	if !got.installRoute {
		t.Fatalf("installRoute=%t want true", got.installRoute)
	}
	if got.installRouteIsSet {
		t.Fatalf("installRouteIsSet=%t want false", got.installRouteIsSet)
	}
}

func TestResolveConnectOptionsRequestOverridesDefaults(t *testing.T) {
	defaults := connectDefaults{
		pathProfile:   "3hop",
		interfaceName: "wgvpn9",
		runPreflight:  false,
		prodMode:      "0",
	}
	runPreflight := true
	prodProfile := true
	installRoute := true
	got := resolveConnectOptions(connectRequest{
		PathProfile:      "1hop",
		Interface:        "wgx0",
		DiscoveryWaitSec: 11,
		ReadyTimeoutSec:  21,
		RunPreflight:     &runPreflight,
		ProdProfile:      &prodProfile,
		InstallRoute:     &installRoute,
	}, defaults)
	if got.profile != "1hop" {
		t.Fatalf("profile=%q want 1hop", got.profile)
	}
	if got.interfaceName != "wgx0" {
		t.Fatalf("interfaceName=%q want wgx0", got.interfaceName)
	}
	if got.discoveryWaitSec != 11 {
		t.Fatalf("discoveryWaitSec=%d want 11", got.discoveryWaitSec)
	}
	if got.readyTimeoutSec != 21 {
		t.Fatalf("readyTimeoutSec=%d want 21", got.readyTimeoutSec)
	}
	if !got.runPreflight {
		t.Fatalf("runPreflight=%t want true", got.runPreflight)
	}
	if !got.prodProfile {
		t.Fatalf("prodProfile=%t want true", got.prodProfile)
	}
	if !got.installRoute {
		t.Fatalf("installRoute=%t want true", got.installRoute)
	}
	if !got.installRouteIsSet {
		t.Fatalf("installRouteIsSet=%t want true", got.installRouteIsSet)
	}
}

func TestDeriveConnectPolicyOneHopKeepsNonProd(t *testing.T) {
	options := resolvedConnectOptions{
		profile:           "1hop",
		prodProfile:       true,
		installRoute:      true,
		installRouteIsSet: false,
	}
	got := deriveConnectPolicy(options)
	if got.prodFlag != 0 {
		t.Fatalf("prodFlag=%d want 0", got.prodFlag)
	}
	if got.betaProfile != 0 {
		t.Fatalf("betaProfile=%d want 0", got.betaProfile)
	}
	if got.installRoute {
		t.Fatalf("installRoute=%t want false for one-hop default", got.installRoute)
	}
}

func TestRunEasyNodeTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "timeout.sh")
	script := "#!/usr/bin/env bash\nset -euo pipefail\nsleep 1\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write timeout script: %v", err)
	}

	svc := &Service{
		scriptPath:     scriptPath,
		commandTimeout: 50 * time.Millisecond,
	}
	out, rc, err := svc.runEasyNode(context.Background(), "ignored")
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	if rc != 124 {
		t.Fatalf("timeout rc=%d want=124", rc)
	}
	if out != "" {
		t.Fatalf("timeout output=%q want empty", out)
	}
}
