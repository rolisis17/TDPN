package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

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

if [[ -n "${LOCALAPI_TEST_OUTPUT_BYTES:-}" ]]; then
  if [[ "${LOCALAPI_TEST_OUTPUT_BYTES}" =~ ^[0-9]+$ ]] && [[ "${LOCALAPI_TEST_OUTPUT_BYTES}" -gt 0 ]]; then
    head -c "${LOCALAPI_TEST_OUTPUT_BYTES}" < /dev/zero | tr '\0' 'A'
  fi
  exit 0
fi

case "$cmd" in
  client-vpn-preflight)
    if [[ "${LOCALAPI_TEST_PREFLIGHT_FAIL:-0}" == "1" ]]; then
      echo "preflight failed"
      exit 42
    fi
    echo "preflight ok"
    ;;
  client-vpn-up)
    subject_file=""
    saw_inline_subject="0"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --subject)
          saw_inline_subject="1"
          if [[ $# -gt 1 ]]; then
            shift 2
          else
            shift
          fi
          ;;
        --subject-file)
          subject_file="${2:-}"
          if [[ $# -gt 1 ]]; then
            shift 2
          else
            shift
          fi
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ "$saw_inline_subject" == "1" ]]; then
      echo "unexpected inline subject flag"
      exit 48
    fi
    if [[ -z "$subject_file" || ! -f "$subject_file" ]]; then
      echo "missing subject file"
      exit 48
    fi
    subject_value="$(tr -d '\r\n' <"$subject_file")"
    if [[ -z "$subject_value" ]]; then
      echo "empty subject file"
      exit 48
    fi
    if [[ "$subject_value" == *$'\n'* || "$subject_value" == *$'\r'* ]]; then
      echo "invalid subject value"
      exit 49
    fi
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
		addr:                "127.0.0.1:8095",
		scriptPath:          scriptPath,
		commandTimeout:      5 * time.Second,
		maxConcurrentCmds:   defaultMaxCommands,
		commandSlots:        make(chan struct{}, defaultMaxCommands),
		allowUpdate:         allowUpdate,
		allowUnauthLoopback: true,
	}
	return svc, logPath
}

func callJSONHandler(t *testing.T, h http.HandlerFunc, method, path, body string) (int, map[string]any) {
	return callJSONHandlerWithHeaders(t, h, method, path, body, nil)
}

func callJSONHandlerWithHeaders(t *testing.T, h http.HandlerFunc, method, path, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodGet {
		if headers == nil {
			headers = map[string]string{}
		}
		if _, hasOrigin := headers["Origin"]; !hasOrigin {
			headers["Origin"] = "http://127.0.0.1:8095"
		}
	}
	for key, value := range headers {
		req.Header.Set(key, value)
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

func mustFlagNonEmptyValue(t *testing.T, parts []string, flag string) string {
	t.Helper()
	flags := commandFlags(parts)
	got, ok := flags[flag]
	if !ok {
		t.Fatalf("missing flag %s in command %q", flag, strings.Join(parts, " "))
	}
	if strings.TrimSpace(got) == "" {
		t.Fatalf("flag %s has empty value in command %q", flag, strings.Join(parts, " "))
	}
	return got
}

func mustNotHaveFlag(t *testing.T, parts []string, flag string) {
	t.Helper()
	if _, ok := commandFlags(parts)[flag]; ok {
		t.Fatalf("flag %s should not be present in command %q", flag, strings.Join(parts, " "))
	}
}

func mustNotContainToken(t *testing.T, parts []string, token string) {
	t.Helper()
	for _, part := range parts {
		if part == token {
			t.Fatalf("token %q should not be present in command %q", token, strings.Join(parts, " "))
		}
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

func TestWriteSecretTempFile(t *testing.T) {
	path, cleanup, err := writeSecretTempFile("localapi-test-", "invite-secret")
	if err != nil {
		t.Fatalf("writeSecretTempFile returned err: %v", err)
	}
	if cleanup == nil {
		t.Fatal("writeSecretTempFile returned nil cleanup")
	}
	defer cleanup()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp file: %v", err)
	}
	if string(content) != "invite-secret" {
		t.Fatalf("temp file content=%q want=%q", string(content), "invite-secret")
	}

	cleanup()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cleanup to remove file, stat err=%v", err)
	}
}

func TestWriteSecretTempFileRejectsEmptySecret(t *testing.T) {
	if _, _, err := writeSecretTempFile("localapi-test-", "   "); err == nil {
		t.Fatal("expected empty secret to be rejected")
	}
}

func TestNewDefaultsAndOverrides(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_ADDR", "")
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", "")
		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UPDATE", "")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "")
		t.Setenv(allowInsecureHTTPEnv, "")
		t.Setenv(maxCommandsEnv, "")
		t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", "")

		s := New()
		if s.addr != defaultAddr {
			t.Fatalf("addr=%q want=%q", s.addr, defaultAddr)
		}
		if s.scriptPath != "" && !filepath.IsAbs(s.scriptPath) {
			t.Fatalf("scriptPath should be absolute or disabled, got=%q", s.scriptPath)
		}
		if s.commandRunner != "" {
			t.Fatalf("commandRunner=%q want empty", s.commandRunner)
		}
		if s.commandTimeout != defaultCommandTimeout {
			t.Fatalf("commandTimeout=%s want=%s", s.commandTimeout, defaultCommandTimeout)
		}
		if s.maxConcurrentCmds != defaultMaxCommands {
			t.Fatalf("maxConcurrentCmds=%d want=%d", s.maxConcurrentCmds, defaultMaxCommands)
		}
		if cap(s.commandSlots) != defaultMaxCommands {
			t.Fatalf("commandSlots cap=%d want=%d", cap(s.commandSlots), defaultMaxCommands)
		}
		if s.allowUpdate {
			t.Fatalf("allowUpdate=%t want=false", s.allowUpdate)
		}
		if s.allowUnauthLoopback {
			t.Fatalf("allowUnauthLoopback=%t want=false", s.allowUnauthLoopback)
		}
		if s.allowInsecureHTTP {
			t.Fatalf("allowInsecureHTTP=%t want=false", s.allowInsecureHTTP)
		}
		if s.authToken != "" {
			t.Fatalf("authToken=%q want empty", s.authToken)
		}
	})

	t.Run("overrides and timeout validation", func(t *testing.T) {
		tmpDir := t.TempDir()
		overrideScriptPath := filepath.Join(tmpDir, "easy_node.sh")
		if err := os.WriteFile(overrideScriptPath, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write override script: %v", err)
		}

		t.Setenv("LOCAL_CONTROL_API_ADDR", "0.0.0.0:9999")
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", " "+overrideScriptPath+" ")
		t.Setenv("LOCAL_CONTROL_API_RUNNER", " bash ")
		t.Setenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC", "240")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UPDATE", "1")
		t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "1")
		t.Setenv(allowInsecureHTTPEnv, "1")
		t.Setenv(maxCommandsEnv, "9")
		t.Setenv("LOCAL_CONTROL_API_AUTH_TOKEN", " local-secret ")

		s := New()
		if s.addr != "0.0.0.0:9999" {
			t.Fatalf("addr=%q", s.addr)
		}
		if s.scriptPath != overrideScriptPath {
			t.Fatalf("scriptPath=%q want=%q", s.scriptPath, overrideScriptPath)
		}
		if s.commandRunner != "bash" {
			t.Fatalf("commandRunner=%q", s.commandRunner)
		}
		if s.commandTimeout != 240*time.Second {
			t.Fatalf("commandTimeout=%s", s.commandTimeout)
		}
		if s.maxConcurrentCmds != 9 {
			t.Fatalf("maxConcurrentCmds=%d want=9", s.maxConcurrentCmds)
		}
		if !s.allowUpdate {
			t.Fatalf("allowUpdate=%t want=true", s.allowUpdate)
		}
		if !s.allowUnauthLoopback {
			t.Fatalf("allowUnauthLoopback=%t want=true", s.allowUnauthLoopback)
		}
		if !s.allowInsecureHTTP {
			t.Fatalf("allowInsecureHTTP=%t want=true", s.allowInsecureHTTP)
		}
		if s.authToken != "local-secret" {
			t.Fatalf("authToken=%q want=%q", s.authToken, "local-secret")
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

		t.Setenv("LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK", "not-bool")
		s = New()
		if s.allowUnauthLoopback {
			t.Fatalf("invalid LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK should default to false")
		}

		t.Setenv(maxCommandsEnv, "0")
		s = New()
		if s.maxConcurrentCmds != defaultMaxCommands {
			t.Fatalf("maxConcurrentCmds=%d want default %d for zero", s.maxConcurrentCmds, defaultMaxCommands)
		}

		t.Setenv(maxCommandsEnv, "bad")
		s = New()
		if s.maxConcurrentCmds != defaultMaxCommands {
			t.Fatalf("maxConcurrentCmds=%d want default %d for invalid value", s.maxConcurrentCmds, defaultMaxCommands)
		}

		t.Setenv(maxCommandsEnv, "1000")
		s = New()
		if s.maxConcurrentCmds != maxAllowedCommands {
			t.Fatalf("maxConcurrentCmds=%d want capped %d", s.maxConcurrentCmds, maxAllowedCommands)
		}
	})

	t.Run("invalid script path fails safe", func(t *testing.T) {
		t.Setenv("LOCAL_CONTROL_API_SCRIPT", filepath.Join(t.TempDir(), "does-not-exist.sh"))
		s := New()
		if s.scriptPath != "" {
			t.Fatalf("scriptPath=%q want empty when configured script path is invalid", s.scriptPath)
		}
	})
}

func TestRunRejectsInsecureNonLoopbackBindByDefault(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.addr = "0.0.0.0:8095"
	svc.allowInsecureHTTP = false

	err := svc.Run(context.Background())
	if err == nil {
		t.Fatal("expected non-loopback insecure bind to be rejected")
	}
	if !strings.Contains(err.Error(), allowInsecureHTTPEnv) {
		t.Fatalf("expected error to mention %s, got %v", allowInsecureHTTPEnv, err)
	}
}

func TestResolveControlScriptPathWithLookup(t *testing.T) {
	origEval := evalSymlinksPath
	t.Cleanup(func() {
		evalSymlinksPath = origEval
	})

	t.Run("anchors default path to executable directory", func(t *testing.T) {
		evalSymlinksPath = func(path string) (string, error) { return path, nil }
		execPath := "/opt/tdpn/bin/localapi"
		want := "/opt/tdpn/bin/scripts/easy_node.sh"
		got, err := resolveControlScriptPathWithLookup(
			"",
			func() (string, error) { return execPath, nil },
			func(path string) (os.FileInfo, error) {
				if path != want {
					return nil, os.ErrNotExist
				}
				return fakeFileInfo{name: "easy_node.sh", mode: 0o755}, nil
			},
		)
		if err != nil {
			t.Fatalf("resolve default script path error: %v", err)
		}
		if got != want {
			t.Fatalf("got=%q want=%q", got, want)
		}
	})

	t.Run("rejects relative path escaping executable directory", func(t *testing.T) {
		evalSymlinksPath = func(path string) (string, error) { return path, nil }
		_, err := resolveControlScriptPathWithLookup(
			"../outside.sh",
			func() (string, error) { return "/opt/tdpn/bin/localapi", nil },
			func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		)
		if err == nil {
			t.Fatalf("expected escaping path to fail")
		}
	})

	t.Run("requires an existing non-directory target", func(t *testing.T) {
		evalSymlinksPath = func(path string) (string, error) { return path, nil }
		_, err := resolveControlScriptPathWithLookup(
			"/opt/tdpn/scripts/easy_node.sh",
			nil,
			func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		)
		if err == nil {
			t.Fatalf("expected missing script path to fail")
		}

		_, err = resolveControlScriptPathWithLookup(
			"/opt/tdpn/scripts",
			nil,
			func(string) (os.FileInfo, error) {
				return fakeFileInfo{name: "scripts", mode: os.ModeDir | 0o755}, nil
			},
		)
		if err == nil {
			t.Fatalf("expected directory script path to fail")
		}
	})

	t.Run("rejects symlink target escaping executable directory", func(t *testing.T) {
		evalSymlinksPath = filepath.EvalSymlinks
		root := t.TempDir()
		execDir := filepath.Join(root, "bin")
		scriptDir := filepath.Join(execDir, "scripts")
		outsidePath := filepath.Join(root, "outside.sh")
		if err := os.MkdirAll(scriptDir, 0o755); err != nil {
			t.Fatalf("mkdir script dir: %v", err)
		}
		if err := os.WriteFile(outsidePath, []byte("#!/usr/bin/env bash\n"), 0o755); err != nil {
			t.Fatalf("write outside script: %v", err)
		}
		linkPath := filepath.Join(scriptDir, "easy_node.sh")
		if err := os.Symlink(outsidePath, linkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		execPath := filepath.Join(execDir, "localapi")
		got, err := resolveControlScriptPathWithLookup("", func() (string, error) { return execPath, nil }, os.Stat)
		if err == nil {
			t.Fatalf("expected symlink escape to fail, got path=%q", got)
		}
		if !strings.Contains(err.Error(), "resolves outside executable directory") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestBuildLifecycleCommandWithPlatform(t *testing.T) {
	t.Run("parses command into binary and args", func(t *testing.T) {
		cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform("systemctl restart tdpn-entry", runtime.GOOS)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if cmdName != "systemctl" {
			t.Fatalf("cmdName=%q want=systemctl", cmdName)
		}
		want := []string{"restart", "tdpn-entry"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("supports quoted args", func(t *testing.T) {
		cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform(`echo "service running"`, runtime.GOOS)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if cmdName != "echo" {
			t.Fatalf("cmdName=%q want=echo", cmdName)
		}
		want := []string{"service running"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("rejects implicit shell control operators", func(t *testing.T) {
		_, _, err := buildLifecycleCommandWithPlatform("echo bad && exit 1", runtime.GOOS)
		if err == nil {
			t.Fatalf("expected command with shell control operators to be rejected")
		}
		if !strings.Contains(err.Error(), "shell control operators") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("allows explicit shell binary invocation", func(t *testing.T) {
		cmdName, cmdArgs, err := buildLifecycleCommandWithPlatform(`bash -lc "echo ok && exit 0"`, runtime.GOOS)
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q want=bash", cmdName)
		}
		want := []string{"-lc", "echo ok && exit 0"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
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

	t.Run("windows sh defaults to bash when no git-bash candidate is available", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(string) string { return "" },
			func(string) bool { return false },
		)
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q", cmdName)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows sh prefers git-bash candidates by default", func(t *testing.T) {
		gitBashPath := `C:\Program Files\Git\bin\bash.exe`
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(string) string { return "" },
			func(path string) bool { return path == gitBashPath },
		)
		if cmdName != gitBashPath {
			t.Fatalf("cmdName=%q want=%q", cmdName, gitBashPath)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows sh honors explicit git-bash path override", func(t *testing.T) {
		override := `D:\portable\git\bin\bash.exe`
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(name string) string {
				if name == "LOCAL_CONTROL_API_GIT_BASH_PATH" {
					return override
				}
				return ""
			},
			func(string) bool { return false },
		)
		if cmdName != override {
			t.Fatalf("cmdName=%q want=%q", cmdName, override)
		}
		want := []string{`C:\tdpn\easy_node.sh`, "client-vpn-status"}
		if strings.Join(cmdArgs, "\t") != strings.Join(want, "\t") {
			t.Fatalf("cmdArgs=%v want=%v", cmdArgs, want)
		}
	})

	t.Run("windows sh can disable git-bash preference", func(t *testing.T) {
		cmdName, cmdArgs := buildEasyNodeCommandWithPlatformWithLookup(
			`C:\tdpn\easy_node.sh`,
			[]string{"client-vpn-status"},
			"windows",
			"",
			func(name string) string {
				if name == "LOCAL_CONTROL_API_PREFER_GIT_BASH" {
					return "0"
				}
				return ""
			},
			func(string) bool { return true },
		)
		if cmdName != "bash" {
			t.Fatalf("cmdName=%q want=bash", cmdName)
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
		"bootstrap_directory":"https://dir.example:8081",
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

	mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir.example:8081")
	mustFlagValue(t, cmds[0], "--discovery-wait-sec", "20")
	mustFlagValue(t, cmds[0], "--prod-profile", "0")
	mustFlagValue(t, cmds[0], "--interface", "wgvpn0")
	mustFlagValue(t, cmds[0], "--operator-floor-check", "1")
	mustFlagValue(t, cmds[0], "--operator-min-operators", "2")
	mustFlagValue(t, cmds[0], "--issuer-quorum-check", "1")
	mustFlagValue(t, cmds[0], "--issuer-min-operators", "2")

	mustNotContainToken(t, cmds[1], "--subject")
	subjectFile := mustFlagNonEmptyValue(t, cmds[1], "--subject-file")
	if _, err := os.Stat(subjectFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("subject file should be cleaned up after connect; stat err=%v path=%q", err, subjectFile)
	}
	mustNotContainToken(t, cmds[1], "inv-test-2hop")
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
					"bootstrap_directory":"https://dir.example:8081",
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
				"bootstrap_directory":"https://dir.example:8081",
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
		"bootstrap_directory":"https://dir.example:8081",
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

		code, _ := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{"bootstrap_directory":"https://dir.example:8081"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("missing invite key status=%d want=%d", code, http.StatusBadRequest)
		}

		code, _ = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{bad`)
		if code != http.StatusBadRequest {
			t.Fatalf("invalid json status=%d want=%d", code, http.StatusBadRequest)
		}
		code, _ = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{"bootstrap_directory":"https://dir.example:8081","invite_key":"inv"}{"extra":1}`)
		if code != http.StatusBadRequest {
			t.Fatalf("trailing json status=%d want=%d", code, http.StatusBadRequest)
		}

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"http://dir.example:8081",
			"invite_key":"inv-insecure-http"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("insecure bootstrap_directory status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "must use https for non-loopback hosts") {
			t.Fatalf("error=%q want insecure remote https guidance", got)
		}

		code, payload = callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-with-control\u0000"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("invalid invite key status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid control characters") {
			t.Fatalf("error=%q want invite key control-char guidance", got)
		}

		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("validation failures should not execute commands, got=%v", cmds)
		}
	})

	t.Run("interface validation rejects non-wireguard names", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-invalid-iface",
			"interface":"eth0"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "interface must start with wg") {
			t.Fatalf("error=%q want interface validation message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid interface should not execute commands, got=%v", cmds)
		}
	})

	t.Run("preflight failure returns conflict and stops", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		t.Setenv("LOCALAPI_TEST_PREFLIGHT_FAIL", "1")

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
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
			"bootstrap_directory":"https://dir.example:8081",
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

func TestHandleConnectSessionRequiredMode(t *testing.T) {
	t.Run("manual overrides are rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"bootstrap_directory":"https://dir.example:8081",
			"invite_key":"inv-manual-disabled"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "manual bootstrap_directory/invite_key overrides are disabled") {
			t.Fatalf("error=%q want manual-overrides-disabled message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("manual override rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("session token is required when mode is enabled", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "connect requires a registered session_token") {
			t.Fatalf("error=%q want session-required message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("session-required rejection should not execute commands, got=%v", cmds)
		}
	})

	t.Run("registered session token resolves connect secrets", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmConnectRequireSession = true
		svc.gpmState = newGPMRuntimeState()
		svc.gpmState.putSession(gpmSession{
			Token:              "gpm-connect-session-token",
			WalletAddress:      "cosmos1connectsession",
			WalletProvider:     "keplr",
			Role:               "client",
			CreatedAt:          time.Now().UTC(),
			ExpiresAt:          time.Now().UTC().Add(time.Hour),
			BootstrapDirectory: "https://dir.example:8081",
			InviteKey:          "wallet:cosmos1connectsession",
		})

		code, payload := callJSONHandler(t, svc.handleConnect, http.MethodPost, "/v1/connect", `{
			"session_token":"gpm-connect-session-token",
			"run_preflight":false
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
		mustFlagValue(t, cmds[0], "--bootstrap-directory", "https://dir.example:8081")
		mustFlagNonEmptyValue(t, cmds[0], "--subject-file")
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
	code, _ = callJSONHandler(t, svc2.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"2hop"}{"extra":1}`)
	if code != http.StatusBadRequest {
		t.Fatalf("trailing json status=%d want=%d", code, http.StatusBadRequest)
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

	t.Run("invalid remote and branch are rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, true)

		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"--upload-pack=sh",
			"branch":"main"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid remote name") {
			t.Fatalf("error=%q want invalid remote message", got)
		}

		code, payload = callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{
			"remote":"origin",
			"branch":"bad..branch"
		}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "invalid branch name") {
			t.Fatalf("error=%q want invalid branch message", got)
		}

		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid update args should not execute commands, got=%v", cmds)
		}
	})

	t.Run("invalid json rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, true)
		code, payload := callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{bad`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		code, payload = callJSONHandler(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{"remote":"origin"}{"extra":1}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid update should not execute commands, got=%v", cmds)
		}
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

func TestServiceLifecycleMethodGuards(t *testing.T) {
	svc, _ := newFakeService(t, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		target  string
	}{
		{name: "service_status", handler: svc.handleServiceStatus, method: http.MethodPost, target: "/v1/service/status"},
		{name: "service_start", handler: svc.handleServiceStart, method: http.MethodGet, target: "/v1/service/start"},
		{name: "service_stop", handler: svc.handleServiceStop, method: http.MethodGet, target: "/v1/service/stop"},
		{name: "service_restart", handler: svc.handleServiceRestart, method: http.MethodGet, target: "/v1/service/restart"},
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

func TestHandleServiceStatusContract(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.serviceStatus = "echo service-running"
	svc.serviceStart = "echo service-start"
	svc.serviceRestart = "echo service-restart"

	code, payload := callJSONHandler(t, svc.handleServiceStatus, http.MethodGet, "/v1/service/status", "")
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, payload)
	}

	serviceMap, ok := payload["service"].(map[string]any)
	if !ok {
		t.Fatalf("service payload missing map: %v", payload)
	}
	if supported, _ := serviceMap["supported"].(bool); !supported {
		t.Fatalf("service.supported=%v want=true", serviceMap["supported"])
	}

	commandsMap, ok := serviceMap["commands"].(map[string]any)
	if !ok {
		t.Fatalf("service.commands missing map: %v", serviceMap)
	}
	if got, _ := commandsMap["status_configured"].(bool); !got {
		t.Fatalf("status_configured=%v want=true", commandsMap["status_configured"])
	}
	if got, _ := commandsMap["start_configured"].(bool); !got {
		t.Fatalf("start_configured=%v want=true", commandsMap["start_configured"])
	}
	if got, _ := commandsMap["stop_configured"].(bool); got {
		t.Fatalf("stop_configured=%v want=false", commandsMap["stop_configured"])
	}
	if got, _ := commandsMap["restart_configured"].(bool); !got {
		t.Fatalf("restart_configured=%v want=true", commandsMap["restart_configured"])
	}

	statusMap, ok := serviceMap["status"].(map[string]any)
	if !ok {
		t.Fatalf("service.status missing map: %v", serviceMap)
	}
	if got, _ := statusMap["ok"].(bool); !got {
		t.Fatalf("service.status.ok=%v want=true", statusMap["ok"])
	}
	if got, _ := statusMap["output"].(string); got != "service-running" {
		t.Fatalf("service.status.output=%q want=service-running", got)
	}
	if got, _ := statusMap["rc"].(float64); int(got) != 0 {
		t.Fatalf("service.status.rc=%v want=0", statusMap["rc"])
	}
	if _, exists := serviceMap["status_error"]; exists {
		t.Fatalf("service.status_error should be absent on success: %v", serviceMap["status_error"])
	}
}

func TestServiceLifecycleMutationNotImplementedWhenUnset(t *testing.T) {
	svc, _ := newFakeService(t, false)

	tests := []struct {
		name    string
		handler http.HandlerFunc
		target  string
		wantErr string
	}{
		{
			name:    "start_unset",
			handler: svc.handleServiceStart,
			target:  "/v1/service/start",
			wantErr: "service start not configured (set LOCAL_CONTROL_API_SERVICE_START_COMMAND)",
		},
		{
			name:    "stop_unset",
			handler: svc.handleServiceStop,
			target:  "/v1/service/stop",
			wantErr: "service stop not configured (set LOCAL_CONTROL_API_SERVICE_STOP_COMMAND)",
		},
		{
			name:    "restart_unset",
			handler: svc.handleServiceRestart,
			target:  "/v1/service/restart",
			wantErr: "service restart not configured (set LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.target, "")
			if code != http.StatusNotImplemented {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			if got, _ := payload["error"].(string); got != tc.wantErr {
				t.Fatalf("error=%q want=%q", got, tc.wantErr)
			}
		})
	}
}

func TestServiceLifecycleMutationSuccess(t *testing.T) {
	tests := []struct {
		name      string
		handlerFn func(*Service) http.HandlerFunc
		target    string
		action    string
		command   string
	}{
		{
			name:      "start_success",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStart },
			target:    "/v1/service/start",
			action:    "start",
			command:   "echo service-started",
		},
		{
			name:      "stop_success",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStop },
			target:    "/v1/service/stop",
			action:    "stop",
			command:   "echo service-stopped",
		},
		{
			name:      "restart_success",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceRestart },
			target:    "/v1/service/restart",
			action:    "restart",
			command:   "echo service-restarted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			switch tc.action {
			case "start":
				svc.serviceStart = tc.command
			case "stop":
				svc.serviceStop = tc.command
			case "restart":
				svc.serviceRestart = tc.command
			default:
				t.Fatalf("unknown action %q", tc.action)
			}

			code, payload := callJSONHandler(t, tc.handlerFn(svc), http.MethodPost, tc.target, "")
			if code != http.StatusOK {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			if got, _ := payload["action"].(string); got != tc.action {
				t.Fatalf("action=%q want=%q", got, tc.action)
			}
			if got, _ := payload["rc"].(float64); int(got) != 0 {
				t.Fatalf("rc=%v want=0", payload["rc"])
			}
			if got, _ := payload["output"].(string); got == "" {
				t.Fatalf("output should not be empty: %v", payload)
			}
			if got, _ := payload["note"].(string); !strings.Contains(got, "/v1/gpm/service/") {
				t.Fatalf("note=%q want gpm migration hint", got)
			}
		})
	}
}

func TestServiceLifecycleMutationFailureReturnsBadGateway(t *testing.T) {
	tests := []struct {
		name      string
		handlerFn func(*Service) http.HandlerFunc
		target    string
		action    string
		command   string
	}{
		{
			name:      "start_failure",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStart },
			target:    "/v1/service/start",
			action:    "start",
			command:   `bash -lc "echo start-failed && exit 23"`,
		},
		{
			name:      "stop_failure",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceStop },
			target:    "/v1/service/stop",
			action:    "stop",
			command:   `bash -lc "echo stop-failed && exit 24"`,
		},
		{
			name:      "restart_failure",
			handlerFn: func(s *Service) http.HandlerFunc { return s.handleServiceRestart },
			target:    "/v1/service/restart",
			action:    "restart",
			command:   `bash -lc "echo restart-failed && exit 25"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newFakeService(t, false)
			switch tc.action {
			case "start":
				svc.serviceStart = tc.command
			case "stop":
				svc.serviceStop = tc.command
			case "restart":
				svc.serviceRestart = tc.command
			default:
				t.Fatalf("unknown action %q", tc.action)
			}

			code, payload := callJSONHandler(t, tc.handlerFn(svc), http.MethodPost, tc.target, "")
			if code != http.StatusBadGateway {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			if got, _ := payload["action"].(string); got != tc.action {
				t.Fatalf("action=%q want=%q", got, tc.action)
			}
			if got, _ := payload["error"].(string); got != "service "+tc.action+" command failed" {
				t.Fatalf("error=%q want=%q", got, "service "+tc.action+" command failed")
			}
			if got, _ := payload["rc"].(float64); int(got) <= 0 {
				t.Fatalf("rc=%v want positive exit code", payload["rc"])
			}
			if got, _ := payload["output"].(string); !strings.Contains(got, tc.action+"-failed") {
				t.Fatalf("output=%q want action failure marker", got)
			}
		})
	}
}

func TestServiceLifecycleMutationAuthRequired(t *testing.T) {
	t.Run("non-loopback requires configured token for lifecycle handlers", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.serviceStart = "echo start-ok"
		svc.serviceStop = "echo stop-ok"
		svc.serviceRestart = "echo restart-ok"

		tests := []struct {
			name    string
			handler http.HandlerFunc
			target  string
		}{
			{name: "start", handler: svc.handleServiceStart, target: "/v1/service/start"},
			{name: "stop", handler: svc.handleServiceStop, target: "/v1/service/stop"},
			{name: "restart", handler: svc.handleServiceRestart, target: "/v1/service/restart"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.target, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("valid bearer token allows lifecycle handlers", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = "service-secret"
		svc.serviceStart = "echo start-ok"
		svc.serviceStop = "echo stop-ok"
		svc.serviceRestart = "echo restart-ok"

		tests := []struct {
			name    string
			handler http.HandlerFunc
			target  string
			action  string
		}{
			{name: "start", handler: svc.handleServiceStart, target: "/v1/service/start", action: "start"},
			{name: "stop", handler: svc.handleServiceStop, target: "/v1/service/stop", action: "stop"},
			{name: "restart", handler: svc.handleServiceRestart, target: "/v1/service/restart", action: "restart"},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.target, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("missing token status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); got != "unauthorized" {
					t.Fatalf("error=%q want=unauthorized", got)
				}

				code, payload = callJSONHandlerWithHeaders(t, tc.handler, http.MethodPost, tc.target, "", map[string]string{
					"Authorization": "Bearer service-secret",
				})
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["action"].(string); got != tc.action {
					t.Fatalf("action=%q want=%q", got, tc.action)
				}
			})
		}
	})
}

func TestGPMServiceLifecycleMutationSessionGate(t *testing.T) {
	t.Run("missing session token rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "session token is required" {
			t.Fatalf("error=%q want session-token-required", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("missing token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("invalid token rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-bad-token"}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "invalid or expired session" {
			t.Fatalf("error=%q want invalid-or-expired-session", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("invalid token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:         "gpm-expired-token",
			Role:          "operator",
			CreatedAt:     time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt:     time.Now().UTC().Add(-time.Minute),
			WalletAddress: "cosmos1expired",
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-expired-token"}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "invalid or expired session" {
			t.Fatalf("error=%q want invalid-or-expired-session", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("expired token should not execute commands, got=%v", cmds)
		}
	})

	t.Run("client role rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:         "gpm-client-token",
			Role:          "client",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
			WalletAddress: "cosmos1client",
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-client-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "operator or admin required") {
			t.Fatalf("error=%q want role gate message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("client role should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role without approved application rejected", func(t *testing.T) {
		svc, logPath := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceStart = "echo gpm-start-ok"
		svc.gpmState.putSession(gpmSession{
			Token:           "gpm-operator-pending-token",
			Role:            "operator",
			CreatedAt:       time.Now().UTC(),
			ExpiresAt:       time.Now().UTC().Add(time.Hour),
			WalletAddress:   "cosmos1operatorpending",
			ChainOperatorID: "operator-pending-1",
		})
		svc.gpmState.upsertOperator(gpmOperatorApplication{
			WalletAddress:   "cosmos1operatorpending",
			ChainOperatorID: "operator-pending-1",
			ServerLabel:     "pending-node",
			Status:          "pending",
			UpdatedAt:       time.Now().UTC(),
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceStart, http.MethodPost, "/v1/gpm/service/start", `{"session_token":"gpm-operator-pending-token"}`)
		if code != http.StatusForbidden {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, `status "pending" is not approved`) {
			t.Fatalf("error=%q want pending-not-approved message", got)
		}
		if cmds := readCommandLog(t, logPath); len(cmds) != 0 {
			t.Fatalf("operator without approved application should not execute commands, got=%v", cmds)
		}
	})

	t.Run("operator role with approved application executes legacy lifecycle command", func(t *testing.T) {
		const lifecycleCommand = "go version"
		tests := []struct {
			name      string
			handlerFn func(*Service) http.HandlerFunc
			target    string
			command   string
		}{
			{name: "start", handlerFn: func(s *Service) http.HandlerFunc { return s.handleGPMServiceStart }, target: "/v1/gpm/service/start", command: lifecycleCommand},
			{name: "stop", handlerFn: func(s *Service) http.HandlerFunc { return s.handleGPMServiceStop }, target: "/v1/gpm/service/stop", command: lifecycleCommand},
			{name: "restart", handlerFn: func(s *Service) http.HandlerFunc { return s.handleGPMServiceRestart }, target: "/v1/gpm/service/restart", command: lifecycleCommand},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				svc, _ := newFakeService(t, false)
				svc.gpmState = newGPMRuntimeState()
				switch tc.name {
				case "start":
					svc.serviceStart = tc.command
				case "stop":
					svc.serviceStop = tc.command
				case "restart":
					svc.serviceRestart = tc.command
				}
				svc.gpmState.putSession(gpmSession{
					Token:           "gpm-operator-token",
					Role:            "operator",
					CreatedAt:       time.Now().UTC(),
					ExpiresAt:       time.Now().UTC().Add(time.Hour),
					WalletAddress:   "cosmos1operator",
					ChainOperatorID: "operator-approved-1",
				})
				svc.gpmState.upsertOperator(gpmOperatorApplication{
					WalletAddress:   "cosmos1operator",
					ChainOperatorID: "operator-approved-1",
					ServerLabel:     "approved-node",
					Status:          "approved",
					UpdatedAt:       time.Now().UTC(),
				})

				code, payload := callJSONHandler(t, tc.handlerFn(svc), http.MethodPost, tc.target, `{"session_token":"gpm-operator-token"}`)
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["action"].(string); got != tc.name {
					t.Fatalf("action=%q want=%q", got, tc.name)
				}
				if got, _ := payload["rc"].(float64); int(got) != 0 {
					t.Fatalf("rc=%v want=0", payload["rc"])
				}
				if got, _ := payload["output"].(string); got == "" {
					t.Fatalf("output should not be empty: %v", payload)
				}
			})
		}
	})

	t.Run("admin role also executes lifecycle command", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.gpmState = newGPMRuntimeState()
		svc.serviceRestart = "go version"
		svc.gpmState.putSession(gpmSession{
			Token:         "gpm-admin-token",
			Role:          "admin",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
			WalletAddress: "cosmos1admin",
		})

		code, payload := callJSONHandler(t, svc.handleGPMServiceRestart, http.MethodPost, "/v1/gpm/service/restart", `{"session_token":"gpm-admin-token"}`)
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["action"].(string); got != "restart" {
			t.Fatalf("action=%q want=restart", got)
		}
		if got, _ := payload["output"].(string); got == "" {
			t.Fatalf("output should not be empty: %v", payload)
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
		{name: "gpm_service_start", handler: svc.handleGPMServiceStart, method: http.MethodGet, target: "/v1/gpm/service/start"},
		{name: "gpm_service_stop", handler: svc.handleGPMServiceStop, method: http.MethodGet, target: "/v1/gpm/service/stop"},
		{name: "gpm_service_restart", handler: svc.handleGPMServiceRestart, method: http.MethodGet, target: "/v1/gpm/service/restart"},
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

func TestMutationAuthGuard(t *testing.T) {
	t.Run("loopback without token requires auth by default", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = false
		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
			t.Fatalf("error=%q want token-not-configured", got)
		}
	})

	t.Run("loopback without token allows developer mode when explicitly enabled", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "127.0.0.1:8095"
		svc.allowUnauthLoopback = true
		code, payload := callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "http://127.0.0.1:8095",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "",
		})
		if code != http.StatusForbidden {
			t.Fatalf("expected missing origin to be blocked, got status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "cross-origin mutation blocked in unauthenticated loopback mode" {
			t.Fatalf("error=%q want=cross-origin mutation blocked in unauthenticated loopback mode", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "http://localhost:3000",
		})
		if code != http.StatusForbidden {
			t.Fatalf("expected cross-origin localhost:3000 to be blocked, got status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "cross-origin mutation blocked in unauthenticated loopback mode" {
			t.Fatalf("error=%q want=cross-origin mutation blocked in unauthenticated loopback mode", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Origin": "http://127.0.0.1:8095",
		})
		if code != http.StatusOK {
			t.Fatalf("expected same-origin loopback mutation to pass, got status=%d body=%v", code, payload)
		}
	})

	t.Run("non-loopback requires configured token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
			t.Fatalf("error=%q want token-not-configured", got)
		}
	})

	t.Run("non-loopback returns 401 for every mutating endpoint when token is unset", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
			body    string
		}{
			{name: "connect", handler: svc.handleConnect, path: "/v1/connect", body: `{"bootstrap_directory":"http://dir.example:8081","invite_key":"inv"}`},
			{name: "disconnect", handler: svc.handleDisconnect, path: "/v1/disconnect", body: ""},
			{name: "set_profile", handler: svc.handleSetProfile, path: "/v1/set_profile", body: `{"path_profile":"2hop"}`},
			{name: "update", handler: svc.handleUpdate, path: "/v1/update", body: `{}`},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodPost, tc.path, tc.body)
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("non-loopback rejects missing or invalid bearer token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = "secret-token"

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "unauthorized" {
			t.Fatalf("error=%q want=unauthorized", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer wrong-token",
		})
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})

	t.Run("non-loopback accepts valid bearer token on mutating endpoints", func(t *testing.T) {
		svc, _ := newFakeService(t, true)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = "secret-token"

		code, payload := callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer secret-token",
		})
		if code != http.StatusOK {
			t.Fatalf("disconnect status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleSetProfile, http.MethodPost, "/v1/set_profile", `{"path_profile":"2hop"}`, map[string]string{
			"Authorization": "Bearer secret-token",
		})
		if code != http.StatusOK {
			t.Fatalf("set_profile status=%d body=%v", code, payload)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleUpdate, http.MethodPost, "/v1/update", `{}`, map[string]string{
			"Authorization": "Bearer secret-token",
		})
		if code != http.StatusOK {
			t.Fatalf("update status=%d body=%v", code, payload)
		}
	})

	t.Run("loopback requires auth when token configured", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.authToken = "loopback-secret"

		code, payload := callJSONHandler(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "unauthorized" {
			t.Fatalf("error=%q want=unauthorized", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleDisconnect, http.MethodPost, "/v1/disconnect", "", map[string]string{
			"Authorization": "Bearer loopback-secret",
		})
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})

	t.Run("read-only endpoints stay open when auth token is configured", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.authToken = "readonly-secret"

		code, payload := callJSONHandler(t, svc.handleHealth, http.MethodGet, "/v1/health", "")
		if code != http.StatusOK {
			t.Fatalf("status=%d body=%v", code, payload)
		}
	})
}

func TestCommandReadAuthGuard(t *testing.T) {
	t.Run("loopback unauth mode blocks cross-origin command reads", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "127.0.0.1:8095"
		svc.allowUnauthLoopback = true

		code, payload := callJSONHandlerWithHeaders(t, svc.handleStatus, http.MethodGet, "/v1/status", "", map[string]string{
			"Origin": "",
		})
		if code != http.StatusForbidden {
			t.Fatalf("expected missing origin to be blocked, got status=%d body=%v", code, payload)
		}
		if got, _ := payload["error"].(string); got != "cross-origin command read blocked in unauthenticated loopback mode" {
			t.Fatalf("error=%q want=cross-origin command read blocked in unauthenticated loopback mode", got)
		}

		code, payload = callJSONHandlerWithHeaders(t, svc.handleStatus, http.MethodGet, "/v1/status", "", map[string]string{
			"Origin": "http://127.0.0.1:8095",
		})
		if code != http.StatusOK {
			t.Fatalf("expected same-origin command read to pass, got status=%d body=%v", code, payload)
		}
	})
}

func TestCommandBackedReadAuthGuard(t *testing.T) {
	t.Run("loopback without token requires auth by default", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = false
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("loopback command-backed reads stay open only in explicit developer mode", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.allowUnauthLoopback = true
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
			})
		}
	})

	t.Run("non-loopback requires configured token", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); !strings.Contains(got, "local api auth token not configured") {
					t.Fatalf("error=%q want token-not-configured", got)
				}
			})
		}
	})

	t.Run("valid bearer token allows command-backed reads on non-loopback", func(t *testing.T) {
		svc, _ := newFakeService(t, false)
		svc.addr = "0.0.0.0:8095"
		svc.authToken = "read-secret"
		svc.serviceStatus = "echo service-running"

		cases := []struct {
			name    string
			handler http.HandlerFunc
			path    string
		}{
			{name: "status", handler: svc.handleStatus, path: "/v1/status"},
			{name: "diagnostics", handler: svc.handleDiagnostics, path: "/v1/get_diagnostics"},
			{name: "service_status", handler: svc.handleServiceStatus, path: "/v1/service/status"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				code, payload := callJSONHandler(t, tc.handler, http.MethodGet, tc.path, "")
				if code != http.StatusUnauthorized {
					t.Fatalf("missing token status=%d body=%v", code, payload)
				}
				if got, _ := payload["error"].(string); got != "unauthorized" {
					t.Fatalf("error=%q want=unauthorized", got)
				}

				code, payload = callJSONHandlerWithHeaders(t, tc.handler, http.MethodGet, tc.path, "", map[string]string{
					"Authorization": "Bearer read-secret",
				})
				if code != http.StatusOK {
					t.Fatalf("status=%d body=%v", code, payload)
				}
			})
		}
	})
}

func TestParseBearerToken(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty", raw: "", want: ""},
		{name: "valid bearer", raw: "Bearer abc123", want: "abc123"},
		{name: "valid lowercase", raw: "bearer token-1", want: "token-1"},
		{name: "missing token", raw: "Bearer", want: ""},
		{name: "wrong scheme", raw: "Basic abc", want: ""},
		{name: "extra fields", raw: "Bearer a b", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseBearerToken(tc.raw); got != tc.want {
				t.Fatalf("parseBearerToken(%q)=%q want=%q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestConstantTimeTokenEqual(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		provided string
		want     bool
	}{
		{name: "exact match", expected: "secret-token", provided: "secret-token", want: true},
		{name: "different value same length", expected: "secret-token", provided: "secret-tokfn", want: false},
		{name: "length mismatch", expected: "secret-token", provided: "secret", want: false},
		{name: "empty expected", expected: "", provided: "secret-token", want: false},
		{name: "empty provided", expected: "secret-token", provided: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := constantTimeTokenEqual(tc.expected, tc.provided); got != tc.want {
				t.Fatalf("constantTimeTokenEqual(%q,%q)=%t want=%t", tc.expected, tc.provided, got, tc.want)
			}
		})
	}
}

func TestWriteJSONSetsNoStoreHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]any{"ok": true})
	res := rec.Result()
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q want=no-store", got)
	}
	if got := res.Header.Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma=%q want=no-cache", got)
	}
	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q want=nosniff", got)
	}
}

func TestIsAllowedVPNInterfaceName(t *testing.T) {
	tests := []struct {
		name  string
		iface string
		allow bool
	}{
		{name: "default", iface: "wgvpn0", allow: true},
		{name: "with punctuation", iface: "wg-localapi_1", allow: true},
		{name: "wrong prefix", iface: "eth0", allow: false},
		{name: "too long", iface: "wg12345678901234", allow: false},
		{name: "empty", iface: "", allow: false},
		{name: "invalid character", iface: "wg;rm", allow: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedVPNInterfaceName(tc.iface)
			if got != tc.allow {
				t.Fatalf("isAllowedVPNInterfaceName(%q)=%t want=%t", tc.iface, got, tc.allow)
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

func TestRunEasyNodeFailsWhenScriptPathUnavailable(t *testing.T) {
	svc := &Service{
		commandTimeout: 2 * time.Second,
	}
	out, rc, err := svc.runEasyNode(context.Background(), "client-vpn-status", "--show-json", "1")
	if err == nil {
		t.Fatalf("expected unavailable script path error, got nil")
	}
	if rc != 127 {
		t.Fatalf("rc=%d want=127", rc)
	}
	if out != "" {
		t.Fatalf("out=%q want empty", out)
	}
	if !strings.Contains(err.Error(), "LOCAL_CONTROL_API_SCRIPT") {
		t.Fatalf("error=%q want LOCAL_CONTROL_API_SCRIPT guidance", err.Error())
	}
}

func TestRunEasyNodeSaturationReturnsConcurrencyError(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.maxConcurrentCmds = 1
	svc.commandSlots = make(chan struct{}, 1)
	svc.commandSlots <- struct{}{}

	out, rc, err := svc.runEasyNode(context.Background(), "client-vpn-status", "--show-json", "1")
	if err == nil {
		t.Fatalf("expected saturation error, got nil")
	}
	if !errors.Is(err, errCommandConcurrencySaturated) {
		t.Fatalf("expected saturation sentinel, got %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d want=0 for pre-exec saturation", rc)
	}
	if out != "" {
		t.Fatalf("out=%q want empty for pre-exec saturation", out)
	}
}

func TestRunEasyNodeTruncatesOversizedOutput(t *testing.T) {
	svc, _ := newFakeService(t, false)
	t.Setenv("LOCALAPI_TEST_OUTPUT_BYTES", strconv.Itoa(maxCommandOutputBytes+4096))

	out, rc, err := svc.runEasyNode(context.Background(), "client-vpn-status", "--show-json", "1")
	if err != nil {
		t.Fatalf("runEasyNode returned error: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d want=0", rc)
	}
	if !strings.Contains(out, "[output truncated to ") {
		t.Fatalf("expected truncated marker, out=%q", out)
	}
	if len(out) <= maxCommandOutputBytes {
		t.Fatalf("expected marker beyond capped payload, len(out)=%d cap=%d", len(out), maxCommandOutputBytes)
	}
	if len(out) > maxCommandOutputBytes+128 {
		t.Fatalf("expected bounded output length, got len=%d", len(out))
	}
}

func TestRunLifecycleCommandTruncatesOversizedOutput(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "lifecycle_oversized.sh")
	script := "#!/usr/bin/env bash\nset -euo pipefail\nhead -c $((2*1024*1024)) < /dev/zero | tr '\\0' 'B'\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write lifecycle script: %v", err)
	}

	svc := &Service{
		commandTimeout:    2 * time.Second,
		maxConcurrentCmds: 1,
		commandSlots:      make(chan struct{}, 1),
	}
	out, rc, err := svc.runLifecycleCommand(context.Background(), scriptPath)
	if err != nil {
		t.Fatalf("runLifecycleCommand returned error: %v", err)
	}
	if rc != 0 {
		t.Fatalf("rc=%d want=0", rc)
	}
	if !strings.Contains(out, "[output truncated to ") {
		t.Fatalf("expected truncated marker, out=%q", out)
	}
	if len(out) > maxCommandOutputBytes+128 {
		t.Fatalf("expected bounded output length, got len=%d", len(out))
	}
}

func TestCommandBackedHandlersReturn429WhenConcurrencySaturated(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.serviceStart = "echo start-ok"
	svc.maxConcurrentCmds = 1
	svc.commandSlots = make(chan struct{}, 1)
	svc.commandSlots <- struct{}{}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		body    string
	}{
		{name: "status", handler: svc.handleStatus, method: http.MethodGet, path: "/v1/status"},
		{name: "disconnect", handler: svc.handleDisconnect, method: http.MethodPost, path: "/v1/disconnect"},
		{name: "service_start", handler: svc.handleServiceStart, method: http.MethodPost, path: "/v1/service/start"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, payload := callJSONHandler(t, tc.handler, tc.method, tc.path, tc.body)
			if code != http.StatusTooManyRequests {
				t.Fatalf("status=%d body=%v", code, payload)
			}
			msg, _ := payload["error"].(string)
			if !strings.Contains(msg, "command concurrency limit reached") {
				t.Fatalf("error=%q want concurrency limit message", msg)
			}
		})
	}
}

func TestIsLoopbackBindAddrRequiresLoopbackDNSResolution(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}

	if isLoopbackBindAddr("localhost:8095") {
		t.Fatal("expected localhost bind to be rejected when DNS resolves to non-loopback")
	}
}

func TestIsAllowedUnauthLoopbackOriginRequiresLoopbackDNSResolution(t *testing.T) {
	originalLookup := lookupIPAddr
	t.Cleanup(func() {
		lookupIPAddr = originalLookup
	})

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	if !isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://localhost:8095") {
		t.Fatal("expected localhost origin to pass when DNS resolves to loopback")
	}

	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.11")}}, nil
	}
	if isAllowedUnauthLoopbackOrigin("127.0.0.1:8095", "http://localhost:8095") {
		t.Fatal("expected localhost origin to be rejected when DNS resolves to non-loopback")
	}
}

func TestGPMAuthChallengeVerifyAndSessionStatus(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"

	challengeBody := `{"wallet_address":"cosmos1testwallet","wallet_provider":"keplr"}`
	code, payload := callJSONHandler(t, svc.handleGPMAuthChallenge, http.MethodPost, "/v1/gpm/auth/challenge", challengeBody)
	if code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%v", code, payload)
	}
	challengeID, _ := payload["challenge_id"].(string)
	if strings.TrimSpace(challengeID) == "" {
		t.Fatalf("challenge_id missing: %v", payload)
	}

	verifyBody := `{"wallet_address":"cosmos1testwallet","wallet_provider":"keplr","challenge_id":"` + challengeID + `","signature":"signed-proof-value"}`
	code, payload = callJSONHandler(t, svc.handleGPMAuthVerify, http.MethodPost, "/v1/gpm/auth/verify", verifyBody)
	if code != http.StatusOK {
		t.Fatalf("verify status=%d body=%v", code, payload)
	}
	sessionToken, _ := payload["session_token"].(string)
	if strings.TrimSpace(sessionToken) == "" {
		t.Fatalf("session_token missing: %v", payload)
	}

	sessionPayload, _ := payload["session"].(map[string]any)
	role, _ := sessionPayload["role"].(string)
	if role != "client" {
		t.Fatalf("session role=%q want=client", role)
	}

	statusBody := `{"session_token":"` + sessionToken + `"}`
	code, payload = callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
	if code != http.StatusOK {
		t.Fatalf("session status=%d body=%v", code, payload)
	}
	sessionPayload, _ = payload["session"].(map[string]any)
	statusRole, _ := sessionPayload["role"].(string)
	if statusRole != "client" {
		t.Fatalf("session status role=%q want=client", statusRole)
	}
}

func TestGPMSessionRefreshAndRevoke(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	const originalToken = "gpm-session-token-original"
	svc.gpmState.putSession(gpmSession{
		Token:          originalToken,
		WalletAddress:  "cosmos1sessionuser",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	refreshBody := `{"session_token":"` + originalToken + `","action":"refresh"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", refreshBody)
	if code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", code, payload)
	}
	action, _ := payload["action"].(string)
	if action != "refresh" {
		t.Fatalf("action=%q want=refresh payload=%v", action, payload)
	}
	refreshedToken, _ := payload["session_token"].(string)
	if strings.TrimSpace(refreshedToken) == "" {
		t.Fatalf("session_token missing after refresh payload=%v", payload)
	}
	if refreshedToken == originalToken {
		t.Fatalf("session_token was not rotated old=%q new=%q", originalToken, refreshedToken)
	}
	if _, ok := svc.gpmState.getSession(originalToken, time.Now().UTC()); ok {
		t.Fatalf("expected original token to be removed after refresh")
	}
	if _, ok := svc.gpmState.getSession(refreshedToken, time.Now().UTC()); !ok {
		t.Fatalf("expected refreshed token to exist")
	}

	revokeBody := `{"session_token":"` + refreshedToken + `","action":"revoke"}`
	code, payload = callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", revokeBody)
	if code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%v", code, payload)
	}
	revokeAction, _ := payload["action"].(string)
	if revokeAction != "revoke" {
		t.Fatalf("action=%q want=revoke payload=%v", revokeAction, payload)
	}
	revoked, _ := payload["revoked"].(bool)
	if !revoked {
		t.Fatalf("expected revoked=true payload=%v", payload)
	}
	if _, ok := svc.gpmState.getSession(refreshedToken, time.Now().UTC()); ok {
		t.Fatalf("expected refreshed token to be removed after revoke")
	}

	statusBody := `{"session_token":"` + refreshedToken + `","action":"status"}`
	code, payload = callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", statusBody)
	if code != http.StatusNotFound {
		t.Fatalf("expected revoked token status 404 got=%d payload=%v", code, payload)
	}
}

func TestGPMSessionActionRejectsUnknownAction(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()
	svc.gpmState.putSession(gpmSession{
		Token:          "gpm-session-token-invalid-action",
		WalletAddress:  "cosmos1sessionaction",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	body := `{"session_token":"gpm-session-token-invalid-action","action":"rotate"}`
	code, payload := callJSONHandler(t, svc.handleGPMSessionStatus, http.MethodPost, "/v1/gpm/session", body)
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "action must be one of") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMClientRegisterUsesManifestAndPersistsSessionConnectSecrets(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	bootstrapDirectory := "https://directory.globalprivatemesh.example:8081"
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{bootstrapDirectory},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token"
	svc.gpmState.putSession(gpmSession{
		Token:          token,
		WalletAddress:  "cosmos1registeredclient",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusOK {
		t.Fatalf("register status=%d body=%v", code, payload)
	}

	profile, _ := payload["profile"].(map[string]any)
	gotBootstrap, _ := profile["bootstrap_directory"].(string)
	if gotBootstrap != bootstrapDirectory {
		t.Fatalf("profile bootstrap_directory=%q want=%q", gotBootstrap, bootstrapDirectory)
	}
	gotProfile, _ := profile["path_profile"].(string)
	if gotProfile != "3hop" {
		t.Fatalf("profile path_profile=%q want=3hop", gotProfile)
	}

	session, ok := svc.gpmState.getSession(token, time.Now().UTC())
	if !ok {
		t.Fatal("expected session to persist after registration")
	}
	if session.BootstrapDirectory != bootstrapDirectory {
		t.Fatalf("session bootstrap_directory=%q want=%q", session.BootstrapDirectory, bootstrapDirectory)
	}
	if !strings.HasPrefix(session.InviteKey, "wallet:") {
		t.Fatalf("session invite_key=%q want wallet:* fallback", session.InviteKey)
	}
	if session.PathProfile != "3hop" {
		t.Fatalf("session path_profile=%q want=3hop", session.PathProfile)
	}
}

func TestGPMClientStatusEndpointRegistrationStates(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	now := time.Now().UTC()

	svc.gpmState.putSession(gpmSession{
		Token:              "gpm-client-status-registered",
		WalletAddress:      "cosmos1registeredstatus",
		WalletProvider:     "keplr",
		Role:               "client",
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Hour),
		BootstrapDirectory: "https://directory.globalprivatemesh.example:8081",
		InviteKey:          "inv-registered",
		PathProfile:        "3hop",
	})
	svc.gpmState.putSession(gpmSession{
		Token:          "gpm-client-status-not-registered",
		WalletAddress:  "cosmos1notregisteredstatus",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	t.Run("registered", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-registered"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		if registration == nil {
			t.Fatalf("registration missing payload=%v", payload)
		}
		gotStatus, _ := registration["status"].(string)
		if gotStatus != "registered" {
			t.Fatalf("registration.status=%q want=registered payload=%v", gotStatus, payload)
		}
		gotWallet, _ := registration["wallet_address"].(string)
		if gotWallet != "cosmos1registeredstatus" {
			t.Fatalf("registration.wallet_address=%q want=cosmos1registeredstatus payload=%v", gotWallet, payload)
		}
		gotBootstrap, _ := registration["bootstrap_directory"].(string)
		if gotBootstrap != "https://directory.globalprivatemesh.example:8081" {
			t.Fatalf("registration.bootstrap_directory=%q payload=%v", gotBootstrap, payload)
		}
		gotProfile, _ := registration["path_profile"].(string)
		if gotProfile != "3hop" {
			t.Fatalf("registration.path_profile=%q want=3hop payload=%v", gotProfile, payload)
		}
	})

	t.Run("not_registered", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-not-registered"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusOK {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		registration, _ := payload["registration"].(map[string]any)
		gotStatus, _ := registration["status"].(string)
		if gotStatus != "not_registered" {
			t.Fatalf("registration.status=%q want=not_registered payload=%v", gotStatus, payload)
		}
		gotWallet, _ := registration["wallet_address"].(string)
		if gotWallet != "cosmos1notregisteredstatus" {
			t.Fatalf("registration.wallet_address=%q want=cosmos1notregisteredstatus payload=%v", gotWallet, payload)
		}
		gotBootstrap, _ := registration["bootstrap_directory"].(string)
		if gotBootstrap != "" {
			t.Fatalf("registration.bootstrap_directory=%q want empty payload=%v", gotBootstrap, payload)
		}
		if _, ok := registration["path_profile"]; ok {
			t.Fatalf("registration.path_profile should be omitted payload=%v", payload)
		}
	})

	t.Run("invalid_session", func(t *testing.T) {
		body := `{"session_token":"gpm-client-status-missing"}`
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", body)
		if code != http.StatusNotFound {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session not found") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})

	t.Run("missing_session_token", func(t *testing.T) {
		code, payload := callJSONHandler(t, svc.handleGPMClientStatus, http.MethodPost, "/v1/gpm/onboarding/client/status", `{}`)
		if code != http.StatusBadRequest {
			t.Fatalf("status=%d payload=%v", code, payload)
		}
		errMsg, _ := payload["error"].(string)
		if !strings.Contains(errMsg, "session_token is required") {
			t.Fatalf("error=%q payload=%v", errMsg, payload)
		}
	})
}

func TestGPMClientRegisterRejectsPinnedMainDomainHostMismatch(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	var manifestHits int
	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":               1,
			"generated_at_utc":      now.Format(time.RFC3339),
			"expires_at_utc":        now.Add(time.Hour).Format(time.RFC3339),
			"bootstrap_directories": []string{"https://directory.globalprivatemesh.example:8081"},
		})
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = "https://pinned.globalprivatemesh.example:8443"
	svc.gpmManifestURL = manifestServer.URL

	const token = "gpm-session-token-mismatch"
	svc.gpmState.putSession(gpmSession{
		Token:          token,
		WalletAddress:  "cosmos1registeredclientmismatch",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "host mismatch") || !strings.Contains(errMsg, "pinned gpm main domain") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if manifestHits != 0 {
		t.Fatalf("expected manifest fetch to be blocked before contact, got %d hits", manifestHits)
	}
}

func TestGPMClientRegisterRejectsPinnedCacheFallbackSourceHostMismatch(t *testing.T) {
	svc, _ := newFakeService(t, false)
	svc.gpmState = newGPMRuntimeState()
	svc.gpmRoleDefault = "client"
	svc.gpmManifestCache = filepath.Join(t.TempDir(), "manifest_cache.json")
	svc.gpmManifestMaxAge = 24 * time.Hour

	now := time.Now().UTC()
	manifestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	t.Cleanup(manifestServer.Close)
	svc.gpmMainDomain = manifestServer.URL
	svc.gpmManifestURL = manifestServer.URL

	cachePath := svc.gpmManifestCache
	cache := gpmBootstrapManifestCacheFile{
		Version:      1,
		FetchedAtUTC: now.Format(time.RFC3339),
		SourceURL:    "https://cache-source.globalprivatemesh.example:8443/v1/bootstrap/manifest",
		Manifest: gpmBootstrapManifest{
			Version:              1,
			GeneratedAtUTC:       now.Add(-time.Minute).Format(time.RFC3339),
			ExpiresAtUTC:         now.Add(time.Hour).Format(time.RFC3339),
			BootstrapDirectories: []string{"https://directory.globalprivatemesh.example:8081"},
		},
	}
	cacheBody, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBody, 0o600); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	const token = "gpm-session-token-cache-mismatch"
	svc.gpmState.putSession(gpmSession{
		Token:          token,
		WalletAddress:  "cosmos1cachemismatch",
		WalletProvider: "keplr",
		Role:           "client",
		CreatedAt:      now,
		ExpiresAt:      now.Add(time.Hour),
	})

	registerBody := `{"session_token":"` + token + `","path_profile":"3hop"}`
	code, payload := callJSONHandler(t, svc.handleGPMClientRegister, http.MethodPost, "/v1/gpm/onboarding/client/register", registerBody)
	if code != http.StatusBadGateway {
		t.Fatalf("register status=%d body=%v", code, payload)
	}
	errMsg, _ := payload["error"].(string)
	if !strings.Contains(errMsg, "cache fallback failed") || !strings.Contains(errMsg, "cached manifest source host mismatch") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
	if !strings.Contains(errMsg, "pinned gpm main domain") {
		t.Fatalf("error=%q payload=%v", errMsg, payload)
	}
}

func TestGPMStateStorePersistAndLoadRoundTrip(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "gpm_state.json")
	now := time.Now().UTC()
	expiresAt := now.Add(2 * time.Hour)

	svc := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	svc.gpmState.putSession(gpmSession{
		Token:              "persist-token",
		WalletAddress:      "cosmos1persist",
		WalletProvider:     "keplr",
		Role:               "operator",
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
		BootstrapDirectory: "https://directory.gpm.example:8081",
		InviteKey:          "wallet:cosmos1persist",
		ChainOperatorID:    "operator-persist-1",
	})
	svc.gpmState.upsertOperator(gpmOperatorApplication{
		WalletAddress:   "cosmos1persist",
		ChainOperatorID: "operator-persist-1",
		ServerLabel:     "persist-node",
		Status:          "approved",
		UpdatedAt:       now,
	})
	svc.persistGPMStateBestEffort("test_roundtrip")

	loaded := &Service{
		gpmStateStorePath: statePath,
		gpmState:          newGPMRuntimeState(),
	}
	loaded.loadGPMStateBestEffort()

	session, ok := loaded.gpmState.getSession("persist-token", now)
	if !ok {
		t.Fatal("expected persisted session to be loaded")
	}
	if session.Role != "operator" {
		t.Fatalf("loaded role=%q want=operator", session.Role)
	}
	if session.ChainOperatorID != "operator-persist-1" {
		t.Fatalf("loaded chain_operator_id=%q want=operator-persist-1", session.ChainOperatorID)
	}

	operator, ok := loaded.gpmState.getOperator("cosmos1persist")
	if !ok {
		t.Fatal("expected persisted operator application to be loaded")
	}
	if operator.Status != "approved" {
		t.Fatalf("loaded operator status=%q want=approved", operator.Status)
	}
}

func TestGPMAuditAppendWritesJSONLine(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		gpmAuditLogPath: auditPath,
	}

	svc.appendGPMAudit("auth_verified", map[string]any{
		"wallet_address": "cosmos1audit",
		"role":           "client",
	})

	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 1 {
		t.Fatalf("audit lines=%d want=1 body=%q", len(lines), string(body))
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("decode audit line: %v", err)
	}
	if record["event"] != "auth_verified" {
		t.Fatalf("event=%v want=auth_verified", record["event"])
	}
	fields, _ := record["fields"].(map[string]any)
	if fields["wallet_address"] != "cosmos1audit" {
		t.Fatalf("wallet_address=%v want=cosmos1audit", fields["wallet_address"])
	}
}

func TestGPMAuditRecentHandlerReturnsMostRecentEntries(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "gpm_audit.jsonl")
	svc := &Service{
		addr:                "127.0.0.1:8095",
		allowUnauthLoopback: true,
		gpmAuditLogPath:     auditPath,
		gpmState:            newGPMRuntimeState(),
	}
	svc.appendGPMAudit("event_one", map[string]any{"idx": 1})
	svc.appendGPMAudit("event_two", map[string]any{"idx": 2})

	code, payload := callJSONHandler(t, svc.handleGPMAuditRecent, http.MethodGet, "/v1/gpm/audit/recent?limit=1", "")
	if code != http.StatusOK {
		t.Fatalf("status=%d payload=%v", code, payload)
	}
	count, _ := payload["count"].(float64)
	if int(count) != 1 {
		t.Fatalf("count=%v want=1 payload=%v", count, payload)
	}
	entries, _ := payload["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries len=%d want=1 payload=%v", len(entries), payload)
	}
	entry, _ := entries[0].(map[string]any)
	if event, _ := entry["event"].(string); event != "event_two" {
		t.Fatalf("event=%q want=event_two entry=%v", event, entry)
	}
}
