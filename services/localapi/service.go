package localapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	defaultAddr             = "127.0.0.1:8095"
	defaultScriptPath       = "./scripts/easy_node.sh"
	defaultCommandTimeout   = 120 * time.Second
	defaultDiscoveryWaitSec = 20
	defaultReadyTimeoutSec  = 35
	defaultPathProfile      = "2hop"
	defaultVPNInterface     = "wgvpn0"
	maxRequestBodyBytes     = 1 << 20
)

type Service struct {
	addr           string
	scriptPath     string
	commandRunner  string
	commandTimeout time.Duration
	allowUpdate    bool
	authToken      string
	serviceStatus  string
	serviceStart   string
	serviceStop    string
	serviceRestart string
}

type connectRequest struct {
	BootstrapDirectory string `json:"bootstrap_directory"`
	InviteKey          string `json:"invite_key"`
	PathProfile        string `json:"path_profile,omitempty"`
	Interface          string `json:"interface,omitempty"`
	DiscoveryWaitSec   int    `json:"discovery_wait_sec,omitempty"`
	ReadyTimeoutSec    int    `json:"ready_timeout_sec,omitempty"`
	RunPreflight       *bool  `json:"run_preflight,omitempty"`
	ProdProfile        *bool  `json:"prod_profile,omitempty"`
	InstallRoute       *bool  `json:"install_route,omitempty"`
}

type connectDefaults struct {
	pathProfile   string
	interfaceName string
	runPreflight  bool
	prodMode      string
}

type resolvedConnectOptions struct {
	profile           string
	interfaceName     string
	discoveryWaitSec  int
	readyTimeoutSec   int
	runPreflight      bool
	prodProfile       bool
	installRoute      bool
	installRouteIsSet bool
}

type connectPolicy struct {
	minOperators       int
	operatorFloorCheck int
	operatorMin        int
	issuerQuorumCheck  int
	issuerMin          int
	betaProfile        int
	prodFlag           int
	installRoute       bool
}

type setProfileRequest struct {
	PathProfile string `json:"path_profile"`
}

type updateRequest struct {
	Remote     string `json:"remote,omitempty"`
	Branch     string `json:"branch,omitempty"`
	AllowDirty *bool  `json:"allow_dirty,omitempty"`
}

func New() *Service {
	addr := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_ADDR"))
	if addr == "" {
		addr = defaultAddr
	}
	scriptPath := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SCRIPT"))
	if scriptPath == "" {
		scriptPath = defaultScriptPath
	}
	commandRunner := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_RUNNER"))
	commandTimeout := defaultCommandTimeout
	if raw := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_COMMAND_TIMEOUT_SEC")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 5 {
			commandTimeout = time.Duration(v) * time.Second
		}
	}
	allowUpdate := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_ALLOW_UPDATE")) == "1"
	authToken := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_AUTH_TOKEN"))
	serviceStatus := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_STATUS_COMMAND"))
	serviceStart := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_START_COMMAND"))
	serviceStop := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_STOP_COMMAND"))
	serviceRestart := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND"))
	return &Service{
		addr:           addr,
		scriptPath:     scriptPath,
		commandRunner:  commandRunner,
		commandTimeout: commandTimeout,
		allowUpdate:    allowUpdate,
		authToken:      authToken,
		serviceStatus:  serviceStatus,
		serviceStart:   serviceStart,
		serviceStop:    serviceStop,
		serviceRestart: serviceRestart,
	}
}

func (s *Service) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/connect", s.handleConnect)
	mux.HandleFunc("/v1/disconnect", s.handleDisconnect)
	mux.HandleFunc("/v1/set_profile", s.handleSetProfile)
	mux.HandleFunc("/v1/get_diagnostics", s.handleDiagnostics)
	mux.HandleFunc("/v1/update", s.handleUpdate)
	mux.HandleFunc("/v1/service/status", s.handleServiceStatus)
	mux.HandleFunc("/v1/service/start", s.handleServiceStart)
	mux.HandleFunc("/v1/service/stop", s.handleServiceStop)
	mux.HandleFunc("/v1/service/restart", s.handleServiceRestart)

	srv := &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("local control api listening on %s script=%s runner=%s update_enabled=%t", s.addr, s.scriptPath, s.commandRunner, s.allowUpdate)
	err := srv.ListenAndServe()
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "local-control-api"})
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "client-vpn-status", "--show-json", "1")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"error":  "status command failed",
			"rc":     rc,
			"output": out,
		})
		return
	}
	var payload any
	if json.Unmarshal([]byte(out), &payload) != nil {
		payload = map[string]any{"raw": out}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": payload})
}

func (s *Service) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in connectRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	in.BootstrapDirectory = strings.TrimSpace(in.BootstrapDirectory)
	in.InviteKey = strings.TrimSpace(in.InviteKey)
	if in.BootstrapDirectory == "" || in.InviteKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "bootstrap_directory and invite_key are required",
		})
		return
	}
	defaults := loadConnectDefaultsFromEnv()
	options := resolveConnectOptions(in, defaults)
	policy := deriveConnectPolicy(options)

	if options.runPreflight {
		preflightArgs := []string{
			"client-vpn-preflight",
			"--bootstrap-directory", in.BootstrapDirectory,
			"--discovery-wait-sec", strconv.Itoa(options.discoveryWaitSec),
			"--prod-profile", strconv.Itoa(policy.prodFlag),
			"--interface", options.interfaceName,
			"--operator-floor-check", strconv.Itoa(policy.operatorFloorCheck),
			"--operator-min-operators", strconv.Itoa(policy.operatorMin),
			"--issuer-quorum-check", strconv.Itoa(policy.issuerQuorumCheck),
			"--issuer-min-operators", strconv.Itoa(policy.issuerMin),
		}
		preflightOut, preflightRC, preflightErr := s.runEasyNode(r.Context(), preflightArgs...)
		if preflightErr != nil {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":     false,
				"stage":  "preflight",
				"rc":     preflightRC,
				"output": preflightOut,
			})
			return
		}
	}

	upArgs := []string{
		"client-vpn-up",
		"--bootstrap-directory", in.BootstrapDirectory,
		"--discovery-wait-sec", strconv.Itoa(options.discoveryWaitSec),
		"--subject", in.InviteKey,
		"--min-sources", "1",
		"--min-operators", strconv.Itoa(policy.minOperators),
		"--path-profile", options.profile,
		"--session-reuse", "1",
		"--allow-session-churn", "0",
		"--operator-floor-check", strconv.Itoa(policy.operatorFloorCheck),
		"--operator-min-operators", strconv.Itoa(policy.operatorMin),
		"--issuer-quorum-check", strconv.Itoa(policy.issuerQuorumCheck),
		"--issuer-min-operators", strconv.Itoa(policy.issuerMin),
		"--beta-profile", strconv.Itoa(policy.betaProfile),
		"--prod-profile", strconv.Itoa(policy.prodFlag),
		"--interface", options.interfaceName,
		"--ready-timeout-sec", strconv.Itoa(options.readyTimeoutSec),
		"--install-route", boolTo01(policy.installRoute),
		"--force-restart", "1",
		"--foreground", "0",
	}
	upOut, upRC, upErr := s.runEasyNode(r.Context(), upArgs...)
	if upErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"stage":  "connect",
			"rc":     upRC,
			"output": upOut,
		})
		return
	}
	statusOut, _, _ := s.runEasyNode(r.Context(), "client-vpn-status", "--show-json", "1")
	var statusPayload any
	if json.Unmarshal([]byte(statusOut), &statusPayload) != nil {
		statusPayload = map[string]any{"raw": statusOut}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"stage":   "connect",
		"output":  upOut,
		"status":  statusPayload,
		"profile": options.profile,
	})
}

func (s *Service) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "client-vpn-down", "--force-iface-cleanup", "1")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
			"error":  "disconnect command failed",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stage": "disconnect", "output": out})
}

func (s *Service) handleSetProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	var in setProfileRequest
	if err := decodeJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	profile := normalizeOptionalPathProfile(in.PathProfile)
	if profile == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    false,
			"error": "path_profile is required (1hop|2hop|3hop)",
		})
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "config-v1-set-profile", "--path-profile", profile)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path_profile": profile, "output": out})
}

func (s *Service) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	out, rc, err := s.runEasyNode(r.Context(), "runtime-doctor", "--show-json", "1")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
		})
		return
	}
	var payload any
	if json.Unmarshal([]byte(out), &payload) != nil {
		payload = map[string]any{"raw": out}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "diagnostics": payload})
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	if !s.allowUpdate {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"ok":    false,
			"error": "update endpoint disabled (set LOCAL_CONTROL_API_ALLOW_UPDATE=1 to enable)",
		})
		return
	}
	var in updateRequest
	if err := decodeOptionalJSONBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json body"})
		return
	}
	args := []string{"self-update", "--show-status", "1"}
	if remote := strings.TrimSpace(in.Remote); remote != "" {
		args = append(args, "--remote", remote)
	}
	if branch := strings.TrimSpace(in.Branch); branch != "" {
		args = append(args, "--branch", branch)
	}
	if in.AllowDirty != nil {
		args = append(args, "--allow-dirty", boolTo01(*in.AllowDirty))
	}
	out, rc, err := s.runEasyNode(r.Context(), args...)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"rc":     rc,
			"output": out,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

func (s *Service) handleServiceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	statusConfigured := strings.TrimSpace(s.serviceStatus) != ""
	startConfigured := strings.TrimSpace(s.serviceStart) != ""
	stopConfigured := strings.TrimSpace(s.serviceStop) != ""
	restartConfigured := strings.TrimSpace(s.serviceRestart) != ""

	lifecycle := map[string]any{
		"supported": true,
		"commands": map[string]any{
			"status_configured":  statusConfigured,
			"start_configured":   startConfigured,
			"stop_configured":    stopConfigured,
			"restart_configured": restartConfigured,
		},
	}

	if statusConfigured {
		out, rc, err := s.runLifecycleCommand(r.Context(), s.serviceStatus)
		lifecycle["status"] = map[string]any{
			"ok":     err == nil,
			"rc":     rc,
			"output": out,
		}
		if err != nil {
			lifecycle["status_error"] = "service status command failed"
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": lifecycle,
	})
}

func (s *Service) handleServiceStart(w http.ResponseWriter, r *http.Request) {
	s.handleServiceMutation(w, r, "start", s.serviceStart, "LOCAL_CONTROL_API_SERVICE_START_COMMAND")
}

func (s *Service) handleServiceStop(w http.ResponseWriter, r *http.Request) {
	s.handleServiceMutation(w, r, "stop", s.serviceStop, "LOCAL_CONTROL_API_SERVICE_STOP_COMMAND")
}

func (s *Service) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	s.handleServiceMutation(w, r, "restart", s.serviceRestart, "LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND")
}

func (s *Service) handleServiceMutation(w http.ResponseWriter, r *http.Request, action, command, envVar string) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if !s.requireMutationAuth(w, r) {
		return
	}
	command = strings.TrimSpace(command)
	if command == "" {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"ok":    false,
			"error": fmt.Sprintf("service %s not configured (set %s)", action, envVar),
		})
		return
	}

	out, rc, err := s.runLifecycleCommand(r.Context(), command)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":     false,
			"action": action,
			"error":  fmt.Sprintf("service %s command failed", action),
			"rc":     rc,
			"output": out,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"action": action,
		"rc":     rc,
		"output": out,
	})
}

func (s *Service) runEasyNode(ctx context.Context, args ...string) (string, int, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, s.commandTimeout)
	defer cancel()

	cmdName, cmdArgs := buildEasyNodeCommandWithPlatform(s.scriptPath, args, runtime.GOOS, s.commandRunner)
	cmd := exec.CommandContext(cmdCtx, cmdName, cmdArgs...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	output := strings.TrimSpace(combined.String())
	if err == nil {
		return output, 0, nil
	}
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return output, 124, fmt.Errorf("command timeout")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, exitErr.ExitCode(), err
	}
	return output, 127, err
}

func (s *Service) runLifecycleCommand(ctx context.Context, rawCommand string) (string, int, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, s.commandTimeout)
	defer cancel()

	cmdName, cmdArgs := buildLifecycleCommandWithPlatform(rawCommand, runtime.GOOS)
	cmd := exec.CommandContext(cmdCtx, cmdName, cmdArgs...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	output := strings.TrimSpace(combined.String())
	if err == nil {
		return output, 0, nil
	}
	if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
		return output, 124, fmt.Errorf("command timeout")
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output, exitErr.ExitCode(), err
	}
	return output, 127, err
}

func buildEasyNodeCommandWithPlatform(scriptPath string, args []string, goos string, commandRunner string) (string, []string) {
	runner := strings.TrimSpace(commandRunner)
	if runner != "" {
		cmdArgs := append([]string{scriptPath}, args...)
		return runner, cmdArgs
	}
	if strings.EqualFold(strings.TrimSpace(goos), "windows") {
		ext := strings.ToLower(strings.TrimSpace(filepath.Ext(scriptPath)))
		if ext == ".ps1" {
			cmdArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scriptPath}, args...)
			return "powershell", cmdArgs
		}
		cmdArgs := append([]string{scriptPath}, args...)
		return "bash", cmdArgs
	}
	return scriptPath, args
}

func buildLifecycleCommandWithPlatform(rawCommand string, goos string) (string, []string) {
	command := strings.TrimSpace(rawCommand)
	if strings.EqualFold(strings.TrimSpace(goos), "windows") {
		return "powershell", []string{"-NoProfile", "-Command", command}
	}
	return "bash", []string{"-lc", command}
}

func decodeJSONBody(r *http.Request, out any) error {
	body, err := readBodyWithLimit(r, maxRequestBodyBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return io.EOF
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func decodeOptionalJSONBody(r *http.Request, out any) error {
	body, err := readBodyWithLimit(r, maxRequestBodyBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func readBodyWithLimit(r *http.Request, maxBytes int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, io.EOF
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", maxBytes)
	}
	return body, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"ok":false,"error":"json marshal failed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func normalizePathProfile(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "", "2", "2hop", "speed", "fast", "balanced":
		return "2hop"
	case "1", "1hop", "speed-1hop":
		return "1hop"
	case "3", "3hop", "private", "privacy":
		return "3hop"
	default:
		return ""
	}
}

func normalizeOptionalPathProfile(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return normalizePathProfile(raw)
}

func loadConnectDefaultsFromEnv() connectDefaults {
	defaults := connectDefaults{
		pathProfile:   defaultPathProfile,
		interfaceName: defaultVPNInterface,
		runPreflight:  true,
		prodMode:      "0",
	}
	if profile := normalizeOptionalPathProfile(os.Getenv("LOCAL_CONTROL_API_CONNECT_PATH_PROFILE")); profile != "" {
		defaults.pathProfile = profile
	} else if profile := normalizeOptionalPathProfile(os.Getenv("CLIENT_PATH_PROFILE")); profile != "" {
		defaults.pathProfile = profile
	}
	if iface := strings.TrimSpace(os.Getenv("LOCAL_CONTROL_API_CONNECT_INTERFACE")); iface != "" {
		defaults.interfaceName = iface
	} else if iface := strings.TrimSpace(os.Getenv("CLIENT_WG_INTERFACE")); iface != "" {
		defaults.interfaceName = iface
	}
	defaults.runPreflight = parseBoolWithDefault(
		firstNonEmpty(
			os.Getenv("LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT"),
			os.Getenv("SIMPLE_CLIENT_RUN_PREFLIGHT"),
		),
		true,
	)
	defaults.prodMode = normalizeProdModeWithDefault(
		firstNonEmpty(
			os.Getenv("LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT"),
			os.Getenv("SIMPLE_CLIENT_PROD_PROFILE_DEFAULT"),
		),
		"0",
	)
	return defaults
}

func resolveConnectOptions(in connectRequest, defaults connectDefaults) resolvedConnectOptions {
	profile := normalizeOptionalPathProfile(in.PathProfile)
	if profile == "" {
		profile = defaults.pathProfile
	}
	interfaceName := strings.TrimSpace(in.Interface)
	if interfaceName == "" {
		interfaceName = defaults.interfaceName
	}
	discoveryWaitSec := in.DiscoveryWaitSec
	if discoveryWaitSec <= 0 {
		discoveryWaitSec = defaultDiscoveryWaitSec
	}
	readyTimeoutSec := in.ReadyTimeoutSec
	if readyTimeoutSec <= 0 {
		readyTimeoutSec = defaultReadyTimeoutSec
	}
	runPreflight := defaults.runPreflight
	if in.RunPreflight != nil {
		runPreflight = *in.RunPreflight
	}
	prodProfile := defaultProdProfileForMode(defaults.prodMode, profile)
	if in.ProdProfile != nil {
		prodProfile = *in.ProdProfile
	}
	installRoute := true
	installRouteIsSet := in.InstallRoute != nil
	if installRouteIsSet {
		installRoute = *in.InstallRoute
	}
	return resolvedConnectOptions{
		profile:           profile,
		interfaceName:     interfaceName,
		discoveryWaitSec:  discoveryWaitSec,
		readyTimeoutSec:   readyTimeoutSec,
		runPreflight:      runPreflight,
		prodProfile:       prodProfile,
		installRoute:      installRoute,
		installRouteIsSet: installRouteIsSet,
	}
}

func deriveConnectPolicy(options resolvedConnectOptions) connectPolicy {
	policy := connectPolicy{
		minOperators:       2,
		operatorFloorCheck: 1,
		operatorMin:        2,
		issuerQuorumCheck:  1,
		issuerMin:          2,
		betaProfile:        1,
		prodFlag:           0,
		installRoute:       options.installRoute,
	}
	if options.profile == "1hop" {
		policy.minOperators = 1
		policy.operatorFloorCheck = 0
		policy.operatorMin = 1
		policy.issuerQuorumCheck = 0
		policy.issuerMin = 1
		policy.betaProfile = 0
		policy.prodFlag = 0
		if !options.installRouteIsSet {
			policy.installRoute = false
		}
		return policy
	}
	if options.prodProfile {
		policy.prodFlag = 1
	}
	return policy
}

func defaultProdProfileForMode(mode string, profile string) bool {
	switch mode {
	case "1":
		return true
	case "auto":
		return profile != "1hop"
	default:
		return false
	}
}

func normalizeProdModeWithDefault(raw string, fallback string) string {
	mode := normalizeProdMode(raw)
	if mode != "" {
		return mode
	}
	return fallback
}

func normalizeProdMode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "auto":
		return "auto"
	case "1", "true", "yes", "y", "on":
		return "1"
	case "0", "false", "no", "n", "off":
		return "0"
	default:
		return ""
	}
}

func parseBoolWithDefault(raw string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch value {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func boolTo01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func (s *Service) requireMutationAuth(w http.ResponseWriter, r *http.Request) bool {
	expected := strings.TrimSpace(s.authToken)
	authRequired := expected != "" || !isLoopbackBindAddr(s.addr)
	if !authRequired {
		return true
	}
	if expected == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "local api auth token not configured"})
		return false
	}
	if parseBearerToken(r.Header.Get("Authorization")) != expected {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthorized"})
		return false
	}
	return true
}

func parseBearerToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Fields(raw)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func isLoopbackBindAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return true
	}
	host := bindAddrHost(addr)
	if host == "" {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func bindAddrHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(addr)
}
