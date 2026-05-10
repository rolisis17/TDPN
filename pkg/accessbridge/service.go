package accessbridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"privacynode/pkg/accesspack"
	"privacynode/pkg/httplimit"
)

type ServiceConfig struct {
	BridgeConfig accesspack.BridgeServiceConfig
	RPS          int
	MaxSources   int
	AbuseLogPath string
	Redirect     bool
	Now          func() time.Time
}

type Service struct {
	config       accesspack.BridgeServiceConfig
	limiter      *httplimit.FixedWindowLimiter
	abuseLogPath string
	redirect     bool
	now          func() time.Time
	mu           sync.Mutex
	requests     map[string]int
	abuseReports int
}

type HealthResponse struct {
	Status   string                           `json:"status"`
	Decision accesspack.BridgeServiceDecision `json:"decision"`
}

type BridgeResponse struct {
	Status                string                           `json:"status"`
	AccessURL             string                           `json:"access_url,omitempty"`
	HelperAbuseReportURL  string                           `json:"helper_abuse_report_url,omitempty"`
	HelperRateLimitPolicy string                           `json:"helper_rate_limit_policy,omitempty"`
	Decision              accesspack.BridgeServiceDecision `json:"decision"`
}

type AbuseReport struct {
	GeneratedAtUTC string `json:"generated_at_utc"`
	Source         string `json:"source"`
	PathID         string `json:"path_id,omitempty"`
	Message        string `json:"message,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
}

type abuseReportInput struct {
	PathID  string `json:"path_id,omitempty"`
	Message string `json:"message,omitempty"`
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.RPS < 0 {
		return nil, fmt.Errorf("rps must be non-negative")
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	service := &Service{
		config:       accesspack.NormalizeBridgeServiceConfig(config.BridgeConfig),
		limiter:      httplimit.NewFixedWindowLimiter(config.RPS, config.MaxSources),
		abuseLogPath: strings.TrimSpace(config.AbuseLogPath),
		redirect:     config.Redirect,
		now:          now,
		requests:     map[string]int{},
	}
	decision := accesspack.EvaluateBridgeServiceRequest(service.config, accesspack.BridgeServiceRequest{}, now())
	if !decision.Allowed {
		return nil, fmt.Errorf("bridge service config failed preflight: %s", decision.Reason)
	}
	if !hasServiceableBridgePath(service.config, now()) {
		return nil, fmt.Errorf("bridge service config has no serviceable HTTP bridge path")
	}
	return service, nil
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/bridge/", s.handleBridge)
	mux.HandleFunc("/abuse", s.handleAbuse)
	return mux
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	decision := accesspack.EvaluateBridgeServiceRequest(s.config, accesspack.BridgeServiceRequest{}, s.now())
	status := http.StatusOK
	outStatus := "ok"
	if !decision.Allowed {
		status = http.StatusServiceUnavailable
		outStatus = "fail"
	}
	writeJSON(w, status, HealthResponse{Status: outStatus, Decision: decision})
}

func (s *Service) handleBridge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pathID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/bridge/"), "/")
	if pathID == "" {
		http.Error(w, "missing bridge path id", http.StatusBadRequest)
		return
	}
	source := sourceKey(r)
	now := s.now()
	if s.limiter != nil && !s.limiter.Allow(source, now) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"status": "rate_limited"})
		return
	}
	s.recordRequest(source)
	decision := accesspack.EvaluateBridgeServiceRequest(s.config, accesspack.BridgeServiceRequest{
		PathID: pathID,
		Source: source,
	}, now)
	if !decision.Allowed {
		writeJSON(w, http.StatusForbidden, BridgeResponse{Status: "denied", Decision: decision})
		return
	}
	accessURL := ""
	if decision.MatchedAccessPath != nil {
		accessURL = decision.MatchedAccessPath.URL
	}
	if s.redirect && accessURL != "" {
		http.Redirect(w, r, accessURL, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, BridgeResponse{
		Status:                "ok",
		AccessURL:             accessURL,
		HelperAbuseReportURL:  decision.HelperAbuseReportURL,
		HelperRateLimitPolicy: decision.HelperRateLimitPolicy,
		Decision:              decision,
	})
}

func (s *Service) handleAbuse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}
	if len(body) > 16*1024 {
		http.Error(w, "abuse report too large", http.StatusRequestEntityTooLarge)
		return
	}
	var input abuseReportInput
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &input); err != nil {
			http.Error(w, "invalid abuse report json", http.StatusBadRequest)
			return
		}
	}
	report := AbuseReport{
		GeneratedAtUTC: s.now().UTC().Format(time.RFC3339),
		Source:         sourceKey(r),
		PathID:         strings.TrimSpace(input.PathID),
		Message:        strings.TrimSpace(input.Message),
		UserAgent:      strings.TrimSpace(r.UserAgent()),
	}
	if err := s.appendAbuseReport(report); err != nil {
		http.Error(w, "abuse report log failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func (s *Service) RequestCount(source string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[source]
}

func (s *Service) AbuseReportCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.abuseReports
}

func (s *Service) recordRequest(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[source]++
}

func (s *Service) appendAbuseReport(report AbuseReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.abuseReports++
	if s.abuseLogPath == "" {
		return nil
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.abuseLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return err
	}
	return nil
}

func sourceKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func hasServiceableBridgePath(config accesspack.BridgeServiceConfig, now time.Time) bool {
	for _, path := range config.AccessPaths {
		decision := accesspack.EvaluateBridgeServiceRequest(config, accesspack.BridgeServiceRequest{PathID: path.PathID}, now)
		if decision.Allowed {
			return true
		}
	}
	return false
}
