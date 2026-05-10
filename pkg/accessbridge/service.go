package accessbridge

import (
	"crypto/sha256"
	"crypto/subtle"
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
	BridgeConfig      accesspack.BridgeServiceConfig
	RPS               int
	MaxSources        int
	AbuseLogPath      string
	Redirect          bool
	AccessCodeSHA256  string
	AllowQueryCode    bool
	TrustProxyHeaders bool
	Now               func() time.Time
}

type Service struct {
	config            accesspack.BridgeServiceConfig
	limiter           *httplimit.FixedWindowLimiter
	abuseLimiter      *httplimit.FixedWindowLimiter
	abuseLogPath      string
	redirect          bool
	accessCodeHash    []byte
	allowQueryCode    bool
	trustProxyHeaders bool
	now               func() time.Time
	mu                sync.Mutex
	requests          map[string]int
	abuseReports      int
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
	accessCodeHash, err := parseAccessCodeHash(config.AccessCodeSHA256)
	if err != nil {
		return nil, err
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	service := &Service{
		config:            accesspack.NormalizeBridgeServiceConfig(config.BridgeConfig),
		limiter:           httplimit.NewFixedWindowLimiter(config.RPS, config.MaxSources),
		abuseLimiter:      httplimit.NewFixedWindowLimiter(config.RPS, config.MaxSources),
		abuseLogPath:      strings.TrimSpace(config.AbuseLogPath),
		redirect:          config.Redirect,
		accessCodeHash:    accessCodeHash,
		allowQueryCode:    config.AllowQueryCode,
		trustProxyHeaders: config.TrustProxyHeaders,
		now:               now,
		requests:          map[string]int{},
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
	setBridgeSecurityHeaders(w)
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
	setBridgeSecurityHeaders(w)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pathID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/bridge/"), "/")
	if pathID == "" {
		http.Error(w, "missing bridge path id", http.StatusBadRequest)
		return
	}
	source := s.sourceKey(r)
	now := s.now()
	if !s.accessCodeAllowed(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"status": "access_code_required"})
		return
	}
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
	setBridgeSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	source := s.sourceKey(r)
	if s.abuseLimiter != nil && !s.abuseLimiter.Allow(source, s.now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"status": "rate_limited"})
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
		Source:         source,
		PathID:         limitText(strings.TrimSpace(input.PathID), 128),
		Message:        limitText(strings.TrimSpace(input.Message), 1024),
		UserAgent:      limitText(strings.TrimSpace(r.UserAgent()), 240),
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

func (s *Service) sourceKey(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		if s.trustProxyHeaders && isLoopbackIP(host) {
			if forwarded := firstForwardedFor(r.Header.Get("X-Forwarded-For")); forwarded != "" {
				return forwarded
			}
		}
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "unknown"
}

func firstForwardedFor(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		ip := strings.TrimSpace(part)
		if parsed := net.ParseIP(ip); parsed != nil {
			return parsed.String()
		}
	}
	return ""
}

func isLoopbackIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	return ip != nil && ip.IsLoopback()
}

func limitText(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	setBridgeSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func setBridgeSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func parseAccessCodeHash(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if len(raw) != sha256.Size*2 {
		return nil, fmt.Errorf("access code sha256 must be %d hex characters", sha256.Size*2)
	}
	out := make([]byte, sha256.Size)
	for i := 0; i < sha256.Size; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := raw[i*2+j]
			switch {
			case c >= '0' && c <= '9':
				b = b<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				b = b<<4 | (c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				b = b<<4 | (c - 'A' + 10)
			default:
				return nil, fmt.Errorf("access code sha256 must be hex")
			}
		}
		out[i] = b
	}
	return out, nil
}

func (s *Service) accessCodeAllowed(r *http.Request) bool {
	if len(s.accessCodeHash) == 0 {
		return true
	}
	code := strings.TrimSpace(r.Header.Get("X-GPM-Bridge-Code"))
	if code == "" && s.allowQueryCode {
		code = strings.TrimSpace(r.URL.Query().Get("code"))
	}
	if code == "" {
		return false
	}
	sum := sha256.Sum256([]byte(code))
	return subtle.ConstantTimeCompare(sum[:], s.accessCodeHash) == 1
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
