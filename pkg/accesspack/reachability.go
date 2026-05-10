package accesspack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultReachabilityTimeout = 8 * time.Second

type ReachabilityOptions struct {
	Timeout         time.Duration
	ProbeExternal   bool
	AllowOnionProbe bool
	Now             time.Time
}

type ReachabilityReport struct {
	Status           string               `json:"status"`
	PackID           string               `json:"pack_id"`
	OrganizationID   string               `json:"organization_id"`
	OrganizationName string               `json:"organization_name"`
	CheckedAtUTC     string               `json:"checked_at_utc"`
	ExpiresAtUTC     string               `json:"expires_at_utc"`
	Summary          ReachabilitySummary  `json:"summary"`
	Results          []ReachabilityResult `json:"results"`
}

type ReachabilitySummary struct {
	Total       int `json:"total"`
	Reachable   int `json:"reachable"`
	Unreachable int `json:"unreachable"`
	Timeout     int `json:"timeout"`
	Skipped     int `json:"skipped"`
}

type ReachabilityResult struct {
	Scope        string `json:"scope"`
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	URL          string `json:"url"`
	Trusted      bool   `json:"trusted"`
	Reachability string `json:"reachability"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	DurationMS   int64  `json:"duration_ms,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func CheckReachability(ctx context.Context, verified VerifiedPack, opts ReachabilityOptions) ReachabilityReport {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultReachabilityTimeout
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	pack := Normalize(verified.Pack)
	report := ReachabilityReport{
		Status:           "ok",
		PackID:           pack.PackID,
		OrganizationID:   pack.Organization.OrgID,
		OrganizationName: pack.Organization.Name,
		CheckedAtUTC:     now.UTC().Format(time.RFC3339),
		ExpiresAtUTC:     strings.TrimSpace(pack.ExpiresAtUTC),
	}
	for _, source := range pack.Sources {
		result := checkURL(ctx, client, "source", source.SourceID, source.Kind, source.URL, false, opts)
		report.add(result)
	}
	for _, path := range pack.AccessPaths {
		result := checkURL(ctx, client, "access_path", path.PathID, path.Kind, path.URL, path.RequiresExternalApp, opts)
		report.add(result)
	}
	return report
}

func (r *ReachabilityReport) add(result ReachabilityResult) {
	r.Results = append(r.Results, result)
	r.Summary.Total++
	switch result.Reachability {
	case "reachable":
		r.Summary.Reachable++
	case "timeout":
		r.Summary.Timeout++
	case "skipped":
		r.Summary.Skipped++
	default:
		r.Summary.Unreachable++
	}
}

func checkURL(ctx context.Context, client *http.Client, scope string, id string, kind string, rawURL string, requiresExternal bool, opts ReachabilityOptions) ReachabilityResult {
	result := ReachabilityResult{
		Scope:        scope,
		ID:           strings.TrimSpace(id),
		Kind:         strings.TrimSpace(kind),
		URL:          strings.TrimSpace(rawURL),
		Trusted:      true,
		Reachability: "unreachable",
	}
	if requiresExternal && !opts.ProbeExternal {
		result.Reachability = "skipped"
		result.Reason = "external_app_required"
		return result
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		result.Reason = "invalid_url"
		return result
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "http" && scheme != "https" {
		result.Reachability = "skipped"
		result.Reason = "unsupported_scheme"
		return result
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(parsed.Hostname())), ".onion") && !opts.AllowOnionProbe {
		result.Reachability = "skipped"
		result.Reason = "onion_probe_disabled"
		return result
	}
	return probeHTTP(ctx, client, result)
}

func probeHTTP(ctx context.Context, client *http.Client, result ReachabilityResult) ReachabilityResult {
	start := time.Now()
	status, reason, err := doProbeRequest(ctx, client, http.MethodHead, result.URL)
	if status == http.StatusMethodNotAllowed {
		status, reason, err = doProbeRequest(ctx, client, http.MethodGet, result.URL)
	}
	result.DurationMS = time.Since(start).Milliseconds()
	result.HTTPStatus = status
	if err != nil {
		if isTimeoutError(err) {
			result.Reachability = "timeout"
			result.Reason = "timeout"
			return result
		}
		result.Reachability = "unreachable"
		result.Reason = reason
		if result.Reason == "" {
			result.Reason = "request_failed"
		}
		return result
	}
	switch {
	case status >= 200 && status < 400:
		result.Reachability = "reachable"
		if status >= 300 {
			result.Reason = "redirect_response"
		}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		result.Reachability = "reachable"
		result.Reason = "auth_or_policy_response"
	default:
		result.Reachability = "unreachable"
		result.Reason = fmt.Sprintf("http_status_%d", status)
	}
	return result
}

func doProbeRequest(ctx context.Context, client *http.Client, method string, rawURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return 0, "invalid_request", err
	}
	req.Header.Set("User-Agent", "gpmrecover/0 access-recovery-probe")
	if method == http.MethodGet {
		req.Header.Set("Range", "bytes=0-0")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, classifyProbeError(err), err
	}
	defer resp.Body.Close()
	if method == http.MethodGet {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	}
	return resp.StatusCode, "", nil
}

func classifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	if isTimeoutError(err) {
		return "timeout"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_error"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return "network_error"
	}
	return "request_failed"
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
