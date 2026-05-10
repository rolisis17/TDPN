package accesspack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckReachabilitySeparatesTrustedReachableAndSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	pack := testPack()
	pack.Sources = []Source{
		{SourceID: "official", Kind: "official", URL: server.URL, Priority: 10},
	}
	pack.AccessPaths = []AccessPath{
		{PathID: "main", Kind: "website", URL: server.URL, Priority: 10},
		{PathID: "onion", Kind: "tor-onion", URL: "http://exampleabcdefghijklmnop.onion", Priority: 20},
		{PathID: "outline", Kind: "outline", URL: "https://outline.example/config", Priority: 30, RequiresExternalApp: true},
	}
	report := CheckReachability(context.Background(), VerifiedPack{Pack: pack}, ReachabilityOptions{
		Timeout: 2 * time.Second,
		Now:     time.Date(2026, 5, 10, 2, 0, 0, 0, time.UTC),
	})
	if report.Summary.Total != 4 {
		t.Fatalf("total=%d want=4 report=%+v", report.Summary.Total, report)
	}
	if report.Summary.Reachable != 2 {
		t.Fatalf("reachable=%d want=2 report=%+v", report.Summary.Reachable, report)
	}
	if report.Summary.Skipped != 2 {
		t.Fatalf("skipped=%d want=2 report=%+v", report.Summary.Skipped, report)
	}
	reasons := map[string]string{}
	for _, result := range report.Results {
		reasons[result.ID] = result.Reason
		if !result.Trusted {
			t.Fatalf("result should be trusted after pack verification: %+v", result)
		}
	}
	if reasons["onion"] != "onion_probe_disabled" {
		t.Fatalf("onion reason=%q want onion_probe_disabled", reasons["onion"])
	}
	if reasons["outline"] != "external_app_required" {
		t.Fatalf("outline reason=%q want external_app_required", reasons["outline"])
	}
}

func TestCheckReachabilityFallbacksFromHeadMethodNotAllowedToGet(t *testing.T) {
	var gotGET bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			gotGET = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(server.Close)

	pack := testPack()
	pack.Sources = nil
	pack.AccessPaths = []AccessPath{{PathID: "main", Kind: "website", URL: server.URL, Priority: 10}}
	report := CheckReachability(context.Background(), VerifiedPack{Pack: pack}, ReachabilityOptions{Timeout: 2 * time.Second})
	if !gotGET {
		t.Fatalf("expected GET fallback")
	}
	if report.Summary.Reachable != 1 {
		t.Fatalf("reachable=%d want=1 report=%+v", report.Summary.Reachable, report)
	}
}
