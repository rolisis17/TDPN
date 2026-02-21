package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"privacynode/pkg/proto"
)

func TestOpenPathWithChallengeRetries(t *testing.T) {
	entryURL := "http://entry.local"
	calls := 0
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": func(req *http.Request) (*http.Response, error) {
			calls++
			var in proto.PathOpenRequest
			_ = json.NewDecoder(req.Body).Decode(&in)
			if calls == 1 {
				return jsonResponse(proto.PathOpenResponse{
					Accepted:   false,
					Reason:     "challenge-required",
					Challenge:  "abc",
					Difficulty: 1,
				})(req)
			}
			if in.PuzzleNonce == "" || in.PuzzleDigest == "" {
				return jsonResponse(proto.PathOpenResponse{Accepted: false, Reason: "missing puzzle"})(req)
			}
			return jsonResponse(proto.PathOpenResponse{
				Accepted:      true,
				SessionID:     "s1",
				EntryDataAddr: "127.0.0.1:51820",
				Transport:     "policy-json",
			})(req)
		},
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	resp, err := c.openPathWithChallenge(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:       "exit-a",
		Token:        "tok",
		Transport:    "policy-json",
		SessionID:    "unused",
		RequestedMTU: 1280,
	})
	if err != nil {
		t.Fatalf("openPathWithChallenge failed: %v", err)
	}
	if !resp.Accepted || resp.SessionID != "s1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if calls != 2 {
		t.Fatalf("expected two open calls, got %d", calls)
	}
}

func TestOpenPathWithChallengeDenied(t *testing.T) {
	entryURL := "http://entry.local"
	handlers := map[string]func(*http.Request) (*http.Response, error){
		entryURL + "/v1/path/open": jsonResponse(proto.PathOpenResponse{
			Accepted: false,
			Reason:   "exit scope denied",
		}),
	}
	c := &Client{
		httpClient: &http.Client{Transport: mockRoundTripper{handlers: handlers}},
	}
	_, err := c.openPathWithChallenge(context.Background(), entryURL, proto.PathOpenRequest{
		ExitID:    "exit-a",
		Token:     "tok",
		Transport: "policy-json",
	})
	if err == nil || !strings.Contains(err.Error(), "path open denied") {
		t.Fatalf("expected denied error, got %v", err)
	}
}

func jsonResponse(v interface{}) func(*http.Request) (*http.Response, error) {
	return func(_ *http.Request) (*http.Response, error) {
		b, _ := json.Marshal(v)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(b)),
		}, nil
	}
}
