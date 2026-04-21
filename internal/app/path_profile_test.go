package app

import (
	"strings"
	"testing"
)

func TestResolvePathProfileValueContract(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		wantCanonical    string
		wantHintContains string
	}{
		{
			name:          "empty defaults to 2hop",
			raw:           "",
			wantCanonical: "2hop",
		},
		{
			name:          "speed maps to 2hop",
			raw:           "speed",
			wantCanonical: "2hop",
		},
		{
			name:          "balanced maps to 2hop",
			raw:           "balanced",
			wantCanonical: "2hop",
		},
		{
			name:          "private maps to 3hop",
			raw:           "private",
			wantCanonical: "3hop",
		},
		{
			name:          "speed-1hop maps to 1hop",
			raw:           "speed-1hop",
			wantCanonical: "1hop",
		},
		{
			name:             "legacy fast alias maps with migration hint",
			raw:              "fast",
			wantCanonical:    "2hop",
			wantHintContains: "legacy TDPN alias",
		},
		{
			name:             "legacy privacy alias maps with migration hint",
			raw:              "privacy",
			wantCanonical:    "3hop",
			wantHintContains: "legacy TDPN alias",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotCanonical, gotHint, err := resolvePathProfileValue(tc.raw, "TEST_PATH_PROFILE")
			if err != nil {
				t.Fatalf("resolvePathProfileValue(%q) err=%v", tc.raw, err)
			}
			if gotCanonical != tc.wantCanonical {
				t.Fatalf("resolvePathProfileValue(%q) canonical=%q want=%q", tc.raw, gotCanonical, tc.wantCanonical)
			}
			if tc.wantHintContains == "" {
				return
			}
			if !strings.Contains(gotHint, tc.wantHintContains) {
				t.Fatalf("resolvePathProfileValue(%q) hint=%q missing %q", tc.raw, gotHint, tc.wantHintContains)
			}
		})
	}
}

func TestResolvePathProfileValueRejectsAmbiguousOrInvalid(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantMessage string
	}{
		{
			name:        "ambiguous csv",
			raw:         "speed,private",
			wantMessage: "ambiguous",
		},
		{
			name:        "ambiguous spaced values",
			raw:         "speed private",
			wantMessage: "ambiguous",
		},
		{
			name:        "invalid token",
			raw:         "turbo",
			wantMessage: "invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := resolvePathProfileValue(tc.raw, "TEST_PATH_PROFILE")
			if err == nil {
				t.Fatalf("expected error for %q", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("error=%q missing %q", err.Error(), tc.wantMessage)
			}
			if !strings.Contains(err.Error(), clientPathProfileAllowedHints) {
				t.Fatalf("error=%q missing allowed-values hint", err.Error())
			}
		})
	}
}
