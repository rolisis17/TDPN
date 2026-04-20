package types

import "testing"

func TestIsObjectiveEvidenceFormat(t *testing.T) {
	t.Parallel()

	const (
		validSHA256Lower = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		validSHA256Upper = "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	)

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "valid sha256 lowercase", value: validSHA256Lower, want: true},
		{name: "valid sha256 uppercase", value: validSHA256Upper, want: true},
		{name: "valid sha256 with surrounding whitespace", value: " \n" + validSHA256Lower + "\t ", want: true},
		{name: "valid object uri", value: "obj://bucket/key", want: true},
		{name: "valid object uri with punctuation", value: "obj://bucket/path/to/file.log?part=1#chunk", want: true},
		{name: "valid object uri with surrounding whitespace", value: "  obj://bucket/key  ", want: true},
		{name: "invalid empty", value: "", want: false},
		{name: "invalid unknown prefix", value: "legacy-proof-format", want: false},
		{name: "invalid uppercase sha prefix", value: "SHA256:abc", want: false},
		{name: "invalid sha256 wrong length", value: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", want: false},
		{name: "invalid sha256 non hex", value: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", want: false},
		{name: "invalid object uri empty path", value: "obj://", want: false},
		{name: "invalid object uri whitespace only path", value: "obj://   \t", want: false},
		{name: "invalid object uri contains space", value: "obj://bucket/key with-space", want: false},
		{name: "invalid object uri contains tab", value: "obj://bucket/\tkey", want: false},
		{name: "invalid object uri contains control character", value: "obj://bucket/key\x00suffix", want: false},
		{name: "invalid object uri contains backslash", value: "obj://bucket\\windows-path", want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsObjectiveEvidenceFormat(tc.value); got != tc.want {
				t.Fatalf("IsObjectiveEvidenceFormat(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}
