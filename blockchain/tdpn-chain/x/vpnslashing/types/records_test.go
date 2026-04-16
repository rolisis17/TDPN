package types

import "testing"

func TestSlashEvidenceValidateBasic(t *testing.T) {
	t.Parallel()

	const (
		validSHA256Lower = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		validSHA256Upper = "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	)

	base := SlashEvidence{
		EvidenceID: "evidence-1",
		Kind:       EvidenceKindObjective,
		ProofHash:  validSHA256Lower,
	}

	tests := []struct {
		name    string
		record  SlashEvidence
		wantErr string
	}{
		{name: "valid sha256 lowercase", record: base},
		{
			name:   "valid sha256 uppercase",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: validSHA256Upper},
		},
		{
			name:   "valid object uri",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/key"},
		},
		{
			name:   "valid object uri nested path edge",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/path/to/file.log?part=1#chunk"},
		},
		{
			name:    "missing evidence id",
			record:  SlashEvidence{Kind: base.Kind, ProofHash: base.ProofHash},
			wantErr: "evidence id is required",
		},
		{
			name:    "non-objective kind",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: "subjective", ProofHash: base.ProofHash},
			wantErr: "evidence kind must be objective",
		},
		{
			name:    "missing proof hash",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind},
			wantErr: "proof hash is required",
		},
		{
			name:    "invalid proof hash format",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "legacy-proof-format"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid wrong sha256 prefix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha-256:proof"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid uppercase sha256 prefix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "SHA256:proof"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid wrong object prefix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "object://bucket/key"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid malformed sha256 separator",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256/proof"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid malformed object separator",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj:/bucket/key"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 too short",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 too long",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 non hex character",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 empty suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 whitespace only suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:\t  \n"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 includes internal whitespace",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde "},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri empty suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri whitespace only suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://   \t"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri whitespace in path",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/key with-space"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri tab in path",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/\tkey"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestPenaltyDecisionValidateBasic(t *testing.T) {
	t.Parallel()

	base := PenaltyDecision{
		PenaltyID:       "penalty-1",
		EvidenceID:      "evidence-1",
		SlashBasisPoint: 25,
	}

	tests := []struct {
		name    string
		record  PenaltyDecision
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing penalty id",
			record:  PenaltyDecision{EvidenceID: base.EvidenceID, SlashBasisPoint: base.SlashBasisPoint},
			wantErr: "penalty id is required",
		},
		{
			name:    "missing evidence id",
			record:  PenaltyDecision{PenaltyID: base.PenaltyID, SlashBasisPoint: base.SlashBasisPoint},
			wantErr: "evidence id is required",
		},
		{
			name:    "slash basis points too high",
			record:  PenaltyDecision{PenaltyID: base.PenaltyID, EvidenceID: base.EvidenceID, SlashBasisPoint: 10001},
			wantErr: "slash basis points cannot exceed 10000",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}
