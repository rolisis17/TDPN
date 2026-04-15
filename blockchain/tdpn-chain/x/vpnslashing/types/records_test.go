package types

import "testing"

func TestSlashEvidenceValidateBasic(t *testing.T) {
	t.Parallel()

	base := SlashEvidence{
		EvidenceID: "evidence-1",
		Kind:       EvidenceKindObjective,
		ProofHash:  "sha256:proof-hash",
	}

	tests := []struct {
		name    string
		record  SlashEvidence
		wantErr string
	}{
		{name: "valid sha256", record: base},
		{
			name:   "valid object uri",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/key"},
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
			name:    "invalid sha256 empty suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:"},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri empty suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://"},
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
