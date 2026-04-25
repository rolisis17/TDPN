package types

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

func TestSlashEvidenceValidateBasic(t *testing.T) {
	t.Parallel()

	const (
		validSHA256Lower = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		validSHA256Upper = "sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	)

	base := SlashEvidence{
		EvidenceID:    "evidence-1",
		ProviderID:    "provider-1",
		SessionID:     "session-1",
		Kind:          EvidenceKindObjective,
		ProofHash:     validSHA256Lower,
		ViolationType: "double-sign",
	}

	tests := []struct {
		name    string
		record  SlashEvidence
		wantErr string
	}{
		{name: "valid sha256 lowercase", record: base},
		{
			name:   "valid canonicalizable evidence id",
			record: SlashEvidence{EvidenceID: " \nEVIDENCE-1\t ", Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
		},
		{
			name:   "valid sha256 uppercase",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: validSHA256Upper, ViolationType: base.ViolationType},
		},
		{
			name:   "valid sha256 with surrounding whitespace",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: " \n" + validSHA256Lower + "\t ", ViolationType: base.ViolationType},
		},
		{
			name:   "valid object uri",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/key", ViolationType: base.ViolationType},
		},
		{
			name:   "valid object uri with surrounding whitespace",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "  obj://bucket/key  ", ViolationType: base.ViolationType},
		},
		{
			name:   "valid object uri nested path edge",
			record: SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/path/to/file.log?part=1#chunk", ViolationType: base.ViolationType},
		},
		{
			name:    "evidence id too long",
			record:  SlashEvidence{EvidenceID: strings.Repeat("e", 129), Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "evidence id exceeds 128 characters",
		},
		{
			name:    "provider id too long",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, ProviderID: strings.Repeat("p", 129), Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "provider id exceeds 128 characters",
		},
		{
			name:    "session id too long",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, ProviderID: base.ProviderID, SessionID: strings.Repeat("s", 129), Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "session id exceeds 128 characters",
		},
		{
			name:    "missing provider id",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, ProviderID: " \t ", SessionID: base.SessionID, Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "provider id is required",
		},
		{
			name:    "missing session id",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, ProviderID: base.ProviderID, SessionID: " \n ", Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "session id is required",
		},
		{
			name:    "proof hash too long",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://" + strings.Repeat("a", 1020), ViolationType: base.ViolationType},
			wantErr: "proof hash exceeds 1024 characters",
		},
		{
			name:    "missing evidence id",
			record:  SlashEvidence{Kind: base.Kind, ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "evidence id is required",
		},
		{
			name:    "non-objective kind",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: "subjective", ProofHash: base.ProofHash, ViolationType: base.ViolationType},
			wantErr: "evidence kind must be objective",
		},
		{
			name:    "missing proof hash",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ViolationType: base.ViolationType},
			wantErr: "proof hash is required",
		},
		{
			name:    "invalid proof hash format",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "legacy-proof-format", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid wrong sha256 prefix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha-256:proof", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid uppercase sha256 prefix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "SHA256:proof", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid wrong object prefix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "object://bucket/key", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid malformed sha256 separator",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256/proof", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid malformed object separator",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj:/bucket/key", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 too short",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 too long",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 non hex character",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 empty suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 whitespace only suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:\t  \n", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid sha256 includes internal whitespace",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde ", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri empty suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri whitespace only suffix",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://   \t", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri whitespace in path",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/key with-space", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
		{
			name:    "invalid object uri tab in path",
			record:  SlashEvidence{EvidenceID: base.EvidenceID, Kind: base.Kind, ProofHash: "obj://bucket/\tkey", ViolationType: base.ViolationType},
			wantErr: "proof hash must use objective format (sha256:<value> or obj://<value>)",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := tc.record
			if record.ProviderID == "" {
				record.ProviderID = base.ProviderID
			}
			if record.SessionID == "" {
				record.SessionID = base.SessionID
			}

			err := record.ValidateBasic()
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
			name:   "valid canonicalizable ids",
			record: PenaltyDecision{PenaltyID: " \tPENALTY-1 ", EvidenceID: " \nEVIDENCE-1 ", SlashBasisPoint: base.SlashBasisPoint},
		},
		{
			name:   "valid jail-only penalty",
			record: PenaltyDecision{PenaltyID: "penalty-jail-only", EvidenceID: base.EvidenceID, SlashBasisPoint: 0, Jailed: true},
		},
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
		{
			name:    "penalty id too long",
			record:  PenaltyDecision{PenaltyID: strings.Repeat("p", 129), EvidenceID: base.EvidenceID, SlashBasisPoint: base.SlashBasisPoint},
			wantErr: "penalty id exceeds 128 characters",
		},
		{
			name:    "no-op penalty decision",
			record:  PenaltyDecision{PenaltyID: base.PenaltyID, EvidenceID: base.EvidenceID, SlashBasisPoint: 0, Jailed: false},
			wantErr: "penalty decision must slash or jail",
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

func TestNormalizeIDHelpers(t *testing.T) {
	t.Parallel()

	if got := NormalizeEvidenceID(" \nEVIDENCE-ABC\t "); got != "evidence-abc" {
		t.Fatalf("expected normalized evidence id %q, got %q", "evidence-abc", got)
	}
	if got := NormalizePenaltyID(" \nPENALTY-ABC\t "); got != "penalty-abc" {
		t.Fatalf("expected normalized penalty id %q, got %q", "penalty-abc", got)
	}
}

func TestSlashEvidenceValidateBasicViolationType(t *testing.T) {
	t.Parallel()

	base := SlashEvidence{
		EvidenceID:    "evidence-violation-type-1",
		ProviderID:    "provider-violation-type-1",
		SessionID:     "session-violation-type-1",
		Kind:          EvidenceKindObjective,
		ProofHash:     "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ViolationType: "double-sign",
	}

	t.Run("empty violation type rejected", func(t *testing.T) {
		t.Parallel()
		record := base
		record.ViolationType = ""
		err := record.ValidateBasic()
		if err == nil {
			t.Fatal("expected empty violation type to fail")
		}
		if err.Error() != "violation type is required" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("whitespace-only violation type rejected", func(t *testing.T) {
		t.Parallel()
		record := base
		record.ViolationType = "  \n\t "
		err := record.ValidateBasic()
		if err == nil {
			t.Fatal("expected whitespace-only violation type to fail")
		}
		if err.Error() != "violation type is required" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	accepted := []string{
		"double-sign",
		"downtime-proof",
		"invalid-settlement-proof",
		"session-replay-proof",
		"sponsor-overdraft-proof",
		"  DOUBLE-SIGN  ",
		"\nDowntime-Proof\t",
		" Invalid-Settlement-Proof ",
		"\tsession-replay-proof",
		"  sponsor-overdraft-proof\n",
	}
	for _, violationType := range accepted {
		violationType := violationType
		t.Run("accepted objective violation type "+violationType, func(t *testing.T) {
			t.Parallel()
			record := base
			record.ViolationType = violationType
			if err := record.ValidateBasic(); err != nil {
				t.Fatalf("expected violation type %q to be accepted, got %v", violationType, err)
			}
		})
	}

	t.Run("rejected non-objective violation type", func(t *testing.T) {
		t.Parallel()
		record := base
		record.ViolationType = "manual-review-only"
		err := record.ValidateBasic()
		if err == nil {
			t.Fatal("expected non-objective violation type to fail")
		}
		if err.Error() != "violation type must be one of: double-sign, downtime-proof, invalid-settlement-proof, session-replay-proof, sponsor-overdraft-proof" {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestSlashEvidenceValidateBasicAllowsTerminalLifecycleStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status chaintypes.ReconciliationStatus
	}{
		{name: "confirmed", status: chaintypes.ReconciliationConfirmed},
		{name: "failed", status: chaintypes.ReconciliationFailed},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := SlashEvidence{
				EvidenceID:    "evidence-status-" + tc.name,
				ProviderID:    "provider-status-" + tc.name,
				SessionID:     "session-status-" + tc.name,
				Kind:          EvidenceKindObjective,
				ProofHash:     "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				ViolationType: "double-sign",
				Status:        tc.status,
			}
			if err := record.ValidateBasic(); err != nil {
				t.Fatalf("expected status %q to remain compatible with objective evidence validation, got %v", tc.status, err)
			}
		})
	}
}

func TestCanonicalObjectiveEvidenceIdentity(t *testing.T) {
	t.Parallel()

	base := SlashEvidence{
		EvidenceID:    "evidence-identity-base",
		Kind:          EvidenceKindObjective,
		ProviderID:    "Provider-Case-1",
		SessionID:     "Session-Case-1",
		ViolationType: "  DOUBLE-SIGN ",
		ProofHash:     "obj://Bucket/Case/Path",
	}

	caseVariant := SlashEvidence{
		EvidenceID:    "evidence-identity-variant",
		Kind:          " OBJECTIVE ",
		ProviderID:    "provider-case-1",
		SessionID:     " session-case-1 ",
		ViolationType: "double-sign",
		ProofHash:     " obj://bucket/case/path ",
	}

	if CanonicalObjectiveEvidenceIdentity(base) != CanonicalObjectiveEvidenceIdentity(caseVariant) {
		t.Fatalf(
			"expected canonical identity equality for case/whitespace variants: base=%q variant=%q",
			CanonicalObjectiveEvidenceIdentity(base),
			CanonicalObjectiveEvidenceIdentity(caseVariant),
		)
	}

	other := base
	other.ProofHash = "obj://bucket/case/path/other"
	if CanonicalObjectiveEvidenceIdentity(base) == CanonicalObjectiveEvidenceIdentity(other) {
		t.Fatalf(
			"expected canonical identity to differ when objective proof reference changes: base=%q other=%q",
			CanonicalObjectiveEvidenceIdentity(base),
			CanonicalObjectiveEvidenceIdentity(other),
		)
	}
}
