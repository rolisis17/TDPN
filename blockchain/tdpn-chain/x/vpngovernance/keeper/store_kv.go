package keeper

import (
	"encoding/json"
	"fmt"
	"strings"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

const (
	policyPrefix      = "policy/"
	decisionPrefix    = "decision/"
	auditActionPrefix = "audit_action/"
	maxKVPayloadBytes = 1 << 20
)

// KVStore adapts KeeperStore onto a generic key/value backend.
type KVStore struct {
	store kvtypes.Store
}

// NewKVStore constructs a vpngovernance KV-backed store.
func NewKVStore(store kvtypes.Store) *KVStore {
	if store == nil {
		store = kvtypes.NewMapStore()
	}
	return &KVStore{store: store}
}

func (s *KVStore) UpsertPolicy(record types.GovernancePolicy) {
	normalized := normalizePolicy(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(policyKey(normalized.PolicyID), payload)
}

func (s *KVStore) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	canonicalPolicyID := canonicalKVToken(policyID)
	if canonicalPolicyID == "" {
		return types.GovernancePolicy{}, false
	}

	payload, ok := s.store.Get(policyKey(canonicalPolicyID))
	if !ok {
		return types.GovernancePolicy{}, false
	}

	record, err := decodePolicy(payload)
	if err != nil {
		return types.GovernancePolicy{}, false
	}
	if record.PolicyID != canonicalPolicyID {
		return types.GovernancePolicy{}, false
	}

	return record, true
}

func (s *KVStore) ListPolicies() []types.GovernancePolicy {
	records, err := s.ListPoliciesWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListPoliciesWithError() ([]types.GovernancePolicy, error) {
	records := make([]types.GovernancePolicy, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(policyPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, policyPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode policy key %q: %w", string(key), err)
			return false
		}

		record, err := decodePolicy(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode policy %q: %w", keyID, err)
			return false
		}
		if record.PolicyID != keyID {
			decodeErr = fmt.Errorf("policy key/value id mismatch: key=%q payload=%q", keyID, record.PolicyID)
			return false
		}

		records = append(records, record)
		return true
	})
	if decodeErr != nil {
		return nil, decodeErr
	}
	return records, nil
}

func (s *KVStore) UpsertDecision(record types.GovernanceDecision) {
	normalized := normalizeDecision(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(decisionKey(normalized.DecisionID), payload)
}

func (s *KVStore) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	canonicalDecisionID := canonicalKVToken(decisionID)
	if canonicalDecisionID == "" {
		return types.GovernanceDecision{}, false
	}

	payload, ok := s.store.Get(decisionKey(canonicalDecisionID))
	if !ok {
		return types.GovernanceDecision{}, false
	}

	record, err := decodeDecision(payload)
	if err != nil {
		return types.GovernanceDecision{}, false
	}
	if record.DecisionID != canonicalDecisionID {
		return types.GovernanceDecision{}, false
	}

	return record, true
}

func (s *KVStore) ListDecisions() []types.GovernanceDecision {
	records, err := s.ListDecisionsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListDecisionsWithError() ([]types.GovernanceDecision, error) {
	records := make([]types.GovernanceDecision, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(decisionPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, decisionPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode decision key %q: %w", string(key), err)
			return false
		}

		record, err := decodeDecision(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode decision %q: %w", keyID, err)
			return false
		}
		if record.DecisionID != keyID {
			decodeErr = fmt.Errorf("decision key/value id mismatch: key=%q payload=%q", keyID, record.DecisionID)
			return false
		}

		records = append(records, record)
		return true
	})
	if decodeErr != nil {
		return nil, decodeErr
	}
	return records, nil
}

func (s *KVStore) PutAuditAction(record types.GovernanceAuditAction) {
	normalized := normalizeAuditAction(record)
	if err := normalized.ValidateBasic(); err != nil {
		return
	}

	payload, err := json.Marshal(normalized)
	if err != nil {
		return
	}
	s.store.Set(auditActionKey(normalized.ActionID), payload)
}

func (s *KVStore) GetAuditAction(actionID string) (types.GovernanceAuditAction, bool) {
	canonicalActionID := canonicalKVToken(actionID)
	if canonicalActionID == "" {
		return types.GovernanceAuditAction{}, false
	}

	payload, ok := s.store.Get(auditActionKey(canonicalActionID))
	if !ok {
		return types.GovernanceAuditAction{}, false
	}

	record, err := decodeAuditAction(payload)
	if err != nil {
		return types.GovernanceAuditAction{}, false
	}
	if record.ActionID != canonicalActionID {
		return types.GovernanceAuditAction{}, false
	}

	return record, true
}

func (s *KVStore) ListAuditActions() []types.GovernanceAuditAction {
	records, err := s.ListAuditActionsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *KVStore) ListAuditActionsWithError() ([]types.GovernanceAuditAction, error) {
	records := make([]types.GovernanceAuditAction, 0)
	var decodeErr error
	s.store.IteratePrefix([]byte(auditActionPrefix), func(key []byte, value []byte) bool {
		keyID, err := parsePrefixedID(key, auditActionPrefix)
		if err != nil {
			decodeErr = fmt.Errorf("decode audit action key %q: %w", string(key), err)
			return false
		}

		record, err := decodeAuditAction(value)
		if err != nil {
			decodeErr = fmt.Errorf("decode audit action %q: %w", keyID, err)
			return false
		}
		if record.ActionID != keyID {
			decodeErr = fmt.Errorf("audit action key/value id mismatch: key=%q payload=%q", keyID, record.ActionID)
			return false
		}

		records = append(records, record)
		return true
	})
	if decodeErr != nil {
		return nil, decodeErr
	}
	return records, nil
}

func policyKey(policyID string) []byte {
	return []byte(policyPrefix + policyID)
}

func decisionKey(decisionID string) []byte {
	return []byte(decisionPrefix + decisionID)
}

func auditActionKey(actionID string) []byte {
	return []byte(auditActionPrefix + actionID)
}

func decodePolicy(payload []byte) (types.GovernancePolicy, error) {
	if len(payload) == 0 {
		return types.GovernancePolicy{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.GovernancePolicy{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.GovernancePolicy
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.GovernancePolicy{}, err
	}
	normalized := normalizePolicy(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.GovernancePolicy{}, err
	}
	return normalized, nil
}

func decodeDecision(payload []byte) (types.GovernanceDecision, error) {
	if len(payload) == 0 {
		return types.GovernanceDecision{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.GovernanceDecision{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.GovernanceDecision
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.GovernanceDecision{}, err
	}
	normalized := normalizeDecision(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.GovernanceDecision{}, err
	}
	return normalized, nil
}

func decodeAuditAction(payload []byte) (types.GovernanceAuditAction, error) {
	if len(payload) == 0 {
		return types.GovernanceAuditAction{}, fmt.Errorf("payload is empty")
	}
	if len(payload) > maxKVPayloadBytes {
		return types.GovernanceAuditAction{}, fmt.Errorf("payload exceeds %d bytes", maxKVPayloadBytes)
	}

	var record types.GovernanceAuditAction
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.GovernanceAuditAction{}, err
	}
	normalized := normalizeAuditAction(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.GovernanceAuditAction{}, err
	}
	return normalized, nil
}

func parsePrefixedID(key []byte, prefix string) (string, error) {
	rawKey := string(key)
	if !strings.HasPrefix(rawKey, prefix) {
		return "", fmt.Errorf("missing prefix %q", prefix)
	}

	suffix := canonicalKVToken(strings.TrimPrefix(rawKey, prefix))
	if suffix == "" {
		return "", fmt.Errorf("key id is empty")
	}
	if rawKey != prefix+suffix {
		return "", fmt.Errorf("key id is not canonical")
	}
	return suffix, nil
}

func canonicalKVToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
