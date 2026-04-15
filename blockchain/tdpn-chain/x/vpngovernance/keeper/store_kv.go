package keeper

import (
	"encoding/json"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

const (
	policyPrefix   = "policy/"
	decisionPrefix = "decision/"
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
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(policyKey(record.PolicyID), payload)
}

func (s *KVStore) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	payload, ok := s.store.Get(policyKey(policyID))
	if !ok {
		return types.GovernancePolicy{}, false
	}

	var record types.GovernancePolicy
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.GovernancePolicy{}, false
	}

	return record, true
}

func (s *KVStore) ListPolicies() []types.GovernancePolicy {
	records := make([]types.GovernancePolicy, 0)
	s.store.IteratePrefix([]byte(policyPrefix), func(_ []byte, value []byte) bool {
		var record types.GovernancePolicy
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func (s *KVStore) UpsertDecision(record types.GovernanceDecision) {
	payload, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.store.Set(decisionKey(record.DecisionID), payload)
}

func (s *KVStore) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	payload, ok := s.store.Get(decisionKey(decisionID))
	if !ok {
		return types.GovernanceDecision{}, false
	}

	var record types.GovernanceDecision
	if err := json.Unmarshal(payload, &record); err != nil {
		return types.GovernanceDecision{}, false
	}

	return record, true
}

func (s *KVStore) ListDecisions() []types.GovernanceDecision {
	records := make([]types.GovernanceDecision, 0)
	s.store.IteratePrefix([]byte(decisionPrefix), func(_ []byte, value []byte) bool {
		var record types.GovernanceDecision
		if err := json.Unmarshal(value, &record); err == nil {
			records = append(records, record)
		}
		return true
	})
	return records
}

func policyKey(policyID string) []byte {
	return []byte(policyPrefix + policyID)
}

func decisionKey(decisionID string) []byte {
	return []byte(decisionPrefix + decisionID)
}
