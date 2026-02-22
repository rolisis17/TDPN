package proto

import "time"

const (
	SubjectKindRelayExit = "relay-exit"
	SubjectKindClient    = "client"
)

type RelayDescriptor struct {
	RelayID        string    `json:"relay_id"`
	Role           string    `json:"role"`
	OperatorID     string    `json:"operator_id,omitempty"`
	OriginOperator string    `json:"origin_operator,omitempty"`
	HopCount       int       `json:"hop_count,omitempty"`
	PubKey         string    `json:"pub_key"`
	Endpoint       string    `json:"endpoint"`
	ControlURL     string    `json:"control_url,omitempty"`
	CountryCode    string    `json:"country_code,omitempty"`
	GeoConfidence  float64   `json:"geo_confidence,omitempty"`
	Region         string    `json:"region"`
	Reputation     float64   `json:"reputation_score,omitempty"`
	Uptime         float64   `json:"uptime_score,omitempty"`
	Capacity       float64   `json:"capacity_score,omitempty"`
	AbusePenalty   float64   `json:"abuse_penalty,omitempty"`
	BondScore      float64   `json:"bond_score,omitempty"`
	StakeScore     float64   `json:"stake_score,omitempty"`
	Capabilities   []string  `json:"capabilities"`
	ValidUntil     time.Time `json:"valid_until"`
	Signature      string    `json:"signature"`
}

type PathOpenRequest struct {
	ExitID          string `json:"exit_id"`
	Token           string `json:"token"`
	TokenProof      string `json:"token_proof,omitempty"`
	TokenProofNonce string `json:"token_proof_nonce,omitempty"`
	ClientInnerPub  string `json:"client_inner_pub"`
	Transport       string `json:"transport,omitempty"`
	RequestedMTU    int    `json:"requested_mtu"`
	RequestedRegion string `json:"requested_region"`
	PuzzleNonce     string `json:"puzzle_nonce,omitempty"`
	PuzzleDigest    string `json:"puzzle_digest,omitempty"`
	SessionID       string `json:"session_id,omitempty"`
}

type PathOpenResponse struct {
	Accepted      bool   `json:"accepted"`
	Reason        string `json:"reason"`
	SessionID     string `json:"session_id,omitempty"`
	EntryDataAddr string `json:"entry_data_addr,omitempty"`
	SessionExp    int64  `json:"session_exp,omitempty"`
	Transport     string `json:"transport,omitempty"`
	ExitInnerPub  string `json:"exit_inner_pub,omitempty"`
	ClientInnerIP string `json:"client_inner_ip,omitempty"`
	ExitInnerIP   string `json:"exit_inner_ip,omitempty"`
	InnerMTU      int    `json:"inner_mtu,omitempty"`
	KeepaliveSec  int    `json:"keepalive_sec,omitempty"`
	SessionKeyID  string `json:"session_key_id,omitempty"`
	Challenge     string `json:"challenge,omitempty"`
	Difficulty    int    `json:"difficulty,omitempty"`
}

type RelayListResponse struct {
	Relays []RelayDescriptor `json:"relays"`
}

type IssueTokenRequest struct {
	Tier      int      `json:"tier"`
	Subject   string   `json:"subject,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	PopPubKey string   `json:"pop_pub_key,omitempty"`
	ExitScope []string `json:"exit_scope,omitempty"`
}

type IssueTokenResponse struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
	JTI     string `json:"jti,omitempty"`
}

type InnerPacket struct {
	DestinationPort int    `json:"destination_port"`
	Payload         string `json:"payload"`
	Nonce           uint64 `json:"nonce"`
}

type PathCloseRequest struct {
	SessionID string `json:"session_id"`
}

type PathCloseResponse struct {
	Closed bool   `json:"closed"`
	Reason string `json:"reason,omitempty"`
}

type SubjectProfile struct {
	Subject      string  `json:"subject"`
	Kind         string  `json:"kind,omitempty"`
	Tier         int     `json:"tier"`
	Reputation   float64 `json:"reputation"`
	Bond         float64 `json:"bond"`
	TierCap      int     `json:"tier_cap,omitempty"`
	DisputeUntil int64   `json:"dispute_until,omitempty"`
	AppealUntil  int64   `json:"appeal_until,omitempty"`
	DisputeCase  string  `json:"dispute_case_id,omitempty"`
	DisputeRef   string  `json:"dispute_evidence_ref,omitempty"`
	AppealCase   string  `json:"appeal_case_id,omitempty"`
	AppealRef    string  `json:"appeal_evidence_ref,omitempty"`
}

type UpsertSubjectRequest struct {
	Subject    string  `json:"subject"`
	Kind       string  `json:"kind,omitempty"`
	Tier       int     `json:"tier"`
	Reputation float64 `json:"reputation"`
	Bond       float64 `json:"bond"`
}

type PromoteSubjectRequest struct {
	Subject string `json:"subject"`
	Tier    int    `json:"tier"`
	Reason  string `json:"reason,omitempty"`
}

type ApplyReputationRequest struct {
	Subject string  `json:"subject"`
	Delta   float64 `json:"delta"`
	Reason  string  `json:"reason,omitempty"`
}

type ApplyBondRequest struct {
	Subject string  `json:"subject"`
	Delta   float64 `json:"delta"`
	Reason  string  `json:"reason,omitempty"`
}

type RecomputeTierRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason,omitempty"`
}

type ApplyDisputeRequest struct {
	Subject           string  `json:"subject"`
	TierCap           int     `json:"tier_cap,omitempty"`
	Until             int64   `json:"until,omitempty"`
	ReputationPenalty float64 `json:"reputation_penalty,omitempty"`
	CaseID            string  `json:"case_id,omitempty"`
	EvidenceRef       string  `json:"evidence_ref,omitempty"`
	Reason            string  `json:"reason,omitempty"`
}

type ClearDisputeRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason,omitempty"`
}

type OpenAppealRequest struct {
	Subject     string `json:"subject"`
	Until       int64  `json:"until,omitempty"`
	CaseID      string `json:"case_id,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

type ResolveAppealRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason,omitempty"`
}

type AuditEvent struct {
	ID          int64   `json:"id"`
	Timestamp   int64   `json:"timestamp"`
	Action      string  `json:"action"`
	Subject     string  `json:"subject,omitempty"`
	Reason      string  `json:"reason,omitempty"`
	CaseID      string  `json:"case_id,omitempty"`
	EvidenceRef string  `json:"evidence_ref,omitempty"`
	Delta       float64 `json:"delta,omitempty"`
	Value       float64 `json:"value,omitempty"`
	TierBefore  int     `json:"tier_before,omitempty"`
	TierAfter   int     `json:"tier_after,omitempty"`
}

type RevokeTokenRequest struct {
	JTI   string `json:"jti"`
	Until int64  `json:"until"`
}

type Revocation struct {
	JTI   string `json:"jti"`
	Until int64  `json:"until"`
}

type RevocationListResponse struct {
	Issuer        string       `json:"issuer,omitempty"`
	KeyEpoch      int64        `json:"key_epoch,omitempty"`
	MinTokenEpoch int64        `json:"min_token_epoch,omitempty"`
	Version       int64        `json:"version,omitempty"`
	GeneratedAt   int64        `json:"generated_at,omitempty"`
	ExpiresAt     int64        `json:"expires_at,omitempty"`
	Revocations   []Revocation `json:"revocations"`
	Signature     string       `json:"signature,omitempty"`
}

type IssuerPubKeysResponse struct {
	Issuer        string   `json:"issuer,omitempty"`
	PubKeys       []string `json:"pub_keys"`
	KeyEpoch      int64    `json:"key_epoch,omitempty"`
	MinTokenEpoch int64    `json:"min_token_epoch,omitempty"`
}

type RelaySelectionScore struct {
	RelayID      string  `json:"relay_id"`
	Role         string  `json:"role,omitempty"`
	Reputation   float64 `json:"reputation_score,omitempty"`
	Uptime       float64 `json:"uptime_score,omitempty"`
	Capacity     float64 `json:"capacity_score,omitempty"`
	AbusePenalty float64 `json:"abuse_penalty,omitempty"`
	BondScore    float64 `json:"bond_score,omitempty"`
	StakeScore   float64 `json:"stake_score,omitempty"`
}

type RelaySelectionFeedResponse struct {
	Operator    string                `json:"operator,omitempty"`
	GeneratedAt int64                 `json:"generated_at,omitempty"`
	ExpiresAt   int64                 `json:"expires_at,omitempty"`
	Scores      []RelaySelectionScore `json:"scores"`
	Signature   string                `json:"signature,omitempty"`
}

type RelayTrustAttestation struct {
	RelayID      string  `json:"relay_id"`
	Role         string  `json:"role,omitempty"`
	OperatorID   string  `json:"operator_id,omitempty"`
	Reputation   float64 `json:"reputation_score,omitempty"`
	Uptime       float64 `json:"uptime_score,omitempty"`
	Capacity     float64 `json:"capacity_score,omitempty"`
	AbusePenalty float64 `json:"abuse_penalty,omitempty"`
	BondScore    float64 `json:"bond_score,omitempty"`
	StakeScore   float64 `json:"stake_score,omitempty"`
	Confidence   float64 `json:"confidence,omitempty"`
	TierCap      int     `json:"tier_cap,omitempty"`
	DisputeUntil int64   `json:"dispute_until,omitempty"`
	AppealUntil  int64   `json:"appeal_until,omitempty"`
	DisputeCase  string  `json:"dispute_case_id,omitempty"`
	DisputeRef   string  `json:"dispute_evidence_ref,omitempty"`
	AppealCase   string  `json:"appeal_case_id,omitempty"`
	AppealRef    string  `json:"appeal_evidence_ref,omitempty"`
}

type RelayTrustAttestationFeedResponse struct {
	Operator     string                  `json:"operator,omitempty"`
	GeneratedAt  int64                   `json:"generated_at,omitempty"`
	ExpiresAt    int64                   `json:"expires_at,omitempty"`
	Attestations []RelayTrustAttestation `json:"attestations"`
	Signature    string                  `json:"signature,omitempty"`
}

type DirectoryPubKeysResponse struct {
	Operator string   `json:"operator,omitempty"`
	PubKeys  []string `json:"pub_keys"`
}

type RelayGossipPushRequest struct {
	PeerURL string            `json:"peer_url"`
	Relays  []RelayDescriptor `json:"relays"`
}

type RelayGossipPushResponse struct {
	Imported int `json:"imported"`
}

type DirectoryPeerListResponse struct {
	Operator    string              `json:"operator,omitempty"`
	GeneratedAt int64               `json:"generated_at,omitempty"`
	ExpiresAt   int64               `json:"expires_at,omitempty"`
	Peers       []string            `json:"peers"`
	PeerHints   []DirectoryPeerHint `json:"peer_hints,omitempty"`
	Signature   string              `json:"signature,omitempty"`
}

type DirectoryPeerHint struct {
	URL      string `json:"url"`
	Operator string `json:"operator,omitempty"`
	PubKey   string `json:"pub_key,omitempty"`
}

type ProviderRelayUpsertRequest struct {
	Token         string   `json:"token,omitempty"`
	RelayID       string   `json:"relay_id"`
	Role          string   `json:"role"`
	PubKey        string   `json:"pub_key"`
	Endpoint      string   `json:"endpoint"`
	ControlURL    string   `json:"control_url"`
	CountryCode   string   `json:"country_code,omitempty"`
	GeoConfidence float64  `json:"geo_confidence,omitempty"`
	Region        string   `json:"region,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	Reputation    float64  `json:"reputation_score,omitempty"`
	Uptime        float64  `json:"uptime_score,omitempty"`
	Capacity      float64  `json:"capacity_score,omitempty"`
	AbusePenalty  float64  `json:"abuse_penalty,omitempty"`
	BondScore     float64  `json:"bond_score,omitempty"`
	StakeScore    float64  `json:"stake_score,omitempty"`
	ValidForSec   int64    `json:"valid_for_sec,omitempty"`
}

type ProviderRelayUpsertResponse struct {
	Accepted bool            `json:"accepted"`
	Reason   string          `json:"reason,omitempty"`
	Relay    RelayDescriptor `json:"relay,omitempty"`
}
