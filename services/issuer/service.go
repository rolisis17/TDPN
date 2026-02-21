package issuer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

type Service struct {
	addr                string
	issuerID            string
	pubKey              ed25519.PublicKey
	privKey             ed25519.PrivateKey
	privateKeyPath      string
	previousPubKeysFile string
	epochStateFile      string
	keyRotateSec        int
	keyHistory          int
	httpSrv             *http.Server
	tokenTTL            time.Duration
	revocationFeedTTL   time.Duration
	trustFeedTTL        time.Duration
	trustConfidence     float64
	trustBondMax        float64
	trustOperatorID     string
	disputeDefaultTTL   time.Duration
	adminToken          string
	mu                  sync.RWMutex
	subjects            map[string]proto.SubjectProfile
	subjectsFile        string
	revocations         map[string]int64
	revocationsFile     string
	audit               []proto.AuditEvent
	auditFile           string
	auditMax            int
	auditSeq            int64
	keyEpoch            int64
	minTokenEpoch       int64
	revocationVersion   int64
}

func New() *Service {
	addr := os.Getenv("ISSUER_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8082"
	}
	issuerID := os.Getenv("ISSUER_ID")
	if issuerID == "" {
		issuerID = "issuer-local"
	}
	adminToken := os.Getenv("ISSUER_ADMIN_TOKEN")
	if adminToken == "" {
		adminToken = "dev-admin-token"
	}
	subjectsFile := os.Getenv("ISSUER_SUBJECTS_FILE")
	if subjectsFile == "" {
		subjectsFile = "data/issuer_subjects.json"
	}
	revocationsFile := os.Getenv("ISSUER_REVOCATIONS_FILE")
	if revocationsFile == "" {
		revocationsFile = "data/issuer_revocations.json"
	}
	auditFile := os.Getenv("ISSUER_AUDIT_FILE")
	if auditFile == "" {
		auditFile = "data/issuer_audit.json"
	}
	auditMax := 5000
	if v := os.Getenv("ISSUER_AUDIT_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			auditMax = n
		}
	}
	privateKeyPath := os.Getenv("ISSUER_PRIVATE_KEY_FILE")
	if privateKeyPath == "" {
		privateKeyPath = "data/issuer_ed25519.key"
	}
	previousPubKeysFile := os.Getenv("ISSUER_PREVIOUS_PUBKEYS_FILE")
	if previousPubKeysFile == "" {
		previousPubKeysFile = "data/issuer_previous_pubkeys.txt"
	}
	epochStateFile := os.Getenv("ISSUER_EPOCHS_FILE")
	if epochStateFile == "" {
		epochStateFile = "data/issuer_epochs.json"
	}
	keyRotateSec := 0
	if v := os.Getenv("ISSUER_KEY_ROTATE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			keyRotateSec = n
		}
	}
	keyHistory := 3
	if v := os.Getenv("ISSUER_KEY_HISTORY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			keyHistory = n
		}
	}
	revocationFeedTTL := 30 * time.Second
	if v := os.Getenv("ISSUER_REVOCATION_FEED_TTL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			revocationFeedTTL = time.Duration(n) * time.Second
		}
	}
	trustFeedTTL := 30 * time.Second
	if v := os.Getenv("ISSUER_TRUST_FEED_TTL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			trustFeedTTL = time.Duration(n) * time.Second
		}
	}
	trustConfidence := 1.0
	if v := os.Getenv("ISSUER_TRUST_CONFIDENCE"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			trustConfidence = clampUnit(n)
		}
	}
	trustBondMax := 500.0
	if v := os.Getenv("ISSUER_TRUST_BOND_MAX"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil && n > 0 {
			trustBondMax = n
		}
	}
	trustOperatorID := strings.TrimSpace(os.Getenv("ISSUER_TRUST_OPERATOR_ID"))
	disputeDefaultTTL := 24 * time.Hour
	if v := os.Getenv("ISSUER_DISPUTE_DEFAULT_TTL_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			disputeDefaultTTL = time.Duration(n) * time.Second
		}
	}
	return &Service{
		addr:                addr,
		issuerID:            issuerID,
		tokenTTL:            10 * time.Minute,
		revocationFeedTTL:   revocationFeedTTL,
		trustFeedTTL:        trustFeedTTL,
		trustConfidence:     trustConfidence,
		trustBondMax:        trustBondMax,
		trustOperatorID:     trustOperatorID,
		disputeDefaultTTL:   disputeDefaultTTL,
		privateKeyPath:      privateKeyPath,
		previousPubKeysFile: previousPubKeysFile,
		epochStateFile:      epochStateFile,
		keyRotateSec:        keyRotateSec,
		keyHistory:          keyHistory,
		adminToken:          adminToken,
		subjects:            make(map[string]proto.SubjectProfile),
		subjectsFile:        subjectsFile,
		revocations:         make(map[string]int64),
		revocationsFile:     revocationsFile,
		audit:               make([]proto.AuditEvent, 0, 128),
		auditFile:           auditFile,
		auditMax:            auditMax,
		keyEpoch:            1,
		minTokenEpoch:       1,
	}
}

func (s *Service) Run(ctx context.Context) error {
	if err := s.loadSubjects(); err != nil {
		log.Printf("issuer subjects load warning: %v", err)
	}
	if err := s.loadRevocations(); err != nil {
		log.Printf("issuer revocations load warning: %v", err)
	}
	if err := s.loadAudit(); err != nil {
		log.Printf("issuer audit load warning: %v", err)
	}
	if err := s.loadOrCreateEpochState(); err != nil {
		log.Printf("issuer epoch state load warning: %v", err)
	}
	pub, priv, err := s.loadOrCreateKeypair()
	if err != nil {
		return fmt.Errorf("issuer key init: %w", err)
	}
	s.pubKey = pub
	s.privKey = priv

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/token", s.handleIssueToken)
	mux.HandleFunc("/v1/pubkey", s.handlePubKey)
	mux.HandleFunc("/v1/pubkeys", s.handlePubKeys)
	mux.HandleFunc("/v1/trust/relays", s.handleRelayTrust)
	mux.HandleFunc("/v1/admin/subject/upsert", s.handleUpsertSubject)
	mux.HandleFunc("/v1/admin/subject/promote", s.handlePromoteSubject)
	mux.HandleFunc("/v1/admin/subject/reputation/apply", s.handleApplyReputation)
	mux.HandleFunc("/v1/admin/subject/bond/apply", s.handleApplyBond)
	mux.HandleFunc("/v1/admin/subject/dispute", s.handleApplyDispute)
	mux.HandleFunc("/v1/admin/subject/dispute/clear", s.handleClearDispute)
	mux.HandleFunc("/v1/admin/subject/appeal/open", s.handleOpenAppeal)
	mux.HandleFunc("/v1/admin/subject/appeal/resolve", s.handleResolveAppeal)
	mux.HandleFunc("/v1/admin/subject/recompute-tier", s.handleRecomputeTier)
	mux.HandleFunc("/v1/admin/subject/get", s.handleGetSubject)
	mux.HandleFunc("/v1/admin/audit", s.handleGetAudit)
	mux.HandleFunc("/v1/admin/revoke-token", s.handleRevokeToken)
	mux.HandleFunc("/v1/revocations", s.handleRevocations)

	s.httpSrv = &http.Server{Addr: s.addr, Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("issuer listening on %s", s.addr)
		errCh <- s.httpSrv.ListenAndServe()
	}()

	var rotateTicker *time.Ticker
	if s.keyRotateSec > 0 {
		rotateTicker = time.NewTicker(time.Duration(s.keyRotateSec) * time.Second)
		defer rotateTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpSrv.Shutdown(shutdownCtx)
			return ctx.Err()
		case err := <-errCh:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		case <-tickerC(rotateTicker):
			if err := s.rotateSigningKey(); err != nil {
				log.Printf("issuer key rotate failed: %v", err)
			} else {
				log.Printf("issuer key rotated epoch=%d min_token_epoch=%d", s.currentKeyEpoch(), s.currentMinTokenEpoch())
			}
		}
	}
}

func (s *Service) loadOrCreateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if s.privateKeyPath == "" {
		return crypto.GenerateEd25519Keypair()
	}
	b, err := os.ReadFile(s.privateKeyPath)
	if err == nil {
		trimmed := strings.TrimSpace(string(b))
		raw, decErr := base64.RawURLEncoding.DecodeString(trimmed)
		if decErr != nil {
			return nil, nil, decErr
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid private key size")
		}
		priv := ed25519.PrivateKey(raw)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, err
	}

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(s.privateKeyPath), 0o755); err != nil {
		return nil, nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString(priv)
	if err := os.WriteFile(s.privateKeyPath, []byte(enc+"\n"), 0o600); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func (s *Service) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req proto.IssueTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Tier < 1 || req.Tier > 3 {
		http.Error(w, "tier must be 1..3", http.StatusBadRequest)
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)

	effectiveTier := s.effectiveTierFor(req.Subject, req.Tier)
	keyEpoch, priv := s.signingKeySnapshot()
	claims := baseClaimsForTier(s.issuerID, req.Subject, keyEpoch, effectiveTier, time.Now().Add(s.tokenTTL), req.ExitScope)
	tok, err := crypto.SignClaims(claims, priv)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	resp := proto.IssueTokenResponse{Token: tok, Expires: claims.ExpiryUnix, JTI: claims.TokenID}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleUpsertSubject(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.UpsertSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Subject == "" || req.Tier < 1 || req.Tier > 3 {
		http.Error(w, "invalid subject or tier", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	prev := s.subjects[req.Subject]
	kind := normalizeSubjectKind(req.Kind, prev.Kind)
	s.subjects[req.Subject] = proto.SubjectProfile{
		Subject:      req.Subject,
		Kind:         kind,
		Tier:         applyTierCap(req.Tier, prev, time.Now().Unix()),
		Reputation:   req.Reputation,
		Bond:         req.Bond,
		TierCap:      prev.TierCap,
		DisputeUntil: prev.DisputeUntil,
		AppealUntil:  prev.AppealUntil,
		DisputeCase:  prev.DisputeCase,
		DisputeRef:   prev.DisputeRef,
		AppealCase:   prev.AppealCase,
		AppealRef:    prev.AppealRef,
	}
	profile := s.subjects[req.Subject]
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-upsert",
		Subject:    req.Subject,
		TierBefore: prev.Tier,
		TierAfter:  profile.Tier,
		Value:      profile.Reputation,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(profile)
}

func (s *Service) handlePromoteSubject(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.PromoteSubjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.Subject == "" || req.Tier < 1 || req.Tier > 3 {
		http.Error(w, "invalid subject or tier", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p := s.subjects[req.Subject]
	beforeTier := p.Tier
	p.Subject = req.Subject
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.Tier = req.Tier
	p.Tier = applyTierCap(p.Tier, p, time.Now().Unix())
	s.subjects[req.Subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-promote",
		Subject:    req.Subject,
		Reason:     req.Reason,
		TierBefore: beforeTier,
		TierAfter:  p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleApplyReputation(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.ApplyReputationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p := s.subjects[req.Subject]
	beforeTier := p.Tier
	p.Subject = req.Subject
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.Reputation = clampUnit(p.Reputation + req.Delta)
	p.Tier = recommendedTier(p)
	p.Tier = applyTierCap(p.Tier, p, time.Now().Unix())
	s.subjects[req.Subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-reputation-apply",
		Subject:    req.Subject,
		Reason:     req.Reason,
		Delta:      req.Delta,
		Value:      p.Reputation,
		TierBefore: beforeTier,
		TierAfter:  p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleApplyBond(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.ApplyBondRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p := s.subjects[req.Subject]
	beforeTier := p.Tier
	p.Subject = req.Subject
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.Bond = maxFloat(0, p.Bond+req.Delta)
	p.Tier = recommendedTier(p)
	p.Tier = applyTierCap(p.Tier, p, time.Now().Unix())
	s.subjects[req.Subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-bond-apply",
		Subject:    req.Subject,
		Reason:     req.Reason,
		Delta:      req.Delta,
		Value:      p.Bond,
		TierBefore: beforeTier,
		TierAfter:  p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleRecomputeTier(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.RecomputeTierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p, ok := s.subjects[req.Subject]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	beforeTier := p.Tier
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.Tier = recommendedTier(p)
	p.Tier = applyTierCap(p.Tier, p, time.Now().Unix())
	s.subjects[req.Subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-recompute-tier",
		Subject:    req.Subject,
		Reason:     req.Reason,
		TierBefore: beforeTier,
		TierAfter:  p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleGetSubject(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sub := r.URL.Query().Get("subject")
	if sub == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	p, ok := s.subjects[sub]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleApplyDispute(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.ApplyDisputeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	tierCap := req.TierCap
	if tierCap < 1 || tierCap > 3 {
		tierCap = 1
	}
	now := time.Now()
	nowUnix := now.Unix()
	until := req.Until
	if until <= nowUnix {
		until = now.Add(s.disputeDefaultTTL).Unix()
	}
	caseID := normalizeCaseID(req.CaseID)
	evidenceRef := normalizeEvidenceRef(req.EvidenceRef)
	penalty := req.ReputationPenalty
	if penalty < 0 {
		penalty = 0
	}
	penalty = clampUnit(penalty)

	s.mu.Lock()
	p := s.subjects[subject]
	beforeTier := p.Tier
	p.Subject = subject
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.Reputation = clampUnit(p.Reputation - penalty)
	p.TierCap = tierCap
	p.DisputeUntil = until
	p.DisputeCase = caseID
	p.DisputeRef = evidenceRef
	p.Tier = applyTierCap(recommendedTier(p), p, nowUnix)
	s.subjects[subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:      "subject-dispute-apply",
		Subject:     subject,
		Reason:      req.Reason,
		CaseID:      caseID,
		EvidenceRef: evidenceRef,
		Delta:       -penalty,
		Value:       float64(until),
		TierBefore:  beforeTier,
		TierAfter:   p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleClearDispute(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.ClearDisputeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	nowUnix := time.Now().Unix()
	s.mu.Lock()
	p, ok := s.subjects[subject]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	beforeTier := p.Tier
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.TierCap = 0
	p.DisputeUntil = 0
	p.DisputeCase = ""
	p.DisputeRef = ""
	p.Tier = applyTierCap(recommendedTier(p), p, nowUnix)
	s.subjects[subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-dispute-clear",
		Subject:    subject,
		Reason:     req.Reason,
		TierBefore: beforeTier,
		TierAfter:  p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleOpenAppeal(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.OpenAppealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	now := time.Now()
	nowUnix := now.Unix()
	until := req.Until
	if until <= nowUnix {
		until = now.Add(s.disputeDefaultTTL).Unix()
	}
	caseID := normalizeCaseID(req.CaseID)
	evidenceRef := normalizeEvidenceRef(req.EvidenceRef)
	s.mu.Lock()
	p := s.subjects[subject]
	beforeTier := p.Tier
	if caseID == "" {
		caseID = normalizeCaseID(p.DisputeCase)
	}
	p.Subject = subject
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.AppealUntil = until
	p.AppealCase = caseID
	p.AppealRef = evidenceRef
	s.subjects[subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:      "subject-appeal-open",
		Subject:     subject,
		Reason:      req.Reason,
		CaseID:      caseID,
		EvidenceRef: evidenceRef,
		Value:       float64(until),
		TierBefore:  beforeTier,
		TierAfter:   p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleResolveAppeal(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.ResolveAppealRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		http.Error(w, "missing subject", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	p, ok := s.subjects[subject]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	beforeTier := p.Tier
	p.Kind = normalizeSubjectKind(p.Kind, "")
	p.AppealUntil = 0
	p.AppealCase = ""
	p.AppealRef = ""
	s.subjects[subject] = p
	s.mu.Unlock()
	if err := s.saveSubjects(); err != nil {
		http.Error(w, "failed to persist subject", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:     "subject-appeal-resolve",
		Subject:    subject,
		Reason:     req.Reason,
		TierBefore: beforeTier,
		TierAfter:  p.Tier,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (s *Service) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	s.mu.RLock()
	out := make([]proto.AuditEvent, 0, len(s.audit))
	for i := len(s.audit) - 1; i >= 0; i-- {
		ev := s.audit[i]
		if subject != "" && ev.Subject != subject {
			continue
		}
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Service) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req proto.RevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.JTI == "" {
		http.Error(w, "missing jti", http.StatusBadRequest)
		return
	}
	if req.Until == 0 {
		req.Until = time.Now().Add(s.tokenTTL).Unix()
	}
	s.mu.Lock()
	s.revocations[req.JTI] = req.Until
	s.revocationVersion++
	s.mu.Unlock()
	if err := s.saveRevocations(); err != nil {
		http.Error(w, "failed to persist revocation", http.StatusInternalServerError)
		return
	}
	s.recordAudit(proto.AuditEvent{
		Action:  "token-revoke",
		Reason:  "admin-revocation",
		Value:   float64(req.Until),
		Subject: req.JTI,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proto.Revocation{JTI: req.JTI, Until: req.Until})
}

func (s *Service) handleRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := s.buildRevocationFeed(time.Now())
	if err != nil {
		http.Error(w, "failed to sign revocation feed", http.StatusInternalServerError)
		return
	}
	if err := writeJSONWithETag(w, r, resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handleRelayTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp, err := s.buildRelayTrustFeed(time.Now())
	if err != nil {
		http.Error(w, "failed to sign trust feed", http.StatusInternalServerError)
		return
	}
	if err := writeJSONWithETag(w, r, resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Admin-Token") != s.adminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Service) effectiveTierFor(subject string, requested int) int {
	if requested < 1 {
		requested = 1
	}
	if requested > 3 {
		requested = 3
	}
	subject = strings.TrimSpace(subject)
	// Unbound/unknown subjects stay Tier-1 only.
	if subject == "" {
		return 1
	}
	s.mu.RLock()
	p, ok := s.subjects[subject]
	s.mu.RUnlock()
	if !ok {
		return 1
	}
	// Relay identities are not eligible for elevated client token tiers.
	if normalizeSubjectKind(p.Kind, "") != proto.SubjectKindClient {
		return 1
	}
	nowUnix := time.Now().Unix()
	eligible := recommendedTier(p)
	if capTier, ok := effectiveTierCapForIssuance(p, nowUnix); ok && eligible > capTier {
		eligible = capTier
	}
	if requested < eligible {
		return requested
	}
	return eligible
}

func (s *Service) handlePubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	pub := base64.RawURLEncoding.EncodeToString(s.pubKey)
	s.mu.RUnlock()
	resp := map[string]string{"pub_key": pub}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func (s *Service) handlePubKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	currPub := base64.RawURLEncoding.EncodeToString(s.pubKey)
	keyEpoch := s.keyEpoch
	minTokenEpoch := s.minTokenEpoch
	s.mu.RUnlock()
	keys := []string{currPub}
	prev, err := loadPreviousPubKeys(s.previousPubKeysFile)
	if err != nil {
		http.Error(w, "invalid previous pubkeys file", http.StatusInternalServerError)
		return
	}
	keys = append(keys, prev...)
	keys = dedupeStrings(keys)
	resp := proto.IssuerPubKeysResponse{
		Issuer:        s.issuerID,
		PubKeys:       keys,
		KeyEpoch:      keyEpoch,
		MinTokenEpoch: minTokenEpoch,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}

func baseClaimsForTier(issuerID string, subject string, keyEpoch int64, tier int, expires time.Time, exitScope []string) crypto.CapabilityClaims {
	claims := crypto.CapabilityClaims{
		Issuer:     issuerID,
		Audience:   "exit",
		Subject:    strings.TrimSpace(subject),
		KeyEpoch:   keyEpoch,
		Tier:       tier,
		ExpiryUnix: expires.Unix(),
		TokenID:    fmt.Sprintf("%d", time.Now().UnixNano()),
		ExitScope:  exitScope,
	}

	switch tier {
	case 1:
		claims.BWKbps = 512
		claims.ConnRate = 20
		claims.MaxConns = 50
		claims.DenyPorts = []int{25}
	case 2:
		claims.BWKbps = 2048
		claims.ConnRate = 100
		claims.MaxConns = 200
		claims.DenyPorts = []int{25}
	case 3:
		claims.BWKbps = 10240
		claims.ConnRate = 300
		claims.MaxConns = 500
	}

	return claims
}

func (s *Service) buildRevocationFeed(now time.Time) (proto.RevocationListResponse, error) {
	nowUnix := now.Unix()
	needsSave := false

	s.mu.Lock()
	for jti, until := range s.revocations {
		if nowUnix >= until {
			delete(s.revocations, jti)
			needsSave = true
		}
	}
	if needsSave {
		s.revocationVersion++
	}
	if s.revocationVersion <= 0 {
		s.revocationVersion = 1
	}
	keyEpoch := s.keyEpoch
	minTokenEpoch := s.minTokenEpoch
	version := s.revocationVersion
	list := make([]proto.Revocation, 0, len(s.revocations))
	for jti, until := range s.revocations {
		list = append(list, proto.Revocation{JTI: jti, Until: until})
	}
	priv := append(ed25519.PrivateKey(nil), s.privKey...)
	s.mu.Unlock()

	if needsSave {
		if err := s.saveRevocations(); err != nil {
			log.Printf("issuer revocation prune persist warning: %v", err)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].JTI < list[j].JTI })

	resp := proto.RevocationListResponse{
		Issuer:        s.issuerID,
		KeyEpoch:      keyEpoch,
		MinTokenEpoch: minTokenEpoch,
		Version:       version,
		GeneratedAt:   nowUnix,
		ExpiresAt:     now.Add(s.revocationFeedTTL).Unix(),
		Revocations:   list,
	}
	sig, err := signRevocationFeed(resp, priv)
	if err != nil {
		return proto.RevocationListResponse{}, err
	}
	resp.Signature = sig
	return resp, nil
}

func signRevocationFeed(feed proto.RevocationListResponse, priv ed25519.PrivateKey) (string, error) {
	if len(priv) == 0 {
		return "", fmt.Errorf("missing issuer private key")
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Service) buildRelayTrustFeed(now time.Time) (proto.RelayTrustAttestationFeedResponse, error) {
	s.mu.RLock()
	priv := append(ed25519.PrivateKey(nil), s.privKey...)
	confidence := clampUnit(s.trustConfidence)
	bondMax := s.trustBondMax
	operatorID := strings.TrimSpace(s.trustOperatorID)
	nowUnix := now.Unix()
	attestations := make([]proto.RelayTrustAttestation, 0, len(s.subjects))
	for _, p := range s.subjects {
		if !isRelayTrustSubject(p) {
			continue
		}
		relayID := strings.TrimSpace(p.Subject)
		if relayID == "" {
			continue
		}
		bondScore := normalizedBondScore(p.Bond, bondMax)
		attConfidence := confidence
		abusePenalty := 0.0
		disputeTierCap := 0
		disputeUntil := int64(0)
		disputeCase := ""
		disputeRef := ""
		appealUntil := normalizeAppealUntil(p.AppealUntil, nowUnix)
		appealCase := ""
		appealRef := ""
		if cap, ok := activeTierCap(p, nowUnix); ok {
			attConfidence = clampUnit(confidence * 0.35)
			abusePenalty = clampUnit(1 - float64(cap)/3)
			disputeTierCap = cap
			disputeUntil = p.DisputeUntil
			disputeCase = normalizeCaseID(p.DisputeCase)
			disputeRef = normalizeEvidenceRef(p.DisputeRef)
			if appealUntil > 0 {
				attConfidence = clampUnit(maxFloat(attConfidence, confidence*0.55))
				abusePenalty = clampUnit(abusePenalty * 0.75)
				appealCase = normalizeCaseID(p.AppealCase)
				appealRef = normalizeEvidenceRef(p.AppealRef)
			}
		} else if appealUntil > 0 {
			attConfidence = clampUnit(confidence * 0.9)
			appealCase = normalizeCaseID(p.AppealCase)
			appealRef = normalizeEvidenceRef(p.AppealRef)
		}
		attestations = append(attestations, proto.RelayTrustAttestation{
			RelayID:      relayID,
			Role:         "exit",
			OperatorID:   operatorID,
			Reputation:   clampUnit(p.Reputation),
			AbusePenalty: abusePenalty,
			BondScore:    bondScore,
			StakeScore:   bondScore,
			Confidence:   attConfidence,
			TierCap:      disputeTierCap,
			DisputeUntil: disputeUntil,
			AppealUntil:  appealUntil,
			DisputeCase:  disputeCase,
			DisputeRef:   disputeRef,
			AppealCase:   appealCase,
			AppealRef:    appealRef,
		})
	}
	s.mu.RUnlock()

	sort.Slice(attestations, func(i, j int) bool {
		if attestations[i].RelayID == attestations[j].RelayID {
			return attestations[i].Role < attestations[j].Role
		}
		return attestations[i].RelayID < attestations[j].RelayID
	})

	feed := proto.RelayTrustAttestationFeedResponse{
		Operator:     s.issuerID,
		GeneratedAt:  now.Unix(),
		ExpiresAt:    now.Add(s.trustFeedTTL).Unix(),
		Attestations: attestations,
	}
	sig, err := crypto.SignRelayTrustAttestationFeed(feed, priv)
	if err != nil {
		return proto.RelayTrustAttestationFeedResponse{}, err
	}
	feed.Signature = sig
	return feed, nil
}

func loadPreviousPubKeys(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, decErr := base64.RawURLEncoding.DecodeString(line)
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid previous pubkey: %s", line)
		}
		out = append(out, line)
	}
	return out, nil
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func writeJSONWithETag(w http.ResponseWriter, r *http.Request, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	etag := fmt.Sprintf("\"%x\"", sum[:8])
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	_, err = w.Write(b)
	return err
}

func (s *Service) saveSubjects() error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.subjects, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.subjectsFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.subjectsFile, data, 0o644)
}

func (s *Service) loadSubjects() error {
	b, err := os.ReadFile(s.subjectsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	tmp := map[string]proto.SubjectProfile{}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	for key, p := range tmp {
		if strings.TrimSpace(p.Subject) == "" {
			p.Subject = key
		}
		p.Kind = normalizeSubjectKind(p.Kind, "")
		tmp[key] = p
	}
	s.mu.Lock()
	s.subjects = tmp
	s.mu.Unlock()
	return nil
}

func (s *Service) saveRevocations() error {
	s.mu.RLock()
	store := revocationStore{
		Version:       s.revocationVersion,
		KeyEpoch:      s.keyEpoch,
		MinTokenEpoch: s.minTokenEpoch,
		Revocations:   cloneRevocations(s.revocations),
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.revocationsFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.revocationsFile, data, 0o644)
}

func (s *Service) loadRevocations() error {
	b, err := os.ReadFile(s.revocationsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var store revocationStore
	if err := json.Unmarshal(b, &store); err == nil && store.Revocations != nil {
		s.mu.Lock()
		s.revocations = store.Revocations
		if store.Version > s.revocationVersion {
			s.revocationVersion = store.Version
		}
		if store.KeyEpoch > s.keyEpoch {
			s.keyEpoch = store.KeyEpoch
		}
		if store.MinTokenEpoch > s.minTokenEpoch {
			s.minTokenEpoch = store.MinTokenEpoch
		}
		s.mu.Unlock()
		return nil
	}

	// Backward compatibility: older file shape was a plain map[jti]until.
	legacy := map[string]int64{}
	if err := json.Unmarshal(b, &legacy); err != nil {
		return err
	}
	s.mu.Lock()
	s.revocations = legacy
	if s.revocationVersion == 0 && len(legacy) > 0 {
		s.revocationVersion = 1
	}
	s.mu.Unlock()
	return nil
}

type revocationStore struct {
	Version       int64            `json:"version"`
	KeyEpoch      int64            `json:"key_epoch,omitempty"`
	MinTokenEpoch int64            `json:"min_token_epoch,omitempty"`
	Revocations   map[string]int64 `json:"revocations"`
}

type issuerEpochState struct {
	KeyEpoch      int64 `json:"key_epoch"`
	MinTokenEpoch int64 `json:"min_token_epoch"`
}

func (s *Service) loadOrCreateEpochState() error {
	if strings.TrimSpace(s.epochStateFile) == "" {
		return nil
	}
	b, err := os.ReadFile(s.epochStateFile)
	if err == nil {
		var st issuerEpochState
		if decErr := json.Unmarshal(b, &st); decErr != nil {
			return decErr
		}
		if st.KeyEpoch <= 0 {
			st.KeyEpoch = 1
		}
		if st.MinTokenEpoch <= 0 {
			st.MinTokenEpoch = st.KeyEpoch
		}
		s.mu.Lock()
		if st.KeyEpoch > s.keyEpoch {
			s.keyEpoch = st.KeyEpoch
		}
		if st.MinTokenEpoch > s.minTokenEpoch {
			s.minTokenEpoch = st.MinTokenEpoch
		}
		s.mu.Unlock()
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return s.saveEpochState()
}

func (s *Service) saveEpochState() error {
	if strings.TrimSpace(s.epochStateFile) == "" {
		return nil
	}
	s.mu.RLock()
	st := issuerEpochState{KeyEpoch: s.keyEpoch, MinTokenEpoch: s.minTokenEpoch}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.epochStateFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.epochStateFile, data, 0o644)
}

func (s *Service) signingKeySnapshot() (int64, ed25519.PrivateKey) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyEpoch, append(ed25519.PrivateKey(nil), s.privKey...)
}

func (s *Service) currentKeyEpoch() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keyEpoch
}

func (s *Service) currentMinTokenEpoch() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.minTokenEpoch
}

func (s *Service) rotateSigningKey() error {
	s.mu.Lock()
	prevPub := base64.RawURLEncoding.EncodeToString(s.pubKey)
	s.mu.Unlock()

	if err := appendPreviousPubKey(s.previousPubKeysFile, prevPub, s.keyHistory); err != nil {
		return err
	}
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		return err
	}
	if err := s.persistPrivateKey(priv); err != nil {
		return err
	}
	s.mu.Lock()
	s.pubKey = pub
	s.privKey = priv
	s.keyEpoch++
	if s.minTokenEpoch < s.keyEpoch {
		s.minTokenEpoch = s.keyEpoch
	}
	s.revocationVersion++
	s.mu.Unlock()

	if err := s.saveEpochState(); err != nil {
		return err
	}
	if err := s.saveRevocations(); err != nil {
		return err
	}
	return nil
}

func (s *Service) persistPrivateKey(priv ed25519.PrivateKey) error {
	if strings.TrimSpace(s.privateKeyPath) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.privateKeyPath), 0o755); err != nil {
		return err
	}
	enc := base64.RawURLEncoding.EncodeToString(priv)
	return os.WriteFile(s.privateKeyPath, []byte(enc+"\n"), 0o600)
}

func appendPreviousPubKey(path string, key string, keep int) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(key) == "" {
		return nil
	}
	keys, err := loadPreviousPubKeys(path)
	if err != nil {
		return err
	}
	keys = append([]string{key}, keys...)
	keys = dedupeStrings(keys)
	if keep > 0 && len(keys) > keep {
		keys = keys[:keep]
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data := strings.Join(keys, "\n")
	if data != "" {
		data += "\n"
	}
	return os.WriteFile(path, []byte(data), 0o644)
}

func cloneRevocations(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func clampUnit(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func normalizedBondScore(bond float64, bondMax float64) float64 {
	if bondMax <= 0 {
		bondMax = 1
	}
	return clampUnit(maxFloat(0, bond) / bondMax)
}

func normalizeSubjectKind(kind string, fallback string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if kind == "" {
		kind = strings.ToLower(strings.TrimSpace(fallback))
	}
	switch kind {
	case "", proto.SubjectKindRelayExit:
		return proto.SubjectKindRelayExit
	case proto.SubjectKindClient:
		return proto.SubjectKindClient
	default:
		return proto.SubjectKindRelayExit
	}
}

func normalizeCaseID(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

func normalizeEvidenceRef(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 512 {
		v = v[:512]
	}
	return v
}

func isRelayTrustSubject(p proto.SubjectProfile) bool {
	return normalizeSubjectKind(p.Kind, "") == proto.SubjectKindRelayExit
}

func maxFloat(a float64, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func recommendedTier(p proto.SubjectProfile) int {
	tier := p.Tier
	if tier < 1 {
		tier = 1
	}
	if tier > 3 {
		tier = 3
	}
	if p.Reputation >= 0.95 && p.Bond >= 500 {
		return 3
	}
	if p.Reputation >= 0.8 || p.Bond >= 100 {
		if tier < 2 {
			return 2
		}
	}
	return tier
}

func activeTierCap(p proto.SubjectProfile, nowUnix int64) (int, bool) {
	capTier := p.TierCap
	if capTier < 1 || capTier > 3 {
		return 0, false
	}
	if p.DisputeUntil <= nowUnix {
		return 0, false
	}
	return capTier, true
}

func normalizeAppealUntil(appealUntil int64, nowUnix int64) int64 {
	if appealUntil <= nowUnix {
		return 0
	}
	return appealUntil
}

func hasActiveAppeal(p proto.SubjectProfile, nowUnix int64) bool {
	return normalizeAppealUntil(p.AppealUntil, nowUnix) > 0
}

func effectiveTierCapForIssuance(p proto.SubjectProfile, nowUnix int64) (int, bool) {
	capTier, ok := activeTierCap(p, nowUnix)
	if !ok {
		return 0, false
	}
	// During active appeal, grant one temporary cap level back while adjudication is pending.
	if hasActiveAppeal(p, nowUnix) && capTier < 3 {
		capTier++
	}
	return capTier, true
}

func applyTierCap(tier int, p proto.SubjectProfile, nowUnix int64) int {
	if capTier, ok := activeTierCap(p, nowUnix); ok && tier > capTier {
		return capTier
	}
	return tier
}

func (s *Service) recordAudit(ev proto.AuditEvent) {
	s.mu.Lock()
	s.auditSeq++
	ev.ID = s.auditSeq
	ev.Timestamp = time.Now().Unix()
	s.audit = append(s.audit, ev)
	if s.auditMax > 0 && len(s.audit) > s.auditMax {
		s.audit = s.audit[len(s.audit)-s.auditMax:]
	}
	s.mu.Unlock()
	if err := s.saveAudit(); err != nil {
		log.Printf("issuer audit persist warning: %v", err)
	}
}

func (s *Service) saveAudit() error {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.audit, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.auditFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.auditFile, data, 0o644)
}

func (s *Service) loadAudit() error {
	b, err := os.ReadFile(s.auditFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []proto.AuditEvent
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	var maxID int64
	for _, ev := range list {
		if ev.ID > maxID {
			maxID = ev.ID
		}
	}
	s.mu.Lock()
	s.audit = list
	s.auditSeq = maxID
	s.mu.Unlock()
	return nil
}

func tickerC(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}
