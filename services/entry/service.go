package entry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nodecrypto "privacynode/pkg/crypto"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
	"privacynode/pkg/securehttp"
)

type sessionState struct {
	exitDataAddr   string
	exitControlURL string
	sessionKeyID   string
	expiresUnix    int64
	transport      string
	clientDataAddr string
	clientLastSeen int64
}

type exitRoute struct {
	controlURL string
	dataAddr   string
	operatorID string
	fetchedAt  time.Time
}

type routeCandidate struct {
	route exitRoute
	votes int
}

type relayDescriptorCandidate struct {
	desc  proto.RelayDescriptor
	votes int
}

type cachedRelayDescriptor struct {
	desc      proto.RelayDescriptor
	fetchedAt time.Time
}

type Service struct {
	addr                  string
	dataAddr              string
	liveWGMode            bool
	wgOnlyMode            bool
	betaStrict            bool
	prodStrict            bool
	operatorID            string
	requireDistinctExitOp bool
	exitControlURL        string
	exitDataAddr          string
	directoryURLs         []string
	directoryMinSources   int
	directoryMinOperators int
	directoryMinVotes     int
	directoryTrustStrict  bool
	directoryTrustTOFU    bool
	directoryTrustFile    string
	routeTTL              time.Duration
	httpClient            *http.Client
	httpSrv               *http.Server
	udpConn               *net.UDPConn

	mu                sync.RWMutex
	sessions          map[string]sessionState
	exitRouteCache    map[string]exitRoute
	relayDescCache    map[string]cachedRelayDescriptor
	openRPS           int
	openBanThreshold  int
	openBanDuration   time.Duration
	openMaxInflight   int
	maxSessions       int
	maxBuckets        int
	maxAbuseEntries   int
	openInflightSem   chan struct{}
	clientRebindAfter time.Duration
	puzzleDifficulty  int
	puzzleAdaptive    bool
	puzzleMax         int
	puzzleSecret      string
	buckets           map[string]rateBucket
	abuse             map[string]abuseState
	nextPruneUnix     int64
}

type rateBucket struct {
	windowUnix int64
	count      int
}

type abuseState struct {
	strikes        int
	bannedUntilSec int64
	lastSeenSec    int64
}

const controlPathRequestMaxBodyBytes int64 = 64 * 1024
const serverReadHeaderTimeout = 10 * time.Second
const serverReadTimeout = 15 * time.Second
const serverWriteTimeout = 30 * time.Second
const serverIdleTimeout = 60 * time.Second
const serverMaxHeaderBytes = 1 << 20
const remoteResponseMaxBodyBytes int64 = 1 << 20
const allowDangerousOutboundPrivateDNS = "ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS"
const defaultEntryMaxSessions = 65536
const defaultEntryMaxRateBuckets = 65536
const defaultEntryMaxAbuseEntries = 65536
const rateBucketRetentionSec int64 = 3
const trustedDirectoryKeysFileMaxBytes int64 = 1 * 1024 * 1024

func New() *Service {
	addr := os.Getenv("ENTRY_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8083"
	}
	dataAddr := os.Getenv("ENTRY_DATA_ADDR")
	if dataAddr == "" {
		dataAddr = "127.0.0.1:51820"
	}
	exitControlURL := os.Getenv("EXIT_CONTROL_URL")
	if exitControlURL == "" {
		exitControlURL = "http://127.0.0.1:8084"
	}
	exitDataAddr := os.Getenv("EXIT_DATA_ADDR")
	if exitDataAddr == "" {
		exitDataAddr = "127.0.0.1:51821"
	}
	directoryURL := os.Getenv("DIRECTORY_URL")
	if directoryURL == "" {
		directoryURL = "http://127.0.0.1:8081"
	}
	directoryURLs := []string{normalizeHTTPURL(directoryURL)}
	if raw := os.Getenv("DIRECTORY_URLS"); raw != "" {
		var parsed []string
		for _, v := range strings.Split(raw, ",") {
			if vv := normalizeHTTPURL(v); vv != "" {
				parsed = append(parsed, vv)
			}
		}
		if len(parsed) > 0 {
			directoryURLs = parsed
		}
	}
	directoryMinSources := envIntOr("ENTRY_DIRECTORY_MIN_SOURCES", "DIRECTORY_MIN_SOURCES", 1)
	directoryMinOperators := envIntOr("ENTRY_DIRECTORY_MIN_OPERATORS", "DIRECTORY_MIN_OPERATORS", 1)
	directoryMinVotes := envIntOr("ENTRY_DIRECTORY_MIN_RELAY_VOTES", "DIRECTORY_MIN_RELAY_VOTES", 1)
	directoryTrustStrict := envBoolOr("ENTRY_DIRECTORY_TRUST_STRICT", "DIRECTORY_TRUST_STRICT", true)
	directoryTrustTOFU := envBoolOr("ENTRY_DIRECTORY_TRUST_TOFU", "DIRECTORY_TRUST_TOFU", false)
	directoryTrustFile := os.Getenv("ENTRY_DIRECTORY_TRUSTED_KEYS_FILE")
	if directoryTrustFile == "" {
		directoryTrustFile = os.Getenv("DIRECTORY_TRUSTED_KEYS_FILE")
	}
	if directoryTrustFile == "" {
		directoryTrustFile = "data/entry_trusted_directory_keys.txt"
	}
	routeTTL := 30 * time.Second
	if v, err := strconv.Atoi(os.Getenv("ENTRY_EXIT_ROUTE_TTL_SEC")); err == nil && v > 0 {
		routeTTL = time.Duration(v) * time.Second
	}
	liveWGMode := os.Getenv("ENTRY_LIVE_WG_MODE") == "1"
	betaStrict := os.Getenv("BETA_STRICT_MODE") == "1" || os.Getenv("ENTRY_BETA_STRICT") == "1"
	prodStrict := os.Getenv("PROD_STRICT_MODE") == "1" || os.Getenv("ENTRY_PROD_STRICT") == "1"
	wgOnlyMode := os.Getenv("WG_ONLY_MODE") == "1" || os.Getenv("ENTRY_WG_ONLY_MODE") == "1"
	if prodStrict {
		wgOnlyMode = true
	}
	operatorID := strings.TrimSpace(os.Getenv("ENTRY_OPERATOR_ID"))
	if operatorID == "" {
		operatorID = strings.TrimSpace(os.Getenv("DIRECTORY_OPERATOR_ID"))
	}
	requireDistinctExitOp := os.Getenv("ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR") == "1"
	openRPS := 20
	if v, err := strconv.Atoi(os.Getenv("ENTRY_OPEN_RPS")); err == nil && v > 0 {
		openRPS = v
	}
	openBanThreshold := 3
	if v, err := strconv.Atoi(os.Getenv("ENTRY_BAN_THRESHOLD")); err == nil && v > 0 {
		openBanThreshold = v
	}
	openBanDuration := 45 * time.Second
	if v, err := strconv.Atoi(os.Getenv("ENTRY_BAN_SEC")); err == nil && v > 0 {
		openBanDuration = time.Duration(v) * time.Second
	}
	openMaxInflight := 128
	if v, err := strconv.Atoi(os.Getenv("ENTRY_MAX_CONCURRENT_OPENS")); err == nil && v > 0 {
		openMaxInflight = v
	}
	maxSessions := envIntOr("ENTRY_MAX_SESSIONS", "", defaultEntryMaxSessions)
	maxBuckets := envIntOr("ENTRY_MAX_RATE_BUCKETS", "", defaultEntryMaxRateBuckets)
	maxAbuseEntries := envIntOr("ENTRY_MAX_ABUSE_ENTRIES", "", defaultEntryMaxAbuseEntries)
	clientRebindAfter := time.Duration(0)
	if v, err := strconv.Atoi(os.Getenv("ENTRY_CLIENT_REBIND_SEC")); err == nil && v > 0 {
		clientRebindAfter = time.Duration(v) * time.Second
	}
	var openInflightSem chan struct{}
	if openMaxInflight > 0 {
		openInflightSem = make(chan struct{}, openMaxInflight)
	}
	puzzleDifficulty := 0
	if v, err := strconv.Atoi(os.Getenv("ENTRY_PUZZLE_DIFFICULTY")); err == nil && v >= 0 && v <= 6 {
		puzzleDifficulty = v
	}
	puzzleSecret := os.Getenv("ENTRY_PUZZLE_SECRET")
	if puzzleSecret == "" {
		puzzleSecret = defaultPuzzleSecret()
	}
	puzzleAdaptive := os.Getenv("ENTRY_PUZZLE_ADAPTIVE") != "0"
	puzzleMax := 6
	return &Service{
		addr:                  addr,
		dataAddr:              dataAddr,
		liveWGMode:            liveWGMode,
		wgOnlyMode:            wgOnlyMode,
		betaStrict:            betaStrict,
		prodStrict:            prodStrict,
		operatorID:            operatorID,
		requireDistinctExitOp: requireDistinctExitOp,
		exitControlURL:        exitControlURL,
		exitDataAddr:          exitDataAddr,
		directoryURLs:         directoryURLs,
		directoryMinSources:   directoryMinSources,
		directoryMinOperators: directoryMinOperators,
		directoryMinVotes:     directoryMinVotes,
		directoryTrustStrict:  directoryTrustStrict,
		directoryTrustTOFU:    directoryTrustTOFU,
		directoryTrustFile:    directoryTrustFile,
		routeTTL:              routeTTL,
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		sessions:              make(map[string]sessionState),
		exitRouteCache:        make(map[string]exitRoute),
		relayDescCache:        make(map[string]cachedRelayDescriptor),
		openRPS:               openRPS,
		openBanThreshold:      openBanThreshold,
		openBanDuration:       openBanDuration,
		openMaxInflight:       openMaxInflight,
		maxSessions:           maxSessions,
		maxBuckets:            maxBuckets,
		maxAbuseEntries:       maxAbuseEntries,
		openInflightSem:       openInflightSem,
		clientRebindAfter:     clientRebindAfter,
		puzzleDifficulty:      puzzleDifficulty,
		puzzleAdaptive:        puzzleAdaptive,
		puzzleMax:             puzzleMax,
		puzzleSecret:          puzzleSecret,
		buckets:               make(map[string]rateBucket),
		abuse:                 make(map[string]abuseState),
	}
}

func (s *Service) Run(ctx context.Context) error {
	httpClient, err := securehttp.NewClient(5 * time.Second)
	if err != nil {
		return fmt.Errorf("entry http tls init: %w", err)
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	configureOutboundDialPolicy(httpClient, envEnabled(allowDangerousOutboundPrivateDNS), s.betaStrict || s.prodStrict)
	s.httpClient = httpClient

	if err := s.validateRuntimeConfig(); err != nil {
		return err
	}
	log.Printf("entry route discovery: directories=%d min_sources=%d min_operators=%d min_votes=%d trust_strict=%t live_wg_mode=%t wg_only=%t distinct_exit_operator=%t operator_id=%s rps=%d ban_threshold=%d ban_sec=%d max_inflight=%d client_rebind_sec=%d",
		len(s.directoryURLs), maxInt(1, s.directoryMinSources), maxInt(1, s.directoryMinOperators), maxInt(1, s.directoryMinVotes), s.directoryTrustStrict,
		s.liveWGMode, s.wgOnlyMode, s.requireDistinctExitOp, strings.TrimSpace(s.operatorID), s.openRPS, s.openBanThreshold, int(s.openBanDuration/time.Second), s.openMaxInflight, int(s.clientRebindAfter/time.Second))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/path/open", s.handlePathOpen)
	mux.HandleFunc("/v1/path/close", s.handlePathClose)
	mux.HandleFunc("/v1/health", s.handleHealth)

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadTimeout:       serverReadTimeout,
		ReadHeaderTimeout: serverReadHeaderTimeout,
		WriteTimeout:      serverWriteTimeout,
		IdleTimeout:       serverIdleTimeout,
		MaxHeaderBytes:    serverMaxHeaderBytes,
	}
	errCh := make(chan error, 2)
	go func() {
		log.Printf("entry listening on %s", s.addr)
		errCh <- securehttp.ListenAndServe(s.httpSrv)
	}()

	if err := s.startUDP(ctx, errCh); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
		if s.udpConn != nil {
			_ = s.udpConn.Close()
		}
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed || strings.Contains(err.Error(), "use of closed network connection") {
			return nil
		}
		return err
	}
}

func (s *Service) validateRuntimeConfig() error {
	if securehttp.Enabled() {
		if s.prodStrict && securehttp.InsecureSkipVerifyConfigured() {
			return fmt.Errorf("PROD_STRICT_MODE forbids MTLS_INSECURE_SKIP_VERIFY")
		}
		if err := securehttp.Validate(); err != nil {
			return fmt.Errorf("invalid mTLS config: %w", err)
		}
	}
	if s.requireDistinctExitOp && strings.TrimSpace(s.operatorID) == "" {
		return fmt.Errorf("ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1 requires ENTRY_OPERATOR_ID or DIRECTORY_OPERATOR_ID")
	}
	if s.wgOnlyMode && !s.liveWGMode {
		return fmt.Errorf("WG_ONLY_MODE requires ENTRY_LIVE_WG_MODE=1")
	}
	if s.betaStrict {
		if !s.liveWGMode {
			return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_LIVE_WG_MODE=1")
		}
		if !s.directoryTrustStrict {
			return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_DIRECTORY_TRUST_STRICT=1")
		}
		if s.directoryTrustTOFU {
			return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_DIRECTORY_TRUST_TOFU=0")
		}
		if !s.requireDistinctExitOp {
			return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1")
		}
		secret := strings.TrimSpace(s.puzzleSecret)
		if secret == "" || secret == "entry-secret-default" {
			return fmt.Errorf("BETA_STRICT_MODE requires non-default ENTRY_PUZZLE_SECRET")
		}
		if len(secret) < 16 {
			return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_PUZZLE_SECRET length>=16")
		}
		if s.puzzleDifficulty <= 0 {
			return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_PUZZLE_DIFFICULTY>0")
		}
		if len(s.directoryURLs) > 1 {
			if s.directoryMinSources < 2 {
				return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_DIRECTORY_MIN_SOURCES>=2 when multiple DIRECTORY_URLS are configured")
			}
			if s.directoryMinOperators < 2 {
				return fmt.Errorf("BETA_STRICT_MODE requires ENTRY_DIRECTORY_MIN_OPERATORS>=2 when multiple DIRECTORY_URLS are configured")
			}
		}
	}
	if s.prodStrict {
		if !s.betaStrict {
			return fmt.Errorf("PROD_STRICT_MODE requires BETA_STRICT_MODE=1")
		}
		if !securehttp.Enabled() {
			return fmt.Errorf("PROD_STRICT_MODE requires MTLS_ENABLE=1")
		}
		if s.directoryTrustTOFU {
			return fmt.Errorf("PROD_STRICT_MODE requires ENTRY_DIRECTORY_TRUST_TOFU=0")
		}
	}
	return nil
}

func (s *Service) startUDP(ctx context.Context, errCh chan<- error) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.dataAddr)
	if err != nil {
		return fmt.Errorf("resolve entry data addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen entry data addr: %w", err)
	}
	s.udpConn = conn
	log.Printf("entry data plane listening on %s", s.dataAddr)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, srcAddr, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				errCh <- readErr
				return
			}
			sessionID, payload, parseErr := relay.ParseDatagram(buf[:n])
			if parseErr != nil {
				continue
			}

			now := time.Now().Unix()
			s.mu.Lock()
			state, exists := s.sessions[sessionID]
			if !exists {
				s.mu.Unlock()
				continue
			}
			if now >= state.expiresUnix {
				delete(s.sessions, sessionID)
				s.mu.Unlock()
				continue
			}
			prevClient := state.clientDataAddr
			state, targetAddr, routed := routePacketTarget(state, srcAddr.String(), now, int64(s.clientRebindAfter/time.Second))
			s.sessions[sessionID] = state
			s.mu.Unlock()
			if !routed {
				log.Printf("entry dropped packet session=%s reason=source-mismatch src=%s client=%s exit=%s",
					sessionID, srcAddr.String(), prevClient, state.exitDataAddr)
				continue
			}
			if prevClient != "" && state.clientDataAddr != prevClient {
				log.Printf("entry client source rebind session=%s old=%s new=%s", sessionID, prevClient, state.clientDataAddr)
			}
			if targetAddr == "" {
				continue
			}
			if ok, reason := allowForwardPayload(state.transport, payload, s.liveWGMode); !ok {
				log.Printf("entry dropped packet session=%s reason=%s transport=%s src=%s payload_len=%d",
					sessionID, reason, state.transport, srcAddr.String(), len(payload))
				continue
			}

			target, resolveErr := net.ResolveUDPAddr("udp", targetAddr)
			if resolveErr != nil {
				continue
			}
			forward := relay.BuildDatagram(sessionID, payload)
			_, _ = conn.WriteToUDP(forward, target)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return nil
}

func (s *Service) handlePathOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req proto.PathOpenRequest
	if err := decodeStrictRequestJSON(w, r, &req, controlPathRequestMaxBodyBytes); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.TokenProof) == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token-proof-required"})
		return
	}
	if s.betaStrict || s.prodStrict {
		if strings.TrimSpace(req.TokenProofNonce) == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token-proof-nonce-required"})
			return
		}
		if !looksLikeTokenProofSignature(req.TokenProof) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token-proof-invalid"})
			return
		}
	}
	if s.liveWGMode && req.Transport != "wireguard-udp" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "transport must be wireguard-udp in entry live mode"})
		return
	}
	clientIP := remoteIP(r.RemoteAddr)
	if s.isBanned(clientIP, time.Now()) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "source-temporarily-blocked"})
		return
	}
	releaseSlot, ok := s.acquireOpenSlot()
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "entry-overloaded"})
		return
	}
	defer releaseSlot()

	count, limited := s.limitOpen(clientIP)
	if limited {
		if s.noteAbuse(clientIP, time.Now()) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "source-temporarily-blocked"})
			return
		}
		ch := s.challengeFor(clientIP, time.Now())
		diff := s.effectiveDifficulty(count)
		if diff > 0 && !verifyPuzzle(ch, req.PuzzleNonce, req.PuzzleDigest, diff) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{
				Accepted:   false,
				Reason:     "challenge-required",
				Challenge:  ch,
				Difficulty: diff,
			})
			return
		}
	}
	if !s.allowNewSession(time.Now().Unix()) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "entry-capacity-exceeded"})
		return
	}
	route, err := s.resolveExitRoute(r.Context(), req.ExitID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "unknown-exit"})
		return
	}
	if s.requireDistinctExitOp {
		entryOp := strings.TrimSpace(s.operatorID)
		exitOp := strings.TrimSpace(route.operatorID)
		if entryOp == "" || exitOp == "" || entryOp == exitOp {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "entry-exit-operator-collision"})
			return
		}
	}
	if reason := s.validateMiddleRelayRequest(r.Context(), req, route); reason != "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: reason})
		return
	}

	sessionID, err := randomSessionID()
	if err != nil {
		http.Error(w, "failed to generate session id", http.StatusInternalServerError)
		return
	}
	req.SessionID = sessionID

	resp, err := s.forwardPathOpen(r.Context(), route.controlURL, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if resp.Accepted {
		expires := resp.SessionExp
		if expires == 0 {
			expires = time.Now().Add(10 * time.Minute).Unix()
		}
		transport := normalizePathTransport(resp.Transport, req.Transport)
		s.mu.Lock()
		s.sessions[sessionID] = sessionState{
			exitDataAddr:   route.dataAddr,
			exitControlURL: route.controlURL,
			sessionKeyID:   strings.TrimSpace(resp.SessionKeyID),
			expiresUnix:    expires,
			transport:      transport,
		}
		s.mu.Unlock()
		resp.SessionID = sessionID
		resp.EntryDataAddr = s.dataAddr
		resp.SessionExp = expires
		resp.Transport = transport
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func looksLikeTokenProofSignature(raw string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	return err == nil && len(sig) == ed25519.SignatureSize
}

func (s *Service) limitOpen(clientIP string) (int, bool) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneStateLocked(now)
	b := s.buckets[clientIP]
	if b.windowUnix == 0 && s.bucketCapacity() > 0 && len(s.buckets) >= s.bucketCapacity() {
		return s.openRPS + 1, true
	}
	if b.windowUnix != now {
		b.windowUnix = now
		b.count = 0
	}
	b.count++
	s.buckets[clientIP] = b
	return b.count, b.count > s.openRPS
}

func (s *Service) acquireOpenSlot() (func(), bool) {
	if s.openInflightSem == nil {
		return func() {}, true
	}
	select {
	case s.openInflightSem <- struct{}{}:
		return func() {
			select {
			case <-s.openInflightSem:
			default:
			}
		}, true
	default:
		return nil, false
	}
}

func (s *Service) isBanned(clientIP string, now time.Time) bool {
	nowSec := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneStateLocked(nowSec)
	state, ok := s.abuse[clientIP]
	if !ok {
		if s.abuseCapacity() > 0 && len(s.abuse) >= s.abuseCapacity() {
			return true
		}
		return false
	}
	if state.bannedUntilSec > nowSec {
		state.lastSeenSec = nowSec
		s.abuse[clientIP] = state
		return true
	}
	if nowSec-state.lastSeenSec > int64(maxInt(90, int(s.openBanDuration/time.Second)*4)) {
		delete(s.abuse, clientIP)
		return false
	}
	state.lastSeenSec = nowSec
	s.abuse[clientIP] = state
	return false
}

func (s *Service) noteAbuse(clientIP string, now time.Time) bool {
	if s.openBanThreshold <= 0 || s.openBanDuration <= 0 {
		return false
	}
	nowSec := now.Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneStateLocked(nowSec)
	state, exists := s.abuse[clientIP]
	if !exists && s.abuseCapacity() > 0 && len(s.abuse) >= s.abuseCapacity() {
		return true
	}
	state.lastSeenSec = nowSec
	if state.bannedUntilSec > nowSec {
		s.abuse[clientIP] = state
		return true
	}
	state.strikes++
	if state.strikes >= s.openBanThreshold {
		state.strikes = 0
		state.bannedUntilSec = nowSec + int64(s.openBanDuration/time.Second)
		s.abuse[clientIP] = state
		return true
	}
	s.abuse[clientIP] = state
	return false
}

func (s *Service) allowNewSession(nowSec int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneStateLocked(nowSec)
	if s.sessionCapacity() <= 0 {
		return true
	}
	return len(s.sessions) < s.sessionCapacity()
}

func (s *Service) sessionCapacity() int {
	if s.maxSessions > 0 {
		return s.maxSessions
	}
	return defaultEntryMaxSessions
}

func (s *Service) bucketCapacity() int {
	if s.maxBuckets > 0 {
		return s.maxBuckets
	}
	return defaultEntryMaxRateBuckets
}

func (s *Service) abuseCapacity() int {
	if s.maxAbuseEntries > 0 {
		return s.maxAbuseEntries
	}
	return defaultEntryMaxAbuseEntries
}

func (s *Service) pruneStateLocked(nowSec int64) {
	if nowSec < s.nextPruneUnix {
		return
	}
	s.nextPruneUnix = nowSec + 1

	for sessionID, state := range s.sessions {
		if state.expiresUnix > 0 && nowSec >= state.expiresUnix {
			delete(s.sessions, sessionID)
		}
	}
	for clientIP, bucket := range s.buckets {
		if bucket.windowUnix <= 0 || nowSec-bucket.windowUnix > rateBucketRetentionSec {
			delete(s.buckets, clientIP)
		}
	}
	abuseIdleSec := int64(maxInt(90, int(s.openBanDuration/time.Second)*4))
	for clientIP, state := range s.abuse {
		if state.bannedUntilSec > nowSec {
			continue
		}
		if nowSec-state.lastSeenSec > abuseIdleSec {
			delete(s.abuse, clientIP)
		}
	}
}

func (s *Service) challengeFor(clientIP string, now time.Time) string {
	epoch := now.Unix() / 15
	base := fmt.Sprintf("%s|%s|%d", clientIP, s.puzzleSecret, epoch)
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

func verifyPuzzle(challenge string, nonce string, digest string, difficulty int) bool {
	if nonce == "" || digest == "" {
		return false
	}
	sum := sha256.Sum256([]byte(challenge + ":" + nonce))
	got := hex.EncodeToString(sum[:])
	if got != digest {
		return false
	}
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(got, prefix)
}

func (s *Service) effectiveDifficulty(currentCount int) int {
	diff := s.puzzleDifficulty
	if !s.puzzleAdaptive || s.openRPS <= 0 {
		return diff
	}
	over := currentCount - s.openRPS
	if over <= 0 {
		return diff
	}
	steps := over / s.openRPS
	diff += steps
	if diff > s.puzzleMax {
		diff = s.puzzleMax
	}
	return diff
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func routePacketTarget(state sessionState, sourceAddr string, nowUnix int64, rebindAfterSec int64) (sessionState, string, bool) {
	if sameUDPAddr(sourceAddr, state.exitDataAddr) {
		if strings.TrimSpace(state.clientDataAddr) == "" {
			return state, "", false
		}
		return state, state.clientDataAddr, true
	}
	if strings.TrimSpace(state.clientDataAddr) == "" {
		state.clientDataAddr = sourceAddr
		state.clientLastSeen = nowUnix
		return state, state.exitDataAddr, true
	}
	if sameUDPAddr(sourceAddr, state.clientDataAddr) {
		state.clientLastSeen = nowUnix
		return state, state.exitDataAddr, true
	}
	if rebindAfterSec > 0 {
		lastSeen := state.clientLastSeen
		if lastSeen == 0 || nowUnix-lastSeen >= rebindAfterSec {
			state.clientDataAddr = sourceAddr
			state.clientLastSeen = nowUnix
			return state, state.exitDataAddr, true
		}
	}
	return state, "", false
}

func sameUDPAddr(a, b string) bool {
	aa, errA := net.ResolveUDPAddr("udp", a)
	bb, errB := net.ResolveUDPAddr("udp", b)
	if errA != nil || errB != nil {
		return a == b
	}
	if aa.Port != bb.Port {
		return false
	}
	if aa.IP == nil || bb.IP == nil {
		return aa.IP.String() == bb.IP.String()
	}
	return aa.IP.Equal(bb.IP)
}

func (s *Service) forwardPathOpen(ctx context.Context, exitControlURL string, in proto.PathOpenRequest) (proto.PathOpenResponse, error) {
	var out proto.PathOpenResponse
	payload, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exitControlURL+"/v1/path/open", bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("exit returned status %d", resp.StatusCode)
	}
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Service) handlePathClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req proto.PathCloseRequest
	if err := decodeStrictRequestJSON(w, r, &req, controlPathRequestMaxBodyBytes); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	state, exists := s.sessions[req.SessionID]
	s.mu.RUnlock()
	if !exists {
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "unknown-session"})
		return
	}
	if state.sessionKeyID != "" &&
		subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.SessionKeyID)), []byte(state.sessionKeyID)) != 1 {
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "session-key-id-mismatch"})
		return
	}
	log.Printf("entry closing session=%s", req.SessionID)

	resp, err := s.forwardPathClose(r.Context(), state.exitControlURL, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.mu.Lock()
	delete(s.sessions, req.SessionID)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Service) forwardPathClose(ctx context.Context, exitControlURL string, in proto.PathCloseRequest) (proto.PathCloseResponse, error) {
	var out proto.PathCloseResponse
	payload, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, exitControlURL+"/v1/path/close", bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("exit returned status %d", resp.StatusCode)
	}
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return out, err
	}
	return out, nil
}

func decodeStrictRequestJSON(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing struct{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing json tokens")
		}
		return err
	}
	return nil
}

func decodeBoundedJSONResponse(body io.Reader, dst any, maxBytes int64) error {
	if body == nil {
		return fmt.Errorf("empty response body")
	}
	if maxBytes <= 0 {
		return fmt.Errorf("invalid response size limit: %d", maxBytes)
	}
	reader := &io.LimitedReader{R: body, N: maxBytes + 1}
	dec := json.NewDecoder(reader)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if reader.N <= 0 {
		return fmt.Errorf("response body exceeds %d bytes", maxBytes)
	}
	var trailer json.RawMessage
	if err := dec.Decode(&trailer); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing json content")
		}
		return err
	}
	if reader.N <= 0 {
		return fmt.Errorf("response body exceeds %d bytes", maxBytes)
	}
	return nil
}

func randomSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func defaultPuzzleSecret() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "entry-secret-default"
	}
	return hex.EncodeToString(buf)
}

func normalizePathTransport(fromExit string, fromRequest string) string {
	transport := strings.TrimSpace(fromExit)
	if transport == "" {
		transport = strings.TrimSpace(fromRequest)
	}
	if transport == "" {
		transport = "policy-json"
	}
	return transport
}

func allowForwardPayload(transport string, payload []byte, liveWGMode bool) (bool, string) {
	if !liveWGMode {
		return true, ""
	}
	if strings.TrimSpace(transport) != "wireguard-udp" {
		return true, ""
	}
	_, raw, err := relay.ParseOpaquePayload(payload)
	if err != nil {
		return false, "invalid-opaque-live"
	}
	if !relay.LooksLikePlausibleWireGuardMessage(raw) {
		return false, "non-wireguard-live"
	}
	return true, ""
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Service) resolveExitRoute(ctx context.Context, exitID string) (exitRoute, error) {
	fallback := exitRoute{
		controlURL: normalizeHTTPURL(s.exitControlURL),
		dataAddr:   strings.TrimSpace(s.exitDataAddr),
		operatorID: strings.TrimSpace(s.operatorID),
	}
	if exitID == "" {
		if s.betaStrict || s.prodStrict {
			return exitRoute{}, fmt.Errorf("exit id required in strict mode")
		}
		return fallback, nil
	}

	now := time.Now()
	requiredSources := maxInt(1, s.directoryMinSources)
	requiredOperators := maxInt(1, s.directoryMinOperators)
	requiredVotes := maxInt(1, s.directoryMinVotes)
	s.mu.RLock()
	cached, ok := s.exitRouteCache[exitID]
	s.mu.RUnlock()
	if ok && now.Sub(cached.fetchedAt) <= s.routeTTL {
		return cached, nil
	}

	candidates := make(map[string]routeCandidate)
	routeVoters := make(map[string]map[string]struct{})
	successSources := 0
	successOperators := make(map[string]struct{})
	var lastErr error

	for _, durl := range s.directoryURLs {
		dirPubs, sourceOperator, err := s.fetchDirectoryPubKeys(ctx, durl)
		if err != nil {
			lastErr = err
			log.Printf("entry directory pubkey fetch failed url=%s err=%v", durl, err)
			continue
		}
		relays, err := s.fetchRelaysVerified(ctx, durl, dirPubs)
		if err != nil {
			lastErr = err
			log.Printf("entry directory relays fetch failed url=%s err=%v", durl, err)
			continue
		}
		successSources++
		successOperators[sourceOperator] = struct{}{}
		seenFromSource := make(map[string]struct{})
		for _, desc := range relays {
			if desc.Role != "exit" || desc.RelayID != exitID {
				continue
			}
			route := normalizeRoute(exitRoute{
				controlURL: normalizeHTTPURL(desc.ControlURL),
				dataAddr:   strings.TrimSpace(desc.Endpoint),
				operatorID: strings.TrimSpace(desc.OperatorID),
				fetchedAt:  now,
			}, fallback)
			if s.betaStrict || s.prodStrict {
				if err := validateStrictExitControlRoute(route.controlURL, route.dataAddr); err != nil {
					lastErr = err
					continue
				}
			}
			key := route.controlURL + "|" + route.dataAddr + "|" + route.operatorID
			if _, ok := seenFromSource[key]; ok {
				continue
			}
			seenFromSource[key] = struct{}{}
			if !markRouteVoter(routeVoters, key, sourceOperator) {
				continue
			}
			c := candidates[key]
			if c.votes == 0 {
				c.route = route
			}
			c.votes++
			candidates[key] = c
		}
	}

	if successSources < requiredSources {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient directory sources")
		}
		return exitRoute{}, fmt.Errorf("exit route quorum not met for %s: success=%d required=%d: %w",
			exitID, successSources, requiredSources, lastErr)
	}
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient directory operators")
		}
		return exitRoute{}, fmt.Errorf("exit route operator quorum not met for %s: operators=%d required=%d: %w",
			exitID, len(successOperators), requiredOperators, lastErr)
	}

	best, ok := pickBestRoute(candidates, requiredVotes)
	if !ok {
		return exitRoute{}, fmt.Errorf("no exit route met vote threshold for %s: required_votes=%d", exitID, requiredVotes)
	}
	s.mu.Lock()
	s.exitRouteCache[exitID] = best
	s.mu.Unlock()
	return best, nil
}

func (s *Service) validateMiddleRelayRequest(ctx context.Context, req proto.PathOpenRequest, route exitRoute) string {
	middleRelayID := strings.TrimSpace(req.MiddleRelayID)
	if middleRelayID == "" {
		return ""
	}
	exitID := strings.TrimSpace(req.ExitID)
	if exitID != "" && middleRelayID == exitID {
		return "middle-relay-equals-exit"
	}
	useCache := !(s.betaStrict || s.prodStrict)
	desc, err := s.resolveRelayDescriptorWithCachePolicy(ctx, middleRelayID, useCache)
	if err != nil {
		return "unknown-middle-relay"
	}
	if !relaySupportsMiddleDescriptor(desc) {
		return "middle-relay-role-invalid"
	}
	middleOp := strings.TrimSpace(desc.OperatorID)
	if middleOp == "" {
		if s.betaStrict || s.prodStrict {
			return "middle-relay-operator-missing"
		}
		return ""
	}
	entryOp := strings.TrimSpace(s.operatorID)
	if entryOp != "" && middleOp == entryOp {
		return "entry-middle-operator-collision"
	}
	exitOp := strings.TrimSpace(route.operatorID)
	if exitOp != "" && middleOp == exitOp {
		return "middle-exit-operator-collision"
	}
	return ""
}

func (s *Service) resolveRelayDescriptor(ctx context.Context, relayID string) (proto.RelayDescriptor, error) {
	return s.resolveRelayDescriptorWithCachePolicy(ctx, relayID, true)
}

func (s *Service) resolveRelayDescriptorWithCachePolicy(ctx context.Context, relayID string, useCache bool) (proto.RelayDescriptor, error) {
	relayID = strings.TrimSpace(relayID)
	if relayID == "" {
		return proto.RelayDescriptor{}, fmt.Errorf("relay id required")
	}
	now := time.Now()
	requiredSources := maxInt(1, s.directoryMinSources)
	requiredOperators := maxInt(1, s.directoryMinOperators)
	requiredVotes := maxInt(1, s.directoryMinVotes)

	if useCache {
		s.mu.RLock()
		cached, ok := s.relayDescCache[relayID]
		s.mu.RUnlock()
		if ok && now.Sub(cached.fetchedAt) <= s.routeTTL {
			return cached.desc, nil
		}
	}

	candidates := make(map[string]relayDescriptorCandidate)
	descriptorVoters := make(map[string]map[string]struct{})
	successSources := 0
	successOperators := make(map[string]struct{})
	var lastErr error

	for _, durl := range s.directoryURLs {
		dirPubs, sourceOperator, err := s.fetchDirectoryPubKeys(ctx, durl)
		if err != nil {
			lastErr = err
			log.Printf("entry directory pubkey fetch failed url=%s err=%v", durl, err)
			continue
		}
		relays, err := s.fetchRelaysVerified(ctx, durl, dirPubs)
		if err != nil {
			lastErr = err
			log.Printf("entry directory relays fetch failed url=%s err=%v", durl, err)
			continue
		}
		successSources++
		successOperators[sourceOperator] = struct{}{}
		seenFromSource := make(map[string]struct{})
		for _, desc := range relays {
			if strings.TrimSpace(desc.RelayID) != relayID {
				continue
			}
			key := relayDescriptorVoteKey(desc)
			if _, alreadySeen := seenFromSource[key]; alreadySeen {
				continue
			}
			seenFromSource[key] = struct{}{}
			if !markRouteVoter(descriptorVoters, key, sourceOperator) {
				continue
			}
			candidate := candidates[key]
			if candidate.votes == 0 {
				candidate.desc = desc
			}
			candidate.votes++
			candidates[key] = candidate
		}
	}

	if successSources < requiredSources {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient directory sources")
		}
		return proto.RelayDescriptor{}, fmt.Errorf("relay descriptor quorum not met for %s: success=%d required=%d: %w",
			relayID, successSources, requiredSources, lastErr)
	}
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient directory operators")
		}
		return proto.RelayDescriptor{}, fmt.Errorf("relay descriptor operator quorum not met for %s: operators=%d required=%d: %w",
			relayID, len(successOperators), requiredOperators, lastErr)
	}
	best, ok := pickBestRelayDescriptor(candidates, requiredVotes)
	if ok && !relaySupportsMiddleDescriptor(best) {
		if middleBest, middleOK := pickBestRelayDescriptorWithFilter(candidates, requiredVotes, relaySupportsMiddleDescriptor); middleOK {
			if relayDescriptorVotes(candidates, middleBest) >= relayDescriptorVotes(candidates, best) {
				best = middleBest
			}
		}
	}
	if !ok {
		return proto.RelayDescriptor{}, fmt.Errorf("no relay descriptor met vote threshold for %s: required_votes=%d", relayID, requiredVotes)
	}
	s.mu.Lock()
	if s.relayDescCache == nil {
		s.relayDescCache = make(map[string]cachedRelayDescriptor)
	}
	s.relayDescCache[relayID] = cachedRelayDescriptor{desc: best, fetchedAt: now}
	s.mu.Unlock()
	return best, nil
}

func relayDescriptorVoteKey(desc proto.RelayDescriptor) string {
	hopRoles := normalizeDescriptorList(desc.HopRoles)
	capabilities := normalizeDescriptorList(desc.Capabilities)
	return strings.Join([]string{
		strings.TrimSpace(desc.RelayID),
		canonicalizeMiddleRoleAlias(strings.ToLower(strings.TrimSpace(desc.Role))),
		strings.TrimSpace(desc.OperatorID),
		normalizeHTTPURL(desc.ControlURL),
		strings.TrimSpace(desc.Endpoint),
		strings.TrimSpace(desc.CountryCode),
		strings.TrimSpace(desc.Region),
		strings.Join(hopRoles, ","),
		strings.Join(capabilities, ","),
	}, "|")
}

func normalizeDescriptorList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := canonicalizeMiddleRoleAlias(strings.ToLower(strings.TrimSpace(value)))
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func pickBestRelayDescriptor(candidates map[string]relayDescriptorCandidate, minVotes int) (proto.RelayDescriptor, bool) {
	return pickBestRelayDescriptorWithFilter(candidates, minVotes, nil)
}

func pickBestRelayDescriptorWithFilter(
	candidates map[string]relayDescriptorCandidate,
	minVotes int,
	filter func(proto.RelayDescriptor) bool,
) (proto.RelayDescriptor, bool) {
	bestVotes := 0
	bestKey := ""
	var bestDesc proto.RelayDescriptor
	for key, candidate := range candidates {
		if candidate.votes < minVotes {
			continue
		}
		if filter != nil && !filter(candidate.desc) {
			continue
		}
		if candidate.votes > bestVotes || (candidate.votes == bestVotes && (bestKey == "" || key < bestKey)) {
			bestVotes = candidate.votes
			bestKey = key
			bestDesc = candidate.desc
		}
	}
	if bestKey == "" {
		return proto.RelayDescriptor{}, false
	}
	return bestDesc, true
}

func relayDescriptorVotes(candidates map[string]relayDescriptorCandidate, desc proto.RelayDescriptor) int {
	if candidate, ok := candidates[relayDescriptorVoteKey(desc)]; ok {
		return candidate.votes
	}
	return 0
}

func relaySupportsMiddleDescriptor(relay proto.RelayDescriptor) bool {
	if hopRoleIsMiddleDescriptor(relay.Role) {
		return true
	}
	for _, hopRole := range relay.HopRoles {
		if hopRoleIsMiddleDescriptor(hopRole) {
			return true
		}
	}
	for _, capability := range relay.Capabilities {
		if hopRoleIsMiddleDescriptor(capability) {
			return true
		}
	}
	return false
}

func hopRoleIsMiddleDescriptor(raw string) bool {
	switch canonicalizeMiddleRoleAlias(strings.ToLower(strings.TrimSpace(raw))) {
	case "micro-relay":
		return true
	default:
		return false
	}
}

func canonicalizeMiddleRoleAlias(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "middle", "relay", "micro_relay", "transit", "three-hop-middle":
		return "micro-relay"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func (s *Service) fetchDirectoryPubKeys(ctx context.Context, directoryURL string) ([]ed25519.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL+"/v1/pubkeys", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		if s.betaStrict || s.prodStrict {
			return nil, "", fmt.Errorf("directory legacy /v1/pubkey fallback is not allowed in strict mode")
		}
		return s.fetchDirectoryPubKeyLegacy(ctx, directoryURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("directory pubkeys status %d", resp.StatusCode)
	}
	var out proto.DirectoryPubKeysResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, "", err
	}
	if err := s.enforceDirectoryTrustSet(out.PubKeys); err != nil {
		return nil, "", err
	}
	keys := make([]ed25519.PublicKey, 0, len(out.PubKeys))
	for _, pubB64 := range out.PubKeys {
		pubB64 = strings.TrimSpace(pubB64)
		raw, decErr := base64.RawURLEncoding.DecodeString(pubB64)
		if decErr != nil || len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("invalid directory pubkey")
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	if len(keys) == 0 {
		return nil, "", fmt.Errorf("directory returned no pubkeys")
	}
	return keys, normalizeDirectoryOperator(out.Operator, out.PubKeys, directoryURL), nil
}

func (s *Service) fetchDirectoryPubKeyLegacy(ctx context.Context, directoryURL string) ([]ed25519.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL+"/v1/pubkey", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("directory pubkey status %d", resp.StatusCode)
	}
	var out map[string]string
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, "", err
	}
	pubB64 := strings.TrimSpace(out["pub_key"])
	if err := s.enforceDirectoryTrust(pubB64); err != nil {
		return nil, "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid directory pubkey")
	}
	return []ed25519.PublicKey{ed25519.PublicKey(raw)}, normalizeDirectoryOperator("", []string{pubB64}, directoryURL), nil
}

func (s *Service) fetchRelaysVerified(ctx context.Context, directoryURL string, dirPubs []ed25519.PublicKey) ([]proto.RelayDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL+"/v1/relays", nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory status %d", resp.StatusCode)
	}
	var out proto.RelayListResponse
	if err := decodeBoundedJSONResponse(resp.Body, &out, remoteResponseMaxBodyBytes); err != nil {
		return nil, err
	}
	for _, desc := range out.Relays {
		if err := verifyRelayDescriptorAny(desc, dirPubs); err != nil {
			return nil, fmt.Errorf("descriptor verify failed relay=%s: %w", desc.RelayID, err)
		}
	}
	return out.Relays, nil
}

func normalizeHTTPURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, "://") {
		base := strings.TrimRight(v, "/")
		host := base
		if cut, _, ok := strings.Cut(base, "/"); ok {
			host = cut
		}
		if isLoopbackURLHost(host) {
			v = "http://" + base
		} else {
			v = "https://" + base
		}
	}
	parsed, err := url.Parse(v)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	if parsed.Scheme == "http" &&
		!isLoopbackURLHost(parsed.Host) &&
		!isLocalDevelopmentURLHost(parsed.Host) &&
		enforceHTTPSControlURL() &&
		!allowDangerousInsecureControlURLHTTP() {
		return ""
	}
	return strings.TrimRight(parsed.String(), "/")
}

func enforceHTTPSControlURL() bool {
	raw := strings.TrimSpace(os.Getenv("ENTRY_REQUIRE_HTTPS_CONTROL_URL"))
	if raw == "" {
		return true
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

func allowDangerousInsecureControlURLHTTP() bool {
	raw := strings.TrimSpace(os.Getenv("ENTRY_ALLOW_INSECURE_CONTROL_URL_HTTP"))
	return raw == "1" || strings.EqualFold(raw, "true")
}

func isLoopbackURLHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.Count(host, ":") == 1 || strings.HasPrefix(host, "[") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func isLocalDevelopmentURLHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.Count(host, ":") == 1 || strings.HasPrefix(host, "[") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
	}
	host = strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	return host != "" && (host == "localhost" || strings.HasSuffix(host, ".local"))
}

func validateStrictExitControlRoute(controlURL, dataAddr string) error {
	parsed, err := url.Parse(controlURL)
	if err != nil {
		return fmt.Errorf("invalid exit control url")
	}
	if !strings.EqualFold(strings.TrimSpace(parsed.Scheme), "https") {
		return fmt.Errorf("exit control url must use https in strict mode")
	}
	controlHost := normalizeHostForCompare(parsed.Hostname())
	if controlHost == "" {
		return fmt.Errorf("exit control url host missing")
	}
	if isDisallowedStrictRouteHost(controlHost) {
		return fmt.Errorf("exit control url host not allowed")
	}
	dataHost := hostFromEndpoint(dataAddr)
	if dataHost != "" && !strings.EqualFold(controlHost, dataHost) {
		return fmt.Errorf("exit control url host must match exit data host")
	}
	return nil
}

func hostFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}
	if hasZoneIdentifierHost(host) {
		return ""
	}
	return normalizeHostForCompare(host)
}

func normalizeHostForCompare(host string) string {
	normalized := strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	return strings.TrimRight(normalized, ".")
}

func hasZoneIdentifierHost(host string) bool {
	normalized := strings.TrimSpace(strings.Trim(host, "[]"))
	return strings.Contains(normalized, "%")
}

func isAmbiguousNumericHostAlias(host string) bool {
	host = normalizeHostForCompare(host)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	decimalOrDotted := true
	for _, ch := range host {
		if (ch < '0' || ch > '9') && ch != '.' {
			decimalOrDotted = false
			break
		}
	}
	if decimalOrDotted {
		return true
	}
	if strings.HasPrefix(host, "0x") {
		hexPart := strings.TrimPrefix(host, "0x")
		if hexPart == "" {
			return false
		}
		for _, ch := range hexPart {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return false
			}
		}
		return true
	}
	return false
}

func isDisallowedStrictRouteHost(host string) bool {
	if hasZoneIdentifierHost(host) {
		return true
	}
	host = normalizeHostForCompare(host)
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if isAmbiguousNumericHostAlias(host) {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

type outboundIPResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

func configureOutboundDialPolicy(client *http.Client, allowDangerousPrivateDNS bool, strictBlockPrivateLiteral bool) {
	if client == nil {
		return
	}
	transport := cloneHTTPTransport(client.Transport)
	transport.Proxy = nil
	if envEnabled("MTLS_ALLOW_PROXY_FROM_ENV") {
		transport.Proxy = http.ProxyFromEnvironment
	}
	resolver := net.DefaultResolver
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		safeAddress, err := resolveSafeDialAddress(ctx, resolver, address, allowDangerousPrivateDNS, strictBlockPrivateLiteral)
		if err != nil {
			return nil, err
		}
		return dialer.DialContext(ctx, network, safeAddress)
	}
	client.Transport = transport
}

func cloneHTTPTransport(base http.RoundTripper) *http.Transport {
	if tr, ok := base.(*http.Transport); ok && tr != nil {
		return tr.Clone()
	}
	if tr, ok := http.DefaultTransport.(*http.Transport); ok && tr != nil {
		return tr.Clone()
	}
	return &http.Transport{}
}

func resolveSafeDialAddress(ctx context.Context, resolver outboundIPResolver, address string, allowDangerousPrivateDNS bool, strictBlockPrivateLiteral bool) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return "", fmt.Errorf("invalid outbound address %q: %w", address, err)
	}
	if hasZoneIdentifierHost(host) {
		return "", fmt.Errorf("outbound host %q includes unsupported zone identifier", host)
	}
	host = normalizeHostForCompare(host)
	if host == "" {
		return "", fmt.Errorf("outbound host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedOutboundDialIP(ip) {
			if strictBlockPrivateLiteral {
				return "", fmt.Errorf("outbound literal host %q is blocked by outbound dial policy (strict mode)", ip.String())
			}
			if !allowDangerousPrivateDNS {
				return "", fmt.Errorf("outbound literal host %q is blocked by outbound dial policy", ip.String())
			}
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("resolve outbound host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("resolve outbound host %q returned no addresses", host)
	}
	loopbackHostname := host == "localhost"
	if loopbackHostname && !allowDangerousPrivateDNS {
		var selectedLoopback net.IP
		for _, candidate := range ips {
			ip := candidate.IP
			if ip == nil {
				continue
			}
			if !ip.IsLoopback() {
				return "", fmt.Errorf("outbound host %q resolved to non-loopback address %q", host, ip.String())
			}
			if selectedLoopback == nil {
				selectedLoopback = ip
			}
		}
		if selectedLoopback == nil {
			return "", fmt.Errorf("outbound host %q resolved only to blocked address classes", host)
		}
		return net.JoinHostPort(selectedLoopback.String(), port), nil
	}
	for _, candidate := range ips {
		ip := candidate.IP
		if ip == nil {
			continue
		}
		if allowDangerousPrivateDNS {
			return net.JoinHostPort(ip.String(), port), nil
		}
		if isDisallowedOutboundDialIP(ip) {
			if loopbackHostname && ip.IsLoopback() {
				return net.JoinHostPort(ip.String(), port), nil
			}
			continue
		}
		return net.JoinHostPort(ip.String(), port), nil
	}
	return "", fmt.Errorf("outbound host %q resolved only to blocked address classes", host)
}

func isDisallowedOutboundDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func normalizeDirectoryOperator(operator string, pubKeys []string, directoryURL string) string {
	operator = strings.TrimSpace(operator)
	if operator != "" {
		return operator
	}
	for _, key := range pubKeys {
		key = strings.TrimSpace(key)
		if key != "" {
			return "key:" + key
		}
	}
	return "url:" + strings.TrimSpace(directoryURL)
}

func markRouteVoter(voters map[string]map[string]struct{}, routeKey string, operator string) bool {
	if strings.TrimSpace(routeKey) == "" || strings.TrimSpace(operator) == "" {
		return false
	}
	ops, ok := voters[routeKey]
	if !ok {
		ops = make(map[string]struct{})
		voters[routeKey] = ops
	}
	if _, exists := ops[operator]; exists {
		return false
	}
	ops[operator] = struct{}{}
	return true
}

func normalizeRoute(route exitRoute, fallback exitRoute) exitRoute {
	if route.controlURL == "" {
		route.controlURL = fallback.controlURL
	}
	if route.dataAddr == "" {
		route.dataAddr = fallback.dataAddr
	}
	return route
}

func pickBestRoute(candidates map[string]routeCandidate, minVotes int) (exitRoute, bool) {
	bestVotes := 0
	bestKey := ""
	var bestRoute exitRoute
	for key, cand := range candidates {
		if cand.votes < minVotes {
			continue
		}
		if cand.votes > bestVotes || (cand.votes == bestVotes && (bestKey == "" || key < bestKey)) {
			bestVotes = cand.votes
			bestKey = key
			bestRoute = cand.route
		}
	}
	if bestKey == "" {
		return exitRoute{}, false
	}
	return bestRoute, true
}

func (s *Service) enforceDirectoryTrust(pubB64 string) error {
	return s.enforceDirectoryTrustSet([]string{pubB64})
}

func (s *Service) enforceDirectoryTrustSet(pubKeys []string) error {
	if !s.directoryTrustStrict {
		return nil
	}
	filtered := dedupeKeyList(pubKeys)
	if len(filtered) == 0 {
		return fmt.Errorf("directory returned no pubkeys")
	}
	trusted, err := loadTrustedKeys(s.directoryTrustFile)
	if err != nil {
		return err
	}
	for _, key := range filtered {
		if _, ok := trusted[key]; ok {
			for _, candidate := range filtered {
				if _, known := trusted[candidate]; !known {
					return fmt.Errorf("directory returned untrusted additional key")
				}
			}
			return nil
		}
	}
	if s.directoryTrustTOFU && len(trusted) == 0 {
		if err := appendTrustedKey(s.directoryTrustFile, filtered[0]); err != nil {
			return err
		}
		log.Printf("entry TOFU pinned directory key to %s", s.directoryTrustFile)
		return nil
	}
	return fmt.Errorf("directory key is not trusted")
}

func dedupeKeyList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, k := range in {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func verifyRelayDescriptorAny(desc proto.RelayDescriptor, pubs []ed25519.PublicKey) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no directory pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := nodecrypto.VerifyRelayDescriptor(desc, pub); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("descriptor signature verification failed")
	}
	return lastErr
}

func loadTrustedKeys(path string) (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	b, err := readFileBounded(path, trustedDirectoryKeysFileMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(line)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid trusted key entry: %s", line)
		}
		keys[line] = struct{}{}
	}
	return keys, nil
}

func readFileBounded(path string, maxBytes int64) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("file path is required")
	}
	lstatInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lstatInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("file %s must not be a symlink", path)
	}
	if !lstatInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("file %s must be a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, statErr := file.Stat()
	if statErr != nil {
		return nil, statErr
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("file %s must be a regular file", path)
	}
	if !os.SameFile(lstatInfo, info) {
		return nil, fmt.Errorf("file %s changed during open", path)
	}
	if maxBytes > 0 {
		if info.Size() > maxBytes {
			return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
		}
	}
	limit := maxBytes
	if limit <= 0 {
		limit = 1
	}
	b, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if maxBytes > 0 && int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds %d bytes", path, maxBytes)
	}
	return b, nil
}

func appendTrustedKey(path string, key string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	existing, err := loadTrustedKeys(path)
	if err != nil {
		return err
	}
	if _, ok := existing[key]; ok {
		return nil
	}
	keys := make([]string, 0, len(existing)+1)
	for existingKey := range existing {
		keys = append(keys, existingKey)
	}
	keys = append(keys, key)
	sort.Strings(keys)

	payload := strings.Join(keys, "\n") + "\n"
	return writeTrustedKeysAtomic(path, []byte(payload), 0o644)
}

func writeTrustedKeysAtomic(path string, payload []byte, perm os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(payload); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(err.Error()), "access is denied") {
			return nil
		}
		return err
	}
	return nil
}

func envIntOr(primary string, fallback string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(primary)); err == nil && v > 0 {
		return v
	}
	if v, err := strconv.Atoi(os.Getenv(fallback)); err == nil && v > 0 {
		return v
	}
	return def
}

func envBoolOr(primary string, fallback string, def bool) bool {
	if raw := os.Getenv(primary); raw != "" {
		return raw == "1"
	}
	if raw := os.Getenv(fallback); raw != "" {
		return raw == "1"
	}
	return def
}

func envEnabled(name string) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
