package entry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	nodecrypto "privacynode/pkg/crypto"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
)

type sessionState struct {
	exitDataAddr   string
	exitControlURL string
	expiresUnix    int64
	transport      string
	clientDataAddr string
	clientLastSeen int64
}

type exitRoute struct {
	controlURL string
	dataAddr   string
	fetchedAt  time.Time
}

type routeCandidate struct {
	route exitRoute
	votes int
}

type Service struct {
	addr                  string
	dataAddr              string
	liveWGMode            bool
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
	openRPS           int
	openBanThreshold  int
	openBanDuration   time.Duration
	openMaxInflight   int
	openInflightSem   chan struct{}
	clientRebindAfter time.Duration
	puzzleDifficulty  int
	puzzleAdaptive    bool
	puzzleMax         int
	puzzleSecret      string
	buckets           map[string]rateBucket
	abuse             map[string]abuseState
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
	directoryTrustStrict := envBoolOr("ENTRY_DIRECTORY_TRUST_STRICT", "DIRECTORY_TRUST_STRICT", false)
	directoryTrustTOFU := envBoolOr("ENTRY_DIRECTORY_TRUST_TOFU", "DIRECTORY_TRUST_TOFU", true)
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
		puzzleSecret = "entry-secret-default"
	}
	puzzleAdaptive := os.Getenv("ENTRY_PUZZLE_ADAPTIVE") != "0"
	puzzleMax := 6
	return &Service{
		addr:                  addr,
		dataAddr:              dataAddr,
		liveWGMode:            liveWGMode,
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
		openRPS:               openRPS,
		openBanThreshold:      openBanThreshold,
		openBanDuration:       openBanDuration,
		openMaxInflight:       openMaxInflight,
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
	log.Printf("entry route discovery: directories=%d min_sources=%d min_operators=%d min_votes=%d trust_strict=%t live_wg_mode=%t rps=%d ban_threshold=%d ban_sec=%d max_inflight=%d client_rebind_sec=%d",
		len(s.directoryURLs), maxInt(1, s.directoryMinSources), maxInt(1, s.directoryMinOperators), maxInt(1, s.directoryMinVotes), s.directoryTrustStrict,
		s.liveWGMode, s.openRPS, s.openBanThreshold, int(s.openBanDuration/time.Second), s.openMaxInflight, int(s.clientRebindAfter/time.Second))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/path/open", s.handlePathOpen)
	mux.HandleFunc("/v1/path/close", s.handlePathClose)
	mux.HandleFunc("/v1/health", s.handleHealth)

	s.httpSrv = &http.Server{Addr: s.addr, Handler: mux}
	errCh := make(chan error, 2)
	go func() {
		log.Printf("entry listening on %s", s.addr)
		errCh <- s.httpSrv.ListenAndServe()
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Transport) == "" {
		req.Transport = "policy-json"
	}
	if strings.TrimSpace(req.TokenProof) == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token-proof-required"})
		return
	}
	if s.liveWGMode && req.Transport != "wireguard-udp" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "transport must be wireguard-udp in entry live mode"})
		return
	}
	route, err := s.resolveExitRoute(r.Context(), req.ExitID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "unknown-exit"})
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

func (s *Service) limitOpen(clientIP string) (int, bool) {
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[clientIP]
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
	state, ok := s.abuse[clientIP]
	if !ok {
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
	state := s.abuse[clientIP]
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		http.Error(w, "missing session_id", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	state, exists := s.sessions[req.SessionID]
	if exists {
		delete(s.sessions, req.SessionID)
	}
	s.mu.Unlock()
	if !exists {
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "unknown-session"})
		return
	}
	log.Printf("entry closing session=%s", req.SessionID)

	resp, err := s.forwardPathClose(r.Context(), state.exitControlURL, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func randomSessionID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
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
	}
	if exitID == "" {
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
				fetchedAt:  now,
			}, fallback)
			key := route.controlURL + "|" + route.dataAddr
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
		return s.fetchDirectoryPubKeyLegacy(ctx, directoryURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("directory pubkeys status %d", resp.StatusCode)
	}
	var out proto.DirectoryPubKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
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
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return v
	}
	return "http://" + v
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
				if _, known := trusted[candidate]; known {
					continue
				}
				if err := appendTrustedKey(s.directoryTrustFile, candidate); err != nil {
					return err
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
		for _, key := range filtered[1:] {
			if err := appendTrustedKey(s.directoryTrustFile, key); err != nil {
				return err
			}
		}
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
	b, err := os.ReadFile(path)
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(key + "\n")
	return err
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

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
