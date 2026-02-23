package exit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/policy"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
	"privacynode/pkg/wg"
)

type sessionInfo struct {
	claims        crypto.CapabilityClaims
	seenNonces    map[uint64]struct{}
	lastActivity  time.Time
	transport     string
	sessionKeyID  string
	clientInnerIP string
	clientPubKey  string
	peerAddr      string
	peerLastSeen  int64
	downNonce     uint64
}

type Service struct {
	addr                  string
	dataAddr              string
	issuerURL             string
	issuerURLs            []string
	revocationsURL        string
	revocationsURLs       []string
	dataMode              string
	opaqueSinkAddr        string
	opaqueSourceAddr      string
	opaqueEcho            bool
	wgPubKey              string
	wgExitIP              string
	wgMTU                 int
	wgKeepaliveSec        int
	ipAllocCursor         uint32
	wgInterface           string
	wgPrivateKey          string
	wgListenPort          int
	wgBackend             string
	wgKernelProxy         bool
	wgKernelTargetUDP     *net.UDPAddr
	wgManager             wg.Manager
	liveWGMode            bool
	egressBackend         string
	egressIface           string
	egressCIDR            string
	egressChain           string
	egressConfigured      bool
	tokenProofReplayGuard bool
	peerRebindAfter       time.Duration
	revocationRefreshSec  int
	accountingFile        string
	accountingFlushSec    int
	enforcer              *policy.Enforcer
	httpClient            *http.Client
	httpSrv               *http.Server
	udpConn               *net.UDPConn
	opaqueSourceConn      *net.UDPConn
	opaqueSinkUDP         *net.UDPAddr

	mu                sync.RWMutex
	issuerPub         ed25519.PublicKey
	issuerPubs        map[string]ed25519.PublicKey
	issuerKeyIssuer   map[string]string
	sessions          map[string]sessionInfo
	wgSessionProxies  map[string]*net.UDPConn
	proofNonceSeen    map[string]map[string]int64
	metrics           exitMetrics
	revokedJTI        map[string]int64
	minTokenEpoch     map[string]int64
	revocationVersion map[string]int64
}

type exitMetrics struct {
	AcceptedPackets         uint64 `json:"accepted_packets"`
	DroppedPackets          uint64 `json:"dropped_packets"`
	AcceptedBytes           uint64 `json:"accepted_bytes"`
	DroppedBytes            uint64 `json:"dropped_bytes"`
	AcceptedTier1Packets    uint64 `json:"accepted_tier1_packets"`
	AcceptedTier2Packets    uint64 `json:"accepted_tier2_packets"`
	AcceptedTier3Packets    uint64 `json:"accepted_tier3_packets"`
	DroppedTier1Packets     uint64 `json:"dropped_tier1_packets"`
	DroppedTier2Packets     uint64 `json:"dropped_tier2_packets"`
	DroppedTier3Packets     uint64 `json:"dropped_tier3_packets"`
	DroppedTokenRevoked     uint64 `json:"dropped_token_revoked"`
	DroppedTokenKeyEpoch    uint64 `json:"dropped_token_key_epoch"`
	DroppedTokenProofReplay uint64 `json:"dropped_token_proof_replay"`
	DroppedSourceMismatch   uint64 `json:"dropped_source_mismatch"`
	DroppedNonWGLive        uint64 `json:"dropped_non_wg_live"`
	ForwardedDownlinkPkts   uint64 `json:"forwarded_downlink_packets"`
	ForwardedDownlinkBytes  uint64 `json:"forwarded_downlink_bytes"`
	DroppedDownlinkPkts     uint64 `json:"dropped_downlink_packets"`
	ActiveSessions          uint64 `json:"active_sessions"`
	AccountingUpdatedUnix   int64  `json:"accounting_updated_unix"`
}

var deriveWGPublicKeyFromPrivateFile = wg.DerivePublicKeyFromPrivateFile

func New() *Service {
	addr := os.Getenv("EXIT_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8084"
	}
	dataAddr := os.Getenv("EXIT_DATA_ADDR")
	if dataAddr == "" {
		dataAddr = "127.0.0.1:51821"
	}
	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "http://127.0.0.1:8082"
	}
	issuerURLs := splitCSV(os.Getenv("ISSUER_URLS"))
	if len(issuerURLs) == 0 {
		issuerURLs = []string{issuerURL}
	}
	issuerURLs = normalizeHTTPURLs(issuerURLs)
	issuerURL = issuerURLs[0]
	revocationsURL := os.Getenv("ISSUER_REVOCATIONS_URL")
	revocationsURLs := splitCSV(os.Getenv("ISSUER_REVOCATIONS_URLS"))
	if len(revocationsURLs) == 0 {
		if revocationsURL != "" {
			revocationsURLs = []string{revocationsURL}
		} else {
			revocationsURLs = make([]string, 0, len(issuerURLs))
			for _, u := range issuerURLs {
				revocationsURLs = append(revocationsURLs, joinURL(u, "/v1/revocations"))
			}
		}
	}
	revocationsURLs = normalizeHTTPURLs(revocationsURLs)
	if len(revocationsURLs) == 0 {
		revocationsURLs = []string{joinURL(issuerURL, "/v1/revocations")}
	}
	revocationsURL = revocationsURLs[0]
	dataMode := os.Getenv("DATA_PLANE_MODE")
	if dataMode == "" {
		dataMode = "json"
	}
	opaqueSinkAddr := os.Getenv("EXIT_OPAQUE_SINK_ADDR")
	opaqueSourceAddr := os.Getenv("EXIT_OPAQUE_SOURCE_ADDR")
	wgPubKey := os.Getenv("EXIT_WG_PUBKEY")
	if wgPubKey == "" {
		wgPubKey = "exit-wg-pubkey-stub"
	}
	wgExitIP := os.Getenv("EXIT_WG_EXIT_IP")
	if wgExitIP == "" {
		wgExitIP = "10.90.0.1/32"
	}
	wgInterface := os.Getenv("EXIT_WG_INTERFACE")
	if wgInterface == "" {
		wgInterface = "wg-exit0"
	}
	wgPrivateKey := os.Getenv("EXIT_WG_PRIVATE_KEY_PATH")
	wgListenPort := 51831
	if raw := strings.TrimSpace(os.Getenv("EXIT_WG_LISTEN_PORT")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 65535 {
			wgListenPort = parsed
		}
	}
	wgBackend := os.Getenv("WG_BACKEND")
	if wgBackend == "" {
		wgBackend = "noop"
	}
	wgKernelProxy := os.Getenv("EXIT_WG_KERNEL_PROXY") == "1"
	var wgManager wg.Manager
	switch wgBackend {
	case "command":
		wgManager = wg.NewCommandManager()
	default:
		wgBackend = "noop"
		wgManager = wg.NewNoopManager()
	}
	liveWGMode := os.Getenv("EXIT_LIVE_WG_MODE") == "1"
	opaqueEcho := true
	if wgBackend == "command" || liveWGMode {
		opaqueEcho = false
	}
	if raw := os.Getenv("EXIT_OPAQUE_ECHO"); raw != "" {
		opaqueEcho = raw != "0"
	}
	egressBackend := os.Getenv("EXIT_EGRESS_BACKEND")
	if egressBackend == "" {
		egressBackend = "noop"
	}
	egressIface := os.Getenv("EXIT_EGRESS_IFACE")
	if egressIface == "" {
		egressIface = "eth0"
	}
	egressCIDR := os.Getenv("EXIT_EGRESS_CIDR")
	if egressCIDR == "" {
		egressCIDR = "10.90.0.0/24"
	}
	egressChain := os.Getenv("EXIT_EGRESS_CHAIN")
	if egressChain == "" {
		egressChain = "PRIVNODE_EGRESS"
	}
	tokenProofReplayGuard := os.Getenv("EXIT_TOKEN_PROOF_REPLAY_GUARD") == "1"
	peerRebindAfter := time.Duration(0)
	if v := os.Getenv("EXIT_PEER_REBIND_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			peerRebindAfter = time.Duration(n) * time.Second
		}
	}
	revocationRefreshSec := 15
	if v := os.Getenv("EXIT_REVOCATION_REFRESH_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			revocationRefreshSec = n
		}
	}
	accountingFile := strings.TrimSpace(os.Getenv("EXIT_ACCOUNTING_FILE"))
	accountingFlushSec := 10
	if v := os.Getenv("EXIT_ACCOUNTING_FLUSH_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			accountingFlushSec = n
		}
	}

	return &Service{
		addr:                  addr,
		dataAddr:              dataAddr,
		issuerURL:             issuerURL,
		issuerURLs:            issuerURLs,
		revocationsURL:        revocationsURL,
		revocationsURLs:       revocationsURLs,
		dataMode:              dataMode,
		opaqueSinkAddr:        opaqueSinkAddr,
		opaqueSourceAddr:      opaqueSourceAddr,
		opaqueEcho:            opaqueEcho,
		wgPubKey:              wgPubKey,
		wgExitIP:              wgExitIP,
		wgMTU:                 1280,
		wgKeepaliveSec:        25,
		ipAllocCursor:         2,
		wgInterface:           wgInterface,
		wgPrivateKey:          wgPrivateKey,
		wgListenPort:          wgListenPort,
		wgBackend:             wgBackend,
		wgKernelProxy:         wgKernelProxy,
		wgManager:             wgManager,
		liveWGMode:            liveWGMode,
		egressBackend:         egressBackend,
		egressIface:           egressIface,
		egressCIDR:            egressCIDR,
		egressChain:           egressChain,
		tokenProofReplayGuard: tokenProofReplayGuard,
		peerRebindAfter:       peerRebindAfter,
		revocationRefreshSec:  revocationRefreshSec,
		accountingFile:        accountingFile,
		accountingFlushSec:    accountingFlushSec,
		enforcer:              policy.NewEnforcer(),
		httpClient:            &http.Client{Timeout: 5 * time.Second},
		issuerPubs:            make(map[string]ed25519.PublicKey),
		issuerKeyIssuer:       make(map[string]string),
		sessions:              make(map[string]sessionInfo),
		wgSessionProxies:      make(map[string]*net.UDPConn),
		proofNonceSeen:        make(map[string]map[string]int64),
		revokedJTI:            make(map[string]int64),
		minTokenEpoch:         make(map[string]int64),
		revocationVersion:     make(map[string]int64),
	}
}

func (s *Service) Run(ctx context.Context) error {
	log.Printf("exit wg backend=%s iface=%s listen_port=%d kernel_proxy=%t opaque_echo=%t token_proof_replay_guard=%t peer_rebind_sec=%d",
		s.wgBackend, s.wgInterface, s.wgListenPort, s.wgKernelProxy, s.opaqueEcho, s.tokenProofReplayGuard, int(s.peerRebindAfter/time.Second))
	if err := s.validateRuntimeConfig(); err != nil {
		return err
	}
	defer s.closeAllWGKernelSessionProxies()
	if s.wgBackend == "command" {
		if err := wg.PreflightCommandBackend(ctx, s.wgInterface, s.wgPrivateKey); err != nil {
			return fmt.Errorf("exit wg preflight failed: %w", err)
		}
		if err := s.ensureCommandWGPubKey(ctx); err != nil {
			return fmt.Errorf("exit wg pubkey init failed: %w", err)
		}
	}
	if s.wgKernelProxy {
		targetAddr := fmt.Sprintf("127.0.0.1:%d", s.wgListenPort)
		target, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			return fmt.Errorf("invalid wg kernel proxy target: %w", err)
		}
		s.wgKernelTargetUDP = target
		log.Printf("exit wg kernel proxy target=%s", targetAddr)
	}
	if s.opaqueSinkAddr != "" {
		sink, err := net.ResolveUDPAddr("udp", s.opaqueSinkAddr)
		if err != nil {
			return fmt.Errorf("invalid EXIT_OPAQUE_SINK_ADDR: %w", err)
		}
		s.opaqueSinkUDP = sink
		log.Printf("exit opaque sink enabled addr=%s", s.opaqueSinkAddr)
	}
	if err := s.refreshIssuerKeys(ctx); err != nil {
		log.Printf("exit startup key fetch failed: %v", err)
	}
	if err := s.refreshRevocations(ctx); err != nil {
		log.Printf("exit startup revocation fetch failed: %v", err)
	}
	if err := s.configureEgress(ctx); err != nil {
		log.Printf("exit egress setup failed: %v", err)
	}
	defer func() {
		if err := s.teardownEgress(context.Background()); err != nil {
			log.Printf("exit egress cleanup failed: %v", err)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/path/open", s.handlePathOpen)
	mux.HandleFunc("/v1/path/close", s.handlePathClose)
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/metrics", s.handleMetrics)

	s.httpSrv = &http.Server{Addr: s.addr, Handler: mux}
	errCh := make(chan error, 2)
	go func() {
		log.Printf("exit listening on %s", s.addr)
		errCh <- s.httpSrv.ListenAndServe()
	}()

	if err := s.startUDP(ctx, errCh); err != nil {
		return err
	}
	if err := s.startOpaqueSource(ctx, errCh); err != nil {
		return err
	}

	refreshTicker := time.NewTicker(30 * time.Second)
	defer refreshTicker.Stop()
	revocationTicker := time.NewTicker(time.Duration(s.revocationRefreshSec) * time.Second)
	defer revocationTicker.Stop()
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()
	var accountingTicker *time.Ticker
	if s.accountingFile != "" {
		accountingTicker = time.NewTicker(time.Duration(s.accountingFlushSec) * time.Second)
		defer accountingTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.httpSrv.Shutdown(shutdownCtx)
			if s.udpConn != nil {
				_ = s.udpConn.Close()
			}
			if s.opaqueSourceConn != nil {
				_ = s.opaqueSourceConn.Close()
			}
			s.closeAllWGKernelSessionProxies()
			if err := s.flushAccountingSnapshot(time.Now()); err != nil {
				log.Printf("exit accounting flush failed: %v", err)
			}
			return ctx.Err()
		case err := <-errCh:
			if err == http.ErrServerClosed || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		case <-refreshTicker.C:
			if err := s.refreshIssuerKeys(ctx); err != nil {
				log.Printf("exit key refresh failed: %v", err)
			}
		case <-revocationTicker.C:
			if err := s.refreshRevocations(ctx); err != nil {
				log.Printf("exit revocation refresh failed: %v", err)
			}
		case <-cleanupTicker.C:
			s.cleanupExpiredSessions(time.Now())
		case <-tickerC(accountingTicker):
			if err := s.flushAccountingSnapshot(time.Now()); err != nil {
				log.Printf("exit accounting flush failed: %v", err)
			}
		}
	}
}

func (s *Service) validateRuntimeConfig() error {
	if s.wgListenPort == 0 {
		s.wgListenPort = 51831
	}
	if s.wgListenPort <= 0 || s.wgListenPort > 65535 {
		return fmt.Errorf("EXIT_WG_LISTEN_PORT must be in 1..65535")
	}
	if s.wgBackend == "command" {
		if s.dataMode != "opaque" {
			return fmt.Errorf("WG_BACKEND=command requires DATA_PLANE_MODE=opaque")
		}
		if s.wgPrivateKey == "" {
			return fmt.Errorf("WG_BACKEND=command requires EXIT_WG_PRIVATE_KEY_PATH")
		}
		if strings.TrimSpace(s.dataAddr) == "" {
			s.dataAddr = "127.0.0.1:51821"
		}
		dataPort, err := udpPortOf(s.dataAddr)
		if err != nil {
			return fmt.Errorf("invalid EXIT_DATA_ADDR: %w", err)
		}
		if dataPort == s.wgListenPort {
			return fmt.Errorf("EXIT_DATA_ADDR port conflicts with EXIT_WG_LISTEN_PORT; choose distinct ports")
		}
	}
	if s.wgKernelProxy {
		if s.dataMode != "opaque" {
			return fmt.Errorf("EXIT_WG_KERNEL_PROXY requires DATA_PLANE_MODE=opaque")
		}
		if s.wgBackend != "command" {
			return fmt.Errorf("EXIT_WG_KERNEL_PROXY requires WG_BACKEND=command")
		}
	}
	if s.liveWGMode {
		if s.dataMode != "opaque" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires DATA_PLANE_MODE=opaque")
		}
		if s.wgBackend != "command" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires WG_BACKEND=command")
		}
		if s.wgPrivateKey == "" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_WG_PRIVATE_KEY_PATH")
		}
		if s.opaqueEcho {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_OPAQUE_ECHO=0")
		}
		if strings.TrimSpace(s.opaqueSinkAddr) == "" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_OPAQUE_SINK_ADDR")
		}
		if strings.TrimSpace(s.opaqueSourceAddr) == "" {
			return fmt.Errorf("EXIT_LIVE_WG_MODE requires EXIT_OPAQUE_SOURCE_ADDR")
		}
	}
	return nil
}

func (s *Service) ensureCommandWGPubKey(ctx context.Context) error {
	if s.wgBackend != "command" {
		return nil
	}
	configured := strings.TrimSpace(s.wgPubKey)
	derived, err := deriveWGPublicKeyFromPrivateFile(ctx, s.wgPrivateKey)
	if err != nil {
		return err
	}
	if wg.IsValidPublicKey(configured) && configured != derived {
		return fmt.Errorf("configured EXIT_WG_PUBKEY does not match EXIT_WG_PRIVATE_KEY_PATH")
	}
	s.wgPubKey = derived
	if configured == "" || configured != derived {
		log.Printf("exit derived wg public key from private key file")
	}
	return nil
}

func (s *Service) startUDP(ctx context.Context, errCh chan<- error) error {
	udpAddr, err := net.ResolveUDPAddr("udp", s.dataAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.udpConn = conn
	log.Printf("exit data plane listening on %s mode=%s", s.dataAddr, s.dataMode)

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

			switch s.dataMode {
			case "opaque":
				nonce, raw, err := relay.ParseOpaquePayload(payload)
				if err != nil {
					continue
				}
				if srcAddr != nil {
					allowed, _, currentPeer := s.allowSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped opaque packet session=%s reason=source-mismatch src=%s peer=%s", sessionID, srcAddr.String(), currentPeer)
						s.recordSourceMismatchDrop(uint64(len(raw)))
						continue
					}
				}
				claims, err := s.authorizeNonce(sessionID, nonce, time.Now())
				if err != nil {
					log.Printf("exit dropped opaque packet session=%s reason=%v", sessionID, err)
					s.recordDrop(uint64(len(raw)), 0)
					continue
				}
				if srcAddr != nil {
					allowed, rebound, previousPeer := s.bindSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped opaque packet session=%s reason=peer-bind-failed src=%s", sessionID, srcAddr.String())
						s.recordDrop(uint64(len(raw)), claims.Tier)
						continue
					}
					if rebound {
						log.Printf("exit peer source rebind session=%s old=%s new=%s", sessionID, previousPeer, srcAddr.String())
					}
				}
				if s.liveWGMode && !relay.LooksLikePlausibleWireGuardMessage(raw) {
					log.Printf("exit dropped opaque packet session=%s reason=non-wireguard-live payload_len=%d", sessionID, len(raw))
					s.recordNonWGLiveDrop(uint64(len(raw)), claims.Tier)
					continue
				}
				if relay.LooksLikeWireGuardMessage(raw) {
					log.Printf("exit accepted opaque packet session=%s payload_len=%d wg_like=true", sessionID, len(raw))
				} else {
					log.Printf("exit accepted opaque packet session=%s payload_len=%d wg_like=false", sessionID, len(raw))
				}
				forwardedToWG := false
				if s.wgKernelProxy {
					if err := s.forwardOpaqueToWGKernel(sessionID, raw); err != nil {
						log.Printf("exit dropped opaque packet session=%s reason=wg-kernel-proxy-failed err=%v", sessionID, err)
						s.recordDrop(uint64(len(raw)), claims.Tier)
						continue
					}
					forwardedToWG = true
				}
				if s.opaqueEcho && srcAddr != nil && !forwardedToWG {
					echoFrame := relay.BuildDatagram(sessionID, payload)
					_, _ = conn.WriteToUDP(echoFrame, srcAddr)
				}
				if s.opaqueSinkUDP != nil {
					_, _ = conn.WriteToUDP(raw, s.opaqueSinkUDP)
				}
				s.recordAccept(uint64(len(raw)), claims.Tier)
			default:
				var inner proto.InnerPacket
				if err := json.Unmarshal(payload, &inner); err != nil {
					continue
				}
				if srcAddr != nil {
					allowed, _, currentPeer := s.allowSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped packet session=%s reason=source-mismatch src=%s peer=%s", sessionID, srcAddr.String(), currentPeer)
						s.recordSourceMismatchDrop(uint64(len(inner.Payload)))
						continue
					}
				}
				claims, err := s.authorizePacket(sessionID, inner, time.Now())
				if err != nil {
					log.Printf("exit dropped packet session=%s reason=%v dest_port=%d", sessionID, err, inner.DestinationPort)
					s.recordDrop(uint64(len(inner.Payload)), 0)
					continue
				}
				if srcAddr != nil {
					allowed, rebound, previousPeer := s.bindSessionPeer(sessionID, srcAddr.String(), time.Now())
					if !allowed {
						log.Printf("exit dropped packet session=%s reason=peer-bind-failed src=%s", sessionID, srcAddr.String())
						s.recordDrop(uint64(len(inner.Payload)), claims.Tier)
						continue
					}
					if rebound {
						log.Printf("exit peer source rebind session=%s old=%s new=%s", sessionID, previousPeer, srcAddr.String())
					}
				}
				log.Printf("exit accepted packet session=%s dest_port=%d payload_len=%d", sessionID, inner.DestinationPort, len(inner.Payload))
				s.recordAccept(uint64(len(inner.Payload)), claims.Tier)
			}
		}
	}()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return nil
}

func (s *Service) startOpaqueSource(ctx context.Context, errCh chan<- error) error {
	sourceAddr := strings.TrimSpace(s.opaqueSourceAddr)
	if sourceAddr == "" {
		return nil
	}
	if s.udpConn == nil {
		return errors.New("opaque source requires exit udp listener")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", sourceAddr)
	if err != nil {
		return fmt.Errorf("invalid EXIT_OPAQUE_SOURCE_ADDR: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	s.opaqueSourceConn = conn
	log.Printf("exit opaque source enabled addr=%s", sourceAddr)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, _, readErr := conn.ReadFromUDP(buf)
			if readErr != nil {
				errCh <- readErr
				return
			}
			if n <= 0 {
				continue
			}
			now := time.Now()
			sessionID, payload, ok := s.parseOpaqueDownlinkPacket(buf[:n], now)
			if !ok {
				s.recordDownlinkDrop()
				continue
			}
			targetAddr, nonce, ok := s.resolveDownlinkTarget(sessionID, now)
			if !ok {
				s.recordDownlinkDrop()
				continue
			}
			targetUDP, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				s.recordDownlinkDrop()
				continue
			}
			frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(nonce, payload))
			if _, err := s.udpConn.WriteToUDP(frame, targetUDP); err != nil {
				s.recordDownlinkDrop()
				continue
			}
			s.recordDownlinkForward(uint64(len(payload)))
		}
	}()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return nil
}

func (s *Service) parseOpaqueDownlinkPacket(frame []byte, now time.Time) (string, []byte, bool) {
	if sessionID, payload, err := relay.ParseDatagram(frame); err == nil && strings.TrimSpace(sessionID) != "" {
		if s.liveWGMode && !relay.LooksLikePlausibleWireGuardMessage(payload) {
			return "", nil, false
		}
		return sessionID, append([]byte(nil), payload...), true
	}
	if s.liveWGMode {
		return "", nil, false
	}
	sessionID := s.singleActiveSession(now.Unix())
	if sessionID == "" {
		return "", nil, false
	}
	return sessionID, append([]byte(nil), frame...), true
}

func (s *Service) singleActiveSession(nowUnix int64) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidate := ""
	for sid, session := range s.sessions {
		if nowUnix >= session.claims.ExpiryUnix {
			continue
		}
		if strings.TrimSpace(session.peerAddr) == "" {
			continue
		}
		if candidate != "" {
			return ""
		}
		candidate = sid
	}
	return candidate
}

func (s *Service) resolveDownlinkTarget(sessionID string, now time.Time) (string, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return "", 0, false
	}
	if now.Unix() >= session.claims.ExpiryUnix {
		staleProxy := s.wgSessionProxies[sessionID]
		delete(s.wgSessionProxies, sessionID)
		delete(s.sessions, sessionID)
		s.metrics.ActiveSessions = uint64(len(s.sessions))
		if staleProxy != nil {
			_ = staleProxy.Close()
		}
		return "", 0, false
	}
	target := strings.TrimSpace(session.peerAddr)
	if target == "" {
		return "", 0, false
	}
	session.downNonce++
	if session.downNonce == 0 {
		session.downNonce = 1
	}
	session.lastActivity = now
	s.sessions[sessionID] = session
	return target, session.downNonce, true
}

func (s *Service) forwardOpaqueToWGKernel(sessionID string, payload []byte) error {
	if !s.wgKernelProxy {
		return nil
	}
	proxyConn, err := s.ensureWGSessionProxy(sessionID)
	if err != nil {
		return err
	}
	target := s.wgKernelTargetUDP
	if target == nil {
		target, err = net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", s.wgListenPort))
		if err != nil {
			return err
		}
		s.wgKernelTargetUDP = target
	}
	_, err = proxyConn.WriteToUDP(payload, target)
	return err
}

func (s *Service) ensureWGSessionProxy(sessionID string) (*net.UDPConn, error) {
	s.mu.RLock()
	existing := s.wgSessionProxies[sessionID]
	s.mu.RUnlock()
	if existing != nil {
		return existing, nil
	}

	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if existing := s.wgSessionProxies[sessionID]; existing != nil {
		s.mu.Unlock()
		_ = proxyConn.Close()
		return existing, nil
	}
	if s.wgSessionProxies == nil {
		s.wgSessionProxies = make(map[string]*net.UDPConn)
	}
	s.wgSessionProxies[sessionID] = proxyConn
	s.mu.Unlock()

	go s.runWGSessionProxy(sessionID, proxyConn)
	return proxyConn, nil
}

func (s *Service) runWGSessionProxy(sessionID string, proxyConn *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, _, err := proxyConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n <= 0 {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		if s.liveWGMode && !relay.LooksLikePlausibleWireGuardMessage(payload) {
			s.recordDownlinkDrop()
			continue
		}
		targetAddr, nonce, ok := s.resolveDownlinkTarget(sessionID, time.Now())
		if !ok {
			s.recordDownlinkDrop()
			continue
		}
		targetUDP, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			s.recordDownlinkDrop()
			continue
		}
		frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(nonce, payload))
		if s.udpConn == nil {
			s.recordDownlinkDrop()
			continue
		}
		if _, err := s.udpConn.WriteToUDP(frame, targetUDP); err != nil {
			s.recordDownlinkDrop()
			continue
		}
		s.recordDownlinkForward(uint64(len(payload)))
	}
}

func (s *Service) closeWGSessionProxy(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	proxyConn := s.wgSessionProxies[sessionID]
	delete(s.wgSessionProxies, sessionID)
	s.mu.Unlock()
	if proxyConn != nil {
		_ = proxyConn.Close()
	}
}

func (s *Service) closeAllWGKernelSessionProxies() {
	s.mu.Lock()
	proxies := make([]*net.UDPConn, 0, len(s.wgSessionProxies))
	for sessionID, proxyConn := range s.wgSessionProxies {
		delete(s.wgSessionProxies, sessionID)
		if proxyConn != nil {
			proxies = append(proxies, proxyConn)
		}
	}
	s.mu.Unlock()
	for _, proxyConn := range proxies {
		_ = proxyConn.Close()
	}
}

func (s *Service) allowSessionPeer(sessionID string, peerAddr string, now time.Time) (bool, bool, string) {
	peerAddr = strings.TrimSpace(peerAddr)
	if sessionID == "" || peerAddr == "" {
		return false, false, ""
	}
	nowUnix := now.Unix()
	rebindAfterSec := int64(s.peerRebindAfter / time.Second)
	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		return false, false, ""
	}
	if nowUnix >= session.claims.ExpiryUnix {
		return false, false, strings.TrimSpace(session.peerAddr)
	}
	return peerSessionDecision(session, peerAddr, nowUnix, rebindAfterSec)
}

func (s *Service) bindSessionPeer(sessionID string, peerAddr string, now time.Time) (bool, bool, string) {
	peerAddr = strings.TrimSpace(peerAddr)
	if sessionID == "" || peerAddr == "" {
		return false, false, ""
	}
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	if !ok {
		s.mu.Unlock()
		return false, false, ""
	}
	nowUnix := now.Unix()
	if nowUnix >= session.claims.ExpiryUnix {
		delete(s.sessions, sessionID)
		s.metrics.ActiveSessions = uint64(len(s.sessions))
		s.mu.Unlock()
		return false, false, strings.TrimSpace(session.peerAddr)
	}
	allowed, rebound, previousPeer := peerSessionDecision(session, peerAddr, nowUnix, int64(s.peerRebindAfter/time.Second))
	if !allowed {
		s.mu.Unlock()
		return false, false, previousPeer
	}
	session.peerAddr = peerAddr
	session.peerLastSeen = nowUnix
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return true, rebound, previousPeer
}

func peerSessionDecision(session sessionInfo, peerAddr string, nowUnix int64, rebindAfterSec int64) (bool, bool, string) {
	peerAddr = strings.TrimSpace(peerAddr)
	currentPeer := strings.TrimSpace(session.peerAddr)
	if peerAddr == "" {
		return false, false, currentPeer
	}
	if currentPeer == "" {
		return true, false, ""
	}
	if sameUDPAddr(peerAddr, currentPeer) {
		return true, false, currentPeer
	}
	if rebindAfterSec > 0 {
		lastSeen := session.peerLastSeen
		if lastSeen <= 0 && !session.lastActivity.IsZero() {
			lastSeen = session.lastActivity.Unix()
		}
		if lastSeen <= 0 || nowUnix-lastSeen >= rebindAfterSec {
			return true, true, currentPeer
		}
	}
	return false, false, currentPeer
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

func udpPortOf(addr string) (int, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", strings.TrimSpace(addr))
	if err != nil {
		return 0, err
	}
	if udpAddr.Port <= 0 || udpAddr.Port > 65535 {
		return 0, fmt.Errorf("invalid udp port")
	}
	return udpAddr.Port, nil
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
	if req.Transport == "" {
		req.Transport = "policy-json"
	}

	claims, issuerKeyID, err := s.verifyToken(req.Token)
	if err != nil {
		log.Printf("exit token verify failed: %v", err)
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token verification failed"})
		return
	}
	nowUnix := time.Now().Unix()
	if err := validatePathOpenClaims(claims, nowUnix); err != nil {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: err.Error()})
		return
	}
	if s.isRevoked(issuerKeyID, claims.TokenID, nowUnix) {
		s.recordRevokedTokenDrop()
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token revoked"})
		return
	}
	if !s.acceptsTokenKeyEpoch(claims, issuerKeyID) {
		s.recordKeyEpochTokenDrop()
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "token key epoch expired"})
		return
	}
	if err := verifyPathOpenTokenProof(req, claims); err != nil {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: err.Error()})
		return
	}
	if err := s.checkAndRememberProofNonce(claims, req, nowUnix); err != nil {
		if err.Error() == "token proof replay" {
			s.recordTokenProofReplayDrop()
		}
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: err.Error()})
		return
	}

	if len(claims.ExitScope) > 0 {
		allowed := false
		for _, id := range claims.ExitScope {
			if id == req.ExitID {
				allowed = true
				break
			}
		}
		if !allowed {
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "exit scope denied"})
			return
		}
	}
	if req.SessionID == "" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "missing session_id"})
		return
	}
	if s.dataMode == "opaque" && req.Transport != "wireguard-udp" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "transport must be wireguard-udp in opaque mode"})
		return
	}
	if s.dataMode == "json" && req.Transport != "policy-json" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "transport must be policy-json in json mode"})
		return
	}
	if req.Transport == "wireguard-udp" && req.ClientInnerPub == "" {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "missing client_inner_pub"})
		return
	}
	if req.Transport == "wireguard-udp" && !wg.IsValidPublicKey(req.ClientInnerPub) {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "invalid client_inner_pub"})
		return
	}
	sessionKeyID, err := randomIDHex(8)
	if err != nil {
		_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "failed to create session key"})
		return
	}
	clientIP := s.allocateClientInnerIP()

	s.mu.Lock()
	staleProxy := s.wgSessionProxies[req.SessionID]
	delete(s.wgSessionProxies, req.SessionID)
	s.sessions[req.SessionID] = sessionInfo{
		claims:        claims,
		seenNonces:    make(map[uint64]struct{}),
		lastActivity:  time.Now(),
		transport:     req.Transport,
		sessionKeyID:  sessionKeyID,
		clientInnerIP: clientIP,
		clientPubKey:  req.ClientInnerPub,
	}
	s.metrics.ActiveSessions = uint64(len(s.sessions))
	s.mu.Unlock()
	if staleProxy != nil {
		_ = staleProxy.Close()
	}

	if req.Transport == "wireguard-udp" {
		wgCfg := wg.SessionConfig{
			SessionID:      req.SessionID,
			SessionKeyID:   sessionKeyID,
			Interface:      s.wgInterface,
			ExitPrivateKey: s.wgPrivateKey,
			ClientPubKey:   req.ClientInnerPub,
			ClientInnerIP:  clientIP,
			ExitInnerIP:    s.wgExitIP,
			ListenPort:     s.wgListenPort,
			MTU:            s.wgMTU,
			KeepaliveSec:   s.wgKeepaliveSec,
		}
		if err := s.wgManager.ConfigureSession(r.Context(), wgCfg); err != nil {
			s.closeWGSessionProxy(req.SessionID)
			s.mu.Lock()
			delete(s.sessions, req.SessionID)
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(proto.PathOpenResponse{Accepted: false, Reason: "wg configure failed"})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := proto.PathOpenResponse{
		Accepted:   true,
		SessionExp: claims.ExpiryUnix,
		Transport:  req.Transport,
	}
	if req.Transport == "wireguard-udp" {
		resp.ExitInnerPub = s.wgPubKey
		resp.ClientInnerIP = clientIP
		resp.ExitInnerIP = s.wgExitIP
		resp.InnerMTU = s.wgMTU
		resp.KeepaliveSec = s.wgKeepaliveSec
		resp.SessionKeyID = sessionKeyID
	}
	_ = json.NewEncoder(w).Encode(resp)
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
	session, exists := s.sessions[req.SessionID]
	staleProxy := s.wgSessionProxies[req.SessionID]
	delete(s.wgSessionProxies, req.SessionID)
	if exists {
		delete(s.sessions, req.SessionID)
		s.metrics.ActiveSessions = uint64(len(s.sessions))
	}
	s.mu.Unlock()
	if staleProxy != nil {
		_ = staleProxy.Close()
	}
	w.Header().Set("Content-Type", "application/json")
	if !exists {
		_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "unknown-session"})
		return
	}
	if session.transport == "wireguard-udp" {
		wgCfg := wg.SessionConfig{
			SessionID:     req.SessionID,
			SessionKeyID:  session.sessionKeyID,
			Interface:     s.wgInterface,
			ClientPubKey:  session.clientPubKey,
			ClientInnerIP: session.clientInnerIP,
		}
		if err := s.wgManager.RemoveSession(r.Context(), wgCfg); err != nil {
			_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: false, Reason: "wg remove failed"})
			return
		}
	}
	log.Printf("exit closed session=%s", req.SessionID)
	_ = json.NewEncoder(w).Encode(proto.PathCloseResponse{Closed: true})
}

func (s *Service) authorizePacket(sessionID string, inner proto.InnerPacket, now time.Time) (crypto.CapabilityClaims, error) {
	claims, err := s.authorizeNonce(sessionID, inner.Nonce, now)
	if err != nil {
		return crypto.CapabilityClaims{}, err
	}
	if err := s.enforcer.Allow(claims, policy.FlowContext{DestinationPort: inner.DestinationPort, Now: now}); err != nil {
		return crypto.CapabilityClaims{}, errors.New("policy-denied")
	}
	return claims, nil
}

func validatePathOpenClaims(claims crypto.CapabilityClaims, nowUnix int64) error {
	if strings.TrimSpace(claims.Audience) != "exit" {
		return errors.New("token audience invalid")
	}
	if strings.TrimSpace(claims.TokenType) != crypto.TokenTypeClientAccess {
		return errors.New("token type invalid")
	}
	if strings.TrimSpace(claims.CNFEd25519) == "" {
		return errors.New("token proof key missing")
	}
	if _, err := crypto.ParseEd25519PublicKey(claims.CNFEd25519); err != nil {
		return errors.New("token proof key invalid")
	}
	if claims.Tier < 1 || claims.Tier > 3 {
		return errors.New("token tier invalid")
	}
	if strings.TrimSpace(claims.TokenID) == "" {
		return errors.New("token id missing")
	}
	if claims.ExpiryUnix <= 0 || nowUnix >= claims.ExpiryUnix {
		return errors.New("token expired")
	}
	if claims.Tier > 1 && strings.TrimSpace(claims.Subject) == "" {
		return errors.New("token subject required for tier>1")
	}
	return nil
}

func verifyPathOpenTokenProof(req proto.PathOpenRequest, claims crypto.CapabilityClaims) error {
	pub, err := crypto.ParseEd25519PublicKey(claims.CNFEd25519)
	if err != nil {
		return errors.New("token proof key invalid")
	}
	input := crypto.PathOpenProofInput{
		Token:           req.Token,
		ExitID:          req.ExitID,
		TokenProofNonce: req.TokenProofNonce,
		ClientInnerPub:  req.ClientInnerPub,
		Transport:       req.Transport,
		RequestedMTU:    req.RequestedMTU,
		RequestedRegion: req.RequestedRegion,
	}
	if err := crypto.VerifyPathOpenProof(req.TokenProof, pub, input); err != nil {
		return errors.New("token proof invalid")
	}
	return nil
}

func (s *Service) checkAndRememberProofNonce(claims crypto.CapabilityClaims, req proto.PathOpenRequest, nowUnix int64) error {
	if !s.tokenProofReplayGuard {
		return nil
	}
	tokenID := strings.TrimSpace(claims.TokenID)
	if tokenID == "" {
		return errors.New("token id missing")
	}
	nonce := strings.TrimSpace(req.TokenProofNonce)
	if nonce == "" {
		return errors.New("token proof nonce required")
	}
	if len(nonce) > 256 {
		return errors.New("token proof nonce invalid")
	}
	exp := claims.ExpiryUnix
	if exp <= nowUnix {
		exp = nowUnix + 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proofNonceSeen == nil {
		s.proofNonceSeen = make(map[string]map[string]int64)
	}
	seen := s.proofNonceSeen[tokenID]
	if seen == nil {
		seen = make(map[string]int64)
		s.proofNonceSeen[tokenID] = seen
	}
	for k, until := range seen {
		if nowUnix >= until {
			delete(seen, k)
		}
	}
	if _, exists := seen[nonce]; exists {
		return errors.New("token proof replay")
	}
	seen[nonce] = exp
	return nil
}

func (s *Service) authorizeNonce(sessionID string, nonce uint64, now time.Time) (crypto.CapabilityClaims, error) {
	s.mu.Lock()
	session, exists := s.sessions[sessionID]
	if !exists {
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("unknown-session")
	}
	if now.Unix() >= session.claims.ExpiryUnix {
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("session-expired")
	}
	if nonce == 0 {
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("missing-nonce")
	}
	if _, seen := session.seenNonces[nonce]; seen {
		s.mu.Unlock()
		return crypto.CapabilityClaims{}, errors.New("replay-detected")
	}
	if len(session.seenNonces) >= 8192 {
		session.seenNonces = make(map[uint64]struct{}, 1024)
	}
	session.seenNonces[nonce] = struct{}{}
	session.lastActivity = now
	claims := session.claims
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return claims, nil
}

func (s *Service) cleanupExpiredSessions(now time.Time) {
	s.mu.Lock()
	var staleProxies []*net.UDPConn
	nowUnix := now.Unix()
	for sid, session := range s.sessions {
		if nowUnix >= session.claims.ExpiryUnix {
			delete(s.sessions, sid)
			if proxyConn := s.wgSessionProxies[sid]; proxyConn != nil {
				staleProxies = append(staleProxies, proxyConn)
			}
			delete(s.wgSessionProxies, sid)
		}
	}
	for tokenID, seen := range s.proofNonceSeen {
		active := false
		for nonce, until := range seen {
			if nowUnix >= until {
				delete(seen, nonce)
				continue
			}
			active = true
		}
		if !active {
			delete(s.proofNonceSeen, tokenID)
		}
	}
	s.metrics.ActiveSessions = uint64(len(s.sessions))
	s.mu.Unlock()
	for _, proxyConn := range staleProxies {
		_ = proxyConn.Close()
	}
}

func (s *Service) verifyToken(token string) (crypto.CapabilityClaims, string, error) {
	snapshotKeys := func() (map[string]ed25519.PublicKey, map[string]string) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		keys := make(map[string]ed25519.PublicKey, len(s.issuerPubs))
		for id, pub := range s.issuerPubs {
			keys[id] = pub
		}
		issuers := make(map[string]string, len(s.issuerKeyIssuer))
		for keyID, issuerID := range s.issuerKeyIssuer {
			issuerID = strings.TrimSpace(issuerID)
			if issuerID == "" {
				continue
			}
			issuers[keyID] = issuerID
		}
		if len(keys) == 0 && len(s.issuerPub) > 0 {
			id := issuerKeyID(s.issuerPub)
			keys[id] = s.issuerPub
		}
		return keys, issuers
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		keys, keyIssuers := snapshotKeys()
		if len(keys) == 0 {
			if err := s.refreshIssuerKeys(context.Background()); err != nil {
				lastErr = errors.New("issuer pubkey unavailable")
				continue
			}
			keys, keyIssuers = snapshotKeys()
		}
		for keyID, pub := range keys {
			claims, err := crypto.VerifyClaims(token, pub)
			if err == nil {
				if expectedIssuer := strings.TrimSpace(keyIssuers[keyID]); expectedIssuer != "" {
					if strings.TrimSpace(claims.Issuer) != expectedIssuer {
						lastErr = errors.New("token issuer mismatch")
						continue
					}
				}
				return claims, keyID, nil
			}
			lastErr = err
		}
		if attempt == 0 {
			if err := s.refreshIssuerKeys(context.Background()); err != nil {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no issuer keys available")
	}
	return crypto.CapabilityClaims{}, "", lastErr
}

func (s *Service) refreshIssuerKeys(ctx context.Context) error {
	if len(s.issuerURLs) == 0 {
		if s.issuerURL == "" {
			return errors.New("missing issuer url")
		}
		s.issuerURLs = []string{normalizeHTTPURL(s.issuerURL)}
	}
	updated := make(map[string]ed25519.PublicKey)
	updatedIssuers := make(map[string]string)
	updatedMinEpoch := make(map[string]int64)
	var lastErr error
	for _, issuerURL := range s.issuerURLs {
		bundle, err := s.fetchIssuerPubKeysFrom(ctx, issuerURL)
		if err != nil {
			lastErr = err
			continue
		}
		for _, pub := range bundle.pubs {
			keyID := issuerKeyID(pub)
			updated[keyID] = pub
			if issuerID := strings.TrimSpace(bundle.issuerID); issuerID != "" {
				updatedIssuers[keyID] = issuerID
			}
		}
		if bundle.issuerID != "" && bundle.minTokenEpoch > 0 {
			if bundle.minTokenEpoch > updatedMinEpoch[bundle.issuerID] {
				updatedMinEpoch[bundle.issuerID] = bundle.minTokenEpoch
			}
		}
	}
	if len(updated) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no issuer keys fetched")
		}
		return lastErr
	}
	s.mu.Lock()
	s.issuerPubs = updated
	s.issuerKeyIssuer = updatedIssuers
	if s.minTokenEpoch == nil {
		s.minTokenEpoch = make(map[string]int64)
	}
	for issuerID, minEpoch := range updatedMinEpoch {
		if minEpoch > s.minTokenEpoch[issuerID] {
			s.minTokenEpoch[issuerID] = minEpoch
		}
	}
	for _, pub := range updated {
		s.issuerPub = pub
		break
	}
	s.mu.Unlock()
	return nil
}

type issuerKeyBundle struct {
	pubs          []ed25519.PublicKey
	issuerID      string
	minTokenEpoch int64
}

func (s *Service) fetchIssuerPubKeysFrom(ctx context.Context, issuerURL string) (issuerKeyBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(issuerURL, "/v1/pubkeys"), nil)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return s.fetchIssuerPubKeyLegacy(ctx, issuerURL)
	}
	if resp.StatusCode != http.StatusOK {
		return issuerKeyBundle{}, errors.New("issuer key endpoint returned non-200")
	}
	var out proto.IssuerPubKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return issuerKeyBundle{}, err
	}
	pubs := make([]ed25519.PublicKey, 0, len(out.PubKeys))
	for _, pubB64 := range out.PubKeys {
		pubB64 = strings.TrimSpace(pubB64)
		raw, err := base64.RawURLEncoding.DecodeString(pubB64)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return issuerKeyBundle{}, fmt.Errorf("invalid issuer pubkey entry")
		}
		pubs = append(pubs, ed25519.PublicKey(raw))
	}
	if len(pubs) == 0 {
		return issuerKeyBundle{}, errors.New("issuer pubkeys endpoint returned empty list")
	}
	return issuerKeyBundle{
		pubs:          pubs,
		issuerID:      strings.TrimSpace(out.Issuer),
		minTokenEpoch: out.MinTokenEpoch,
	}, nil
}

func (s *Service) fetchIssuerPubKeyLegacy(ctx context.Context, issuerURL string) (issuerKeyBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(issuerURL, "/v1/pubkey"), nil)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return issuerKeyBundle{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return issuerKeyBundle{}, errors.New("issuer key endpoint returned non-200")
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return issuerKeyBundle{}, err
	}
	pubB64 := strings.TrimSpace(out["pub_key"])
	pub, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return issuerKeyBundle{}, errors.New("invalid issuer pubkey")
	}
	return issuerKeyBundle{pubs: []ed25519.PublicKey{ed25519.PublicKey(pub)}}, nil
}

func randomIDHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func (s *Service) allocateClientInnerIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ipAllocCursor >= 250 {
		s.ipAllocCursor = 2
	}
	ip := fmt.Sprintf("10.90.0.%d/32", s.ipAllocCursor)
	s.ipAllocCursor++
	return ip
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Service) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	s.mu.RLock()
	m := s.metrics
	s.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(m)
}

func (s *Service) recordAccept(bytes uint64, tier int) {
	s.mu.Lock()
	s.metrics.AcceptedPackets++
	s.metrics.AcceptedBytes += bytes
	switch tier {
	case 1:
		s.metrics.AcceptedTier1Packets++
	case 2:
		s.metrics.AcceptedTier2Packets++
	case 3:
		s.metrics.AcceptedTier3Packets++
	}
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordDrop(bytes uint64, tier int) {
	s.mu.Lock()
	s.metrics.DroppedPackets++
	s.metrics.DroppedBytes += bytes
	switch tier {
	case 1:
		s.metrics.DroppedTier1Packets++
	case 2:
		s.metrics.DroppedTier2Packets++
	case 3:
		s.metrics.DroppedTier3Packets++
	}
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordRevokedTokenDrop() {
	s.mu.Lock()
	s.metrics.DroppedTokenRevoked++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordKeyEpochTokenDrop() {
	s.mu.Lock()
	s.metrics.DroppedTokenKeyEpoch++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordTokenProofReplayDrop() {
	s.mu.Lock()
	s.metrics.DroppedTokenProofReplay++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordSourceMismatchDrop(bytes uint64) {
	s.mu.Lock()
	s.metrics.DroppedSourceMismatch++
	s.metrics.DroppedPackets++
	s.metrics.DroppedBytes += bytes
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordNonWGLiveDrop(bytes uint64, tier int) {
	s.mu.Lock()
	s.metrics.DroppedNonWGLive++
	s.metrics.DroppedPackets++
	s.metrics.DroppedBytes += bytes
	switch tier {
	case 1:
		s.metrics.DroppedTier1Packets++
	case 2:
		s.metrics.DroppedTier2Packets++
	case 3:
		s.metrics.DroppedTier3Packets++
	}
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordDownlinkForward(bytes uint64) {
	s.mu.Lock()
	s.metrics.ForwardedDownlinkPkts++
	s.metrics.ForwardedDownlinkBytes += bytes
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) recordDownlinkDrop() {
	s.mu.Lock()
	s.metrics.DroppedDownlinkPkts++
	s.metrics.AccountingUpdatedUnix = time.Now().Unix()
	s.mu.Unlock()
}

func (s *Service) configureEgress(ctx context.Context) error {
	if s.egressBackend != "command" {
		return nil
	}
	for _, cmdStr := range buildEgressSetupCommands(s.egressChain, s.egressCIDR, s.egressIface) {
		if err := runShell(ctx, cmdStr); err != nil {
			return fmt.Errorf("egress setup failed cmd=%q: %w", cmdStr, err)
		}
	}
	s.egressConfigured = true
	return nil
}

func (s *Service) teardownEgress(ctx context.Context) error {
	if s.egressBackend != "command" || !s.egressConfigured {
		return nil
	}
	var firstErr error
	for _, cmdStr := range buildEgressCleanupCommands(s.egressChain, s.egressCIDR, s.egressIface) {
		if err := runShell(ctx, cmdStr); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("egress cleanup failed cmd=%q: %w", cmdStr, err)
		}
	}
	s.egressConfigured = false
	return firstErr
}

func buildEgressSetupCommands(chain string, cidr string, iface string) []string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		chain = "PRIVNODE_EGRESS"
	}
	return []string{
		"sysctl -w net.ipv4.ip_forward=1 >/dev/null",
		fmt.Sprintf("iptables -t nat -N %s 2>/dev/null || true", chain),
		fmt.Sprintf("iptables -t nat -F %s", chain),
		fmt.Sprintf("iptables -t nat -A %s -s %s -o %s -j MASQUERADE", chain, cidr, iface),
		fmt.Sprintf("iptables -t nat -C POSTROUTING -j %s 2>/dev/null || iptables -t nat -A POSTROUTING -j %s", chain, chain),
		fmt.Sprintf("iptables -C FORWARD -s %s -o %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -s %s -o %s -j ACCEPT", cidr, iface, cidr, iface),
		fmt.Sprintf("iptables -C FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -i %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -i %s -j ACCEPT", cidr, iface, cidr, iface),
	}
}

func buildEgressCleanupCommands(chain string, cidr string, iface string) []string {
	chain = strings.TrimSpace(chain)
	if chain == "" {
		chain = "PRIVNODE_EGRESS"
	}
	return []string{
		fmt.Sprintf("iptables -D FORWARD -s %s -o %s -j ACCEPT 2>/dev/null || true", cidr, iface),
		fmt.Sprintf("iptables -D FORWARD -d %s -m conntrack --ctstate ESTABLISHED,RELATED -i %s -j ACCEPT 2>/dev/null || true", cidr, iface),
		fmt.Sprintf("iptables -t nat -D POSTROUTING -j %s 2>/dev/null || true", chain),
		fmt.Sprintf("iptables -t nat -F %s 2>/dev/null || true", chain),
		fmt.Sprintf("iptables -t nat -X %s 2>/dev/null || true", chain),
	}
}

func runShell(ctx context.Context, cmdStr string) error {
	cmd := exec.CommandContext(ctx, "sh", "-lc", cmdStr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *Service) flushAccountingSnapshot(now time.Time) error {
	if strings.TrimSpace(s.accountingFile) == "" {
		return nil
	}
	s.mu.RLock()
	metrics := s.metrics
	metrics.ActiveSessions = uint64(len(s.sessions))
	s.mu.RUnlock()
	snapshot := map[string]interface{}{
		"generated_at": now.Unix(),
		"metrics":      metrics,
	}
	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.accountingFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := s.accountingFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.accountingFile)
}

func tickerC(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func (s *Service) refreshRevocations(ctx context.Context) error {
	// Keep issuer keys fresh before validating signed revocation feeds.
	// This prevents false signature failures during issuer key rollover.
	_ = s.refreshIssuerKeys(ctx)

	urls := s.revocationsURLs
	if len(urls) == 0 && s.revocationsURL != "" {
		urls = []string{s.revocationsURL}
	}
	if len(urls) == 0 {
		return errors.New("missing revocation urls")
	}
	now := time.Now().Unix()
	success := 0
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("revocations endpoint returned %d", resp.StatusCode)
			continue
		}
		var out proto.RevocationListResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			_ = resp.Body.Close()
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if err := s.applyRevocationFeed(out, now); err != nil {
			lastErr = err
			continue
		}
		success++
	}
	if success == 0 {
		if lastErr == nil {
			lastErr = errors.New("no revocation feed updated")
		}
		return lastErr
	}
	return nil
}

func (s *Service) applyRevocationFeed(feed proto.RevocationListResponse, now int64) error {
	keyID, err := s.verifyRevocationFeed(feed, now)
	if err != nil {
		return err
	}
	issuerID := strings.TrimSpace(feed.Issuer)
	if issuerID == "" {
		issuerID = keyID
	}

	s.mu.Lock()
	if s.revocationVersion == nil {
		s.revocationVersion = make(map[string]int64)
	}
	if s.minTokenEpoch == nil {
		s.minTokenEpoch = make(map[string]int64)
	}
	if s.revokedJTI == nil {
		s.revokedJTI = make(map[string]int64)
	}
	if feed.Version > 0 {
		if prev, ok := s.revocationVersion[issuerID]; ok && feed.Version < prev {
			s.mu.Unlock()
			return errors.New("revocation feed version rollback detected")
		}
		s.revocationVersion[issuerID] = feed.Version
	}
	requiredEpoch := feed.MinTokenEpoch
	if requiredEpoch <= 0 {
		requiredEpoch = feed.KeyEpoch
	}
	if requiredEpoch > 0 {
		if prev := s.minTokenEpoch[issuerID]; requiredEpoch > prev {
			s.minTokenEpoch[issuerID] = requiredEpoch
		}
	}
	for k := range s.revokedJTI {
		if strings.HasPrefix(k, keyID+"|") {
			delete(s.revokedJTI, k)
		}
	}
	for _, r := range feed.Revocations {
		if r.JTI == "" || now >= r.Until {
			continue
		}
		s.revokedJTI[keyID+"|"+r.JTI] = r.Until
	}
	s.mu.Unlock()
	return nil
}

func (s *Service) acceptsTokenKeyEpoch(claims crypto.CapabilityClaims, issuerKeyID string) bool {
	issuerID := strings.TrimSpace(claims.Issuer)
	s.mu.RLock()
	if mapped := strings.TrimSpace(s.issuerKeyIssuer[issuerKeyID]); mapped != "" {
		issuerID = mapped
	}
	minEpoch := s.minTokenEpoch[issuerID]
	s.mu.RUnlock()
	if issuerID == "" || minEpoch <= 0 {
		return true
	}
	return claims.KeyEpoch >= minEpoch
}

func (s *Service) verifyRevocationFeed(feed proto.RevocationListResponse, now int64) (string, error) {
	if feed.Signature == "" {
		return "*", nil
	}
	if feed.ExpiresAt > 0 && now >= feed.ExpiresAt {
		return "", errors.New("revocation feed expired")
	}
	if feed.GeneratedAt > 0 && feed.GeneratedAt > now+60 {
		return "", errors.New("revocation feed generated_at too far in future")
	}

	sigRaw, err := base64.RawURLEncoding.DecodeString(feed.Signature)
	if err != nil {
		return "", fmt.Errorf("invalid revocation signature encoding: %w", err)
	}
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", fmt.Errorf("marshal revocation feed: %w", err)
	}

	s.mu.RLock()
	keys := make(map[string]ed25519.PublicKey, len(s.issuerPubs))
	for id, pub := range s.issuerPubs {
		keys[id] = pub
	}
	if len(keys) == 0 && len(s.issuerPub) > 0 {
		id := issuerKeyID(s.issuerPub)
		keys[id] = s.issuerPub
	}
	s.mu.RUnlock()

	if len(keys) == 0 {
		return "", errors.New("issuer pubkey unavailable for revocation verification")
	}
	for keyID, pub := range keys {
		if ed25519.Verify(pub, payload, sigRaw) {
			return keyID, nil
		}
	}
	return "", errors.New("revocation feed signature invalid")
}

func (s *Service) isRevoked(issuerKeyID string, jti string, now int64) bool {
	if jti == "" {
		return false
	}
	s.mu.RLock()
	until, ok := s.revokedJTI[issuerKeyID+"|"+jti]
	if !ok {
		until, ok = s.revokedJTI["*|"+jti]
	}
	s.mu.RUnlock()
	return ok && now < until
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func normalizeHTTPURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return strings.TrimRight(v, "/")
	}
	return "http://" + strings.TrimRight(v, "/")
}

func normalizeHTTPURLs(urls []string) []string {
	if len(urls) == 0 {
		return nil
	}
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		norm := normalizeHTTPURL(u)
		if norm == "" {
			continue
		}
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	return out
}

func joinURL(base string, path string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}

func issuerKeyID(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}
