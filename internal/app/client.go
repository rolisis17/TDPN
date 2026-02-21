package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
	"privacynode/pkg/wg"
)

type Client struct {
	directoryURL          string
	directoryURLs         []string
	directoryMinSources   int
	directoryMinOperators int
	directoryMinVotes     int
	issuerURL             string
	subject               string
	entryURL              string
	exitControlURL        string
	dataMode              string
	clientWGPub           string
	trustStrict           bool
	trustTOFU             bool
	trustFile             string
	innerSource           string
	innerUDPAddr          string
	innerMaxPkts          int
	opaqueSinkAddr        string
	opaqueDrainMS         int
	wgBackend             string
	wgInterface           string
	wgPrivateKey          string
	wgManager             wg.ClientManager
	liveWGMode            bool
	healthCheckEnabled    bool
	healthCheckTimeout    time.Duration
	healthCacheTTL        time.Duration
	preferredExitCountry  string
	preferredExitRegion   string
	minGeoConfidence      float64
	localityFallbackOrder []string
	strictExitLocality    bool
	maxExitsPerOperator   int
	pathOpenMaxAttempts   int
	maxPairCandidates     int
	bootstrapInterval     time.Duration
	exitExplorationPct    int
	exitSelectionSeed     int64
	selectionFeedDisable  bool
	selectionFeedRequire  bool
	selectionFeedMinVotes int
	trustFeedDisable      bool
	trustFeedRequire      bool
	trustFeedMinVotes     int
	healthMu              sync.Mutex
	healthCache           map[string]healthProbeState
	httpClient            *http.Client
}

type healthProbeState struct {
	ok        bool
	checkedAt time.Time
}

type relayPair struct {
	entry proto.RelayDescriptor
	exit  proto.RelayDescriptor
}

func NewClient() *Client {
	directoryURL := os.Getenv("DIRECTORY_URL")
	if directoryURL == "" {
		directoryURL = "http://127.0.0.1:8081"
	}
	directoryURLs := []string{directoryURL}
	if raw := os.Getenv("DIRECTORY_URLS"); raw != "" {
		var parsed []string
		for _, v := range strings.Split(raw, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				parsed = append(parsed, v)
			}
		}
		if len(parsed) > 0 {
			directoryURLs = parsed
			directoryURL = parsed[0]
		}
	}
	directoryMinSources := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_MIN_SOURCES")); err == nil && v > 0 {
		directoryMinSources = v
	}
	directoryMinOperators := 1
	if v := strings.TrimSpace(os.Getenv("CLIENT_DIRECTORY_MIN_OPERATORS")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			directoryMinOperators = parsed
		}
	} else if v, err := strconv.Atoi(os.Getenv("DIRECTORY_MIN_OPERATORS")); err == nil && v > 0 {
		directoryMinOperators = v
	}
	directoryMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("DIRECTORY_MIN_RELAY_VOTES")); err == nil && v > 0 {
		directoryMinVotes = v
	}
	issuerURL := os.Getenv("ISSUER_URL")
	if issuerURL == "" {
		issuerURL = "http://127.0.0.1:8082"
	}
	subject := strings.TrimSpace(os.Getenv("CLIENT_SUBJECT"))
	entryURL := os.Getenv("ENTRY_URL")
	if entryURL == "" {
		entryURL = "http://127.0.0.1:8083"
	}
	exitControlURL := os.Getenv("EXIT_CONTROL_URL")
	if exitControlURL == "" {
		exitControlURL = "http://127.0.0.1:8084"
	}
	dataMode := os.Getenv("DATA_PLANE_MODE")
	if dataMode == "" {
		dataMode = "json"
	}
	clientWGPub := os.Getenv("CLIENT_WG_PUBLIC_KEY")
	if clientWGPub == "" {
		clientWGPub = randomWGPublicKeyLike()
	}
	trustStrict := os.Getenv("DIRECTORY_TRUST_STRICT") == "1"
	trustTOFU := os.Getenv("DIRECTORY_TRUST_TOFU") != "0"
	trustFile := os.Getenv("DIRECTORY_TRUSTED_KEYS_FILE")
	if trustFile == "" {
		trustFile = "data/trusted_directory_keys.txt"
	}
	innerSource := os.Getenv("CLIENT_INNER_SOURCE")
	if innerSource == "" {
		innerSource = "synthetic"
	}
	innerUDPAddr := os.Getenv("CLIENT_INNER_UDP_ADDR")
	if innerUDPAddr == "" {
		innerUDPAddr = "127.0.0.1:51900"
	}
	innerMaxPkts := 16
	opaqueSinkAddr := os.Getenv("CLIENT_OPAQUE_SINK_ADDR")
	opaqueDrainMS := 1200
	if v, err := strconv.Atoi(os.Getenv("CLIENT_OPAQUE_DRAIN_MS")); err == nil && v > 0 {
		opaqueDrainMS = v
	}
	wgBackend := os.Getenv("CLIENT_WG_BACKEND")
	if wgBackend == "" {
		wgBackend = "noop"
	}
	wgInterface := os.Getenv("CLIENT_WG_INTERFACE")
	if wgInterface == "" {
		wgInterface = "wg-client0"
	}
	wgPrivateKey := os.Getenv("CLIENT_WG_PRIVATE_KEY_PATH")
	liveWGMode := os.Getenv("CLIENT_LIVE_WG_MODE") == "1"
	healthCheckEnabled := os.Getenv("CLIENT_SELECTION_HEALTHCHECK") != "0"
	if os.Getenv("CLIENT_HEALTHCHECK_DISABLE") == "1" {
		healthCheckEnabled = false
	}
	healthTimeoutMS := 700
	if v, err := strconv.Atoi(os.Getenv("CLIENT_HEALTHCHECK_TIMEOUT_MS")); err == nil && v > 0 {
		healthTimeoutMS = v
	}
	healthCacheSec := 5
	if v, err := strconv.Atoi(os.Getenv("CLIENT_HEALTHCHECK_CACHE_SEC")); err == nil && v > 0 {
		healthCacheSec = v
	}
	preferredExitCountry := normalizeCountryCode(os.Getenv("CLIENT_EXIT_COUNTRY"))
	preferredExitRegion := normalizeRegion(os.Getenv("CLIENT_EXIT_REGION"))
	minGeoConfidence := 0.0
	if v := strings.TrimSpace(os.Getenv("CLIENT_EXIT_MIN_GEO_CONFIDENCE")); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil {
			minGeoConfidence = clampUnit(parsed)
		}
	}
	localityFallbackOrder := parseLocalityFallbackOrder(os.Getenv("CLIENT_EXIT_LOCALITY_FALLBACK_ORDER"))
	strictExitLocality := os.Getenv("CLIENT_EXIT_STRICT_LOCALITY") == "1"
	maxExitsPerOperator := 0
	if v, err := strconv.Atoi(os.Getenv("CLIENT_MAX_EXITS_PER_OPERATOR")); err == nil && v > 0 {
		maxExitsPerOperator = v
	}
	pathOpenMaxAttempts := 4
	if v, err := strconv.Atoi(os.Getenv("CLIENT_PATH_OPEN_MAX_ATTEMPTS")); err == nil && v > 0 {
		pathOpenMaxAttempts = v
	}
	maxPairCandidates := 12
	if v, err := strconv.Atoi(os.Getenv("CLIENT_MAX_PAIR_CANDIDATES")); err == nil && v > 0 {
		maxPairCandidates = v
	}
	exitExplorationPct := 10
	if v, err := strconv.Atoi(os.Getenv("CLIENT_EXIT_EXPLORATION_PCT")); err == nil {
		switch {
		case v < 0:
			exitExplorationPct = 0
		case v > 100:
			exitExplorationPct = 100
		default:
			exitExplorationPct = v
		}
	}
	var exitSelectionSeed int64
	if v := strings.TrimSpace(os.Getenv("CLIENT_EXIT_SELECTION_SEED")); v != "" {
		if parsed, err := strconv.ParseInt(v, 10, 64); err == nil {
			exitSelectionSeed = parsed
		}
	}
	selectionFeedDisable := os.Getenv("CLIENT_SELECTION_FEED_DISABLE") == "1"
	selectionFeedRequire := os.Getenv("CLIENT_SELECTION_FEED_REQUIRE") == "1"
	selectionFeedMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("CLIENT_SELECTION_FEED_MIN_VOTES")); err == nil && v > 0 {
		selectionFeedMinVotes = v
	}
	trustFeedDisable := os.Getenv("CLIENT_TRUST_FEED_DISABLE") == "1"
	trustFeedRequire := os.Getenv("CLIENT_TRUST_FEED_REQUIRE") == "1"
	trustFeedMinVotes := 1
	if v, err := strconv.Atoi(os.Getenv("CLIENT_TRUST_FEED_MIN_VOTES")); err == nil && v > 0 {
		trustFeedMinVotes = v
	}
	bootstrapIntervalSec := 5
	if v, err := strconv.Atoi(os.Getenv("CLIENT_BOOTSTRAP_INTERVAL_SEC")); err == nil && v > 0 {
		bootstrapIntervalSec = v
	}
	var wgManager wg.ClientManager
	switch wgBackend {
	case "command":
		wgManager = wg.NewCommandClientManager()
	default:
		wgBackend = "noop"
		wgManager = wg.NewNoopClientManager()
	}

	return &Client{
		directoryURL:          directoryURL,
		directoryURLs:         directoryURLs,
		directoryMinSources:   directoryMinSources,
		directoryMinOperators: directoryMinOperators,
		directoryMinVotes:     directoryMinVotes,
		issuerURL:             issuerURL,
		subject:               subject,
		entryURL:              entryURL,
		exitControlURL:        exitControlURL,
		dataMode:              dataMode,
		clientWGPub:           clientWGPub,
		trustStrict:           trustStrict,
		trustTOFU:             trustTOFU,
		trustFile:             trustFile,
		innerSource:           innerSource,
		innerUDPAddr:          innerUDPAddr,
		innerMaxPkts:          innerMaxPkts,
		opaqueSinkAddr:        opaqueSinkAddr,
		opaqueDrainMS:         opaqueDrainMS,
		wgBackend:             wgBackend,
		wgInterface:           wgInterface,
		wgPrivateKey:          wgPrivateKey,
		wgManager:             wgManager,
		liveWGMode:            liveWGMode,
		healthCheckEnabled:    healthCheckEnabled,
		healthCheckTimeout:    time.Duration(healthTimeoutMS) * time.Millisecond,
		healthCacheTTL:        time.Duration(healthCacheSec) * time.Second,
		preferredExitCountry:  preferredExitCountry,
		preferredExitRegion:   preferredExitRegion,
		minGeoConfidence:      minGeoConfidence,
		localityFallbackOrder: localityFallbackOrder,
		strictExitLocality:    strictExitLocality,
		maxExitsPerOperator:   maxExitsPerOperator,
		pathOpenMaxAttempts:   pathOpenMaxAttempts,
		maxPairCandidates:     maxPairCandidates,
		bootstrapInterval:     time.Duration(bootstrapIntervalSec) * time.Second,
		exitExplorationPct:    exitExplorationPct,
		exitSelectionSeed:     exitSelectionSeed,
		selectionFeedDisable:  selectionFeedDisable,
		selectionFeedRequire:  selectionFeedRequire,
		selectionFeedMinVotes: selectionFeedMinVotes,
		trustFeedDisable:      trustFeedDisable,
		trustFeedRequire:      trustFeedRequire,
		trustFeedMinVotes:     trustFeedMinVotes,
		healthCache:           make(map[string]healthProbeState),
		httpClient:            &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Client) Run(ctx context.Context) error {
	bootstrapInterval := c.bootstrapInterval
	if bootstrapInterval <= 0 {
		bootstrapInterval = 5 * time.Second
	}
	log.Printf("client role enabled: directories=%d min_sources=%d min_operators=%d min_votes=%d issuer=%s subject=%s entry=%s mode=%s source=%s trust_strict=%t wg_backend=%s iface=%s health_check=%t path_attempts=%d exit_country=%s exit_region=%s min_geo_confidence=%.2f locality_fallback=%s strict_locality=%t max_exits_per_operator=%d exit_exploration_pct=%d selection_feed_disable=%t selection_feed_require=%t selection_feed_min_votes=%d trust_feed_disable=%t trust_feed_require=%t trust_feed_min_votes=%d bootstrap_interval_sec=%d",
		len(c.directoryURLs), c.directoryMinSources, c.directoryMinOperators, c.directoryMinVotes, c.issuerURL, c.subject, c.entryURL, c.dataMode, c.innerSource, c.trustStrict, c.wgBackend, c.wgInterface, c.healthCheckEnabled, c.pathOpenMaxAttempts, c.preferredExitCountry, c.preferredExitRegion, c.minGeoConfidence, strings.Join(c.localityFallbackOrder, ","), c.strictExitLocality, c.maxExitsPerOperator, c.exitExplorationPct, c.selectionFeedDisable, c.selectionFeedRequire, c.selectionFeedMinVotes, c.trustFeedDisable, c.trustFeedRequire, c.trustFeedMinVotes, int(bootstrapInterval/time.Second))
	if err := c.validateRuntimeConfig(); err != nil {
		return err
	}
	if c.wgBackend == "command" {
		if err := wg.PreflightCommandClientBackend(ctx, c.wgInterface, c.wgPrivateKey); err != nil {
			return fmt.Errorf("client wg preflight failed: %w", err)
		}
	}
	if c.dataMode == "opaque" && !wg.IsValidPublicKey(c.clientWGPub) {
		log.Printf("client invalid CLIENT_WG_PUBLIC_KEY format; falling back to generated key")
		c.clientWGPub = randomWGPublicKeyLike()
	}

	if err := c.bootstrap(ctx); err != nil {
		log.Printf("client bootstrap failed: %v", err)
	}

	ticker := time.NewTicker(bootstrapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := c.bootstrap(ctx); err != nil {
				log.Printf("client bootstrap retry failed: %v", err)
			}
		}
	}
}

func (c *Client) validateRuntimeConfig() error {
	if c.wgBackend == "command" {
		if c.dataMode != "opaque" {
			return fmt.Errorf("CLIENT_WG_BACKEND=command requires DATA_PLANE_MODE=opaque")
		}
		if c.innerSource != "udp" {
			return fmt.Errorf("CLIENT_WG_BACKEND=command requires CLIENT_INNER_SOURCE=udp")
		}
		if c.wgPrivateKey == "" {
			return fmt.Errorf("CLIENT_WG_BACKEND=command requires CLIENT_WG_PRIVATE_KEY_PATH")
		}
	}
	if c.liveWGMode {
		if c.dataMode != "opaque" {
			return fmt.Errorf("CLIENT_LIVE_WG_MODE requires DATA_PLANE_MODE=opaque")
		}
		if c.innerSource != "udp" {
			return fmt.Errorf("CLIENT_LIVE_WG_MODE requires CLIENT_INNER_SOURCE=udp")
		}
		if c.wgBackend != "command" {
			return fmt.Errorf("CLIENT_LIVE_WG_MODE requires CLIENT_WG_BACKEND=command")
		}
		if c.wgPrivateKey == "" {
			return fmt.Errorf("CLIENT_LIVE_WG_MODE requires CLIENT_WG_PRIVATE_KEY_PATH")
		}
		if strings.TrimSpace(c.opaqueSinkAddr) == "" {
			return fmt.Errorf("CLIENT_LIVE_WG_MODE requires CLIENT_OPAQUE_SINK_ADDR")
		}
	}
	return nil
}

func (c *Client) bootstrap(ctx context.Context) error {
	relays, err := c.fetchRelaysFederated(ctx)
	if err != nil {
		return err
	}

	pairs := c.rankRelayPairs(ctx, relays)
	if len(pairs) == 0 {
		if c.strictExitLocality && (c.preferredExitCountry != "" || c.preferredExitRegion != "") {
			return fmt.Errorf("no suitable entry/exit relays found for strict locality country=%s region=%s",
				c.preferredExitCountry, c.preferredExitRegion)
		}
		return fmt.Errorf("no suitable entry/exit relays found")
	}

	var (
		selectedPair    relayPair
		tokenResp       proto.IssueTokenResponse
		pathResp        proto.PathOpenResponse
		entryControlURL string
		exitControlURL  string
	)
	_, err = attemptPairs(pairs, c.pathOpenMaxAttempts, func(pair relayPair) error {
		entryControlURL = c.entryControlURLFor(pair.entry)
		exitControlURL = c.exitControlURLFor(pair.exit)

		tok, err := c.issueToken(ctx, proto.IssueTokenRequest{
			Tier:      1,
			Subject:   c.subject,
			ExitScope: []string{pair.exit.RelayID},
		})
		if err != nil {
			return fmt.Errorf("issue token for exit=%s: %w", pair.exit.RelayID, err)
		}
		resp, err := c.openPathWithChallenge(ctx, entryControlURL, proto.PathOpenRequest{
			ExitID:          pair.exit.RelayID,
			Token:           tok.Token,
			ClientInnerPub:  c.clientWGPub,
			Transport:       requestedTransport(c.dataMode),
			RequestedMTU:    1280,
			RequestedRegion: pair.exit.Region,
		})
		if err != nil {
			return err
		}
		selectedPair = pair
		tokenResp = tok
		pathResp = resp
		return nil
	})
	if err != nil {
		return err
	}

	if pathResp.SessionID == "" || pathResp.EntryDataAddr == "" {
		return fmt.Errorf("path open missing session data")
	}
	if pathResp.Transport != "" && pathResp.Transport != requestedTransport(c.dataMode) {
		return fmt.Errorf("path transport mismatch: requested=%s got=%s", requestedTransport(c.dataMode), pathResp.Transport)
	}
	if pathResp.Transport == "wireguard-udp" {
		log.Printf("client received wg-session config: key_id=%s exit_pub=%s client_ip=%s exit_ip=%s mtu=%d keepalive=%ds",
			pathResp.SessionKeyID,
			pathResp.ExitInnerPub,
			pathResp.ClientInnerIP,
			pathResp.ExitInnerIP,
			pathResp.InnerMTU,
			pathResp.KeepaliveSec,
		)
		cfg := wg.ClientSessionConfig{
			SessionID:        pathResp.SessionID,
			SessionKeyID:     pathResp.SessionKeyID,
			Interface:        c.wgInterface,
			ClientPrivateKey: c.wgPrivateKey,
			ExitPublicKey:    pathResp.ExitInnerPub,
			ClientInnerIP:    pathResp.ClientInnerIP,
			Endpoint:         pathResp.EntryDataAddr,
			AllowedIPs:       "0.0.0.0/0",
			MTU:              pathResp.InnerMTU,
			KeepaliveSec:     pathResp.KeepaliveSec,
		}
		if err := c.wgManager.ConfigureClientSession(ctx, cfg); err != nil {
			return fmt.Errorf("client wg configure failed: %w", err)
		}
	}

	switch c.dataMode {
	case "opaque":
		if err := c.sendOpaqueTraffic(ctx, pathResp.EntryDataAddr, pathResp.SessionID); err != nil {
			return err
		}
	default:
		if err := c.sendJSONInnerPacket(pathResp.EntryDataAddr, pathResp.SessionID, proto.InnerPacket{
			DestinationPort: 443,
			Payload:         "hello-over-two-hop",
			Nonce:           randomNonce(),
		}); err != nil {
			return err
		}
		if err := c.sendJSONInnerPacket(pathResp.EntryDataAddr, pathResp.SessionID, proto.InnerPacket{
			DestinationPort: 25,
			Payload:         "smtp-probe",
			Nonce:           randomNonce(),
		}); err != nil {
			return err
		}
	}

	log.Printf("client selected entry=%s (%s) exit=%s (%s) token_exp=%d",
		selectedPair.entry.RelayID,
		entryControlURL,
		selectedPair.exit.RelayID,
		exitControlURL,
		tokenResp.Expires,
	)
	if err := c.closePath(ctx, entryControlURL, proto.PathCloseRequest{SessionID: pathResp.SessionID}); err != nil {
		return err
	}
	if pathResp.Transport == "wireguard-udp" {
		cfg := wg.ClientSessionConfig{
			SessionID:     pathResp.SessionID,
			SessionKeyID:  pathResp.SessionKeyID,
			Interface:     c.wgInterface,
			ExitPublicKey: pathResp.ExitInnerPub,
		}
		if err := c.wgManager.RemoveClientSession(ctx, cfg); err != nil {
			return fmt.Errorf("client wg remove failed: %w", err)
		}
	}
	return nil
}

func requestedTransport(mode string) string {
	if mode == "opaque" {
		return "wireguard-udp"
	}
	return "policy-json"
}

func (c *Client) sendOpaqueTraffic(ctx context.Context, entryDataAddr string, sessionID string) error {
	entryUDP, err := net.ResolveUDPAddr("udp", entryDataAddr)
	if err != nil {
		return err
	}
	outerConn, err := net.DialUDP("udp", nil, entryUDP)
	if err != nil {
		return err
	}
	defer outerConn.Close()

	var sinkConn *net.UDPConn
	if c.opaqueSinkAddr != "" {
		sinkUDP, err := net.ResolveUDPAddr("udp", c.opaqueSinkAddr)
		if err != nil {
			return err
		}
		sinkConn, err = net.DialUDP("udp", nil, sinkUDP)
		if err != nil {
			return err
		}
		defer sinkConn.Close()
	}

	sendOpaque := func(payload []byte) error {
		return c.sendOpaqueInnerPacketConn(outerConn, sessionID, randomNonce(), payload)
	}

	upCount := 0
	if c.innerSource == "udp" {
		count, err := c.forwardOpaqueFromUDP(ctx, sendOpaque)
		if err != nil {
			return err
		}
		upCount = count
		if count > 0 {
			log.Printf("client forwarded opaque udp packets count=%d", count)
		}
		if !c.allowSyntheticFallback() && count == 0 {
			return fmt.Errorf("command/live WG mode received no UDP packets from %s", c.innerUDPAddr)
		}
	}

	// Fallback synthetic payloads so development mode always exercises the path.
	if upCount == 0 {
		if !c.allowSyntheticFallback() {
			if c.innerSource != "udp" {
				return fmt.Errorf("command WG mode requires CLIENT_INNER_SOURCE=udp")
			}
			return fmt.Errorf("no opaque UDP packets received from %s", c.innerUDPAddr)
		}
		wgLike := []byte{1, 0, 0, 0, 10, 11, 12, 13}
		if err := sendOpaque(wgLike); err != nil {
			return err
		}
		if err := sendOpaque([]byte("wg-like-datagram")); err != nil {
			return err
		}
		upCount = 2
	}

	downCount, err := c.drainOpaqueDownlink(ctx, outerConn, sessionID, sinkConn, time.Duration(c.opaqueDrainMS)*time.Millisecond)
	if err != nil {
		return err
	}
	if downCount > 0 {
		log.Printf("client downlink opaque packets count=%d sink=%s", downCount, c.opaqueSinkAddr)
	}
	return nil
}

func (c *Client) forwardOpaqueFromUDP(ctx context.Context, sendFrame func([]byte) error) (int, error) {
	addr, err := net.ResolveUDPAddr("udp", c.innerUDPAddr)
	if err != nil {
		return 0, err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 64*1024)
	count := 0
	for count < c.innerMaxPkts {
		select {
		case <-ctx.Done():
			return count, ctx.Err()
		default:
		}
		n, _, readErr := conn.ReadFromUDP(buf)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				return count, nil
			}
			return count, readErr
		}
		if n <= 0 {
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		if err := sendFrame(payload); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (c *Client) drainOpaqueDownlink(ctx context.Context, outerConn *net.UDPConn, sessionID string, sinkConn *net.UDPConn, window time.Duration) (int, error) {
	if window <= 0 {
		return 0, nil
	}
	deadline := time.Now().Add(window)
	buf := make([]byte, 64*1024)
	count := 0
	for {
		select {
		case <-ctx.Done():
			return count, ctx.Err()
		default:
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return count, nil
		}
		wait := minDuration(remaining, 250*time.Millisecond)
		_ = outerConn.SetReadDeadline(time.Now().Add(wait))
		n, readErr := outerConn.Read(buf)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				continue
			}
			return count, readErr
		}
		if n <= 0 {
			continue
		}
		gotSession, payload, parseErr := relay.ParseDatagram(buf[:n])
		if parseErr != nil || gotSession != sessionID {
			continue
		}
		_, raw, opaqueErr := relay.ParseOpaquePayload(payload)
		if opaqueErr != nil {
			continue
		}
		if c.liveWGMode && !relay.LooksLikeWireGuardMessage(raw) {
			log.Printf("client dropped opaque downlink reason=non-wireguard-live payload_len=%d", len(raw))
			continue
		}
		if sinkConn != nil {
			if _, err := sinkConn.Write(raw); err != nil {
				return count, err
			}
		}
		count++
	}
}

func minDuration(a time.Duration, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (c *Client) allowSyntheticFallback() bool {
	return !c.liveWGMode && c.wgBackend != "command"
}

func (c *Client) sendJSONInnerPacket(entryDataAddr string, sessionID string, inner proto.InnerPacket) error {
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		return err
	}
	return c.sendFrame(entryDataAddr, sessionID, innerBytes)
}

func (c *Client) sendOpaqueInnerPacket(entryDataAddr string, sessionID string, nonce uint64, payload []byte) error {
	buf := relay.BuildOpaquePayload(nonce, payload)
	return c.sendFrame(entryDataAddr, sessionID, buf)
}

func (c *Client) sendOpaqueInnerPacketConn(conn *net.UDPConn, sessionID string, nonce uint64, payload []byte) error {
	buf := relay.BuildOpaquePayload(nonce, payload)
	frame := relay.BuildDatagram(sessionID, buf)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	return nil
}

func (c *Client) sendFrame(entryDataAddr string, sessionID string, payload []byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", entryDataAddr)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	frame := relay.BuildDatagram(sessionID, payload)
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	return nil
}

func randomNonce() uint64 {
	var b [8]byte
	if _, err := io.ReadFull(crand.Reader, b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	nonce := uint64(b[0])<<56 |
		uint64(b[1])<<48 |
		uint64(b[2])<<40 |
		uint64(b[3])<<32 |
		uint64(b[4])<<24 |
		uint64(b[5])<<16 |
		uint64(b[6])<<8 |
		uint64(b[7])
	if nonce == 0 {
		return 1
	}
	return nonce
}

func randomWGPublicKeyLike() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(crand.Reader, b); err != nil {
		for i := range b {
			b[i] = byte(i + 1)
		}
	}
	encoded, err := wg.EncodeKeyBase64(b)
	if err != nil {
		return ""
	}
	return encoded
}

func solvePuzzle(challenge string, difficulty int, maxIters int) (string, string, bool) {
	prefix := strings.Repeat("0", difficulty)
	for i := 0; i < maxIters; i++ {
		nonce := fmt.Sprintf("%x", i)
		sum := sha256.Sum256([]byte(challenge + ":" + nonce))
		digest := hex.EncodeToString(sum[:])
		if strings.HasPrefix(digest, prefix) {
			return nonce, digest, true
		}
	}
	return "", "", false
}

func (c *Client) openPath(ctx context.Context, entryControlURL string, in proto.PathOpenRequest) (proto.PathOpenResponse, error) {
	var out proto.PathOpenResponse
	payload, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(entryControlURL, "/v1/path/open"), bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("entry returned status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) openPathWithChallenge(ctx context.Context, entryControlURL string, in proto.PathOpenRequest) (proto.PathOpenResponse, error) {
	resp, err := c.openPath(ctx, entryControlURL, in)
	if err != nil {
		return proto.PathOpenResponse{}, err
	}
	if !resp.Accepted && resp.Reason == "challenge-required" && resp.Challenge != "" && resp.Difficulty > 0 {
		nonce, digest, ok := solvePuzzle(resp.Challenge, resp.Difficulty, 250000)
		if !ok {
			return proto.PathOpenResponse{}, fmt.Errorf("failed to solve entry challenge")
		}
		in.PuzzleNonce = nonce
		in.PuzzleDigest = digest
		resp, err = c.openPath(ctx, entryControlURL, in)
		if err != nil {
			return proto.PathOpenResponse{}, err
		}
	}
	if !resp.Accepted {
		return proto.PathOpenResponse{}, fmt.Errorf("path open denied: %s", resp.Reason)
	}
	return resp, nil
}

func (c *Client) closePath(ctx context.Context, entryControlURL string, in proto.PathCloseRequest) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(entryControlURL, "/v1/path/close"), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("entry returned status %d on path close", resp.StatusCode)
	}
	var out proto.PathCloseResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if !out.Closed {
		return fmt.Errorf("path close denied: %s", out.Reason)
	}
	return nil
}

func (c *Client) fetchRelaysFrom(ctx context.Context, directoryURL string, dirPubs []ed25519.PublicKey) ([]proto.RelayDescriptor, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(directoryURL, "/v1/relays"), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("directory returned status %d", resp.StatusCode)
	}

	var out proto.RelayListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	for _, desc := range out.Relays {
		if err := verifyRelayDescriptorAny(desc, dirPubs); err != nil {
			return nil, fmt.Errorf("descriptor verify failed for relay=%s: %w", desc.RelayID, err)
		}
	}
	return out.Relays, nil
}

func (c *Client) fetchSelectionFeedFrom(ctx context.Context, directoryURL string, dirPubs []ed25519.PublicKey) (map[string]selectionScore, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(directoryURL, "/v1/selection-feed"), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("selection feed returned status %d", resp.StatusCode)
	}

	var out proto.RelaySelectionFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, err
	}
	if err := verifySelectionFeedAny(out, dirPubs, time.Now()); err != nil {
		return nil, false, err
	}

	scores := make(map[string]selectionScore, len(out.Scores))
	for _, s := range out.Scores {
		role := strings.TrimSpace(s.Role)
		if role == "" {
			role = "exit"
		}
		key := relayCandidateKey(s.RelayID, role)
		scores[key] = selectionScore{
			reputation:   clampUnit(s.Reputation),
			uptime:       clampUnit(s.Uptime),
			capacity:     clampUnit(s.Capacity),
			abusePenalty: clampUnit(s.AbusePenalty),
			bondScore:    clampUnit(s.BondScore),
			stakeScore:   clampUnit(s.StakeScore),
		}
	}
	return scores, true, nil
}

func (c *Client) fetchTrustFeedFrom(ctx context.Context, directoryURL string, dirPubs []ed25519.PublicKey) (map[string]trustScore, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(directoryURL, "/v1/trust-attestations"), nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("trust feed returned status %d", resp.StatusCode)
	}

	var out proto.RelayTrustAttestationFeedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, false, err
	}
	if err := verifyTrustFeedAny(out, dirPubs, time.Now()); err != nil {
		return nil, false, err
	}

	scores := make(map[string]trustScore, len(out.Attestations))
	for _, a := range out.Attestations {
		role := strings.TrimSpace(a.Role)
		if role == "" {
			role = "exit"
		}
		key := relayCandidateKey(a.RelayID, role)
		scores[key] = trustScore{
			reputation:   clampUnit(a.Reputation),
			uptime:       clampUnit(a.Uptime),
			capacity:     clampUnit(a.Capacity),
			abusePenalty: clampUnit(a.AbusePenalty),
			bondScore:    clampUnit(a.BondScore),
			stakeScore:   clampUnit(a.StakeScore),
			confidence:   clampUnit(a.Confidence),
			tierCap:      a.TierCap,
			disputeUntil: a.DisputeUntil,
			appealUntil:  a.AppealUntil,
		}
	}
	return scores, true, nil
}

func verifyRelayDescriptorAny(desc proto.RelayDescriptor, pubs []ed25519.PublicKey) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no directory pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelayDescriptor(desc, pub); err == nil {
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

func verifySelectionFeedAny(feed proto.RelaySelectionFeedResponse, pubs []ed25519.PublicKey, now time.Time) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no directory pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelaySelectionFeed(feed, pub, now); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("selection feed signature verification failed")
	}
	return lastErr
}

func verifyTrustFeedAny(feed proto.RelayTrustAttestationFeedResponse, pubs []ed25519.PublicKey, now time.Time) error {
	if len(pubs) == 0 {
		return fmt.Errorf("no directory pubkeys available")
	}
	var lastErr error
	for _, pub := range pubs {
		if err := crypto.VerifyRelayTrustAttestationFeed(feed, pub, now); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("trust feed signature verification failed")
	}
	return lastErr
}

func (c *Client) fetchDirectoryPubKey(ctx context.Context) (ed25519.PublicKey, error) {
	pubs, _, err := c.fetchDirectoryPubKeysFrom(ctx, c.directoryURL)
	if err != nil {
		return nil, err
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("directory returned no pubkeys")
	}
	return pubs[0], nil
}

func (c *Client) fetchDirectoryPubKeysFrom(ctx context.Context, directoryURL string) ([]ed25519.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(directoryURL, "/v1/pubkeys"), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return c.fetchDirectoryPubKeyLegacy(ctx, directoryURL)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("directory pubkeys status %d", resp.StatusCode)
	}
	var out proto.DirectoryPubKeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, "", err
	}
	if err := c.enforceDirectoryTrustSet(out.PubKeys); err != nil {
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

func (c *Client) fetchDirectoryPubKeyLegacy(ctx context.Context, directoryURL string) ([]ed25519.PublicKey, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, joinURL(directoryURL, "/v1/pubkey"), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := c.httpClient.Do(req)
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
	raw, err := base64.RawURLEncoding.DecodeString(pubB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid directory pubkey")
	}
	if err := c.enforceDirectoryTrust(pubB64); err != nil {
		return nil, "", err
	}
	return []ed25519.PublicKey{ed25519.PublicKey(raw)}, normalizeDirectoryOperator("", []string{pubB64}, directoryURL), nil
}

type relayCandidate struct {
	desc              proto.RelayDescriptor
	votes             int
	scoreSamples      int
	reputationSum     float64
	uptimeSum         float64
	capacitySum       float64
	abuseSum          float64
	bondSum           float64
	stakeSum          float64
	feedVotes         int
	feedRepSum        float64
	feedUptimeSum     float64
	feedCapSum        float64
	feedAbuseSum      float64
	feedBondSum       float64
	feedStakeSum      float64
	trustVotes        int
	trustRepSum       float64
	trustUptimeSum    float64
	trustCapSum       float64
	trustAbuseSum     float64
	trustBondSum      float64
	trustStakeSum     float64
	trustConfSum      float64
	trustDisputeVotes int
	trustDisputeCap   int
	trustDisputeUntil int64
	trustAppealVotes  int
	trustAppealUntil  int64
}

type selectionScore struct {
	reputation   float64
	uptime       float64
	capacity     float64
	abusePenalty float64
	bondScore    float64
	stakeScore   float64
}

type trustScore struct {
	reputation   float64
	uptime       float64
	capacity     float64
	abusePenalty float64
	bondScore    float64
	stakeScore   float64
	confidence   float64
	tierCap      int
	disputeUntil int64
	appealUntil  int64
}

func relayCandidateKey(relayID string, role string) string {
	return relayID + "|" + role
}

func markVoter(voterSet map[string]map[string]struct{}, key string, operator string) bool {
	if strings.TrimSpace(key) == "" || strings.TrimSpace(operator) == "" {
		return false
	}
	ops, ok := voterSet[key]
	if !ok {
		ops = make(map[string]struct{})
		voterSet[key] = ops
	}
	if _, exists := ops[operator]; exists {
		return false
	}
	ops[operator] = struct{}{}
	return true
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

func (c *Client) fetchRelaysFederated(ctx context.Context) ([]proto.RelayDescriptor, error) {
	candidates := make(map[string]relayCandidate)
	success := 0
	successOperators := make(map[string]struct{})
	relayVoters := make(map[string]map[string]struct{})
	feedVoters := make(map[string]map[string]struct{})
	trustVoters := make(map[string]map[string]struct{})
	disputeVoters := make(map[string]map[string]struct{})
	appealVoters := make(map[string]map[string]struct{})
	var lastErr error
	for _, durl := range c.directoryURLs {
		pubs, sourceOperator, err := c.fetchDirectoryPubKeysFrom(ctx, durl)
		if err != nil {
			lastErr = err
			log.Printf("client directory fetch pubkey failed url=%s err=%v", durl, err)
			continue
		}
		relays, err := c.fetchRelaysFrom(ctx, durl, pubs)
		if err != nil {
			lastErr = err
			log.Printf("client directory fetch relays failed url=%s err=%v", durl, err)
			continue
		}
		var selectionScores map[string]selectionScore
		if !c.selectionFeedDisable {
			fetchedScores, ok, feedErr := c.fetchSelectionFeedFrom(ctx, durl, pubs)
			switch {
			case feedErr != nil:
				if c.selectionFeedRequire {
					lastErr = feedErr
					log.Printf("client directory selection feed failed url=%s err=%v", durl, feedErr)
					continue
				}
				log.Printf("client directory selection feed ignored url=%s err=%v", durl, feedErr)
			case !ok:
				if c.selectionFeedRequire {
					lastErr = fmt.Errorf("selection feed unavailable")
					log.Printf("client directory selection feed unavailable url=%s", durl)
					continue
				}
			default:
				selectionScores = fetchedScores
			}
		}
		var trustScores map[string]trustScore
		if !c.trustFeedDisable {
			fetchedTrust, ok, trustErr := c.fetchTrustFeedFrom(ctx, durl, pubs)
			switch {
			case trustErr != nil:
				if c.trustFeedRequire {
					lastErr = trustErr
					log.Printf("client directory trust feed failed url=%s err=%v", durl, trustErr)
					continue
				}
				log.Printf("client directory trust feed ignored url=%s err=%v", durl, trustErr)
			case !ok:
				if c.trustFeedRequire {
					lastErr = fmt.Errorf("trust feed unavailable")
					log.Printf("client directory trust feed unavailable url=%s", durl)
					continue
				}
			default:
				trustScores = fetchedTrust
			}
		}
		success++
		successOperators[sourceOperator] = struct{}{}
		seenFromSource := make(map[string]struct{})
		for _, desc := range relays {
			key := relayCandidateKey(desc.RelayID, desc.Role)
			if _, ok := seenFromSource[key]; ok {
				continue
			}
			seenFromSource[key] = struct{}{}
			candidate := candidates[key]
			if markVoter(relayVoters, key, sourceOperator) {
				if candidate.votes == 0 {
					candidate.desc = desc
				}
				candidate.votes++
				candidate.reputationSum += clampUnit(desc.Reputation)
				candidate.uptimeSum += clampUnit(desc.Uptime)
				candidate.capacitySum += clampUnit(desc.Capacity)
				candidate.abuseSum += clampUnit(desc.AbusePenalty)
				candidate.bondSum += clampUnit(desc.BondScore)
				candidate.stakeSum += clampUnit(desc.StakeScore)
				candidate.scoreSamples++
			}
			if score, ok := selectionScores[key]; ok && markVoter(feedVoters, key, sourceOperator) {
				candidate.feedVotes++
				candidate.feedRepSum += clampUnit(score.reputation)
				candidate.feedUptimeSum += clampUnit(score.uptime)
				candidate.feedCapSum += clampUnit(score.capacity)
				candidate.feedAbuseSum += clampUnit(score.abusePenalty)
				candidate.feedBondSum += clampUnit(score.bondScore)
				candidate.feedStakeSum += clampUnit(score.stakeScore)
			}
			if trust, ok := trustScores[key]; ok && markVoter(trustVoters, key, sourceOperator) {
				conf := clampUnit(trust.confidence)
				if conf <= 0 {
					conf = 1
				}
				candidate.trustVotes++
				candidate.trustConfSum += conf
				candidate.trustRepSum += clampUnit(trust.reputation) * conf
				candidate.trustUptimeSum += clampUnit(trust.uptime) * conf
				candidate.trustCapSum += clampUnit(trust.capacity) * conf
				candidate.trustAbuseSum += clampUnit(trust.abusePenalty) * conf
				candidate.trustBondSum += clampUnit(trust.bondScore) * conf
				candidate.trustStakeSum += clampUnit(trust.stakeScore) * conf
				if capTier, until, ok := normalizeDispute(trust.tierCap, trust.disputeUntil, time.Now().Unix()); ok &&
					markVoter(disputeVoters, key, sourceOperator) {
					candidate.trustDisputeVotes++
					candidate.trustDisputeCap = minPositiveTier(candidate.trustDisputeCap, capTier)
					if until > candidate.trustDisputeUntil {
						candidate.trustDisputeUntil = until
					}
				}
				if appealUntil := normalizeAppeal(trust.appealUntil, time.Now().Unix()); appealUntil > 0 &&
					markVoter(appealVoters, key, sourceOperator) {
					candidate.trustAppealVotes++
					if appealUntil > candidate.trustAppealUntil {
						candidate.trustAppealUntil = appealUntil
					}
				}
			}
			// Keep one verified descriptor for candidate output even if this operator was deduped.
			if candidate.desc.RelayID == "" {
				candidate.desc = desc
			}
			candidates[key] = candidate
		}
	}
	if success < c.directoryMinSources {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient directory sources")
		}
		return nil, fmt.Errorf("directory quorum not met: success=%d required=%d: %w", success, c.directoryMinSources, lastErr)
	}
	requiredOperators := maxInt(1, c.directoryMinOperators)
	if len(successOperators) < requiredOperators {
		if lastErr == nil {
			lastErr = fmt.Errorf("insufficient directory operators")
		}
		return nil, fmt.Errorf("directory operator quorum not met: operators=%d required=%d: %w", len(successOperators), requiredOperators, lastErr)
	}
	out := make([]proto.RelayDescriptor, 0, len(candidates))
	for _, cand := range candidates {
		if cand.votes >= c.directoryMinVotes {
			desc := cand.desc
			if !c.selectionFeedDisable && cand.feedVotes >= c.selectionFeedMinVotes {
				n := float64(cand.feedVotes)
				desc.Reputation = cand.feedRepSum / n
				desc.Uptime = cand.feedUptimeSum / n
				desc.Capacity = cand.feedCapSum / n
				desc.AbusePenalty = cand.feedAbuseSum / n
				desc.BondScore = cand.feedBondSum / n
				desc.StakeScore = cand.feedStakeSum / n
			} else if cand.scoreSamples > 0 {
				n := float64(cand.scoreSamples)
				desc.Reputation = cand.reputationSum / n
				desc.Uptime = cand.uptimeSum / n
				desc.Capacity = cand.capacitySum / n
				desc.AbusePenalty = cand.abuseSum / n
				desc.BondScore = cand.bondSum / n
				desc.StakeScore = cand.stakeSum / n
			}
			if !c.trustFeedDisable && cand.trustVotes >= c.trustFeedMinVotes && cand.trustConfSum > 0 {
				n := cand.trustConfSum
				trustRep := cand.trustRepSum / n
				trustUptime := cand.trustUptimeSum / n
				trustCap := cand.trustCapSum / n
				trustAbuse := cand.trustAbuseSum / n
				trustBond := cand.trustBondSum / n
				trustStake := cand.trustStakeSum / n
				conf := clampUnit(cand.trustConfSum / float64(cand.trustVotes))
				desc.Reputation = clampUnit((1-conf)*desc.Reputation + conf*trustRep)
				desc.Uptime = clampUnit((1-conf)*desc.Uptime + conf*trustUptime)
				desc.Capacity = clampUnit((1-conf)*desc.Capacity + conf*trustCap)
				desc.AbusePenalty = clampUnit((1-conf)*desc.AbusePenalty + conf*trustAbuse)
				desc.BondScore = clampUnit((1-conf)*desc.BondScore + conf*trustBond)
				desc.StakeScore = clampUnit((1-conf)*desc.StakeScore + conf*trustStake)
			}
			if !c.trustFeedDisable && cand.trustDisputeVotes >= c.trustFeedMinVotes {
				penalty := disputePenaltyFromTierCap(cand.trustDisputeCap)
				if cand.trustAppealVotes >= c.trustFeedMinVotes && normalizeAppeal(cand.trustAppealUntil, time.Now().Unix()) > 0 {
					penalty = clampUnit(penalty * 0.7)
				}
				desc.AbusePenalty = clampUnit(maxFloat(desc.AbusePenalty, penalty))
				desc.Reputation = clampUnit(desc.Reputation * (1 - 0.40*penalty))
				desc.Capacity = clampUnit(desc.Capacity * (1 - 0.25*penalty))
			}
			out = append(out, desc)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no relays met vote threshold: required_votes=%d", c.directoryMinVotes)
	}
	return out, nil
}

func (c *Client) issueToken(ctx context.Context, in proto.IssueTokenRequest) (proto.IssueTokenResponse, error) {
	var out proto.IssueTokenResponse
	payload, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(c.issuerURL, "/v1/token"), bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("issuer returned status %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) selectEntryExit(ctx context.Context, relays []proto.RelayDescriptor) (proto.RelayDescriptor, proto.RelayDescriptor, bool) {
	pairs := c.rankRelayPairs(ctx, relays)
	if len(pairs) == 0 {
		return proto.RelayDescriptor{}, proto.RelayDescriptor{}, false
	}
	return pairs[0].entry, pairs[0].exit, true
}

func (c *Client) rankRelayPairs(ctx context.Context, relays []proto.RelayDescriptor) []relayPair {
	entries := make([]proto.RelayDescriptor, 0, len(relays))
	exits := make([]proto.RelayDescriptor, 0, len(relays))
	for _, r := range relays {
		switch r.Role {
		case "entry":
			entries = append(entries, r)
		case "exit":
			exits = append(exits, r)
		}
	}
	if len(entries) == 0 || len(exits) == 0 {
		return nil
	}

	healthyEntries := entries
	healthyExits := exits
	if c.healthCheckEnabled {
		healthyEntries = filterHealthy(entries, func(r proto.RelayDescriptor) bool {
			return c.relayHealthy(ctx, c.entryControlURLFor(r))
		})
		healthyExits = filterHealthy(exits, func(r proto.RelayDescriptor) bool {
			return c.relayHealthy(ctx, c.exitControlURLFor(r))
		})
		if len(healthyEntries) == 0 {
			healthyEntries = entries
		}
		if len(healthyExits) == 0 {
			healthyExits = exits
		}
	}
	selectedExits, localityMode := c.selectPreferredExits(healthyExits)
	if localityMode != "" {
		log.Printf("client exit locality selection mode=%s candidates=%d", localityMode, len(selectedExits))
	}
	if len(selectedExits) == 0 {
		if c.strictExitLocality {
			return nil
		}
		selectedExits = healthyExits
	}
	if c.maxExitsPerOperator > 0 {
		capped := capExitsPerOperator(selectedExits, c.maxExitsPerOperator)
		if len(capped) > 0 {
			if len(capped) != len(selectedExits) {
				log.Printf("client exit operator cap applied max=%d before=%d after=%d", c.maxExitsPerOperator, len(selectedExits), len(capped))
			}
			selectedExits = capped
		}
	}
	selectedExits, weightedMode := c.orderExitsForSelection(selectedExits)
	if weightedMode != "" {
		log.Printf("client exit weighted ordering mode=%s candidates=%d exploration_pct=%d", weightedMode, len(selectedExits), c.exitExplorationPct)
	}

	pairs := make([]relayPair, 0, len(healthyEntries)*len(selectedExits))
	seen := make(map[string]struct{})
	addPair := func(entry proto.RelayDescriptor, exit proto.RelayDescriptor) {
		key := entry.RelayID + "|" + exit.RelayID
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		pairs = append(pairs, relayPair{entry: entry, exit: exit})
	}

	// Prefer same-region pairs when available, then append all remaining pairs.
	for _, e := range healthyEntries {
		if e.Region == "" {
			continue
		}
		for _, x := range selectedExits {
			if x.Region == e.Region {
				addPair(e, x)
			}
		}
	}
	for _, e := range healthyEntries {
		for _, x := range selectedExits {
			addPair(e, x)
		}
	}
	if c.maxPairCandidates > 0 && len(pairs) > c.maxPairCandidates {
		pairs = pairs[:c.maxPairCandidates]
	}
	return pairs
}

func filterHealthy(relays []proto.RelayDescriptor, healthy func(proto.RelayDescriptor) bool) []proto.RelayDescriptor {
	out := make([]proto.RelayDescriptor, 0, len(relays))
	for _, r := range relays {
		if healthy(r) {
			out = append(out, r)
		}
	}
	return out
}

func capExitsPerOperator(exits []proto.RelayDescriptor, maxPerOperator int) []proto.RelayDescriptor {
	if maxPerOperator <= 0 {
		return exits
	}
	counts := make(map[string]int)
	out := make([]proto.RelayDescriptor, 0, len(exits))
	for _, x := range exits {
		key := operatorKey(x)
		if counts[key] >= maxPerOperator {
			continue
		}
		counts[key]++
		out = append(out, x)
	}
	return out
}

func operatorKey(desc proto.RelayDescriptor) string {
	v := strings.TrimSpace(desc.OperatorID)
	if v != "" {
		return v
	}
	return "relay:" + desc.RelayID
}

func (c *Client) selectPreferredExits(exits []proto.RelayDescriptor) ([]proto.RelayDescriptor, string) {
	country := normalizeCountryCode(c.preferredExitCountry)
	region := normalizeRegion(c.preferredExitRegion)
	if country == "" && region == "" {
		return exits, ""
	}

	modes := c.localityFallbackOrder
	if len(modes) == 0 {
		modes = parseLocalityFallbackOrder("")
	}
	for _, mode := range modes {
		switch mode {
		case "country":
			if country == "" {
				continue
			}
			if matches := c.filterExitsByCountry(exits, country); len(matches) > 0 {
				return matches, "country"
			}
		case "region":
			if region == "" {
				continue
			}
			if matches := c.filterExitsByRegion(exits, region); len(matches) > 0 {
				return matches, "region"
			}
		case "region-prefix":
			if region == "" {
				continue
			}
			prefix := regionPrefix(region)
			if prefix == "" {
				continue
			}
			matches := make([]proto.RelayDescriptor, 0, len(exits))
			for _, x := range exits {
				if !c.geoConfidenceOK(x) {
					continue
				}
				if strings.HasPrefix(normalizeRegion(x.Region), prefix+"-") || normalizeRegion(x.Region) == prefix {
					matches = append(matches, x)
				}
			}
			if len(matches) > 0 {
				return matches, "region-prefix"
			}
		case "global":
			if c.strictExitLocality {
				continue
			}
			return exits, "fallback-global"
		}
	}
	if c.strictExitLocality {
		return nil, "strict-locality-no-match"
	}
	return exits, "fallback-global"
}

func (c *Client) filterExitsByCountry(exits []proto.RelayDescriptor, country string) []proto.RelayDescriptor {
	matches := make([]proto.RelayDescriptor, 0, len(exits))
	for _, x := range exits {
		if !c.geoConfidenceOK(x) {
			continue
		}
		if normalizeCountryCode(x.CountryCode) == country {
			matches = append(matches, x)
		}
	}
	return matches
}

func (c *Client) filterExitsByRegion(exits []proto.RelayDescriptor, region string) []proto.RelayDescriptor {
	matches := make([]proto.RelayDescriptor, 0, len(exits))
	for _, x := range exits {
		if !c.geoConfidenceOK(x) {
			continue
		}
		if normalizeRegion(x.Region) == region {
			matches = append(matches, x)
		}
	}
	return matches
}

func (c *Client) geoConfidenceOK(exit proto.RelayDescriptor) bool {
	if c.minGeoConfidence <= 0 {
		return true
	}
	return clampUnit(exit.GeoConfidence) >= c.minGeoConfidence
}

func parseLocalityFallbackOrder(raw string) []string {
	defaultOrder := []string{"country", "region", "region-prefix", "global"}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultOrder
	}
	allowed := map[string]struct{}{
		"country":       {},
		"region":        {},
		"region-prefix": {},
		"global":        {},
	}
	var out []string
	seen := make(map[string]struct{})
	for _, item := range strings.Split(raw, ",") {
		mode := strings.ToLower(strings.TrimSpace(item))
		if _, ok := allowed[mode]; !ok {
			continue
		}
		if _, ok := seen[mode]; ok {
			continue
		}
		seen[mode] = struct{}{}
		out = append(out, mode)
	}
	if len(out) == 0 {
		return defaultOrder
	}
	return out
}

func regionPrefix(region string) string {
	region = normalizeRegion(region)
	if region == "" {
		return ""
	}
	if i := strings.Index(region, "-"); i > 0 {
		return region[:i]
	}
	return region
}

type scoredExit struct {
	desc   proto.RelayDescriptor
	weight float64
}

func (c *Client) orderExitsForSelection(exits []proto.RelayDescriptor) ([]proto.RelayDescriptor, string) {
	if len(exits) <= 1 {
		return exits, ""
	}
	scored, enabled := scoreExits(exits)
	if !enabled {
		return exits, ""
	}
	seed := c.exitSelectionSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := mrand.New(mrand.NewSource(seed))
	return weightedExitOrder(scored, c.exitExplorationPct, rng), "weighted-random"
}

func scoreExits(exits []proto.RelayDescriptor) ([]scoredExit, bool) {
	scored := make([]scoredExit, 0, len(exits))
	hasSignals := false
	for _, x := range exits {
		score, signaled := exitSelectionScore(x)
		if signaled {
			hasSignals = true
		}
		weight := score
		if weight < 0.01 {
			weight = 0.01
		}
		scored = append(scored, scoredExit{desc: x, weight: weight})
	}
	if !hasSignals || weightsNearlyEqual(scored) {
		return nil, false
	}
	return scored, true
}

func weightsNearlyEqual(scored []scoredExit) bool {
	if len(scored) <= 1 {
		return true
	}
	base := scored[0].weight
	for i := 1; i < len(scored); i++ {
		if math.Abs(scored[i].weight-base) > 1e-9 {
			return false
		}
	}
	return true
}

func exitSelectionScore(desc proto.RelayDescriptor) (float64, bool) {
	reputation := clampUnit(desc.Reputation)
	uptime := clampUnit(desc.Uptime)
	capacity := clampUnit(desc.Capacity)
	abusePenalty := clampUnit(desc.AbusePenalty)
	bondScore := clampUnit(desc.BondScore)
	stakeScore := clampUnit(desc.StakeScore)
	signaled := desc.Reputation != 0 || desc.Uptime != 0 || desc.Capacity != 0 || desc.AbusePenalty != 0 || desc.BondScore != 0 || desc.StakeScore != 0
	score := 0.45*reputation + 0.25*uptime + 0.20*capacity + 0.15*bondScore + 0.10*stakeScore - 0.5*abusePenalty
	if score < 0 {
		score = 0
	}
	return score, signaled
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

func maxFloat(a float64, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func normalizeDispute(tierCap int, disputeUntil int64, nowUnix int64) (int, int64, bool) {
	if tierCap < 1 || tierCap > 3 {
		return 0, 0, false
	}
	if disputeUntil <= nowUnix {
		return 0, 0, false
	}
	return tierCap, disputeUntil, true
}

func normalizeAppeal(appealUntil int64, nowUnix int64) int64 {
	if appealUntil <= nowUnix {
		return 0
	}
	return appealUntil
}

func minPositiveTier(curr int, next int) int {
	if next < 1 || next > 3 {
		return curr
	}
	if curr < 1 || curr > 3 {
		return next
	}
	if next < curr {
		return next
	}
	return curr
}

func disputePenaltyFromTierCap(tierCap int) float64 {
	switch tierCap {
	case 1:
		return 0.85
	case 2:
		return 0.55
	case 3:
		return 0.25
	default:
		return 0
	}
}

func weightedExitOrder(scored []scoredExit, explorationPct int, rng *mrand.Rand) []proto.RelayDescriptor {
	if len(scored) == 0 {
		return nil
	}
	if explorationPct < 0 {
		explorationPct = 0
	}
	if explorationPct > 100 {
		explorationPct = 100
	}

	exploreCount := int(math.Round(float64(len(scored)) * float64(explorationPct) / 100.0))
	if len(scored) > 1 && exploreCount >= len(scored) {
		exploreCount = len(scored) - 1
	}
	if exploreCount < 0 {
		exploreCount = 0
	}
	exploitCount := len(scored) - exploreCount

	exploit, remaining := pickWeighted(scored, exploitCount, rng, false)
	explore, _ := pickWeighted(remaining, exploreCount, rng, true)

	ordered := make([]proto.RelayDescriptor, 0, len(scored))
	limit := len(exploit)
	if len(explore) > limit {
		limit = len(explore)
	}
	for i := 0; i < limit; i++ {
		if i < len(exploit) {
			ordered = append(ordered, exploit[i].desc)
		}
		if i < len(explore) {
			ordered = append(ordered, explore[i].desc)
		}
	}
	return ordered
}

func pickWeighted(pool []scoredExit, count int, rng *mrand.Rand, inverse bool) ([]scoredExit, []scoredExit) {
	if count <= 0 || len(pool) == 0 {
		return nil, append([]scoredExit(nil), pool...)
	}
	if count > len(pool) {
		count = len(pool)
	}
	if rng == nil {
		rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))
	}

	work := append([]scoredExit(nil), pool...)
	picked := make([]scoredExit, 0, count)
	for len(picked) < count && len(work) > 0 {
		idx := pickWeightedIndex(work, rng, inverse)
		picked = append(picked, work[idx])
		work = append(work[:idx], work[idx+1:]...)
	}
	return picked, work
}

func pickWeightedIndex(pool []scoredExit, rng *mrand.Rand, inverse bool) int {
	total := 0.0
	for _, item := range pool {
		w := item.weight
		if w < 0.01 {
			w = 0.01
		}
		if inverse {
			w = 1.0 / w
		}
		total += w
	}
	if total <= 0 {
		return 0
	}

	target := rng.Float64() * total
	cumulative := 0.0
	for i, item := range pool {
		w := item.weight
		if w < 0.01 {
			w = 0.01
		}
		if inverse {
			w = 1.0 / w
		}
		cumulative += w
		if target <= cumulative {
			return i
		}
	}
	return len(pool) - 1
}

func attemptPairs(pairs []relayPair, maxAttempts int, attempt func(relayPair) error) (relayPair, error) {
	if len(pairs) == 0 {
		return relayPair{}, fmt.Errorf("no relay pairs available")
	}
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	limit := maxAttempts
	if limit > len(pairs) {
		limit = len(pairs)
	}

	failures := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		pair := pairs[i]
		if err := attempt(pair); err == nil {
			return pair, nil
		} else {
			failures = append(failures, fmt.Sprintf("%s->%s: %v", pair.entry.RelayID, pair.exit.RelayID, err))
		}
	}
	return relayPair{}, fmt.Errorf("all path-open attempts failed (%d/%d): %s", limit, len(pairs), strings.Join(failures, "; "))
}

func (c *Client) relayHealthy(ctx context.Context, controlURL string) bool {
	if !c.healthCheckEnabled {
		return true
	}
	controlURL = normalizeControlURL(controlURL)
	if controlURL == "" {
		return false
	}
	now := time.Now()
	c.healthMu.Lock()
	if st, ok := c.healthCache[controlURL]; ok && now.Sub(st.checkedAt) <= c.healthCacheTTL {
		c.healthMu.Unlock()
		return st.ok
	}
	c.healthMu.Unlock()

	checkCtx := ctx
	var cancel context.CancelFunc
	if c.healthCheckTimeout > 0 {
		checkCtx, cancel = context.WithTimeout(ctx, c.healthCheckTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, joinURL(controlURL, "/v1/health"), nil)
	if err != nil {
		return false
	}
	resp, err := c.httpClient.Do(req)
	ok := err == nil && resp != nil && resp.StatusCode == http.StatusOK
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	c.healthMu.Lock()
	if c.healthCache == nil {
		c.healthCache = make(map[string]healthProbeState)
	}
	c.healthCache[controlURL] = healthProbeState{ok: ok, checkedAt: now}
	c.healthMu.Unlock()
	return ok
}

func normalizeCountryCode(raw string) string {
	v := strings.ToUpper(strings.TrimSpace(raw))
	if len(v) > 2 {
		return v[:2]
	}
	return v
}

func normalizeRegion(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func (c *Client) entryControlURLFor(entry proto.RelayDescriptor) string {
	if v := normalizeControlURL(entry.ControlURL); v != "" {
		return v
	}
	return normalizeControlURL(c.entryURL)
}

func (c *Client) exitControlURLFor(exit proto.RelayDescriptor) string {
	if v := normalizeControlURL(exit.ControlURL); v != "" {
		return v
	}
	return normalizeControlURL(c.exitControlURL)
}

func normalizeControlURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		return v
	}
	return "http://" + v
}

func joinURL(base string, path string) string {
	base = strings.TrimRight(base, "/")
	if path == "" {
		return base
	}
	if strings.HasPrefix(path, "/") {
		return base + path
	}
	return base + "/" + path
}
