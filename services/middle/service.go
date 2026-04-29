package middle

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Service struct {
	addr          string
	dataAddr      string
	entryDataAddr string
	exitDataAddr  string
	observedFile  string
	readyFile     string

	httpSrv *http.Server
	udpConn *net.UDPConn

	mu    sync.RWMutex
	state middleRouteState
}

type middleRouteState struct {
	entryAddr   *net.UDPAddr
	entryToExit int64
	exitToEntry int64
	lastLen     int
	lastSrc     string
	lastTarget  string
	lastAt      time.Time
}

func New() *Service {
	addr := strings.TrimSpace(os.Getenv("MIDDLE_ADDR"))
	if addr == "" {
		addr = "127.0.0.1:8085"
	}
	dataAddr := strings.TrimSpace(os.Getenv("MIDDLE_DATA_ADDR"))
	if dataAddr == "" {
		dataAddr = "127.0.0.1:51822"
	}
	entryDataAddr := strings.TrimSpace(os.Getenv("MIDDLE_ENTRY_DATA_ADDR"))
	exitDataAddr := strings.TrimSpace(os.Getenv("MIDDLE_EXIT_DATA_ADDR"))
	return &Service{
		addr:          addr,
		dataAddr:      dataAddr,
		entryDataAddr: entryDataAddr,
		exitDataAddr:  exitDataAddr,
		observedFile:  strings.TrimSpace(os.Getenv("MIDDLE_OBSERVED_FILE")),
		readyFile:     strings.TrimSpace(os.Getenv("MIDDLE_READY_FILE")),
	}
}

func (s *Service) Run(ctx context.Context) error {
	if strings.TrimSpace(s.dataAddr) == "" {
		return fmt.Errorf("middle data address required")
	}
	if strings.TrimSpace(s.entryDataAddr) == "" {
		return fmt.Errorf("MIDDLE_ENTRY_DATA_ADDR is required")
	}
	if strings.TrimSpace(s.exitDataAddr) == "" {
		return fmt.Errorf("MIDDLE_EXIT_DATA_ADDR is required")
	}
	listenAddr, err := net.ResolveUDPAddr("udp", s.dataAddr)
	if err != nil {
		return fmt.Errorf("resolve middle data addr: %w", err)
	}
	entryAddr, err := net.ResolveUDPAddr("udp", s.entryDataAddr)
	if err != nil {
		return fmt.Errorf("resolve middle entry data addr: %w", err)
	}
	exitAddr, err := net.ResolveUDPAddr("udp", s.exitDataAddr)
	if err != nil {
		return fmt.Errorf("resolve middle exit data addr: %w", err)
	}
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen middle udp: %w", err)
	}
	s.udpConn = conn
	defer conn.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/ready", s.handleReady)
	mux.HandleFunc("/v1/stats", s.handleStats)
	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	httpLn, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen middle control addr: %w", err)
	}
	defer httpLn.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- s.forwardLoop(ctx, conn, entryAddr, exitAddr)
	}()
	go func() {
		if s.readyFile != "" {
			_ = os.WriteFile(s.readyFile, []byte("ready\n"), 0o600)
		}
		log.Printf("middle relay listening control=%s data=%s entry_data=%s exit_data=%s", s.addr, conn.LocalAddr().String(), entryAddr.String(), exitAddr.String())
		if err := s.httpSrv.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutdownCtx)
		_ = conn.Close()
		s.removeReadyFile()
		return ctx.Err()
	case err := <-errCh:
		if err != nil {
			s.removeReadyFile()
			return err
		}
		s.removeReadyFile()
		return nil
	}
}

func (s *Service) forwardLoop(ctx context.Context, conn *net.UDPConn, entryAddr *net.UDPAddr, exitAddr *net.UDPAddr) error {
	buf := make([]byte, 64*1024)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return fmt.Errorf("read middle udp: %w", err)
		}
		if n <= 0 {
			continue
		}
		target, ok := s.route(src, entryAddr, exitAddr, n)
		if !ok {
			continue
		}
		if _, err := conn.WriteToUDP(buf[:n], target); err != nil {
			return fmt.Errorf("forward middle udp: %w", err)
		}
	}
}

func (s *Service) route(src *net.UDPAddr, entryAddr *net.UDPAddr, exitAddr *net.UDPAddr, packetLen int) (*net.UDPAddr, bool) {
	s.mu.Lock()
	next, target, ok := routeMiddlePacket(s.state, src, entryAddr, exitAddr, packetLen, time.Now().UTC())
	if ok {
		s.state = next
	}
	snapshot := s.state
	s.mu.Unlock()
	if ok {
		s.writeObserved(snapshot)
	}
	return target, ok
}

func routeMiddlePacket(state middleRouteState, src *net.UDPAddr, entryAddr *net.UDPAddr, exitAddr *net.UDPAddr, packetLen int, now time.Time) (middleRouteState, *net.UDPAddr, bool) {
	if src == nil || entryAddr == nil || exitAddr == nil {
		return state, nil, false
	}
	var target *net.UDPAddr
	if sameUDPAddr(src, exitAddr) {
		target = entryAddr
		state.entryAddr = entryAddr
		state.exitToEntry++
	} else if sameUDPAddr(src, entryAddr) {
		state.entryAddr = entryAddr
		target = exitAddr
		state.entryToExit++
	} else {
		return state, nil, false
	}
	state.lastLen = packetLen
	state.lastSrc = src.String()
	state.lastTarget = target.String()
	state.lastAt = now
	return state, target, true
}

func sameUDPAddr(a *net.UDPAddr, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.udpConn == nil {
		http.Error(w, "middle data plane not ready", http.StatusServiceUnavailable)
		return
	}
	if strings.TrimSpace(s.entryDataAddr) == "" || strings.TrimSpace(s.exitDataAddr) == "" {
		http.Error(w, "middle static route not configured", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Service) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	state := s.state
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entry_to_exit": state.entryToExit,
		"exit_to_entry": state.exitToEntry,
		"last_len":      state.lastLen,
		"last_src":      state.lastSrc,
		"last_target":   state.lastTarget,
		"last_at_utc":   state.lastAt.Format(time.RFC3339),
	})
}

func (s *Service) writeObserved(state middleRouteState) {
	if s.observedFile == "" {
		return
	}
	content := fmt.Sprintf("entry_to_exit=%d exit_to_entry=%d last_len=%d last_src=%s last_target=%s at=%s\n",
		state.entryToExit,
		state.exitToEntry,
		state.lastLen,
		state.lastSrc,
		state.lastTarget,
		state.lastAt.Format(time.RFC3339),
	)
	if err := os.WriteFile(s.observedFile, []byte(content), 0o600); err != nil {
		log.Printf("middle relay observed-file write failed: %v", err)
	}
}

func (s *Service) removeReadyFile() {
	if s.readyFile == "" {
		return
	}
	if err := os.Remove(s.readyFile); err != nil && !os.IsNotExist(err) {
		log.Printf("middle relay ready-file cleanup failed: %v", err)
	}
}
