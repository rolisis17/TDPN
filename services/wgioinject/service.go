package wgioinject

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
)

type Service struct {
	targetAddr string
	interval   time.Duration
	wgLikePct  int
}

func New() *Service {
	target := envOr("WGIOINJECT_TARGET_ADDR", "127.0.0.1:52000")
	intervalMS := envOr("WGIOINJECT_INTERVAL_MS", "200")
	iv, err := strconv.Atoi(intervalMS)
	if err != nil || iv <= 0 {
		iv = 200
	}
	pctStr := envOr("WGIOINJECT_WG_LIKE_PCT", "80")
	pct, err := strconv.Atoi(pctStr)
	if err != nil || pct < 0 || pct > 100 {
		pct = 80
	}
	return &Service{targetAddr: target, interval: time.Duration(iv) * time.Millisecond, wgLikePct: pct}
}

func (s *Service) Run(ctx context.Context) error {
	target, err := net.ResolveUDPAddr("udp", s.targetAddr)
	if err != nil {
		return fmt.Errorf("resolve inject target: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return fmt.Errorf("dial inject target: %w", err)
	}
	defer conn.Close()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	log.Printf("wgioinject enabled: target=%s interval=%s wg_like_pct=%d", s.targetAddr, s.interval, s.wgLikePct)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	count := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			count++
			pkt := makePacket(rng.Intn(100) < s.wgLikePct, count)
			if _, err := conn.Write(pkt); err != nil {
				return err
			}
			if count%20 == 0 {
				log.Printf("wgioinject sent packets=%d", count)
			}
		}
	}
}

func makePacket(wgLike bool, seq int) []byte {
	if wgLike {
		return []byte{1, 0, 0, 0, byte(seq & 0xff), 0x41, 0x42, 0x43, 0x44}
	}
	return []byte(fmt.Sprintf("nonwg-%d", seq))
}

func envOr(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
