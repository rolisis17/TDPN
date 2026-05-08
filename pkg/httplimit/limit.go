package httplimit

import (
	"sync"
	"time"
)

type FixedWindowLimiter struct {
	mu        sync.Mutex
	rps       int
	maxKeys   int
	buckets   map[string]rateBucket
	nextPrune int64
}

type rateBucket struct {
	windowUnix int64
	count      int
}

func NewFixedWindowLimiter(rps int, maxKeys int) *FixedWindowLimiter {
	if rps <= 0 {
		return nil
	}
	if maxKeys < 0 {
		maxKeys = 0
	}
	return &FixedWindowLimiter{
		rps:     rps,
		maxKeys: maxKeys,
		buckets: make(map[string]rateBucket),
	}
}

func (l *FixedWindowLimiter) Allow(key string, now time.Time) bool {
	if l == nil || l.rps <= 0 {
		return true
	}
	if key == "" {
		key = "unknown"
	}
	nowSec := now.Unix()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(nowSec)
	b, exists := l.buckets[key]
	if !exists && l.maxKeys > 0 && len(l.buckets) >= l.maxKeys {
		return false
	}
	if b.windowUnix != nowSec {
		b.windowUnix = nowSec
		b.count = 0
	}
	b.count++
	l.buckets[key] = b
	return b.count <= l.rps
}

func (l *FixedWindowLimiter) pruneLocked(nowSec int64) {
	if nowSec < l.nextPrune {
		return
	}
	l.nextPrune = nowSec + 1
	for key, b := range l.buckets {
		if b.windowUnix <= 0 || nowSec-b.windowUnix > 3 {
			delete(l.buckets, key)
		}
	}
}

type InflightLimiter struct {
	sem chan struct{}
}

func NewInflightLimiter(max int) *InflightLimiter {
	if max <= 0 {
		return nil
	}
	return &InflightLimiter{sem: make(chan struct{}, max)}
}

func (l *InflightLimiter) Acquire() (func(), bool) {
	if l == nil || l.sem == nil {
		return func() {}, true
	}
	select {
	case l.sem <- struct{}{}:
		return func() {
			select {
			case <-l.sem:
			default:
			}
		}, true
	default:
		return nil, false
	}
}
