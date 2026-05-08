package httplimit

import (
	"testing"
	"time"
)

func TestFixedWindowLimiterAllow(t *testing.T) {
	limiter := NewFixedWindowLimiter(2, 0)
	now := time.Unix(100, 0)

	if !limiter.Allow("client-a", now) {
		t.Fatal("first request should pass")
	}
	if !limiter.Allow("client-a", now) {
		t.Fatal("second request should pass")
	}
	if limiter.Allow("client-a", now) {
		t.Fatal("third request in same window should be limited")
	}
	if !limiter.Allow("client-a", now.Add(time.Second)) {
		t.Fatal("new second should reset fixed window")
	}
}

func TestFixedWindowLimiterMaxKeys(t *testing.T) {
	limiter := NewFixedWindowLimiter(2, 1)
	now := time.Unix(0, 0)

	if !limiter.Allow("client-a", now) {
		t.Fatal("first key should pass")
	}
	if !limiter.Allow("client-a", now) {
		t.Fatal("existing key should not be rejected as a new key at unix epoch")
	}
	if limiter.Allow("client-b", now) {
		t.Fatal("second key should be rejected while key table is full")
	}
	if !limiter.Allow("client-b", now.Add(5*time.Second)) {
		t.Fatal("stale key should be pruned after retention window")
	}
}

func TestFixedWindowLimiterNilAndDisabled(t *testing.T) {
	if NewFixedWindowLimiter(0, 10) != nil {
		t.Fatal("non-positive rps should disable limiter")
	}
	var limiter *FixedWindowLimiter
	if !limiter.Allow("client-a", time.Now()) {
		t.Fatal("nil limiter should allow")
	}
}

func TestInflightLimiter(t *testing.T) {
	limiter := NewInflightLimiter(1)
	release, ok := limiter.Acquire()
	if !ok {
		t.Fatal("first acquire should pass")
	}
	if _, ok := limiter.Acquire(); ok {
		t.Fatal("second acquire should be limited")
	}
	release()
	if _, ok := limiter.Acquire(); !ok {
		t.Fatal("acquire should pass after release")
	}
}

func TestInflightLimiterNilAndDisabled(t *testing.T) {
	if NewInflightLimiter(0) != nil {
		t.Fatal("non-positive max should disable limiter")
	}
	var limiter *InflightLimiter
	release, ok := limiter.Acquire()
	if !ok {
		t.Fatal("nil limiter should allow")
	}
	release()
}
