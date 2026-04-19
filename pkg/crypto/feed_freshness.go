package crypto

import (
	"fmt"
	"time"
)

const (
	relayFeedMaxFutureSkew = 60 * time.Second
	relayFeedMaxAge        = 24 * time.Hour
	relayFeedMaxLifetime   = 24 * time.Hour
)

func verifySignedFeedFreshness(feedType string, generatedAt, expiresAt int64, now time.Time) error {
	if generatedAt <= 0 {
		return fmt.Errorf("%s missing generated_at", feedType)
	}
	if expiresAt <= 0 {
		return fmt.Errorf("%s missing expires_at", feedType)
	}
	if expiresAt <= generatedAt {
		return fmt.Errorf("%s expires_at must be greater than generated_at", feedType)
	}
	if expiresAt-generatedAt > int64(relayFeedMaxLifetime/time.Second) {
		return fmt.Errorf("%s expires_at exceeds max lifetime", feedType)
	}

	nowUnix := now.Unix()
	if nowUnix >= expiresAt {
		return fmt.Errorf("%s expired", feedType)
	}
	if generatedAt > nowUnix+int64(relayFeedMaxFutureSkew/time.Second) {
		return fmt.Errorf("%s generated_at too far in future", feedType)
	}
	if expiresAt > nowUnix+int64((relayFeedMaxFutureSkew+relayFeedMaxLifetime)/time.Second) {
		return fmt.Errorf("%s expires_at too far in future", feedType)
	}
	if generatedAt < nowUnix-int64(relayFeedMaxAge/time.Second) {
		return fmt.Errorf("%s stale: generated_at exceeds max age", feedType)
	}
	return nil
}
