package keeper

import (
	"crypto/sha256"
	"encoding/hex"
)

func testSHAProof(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
