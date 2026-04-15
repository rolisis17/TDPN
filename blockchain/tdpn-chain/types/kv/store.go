package kv

// Store defines the minimal key/value operations needed by keeper adapters.
type Store interface {
	Get(key []byte) ([]byte, bool)
	Set(key, value []byte)
	Delete(key []byte)
	IteratePrefix(prefix []byte, fn func(key, value []byte) bool)
}
