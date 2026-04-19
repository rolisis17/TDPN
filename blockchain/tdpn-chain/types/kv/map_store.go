package kv

import (
	"sort"
	"strings"
	"sync"
)

// MapStore is a thread-safe in-memory Store implementation used for scaffolding and tests.
type MapStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMapStore builds a ready-to-use map-backed Store.
func NewMapStore() *MapStore {
	return &MapStore{
		data: make(map[string][]byte),
	}
}

var _ Store = (*MapStore)(nil)

func (s *MapStore) Get(key []byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, ok := s.data[string(key)]
	if !ok {
		return nil, false
	}

	return cloneBytes(value), true
}

func (s *MapStore) Set(key, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[string(key)] = cloneBytes(value)
}

func (s *MapStore) Delete(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, string(key))
}

func (s *MapStore) IteratePrefix(prefix []byte, fn func(key, value []byte) bool) {
	s.mu.RLock()
	keys := make([]string, 0, len(s.data))
	matchPrefix := string(prefix)
	for key := range s.data {
		if strings.HasPrefix(key, matchPrefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	entries := make([]struct {
		key   []byte
		value []byte
	}, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, struct {
			key   []byte
			value []byte
		}{
			key:   []byte(key),
			value: cloneBytes(s.data[key]),
		})
	}
	s.mu.RUnlock()

	for _, entry := range entries {
		if !fn(entry.key, entry.value) {
			return
		}
	}
}

func cloneBytes(input []byte) []byte {
	if input == nil {
		return nil
	}
	out := make([]byte, len(input))
	copy(out, input)
	return out
}
