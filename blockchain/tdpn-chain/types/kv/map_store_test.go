package kv

import "testing"

func TestMapStoreSetGetDelete(t *testing.T) {
	t.Parallel()

	store := NewMapStore()
	key := []byte("alpha")
	value := []byte("one")
	store.Set(key, value)

	value[0] = 'x'

	got, ok := store.Get(key)
	if !ok {
		t.Fatal("expected key to exist")
	}
	if string(got) != "one" {
		t.Fatalf("expected value %q, got %q", "one", string(got))
	}

	got[0] = 'z'
	again, ok := store.Get(key)
	if !ok {
		t.Fatal("expected key to exist on second read")
	}
	if string(again) != "one" {
		t.Fatalf("expected stored value to be immutable copy, got %q", string(again))
	}

	store.Delete(key)
	if _, ok := store.Get(key); ok {
		t.Fatal("expected key to be deleted")
	}
}

func TestMapStoreIteratePrefix(t *testing.T) {
	t.Parallel()

	store := NewMapStore()
	store.Set([]byte("foo/1"), []byte("a"))
	store.Set([]byte("foo/2"), []byte("b"))
	store.Set([]byte("bar/1"), []byte("c"))

	seen := make([]string, 0, 2)
	store.IteratePrefix([]byte("foo/"), func(key, value []byte) bool {
		seen = append(seen, string(key)+"="+string(value))
		return true
	})

	if len(seen) != 2 {
		t.Fatalf("expected 2 matched records, got %d", len(seen))
	}
	if seen[0] != "foo/1=a" || seen[1] != "foo/2=b" {
		t.Fatalf("unexpected iteration order/content: %+v", seen)
	}
}
