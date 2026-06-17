package trie

import (
	"net"
	"sync"
)

// LockedTrie wraps a Trie with a RWMutex so a trie built by one goroutine can
// be safely queried from others (CountAll / CountInRange). To make that safety
// honest, the write/build methods (BuildSorted, Insert) are shadowed below and
// take the write lock, so the embedded *Trie is never mutated while a reader
// holds the read lock. The embedded SeqNodeAllocator is still not safe for
// concurrent node allocation, so all writes must come from a single goroutine;
// the lock only serializes writes against concurrent readers.
type LockedTrie struct {
	*Trie
	mutex sync.RWMutex
}

// NewLockedTrieSeq creates a LockedTrie whose embedded Trie is backed by the
// lock-free sequential bump allocator (see NewTrieSeq). It is intended for the
// single-threaded static build path where each trie is built by exactly one
// goroutine via BuildSorted; the embedded mutex then guards concurrent
// read-side queries (CountAll, CountInRange). The seq allocator
// is not safe for concurrent node allocation, so all inserts must come from a
// single goroutine.
func NewLockedTrieSeq() *LockedTrie {
	return &LockedTrie{
		Trie: NewTrieSeq(),
	}
}

// BuildSorted builds the embedded trie under the write lock so the build is
// serialized against concurrent read-side queries. It shadows Trie.BuildSorted.
func (lt *LockedTrie) BuildSorted(ips []uint32) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()
	lt.Trie.BuildSorted(ips)
}

// Insert adds an IP under the write lock so the mutation is serialized against
// concurrent read-side queries. It shadows Trie.Insert.
func (lt *LockedTrie) Insert(ip net.IP) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()
	lt.Trie.Insert(ip)
}

// CountAll returns the total count thread-safely. It shadows the embedded
// Trie.CountAll, adding read-locking.
func (lt *LockedTrie) CountAll() uint32 {
	lt.mutex.RLock()
	defer lt.mutex.RUnlock()
	return lt.Trie.CountAll()
}

// CountInRange returns count in CIDR range thread-safely. It shadows the
// embedded Trie.CountInRange, adding read-locking.
func (lt *LockedTrie) CountInRange(cidr string) (uint32, error) {
	lt.mutex.RLock()
	defer lt.mutex.RUnlock()
	return lt.Trie.CountInRange(cidr)
}
