package trie

import (
	"sync"
)

// ParallelTrie wraps a Trie with a RWMutex so a trie built by one goroutine
// can be safely queried from others (CountAll / CountInRange).
type ParallelTrie struct {
	*Trie
	mutex sync.RWMutex
}

// NewParallelTrieSeq creates a ParallelTrie whose embedded Trie is backed by the
// lock-free sequential bump allocator (see NewTrieSeq). It is intended for the
// single-threaded static build path where each trie is built by exactly one
// goroutine via BuildSortedUint32; the embedded mutex then guards concurrent
// read-side queries (ParallelCountAll, ParallelCountInRange). The seq allocator
// is not safe for concurrent node allocation, so all inserts must come from a
// single goroutine.
func NewParallelTrieSeq() *ParallelTrie {
	return &ParallelTrie{
		Trie: NewTrieSeq(),
	}
}

// ParallelCountAll returns the total count thread-safely
func (pt *ParallelTrie) ParallelCountAll() uint32 {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.CountAll()
}

// ParallelCountInRange returns count in CIDR range thread-safely
func (pt *ParallelTrie) ParallelCountInRange(cidr string) (uint32, error) {
	pt.mutex.RLock()
	defer pt.mutex.RUnlock()
	return pt.CountInRange(cidr)
}
