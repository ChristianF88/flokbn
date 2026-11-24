package pools

import (
	"sync"
)

// TrieNode structure (defined here to avoid import cycles)
type TrieNode struct {
	Children [2]*TrieNode
	Count    uint32
}

// NodeAllocator pre-allocates chunks of nodes for better performance and
// is safe for concurrent GetNode calls (mutex-guarded). Its only user is
// trie.NewTrie(), which no production path calls any more: both the static
// pipeline and the live sliding window build their tries from a single
// goroutine with trie.NewTrieSeq, on the lock-free SeqNodeAllocator below.
// NewTrie() remains for tests and benchmarks.
type NodeAllocator struct {
	mu           sync.Mutex
	chunks       [][]TrieNode
	currentIndex int
	chunkSize    int
}

// NewNodeAllocator creates a new node allocator
func NewNodeAllocator() *NodeAllocator {
	return &NodeAllocator{
		chunks:    make([][]TrieNode, 0, 10),
		chunkSize: 16384, // Allocate nodes in chunks of 16K (16384 * 24 bytes = ~384KB per chunk, reduces mutex acquisitions)
	}
}

// GetNode returns a pointer to a new zeroed TrieNode.
// Thread-safe. Chunk allocation happens outside the lock to avoid
// holding the mutex during a 16384 * 24 = ~384KB heap allocation.
func (na *NodeAllocator) GetNode() *TrieNode {
	na.mu.Lock()

	// Fast path: space available in current (last) chunk
	if len(na.chunks) > 0 && na.currentIndex < na.chunkSize {
		node := &na.chunks[len(na.chunks)-1][na.currentIndex]
		na.currentIndex++
		na.mu.Unlock()
		return node
	}
	na.mu.Unlock()

	// Slow path: allocate new chunk outside the lock
	newChunk := make([]TrieNode, na.chunkSize)

	na.mu.Lock()
	// Double-check: another goroutine may have already allocated a chunk
	if len(na.chunks) == 0 || na.currentIndex >= na.chunkSize {
		na.chunks = append(na.chunks, newChunk)
		na.currentIndex = 0
	}

	node := &na.chunks[len(na.chunks)-1][na.currentIndex]
	na.currentIndex++
	na.mu.Unlock()
	return node
}

// SeqNodeAllocator is a lock-free bump allocator for single-threaded trie
// builds. It hands out zeroed TrieNodes from chunk-sized backing arrays and
// retains every chunk so the returned pointers stay valid for the lifetime of
// the allocator. It is NOT safe for concurrent use.
type SeqNodeAllocator struct {
	chunk     []TrieNode
	idx       int
	chunkSize int
	chunks    [][]TrieNode
}

// NewSeqNodeAllocator creates a new lock-free sequential allocator.
func NewSeqNodeAllocator() *SeqNodeAllocator {
	return &SeqNodeAllocator{chunkSize: 16384}
}

// GetNode returns a pointer to a new zeroed TrieNode.
// Single-thread use only; no synchronization. make() zeroes each chunk so the
// returned node has Children=[nil,nil] and Count=0.
func (a *SeqNodeAllocator) GetNode() *TrieNode {
	if a.idx >= len(a.chunk) {
		a.chunk = make([]TrieNode, a.chunkSize)
		a.chunks = append(a.chunks, a.chunk)
		a.idx = 0
	}
	n := &a.chunk[a.idx]
	a.idx++
	return n
}
