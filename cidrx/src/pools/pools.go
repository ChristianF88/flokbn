package pools

import (
	"sync"
)

// TrieNode structure (defined here to avoid import cycles)
type TrieNode struct {
	Children [2]*TrieNode
	Count    uint32
}

// NodeAllocator pre-allocates chunks of nodes for better performance
// Thread-safe allocator with mutex protection
type NodeAllocator struct {
	mu           sync.Mutex
	chunks       [][]TrieNode
	currentChunk int
	currentIndex int
	chunkSize    int
}

// NewNodeAllocator creates a new node allocator
func NewNodeAllocator() *NodeAllocator {
	return &NodeAllocator{
		chunks:    make([][]TrieNode, 0, 10),
		chunkSize: 16384, // Allocate nodes in chunks of 16K (~320KB per chunk, reduces mutex acquisitions)
	}
}

// GetNode returns a pointer to a new zeroed TrieNode.
// Thread-safe. Chunk allocation happens outside the lock to avoid
// holding the mutex during a ~49KB heap allocation.
func (na *NodeAllocator) GetNode() *TrieNode {
	na.mu.Lock()

	// Fast path: space available in current chunk
	if len(na.chunks) > 0 && na.currentIndex < na.chunkSize {
		node := &na.chunks[na.currentChunk][na.currentIndex]
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
		na.currentChunk = len(na.chunks) - 1
		na.currentIndex = 0
	}

	node := &na.chunks[na.currentChunk][na.currentIndex]
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

// GlobalPools provides centralized memory pooling for performance optimization
type GlobalPools struct {
	StringSlices sync.Pool
}

// Pools is the global instance of memory pools
var Pools = &GlobalPools{
	StringSlices: sync.Pool{
		New: func() interface{} {
			slice := make([]string, 0, 256)
			return &slice
		},
	},
}

// GetStringSlice gets a string slice from the pool and resets it
func (gp *GlobalPools) GetStringSlice() []string {
	slicePtr := gp.StringSlices.Get().(*[]string)
	*slicePtr = (*slicePtr)[:0]
	return *slicePtr
}

// ReturnStringSlice returns a string slice to the pool
func (gp *GlobalPools) ReturnStringSlice(slice []string) {
	if cap(slice) < 2048 {
		emptySlice := slice[:0]
		gp.StringSlices.Put(&emptySlice)
	}
}
