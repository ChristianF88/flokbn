package pools

// TrieNode structure (defined here to avoid import cycles)
type TrieNode struct {
	Children [2]*TrieNode
	Count    uint32
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
