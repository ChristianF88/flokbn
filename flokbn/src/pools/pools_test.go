package pools

import "testing"

// TestSeqNodeAllocatorDistinctZeroed verifies the lock-free sequential
// allocator also hands out distinct, zeroed nodes across chunk boundaries.
func TestSeqNodeAllocatorDistinctZeroed(t *testing.T) {
	a := NewSeqNodeAllocator()
	const n = 16384*2 + 5
	seen := make(map[*TrieNode]struct{}, n)
	for i := 0; i < n; i++ {
		node := a.GetNode()
		if node == nil {
			t.Fatalf("GetNode returned nil at i=%d", i)
		}
		if node.Children[0] != nil || node.Children[1] != nil || node.Count != 0 {
			t.Fatalf("GetNode returned non-zeroed node at i=%d: %+v", i, *node)
		}
		if _, dup := seen[node]; dup {
			t.Fatalf("GetNode returned a duplicate pointer at i=%d", i)
		}
		seen[node] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct nodes, got %d", n, len(seen))
	}
}
