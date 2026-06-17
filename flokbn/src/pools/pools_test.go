package pools

import (
	"sync"
	"testing"
)

// TestNodeAllocatorDistinctZeroed verifies GetNode hands out distinct, zeroed
// nodes and crosses a chunk boundary correctly after the currentChunk field
// removal (the allocator now indexes chunks[len(chunks)-1] directly).
func TestNodeAllocatorDistinctZeroed(t *testing.T) {
	na := NewNodeAllocator()
	// chunkSize is 16384; request enough to span more than one chunk.
	const n = 16384*2 + 5
	seen := make(map[*TrieNode]struct{}, n)
	for i := 0; i < n; i++ {
		node := na.GetNode()
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

// TestNodeAllocatorConcurrentGetNode exercises the retained mutex under
// concurrent load so `go test -race` validates the locking is correct (the
// allocator's thread-safety is documented but no production path contends it).
func TestNodeAllocatorConcurrentGetNode(t *testing.T) {
	na := NewNodeAllocator()
	const goroutines = 8
	const perG = 5000

	var wg sync.WaitGroup
	results := make([][]*TrieNode, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			local := make([]*TrieNode, perG)
			for i := 0; i < perG; i++ {
				local[i] = na.GetNode()
			}
			results[g] = local
		}(g)
	}
	wg.Wait()

	// All returned pointers must be distinct (no two GetNode calls alias).
	seen := make(map[*TrieNode]struct{}, goroutines*perG)
	for g := 0; g < goroutines; g++ {
		for _, node := range results[g] {
			if node == nil {
				t.Fatal("concurrent GetNode returned nil")
			}
			if _, dup := seen[node]; dup {
				t.Fatal("concurrent GetNode returned an aliased pointer")
			}
			seen[node] = struct{}{}
		}
	}
	if len(seen) != goroutines*perG {
		t.Fatalf("expected %d distinct nodes, got %d", goroutines*perG, len(seen))
	}
}
