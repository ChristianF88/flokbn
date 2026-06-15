package iputils

// RadixSortUint32 performs an in-place 8-bit radix sort on a slice of uint32 values.
// This is O(n) vs sort.Slice's O(n log n) and avoids interface dispatch overhead.
// For 1M uint32 values, this is typically 5-10x faster than sort.Slice.
//
// Uses 4 passes over the data (one per byte), with counting sort at each pass.
// The scratch buffer is allocated once and reused across passes.
func RadixSortUint32(data []uint32) {
	n := len(data)
	if n <= 1 {
		return
	}

	// For very small arrays, insertion sort is faster
	if n <= 64 {
		insertionSortUint32(data)
		return
	}

	// Allocate scratch buffer once for all passes
	scratch := make([]uint32, n)

	// 4 passes: sort by each byte from least significant to most significant
	// Pass 0: bits 0-7 (least significant byte)
	radixPass(data, scratch, 0)
	// Pass 1: bits 8-15
	radixPass(scratch, data, 8)
	// Pass 2: bits 16-23
	radixPass(data, scratch, 16)
	// Pass 3: bits 24-31 (most significant byte)
	radixPass(scratch, data, 24)
}

// radixPass performs one pass of counting sort based on a specific byte position.
// src is the input, dst is the output. shift is the bit position (0, 8, 16, or 24).
func radixPass(src, dst []uint32, shift uint) {
	// Count occurrences of each byte value
	var counts [256]int

	for _, v := range src {
		b := (v >> shift) & 0xFF
		counts[b]++
	}

	// Convert counts to prefix sums (starting positions)
	total := 0
	for i := range counts {
		count := counts[i]
		counts[i] = total
		total += count
	}

	// Place elements in sorted order
	for _, v := range src {
		b := (v >> shift) & 0xFF
		dst[counts[b]] = v
		counts[b]++
	}
}

// CountDistinctSorted returns the number of distinct values in an
// ASCENDING-sorted slice (e.g. the output of RadixSortUint32). It is a single
// branch-predictable linear pass with zero allocations, so it can be used to
// derive a true unique-IP count off the trie insert hot path.
func CountDistinctSorted(data []uint32) int {
	if len(data) == 0 {
		return 0
	}
	distinct := 1
	prev := data[0]
	for _, v := range data[1:] {
		if v != prev {
			distinct++
			prev = v
		}
	}
	return distinct
}

// insertionSortUint32 for small slices where radix overhead isn't worthwhile
func insertionSortUint32(data []uint32) {
	for i := 1; i < len(data); i++ {
		key := data[i]
		j := i - 1
		for j >= 0 && data[j] > key {
			data[j+1] = data[j]
			j--
		}
		data[j+1] = key
	}
}
