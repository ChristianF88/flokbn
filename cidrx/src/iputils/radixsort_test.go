package iputils

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

func TestRadixSortUint32_Empty(t *testing.T) {
	var data []uint32
	RadixSortUint32(data)
	if len(data) != 0 {
		t.Error("empty slice should remain empty")
	}
}

func TestRadixSortUint32_Single(t *testing.T) {
	data := []uint32{42}
	RadixSortUint32(data)
	if data[0] != 42 {
		t.Errorf("single element should remain 42, got %d", data[0])
	}
}

func TestRadixSortUint32_AlreadySorted(t *testing.T) {
	data := []uint32{1, 2, 3, 4, 5}
	RadixSortUint32(data)
	for i := 1; i < len(data); i++ {
		if data[i] < data[i-1] {
			t.Errorf("not sorted at index %d: %d < %d", i, data[i], data[i-1])
		}
	}
}

func TestRadixSortUint32_Reversed(t *testing.T) {
	data := []uint32{5, 4, 3, 2, 1}
	RadixSortUint32(data)
	expected := []uint32{1, 2, 3, 4, 5}
	for i, v := range data {
		if v != expected[i] {
			t.Errorf("index %d: expected %d, got %d", i, expected[i], v)
		}
	}
}

func TestRadixSortUint32_Duplicates(t *testing.T) {
	data := []uint32{3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5}
	RadixSortUint32(data)
	for i := 1; i < len(data); i++ {
		if data[i] < data[i-1] {
			t.Errorf("not sorted at index %d: %d < %d", i, data[i], data[i-1])
		}
	}
}

func TestRadixSortUint32_AllSame(t *testing.T) {
	data := []uint32{7, 7, 7, 7, 7}
	RadixSortUint32(data)
	for _, v := range data {
		if v != 7 {
			t.Errorf("expected 7, got %d", v)
		}
	}
}

func TestRadixSortUint32_LargeValues(t *testing.T) {
	data := []uint32{0xFFFFFFFF, 0, 0x80000000, 1, 0x7FFFFFFF}
	RadixSortUint32(data)
	expected := []uint32{0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF}
	for i, v := range data {
		if v != expected[i] {
			t.Errorf("index %d: expected %d, got %d", i, expected[i], v)
		}
	}
}

func TestRadixSortUint32_RandomData(t *testing.T) {
	sizes := []int{100, 1000, 10000, 100000}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			rng := rand.New(rand.NewSource(42))
			data := make([]uint32, size)
			for i := range data {
				data[i] = rng.Uint32()
			}

			// Sort with radix sort
			RadixSortUint32(data)

			// Verify sorted
			for i := 1; i < len(data); i++ {
				if data[i] < data[i-1] {
					t.Fatalf("not sorted at index %d: %d < %d", i, data[i], data[i-1])
				}
			}
		})
	}
}

func TestRadixSortUint32_MatchesStdSort(t *testing.T) {
	rng := rand.New(rand.NewSource(123))
	size := 50000
	data1 := make([]uint32, size)
	data2 := make([]uint32, size)
	for i := range data1 {
		v := rng.Uint32()
		data1[i] = v
		data2[i] = v
	}

	RadixSortUint32(data1)
	sort.Slice(data2, func(i, j int) bool { return data2[i] < data2[j] })

	for i := range data1 {
		if data1[i] != data2[i] {
			t.Fatalf("mismatch at index %d: radix=%d, std=%d", i, data1[i], data2[i])
		}
	}
}

func TestRadixSortUint32_SmallSlices(t *testing.T) {
	// Test sizes 2 through 64 (insertion sort boundary)
	for size := 2; size <= 64; size++ {
		rng := rand.New(rand.NewSource(int64(size)))
		data := make([]uint32, size)
		for i := range data {
			data[i] = rng.Uint32()
		}
		RadixSortUint32(data)
		for i := 1; i < len(data); i++ {
			if data[i] < data[i-1] {
				t.Fatalf("size %d: not sorted at index %d", size, i)
			}
		}
	}
}

// Benchmarks

func BenchmarkRadixVsStdSort(b *testing.B) {
	sizes := []int{1000, 10000, 100000, 500000, 1000000}

	for _, size := range sizes {
		rng := rand.New(rand.NewSource(42))
		original := make([]uint32, size)
		for i := range original {
			original[i] = rng.Uint32()
		}

		b.Run(fmt.Sprintf("RadixSort_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				data := make([]uint32, size)
				copy(data, original)
				RadixSortUint32(data)
			}
		})

		b.Run(fmt.Sprintf("StdSort_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				data := make([]uint32, size)
				copy(data, original)
				sort.Slice(data, func(a, c int) bool {
					return data[a] < data[c]
				})
			}
		})
	}
}

func TestCountDistinctSorted(t *testing.T) {
	tests := []struct {
		name string
		data []uint32
		want int
	}{
		{"empty", nil, 0},
		{"single", []uint32{42}, 1},
		{"all same", []uint32{7, 7, 7, 7}, 1},
		{"all distinct", []uint32{1, 2, 3, 4, 5}, 5},
		{"mixed runs", []uint32{1, 1, 2, 3, 3, 3, 4}, 4},
		{"duplicates at ends", []uint32{0, 0, 5, 9, 9}, 3},
		{"max values", []uint32{0, 4294967295, 4294967295}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountDistinctSorted(tt.data); got != tt.want {
				t.Errorf("CountDistinctSorted(%v) = %d, want %d", tt.data, got, tt.want)
			}
		})
	}
}

func TestCountDistinctSorted_MatchesMap(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	data := make([]uint32, 100000)
	seen := make(map[uint32]bool)
	for i := range data {
		// Constrained range to force plenty of duplicates
		data[i] = uint32(rng.Intn(30000))
		seen[data[i]] = true
	}
	RadixSortUint32(data)
	if got := CountDistinctSorted(data); got != len(seen) {
		t.Errorf("CountDistinctSorted = %d, want %d", got, len(seen))
	}
}

func BenchmarkCountDistinctSorted(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	data := make([]uint32, 1000000)
	for i := range data {
		data[i] = rng.Uint32() % 500000 // ~50% duplicates
	}
	RadixSortUint32(data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CountDistinctSorted(data)
	}
}
