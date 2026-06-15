package logparser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ChristianF88/flokbn/ingestor"
)

// FieldExtractor represents a compiled field extraction operation
type FieldExtractor struct {
	FieldType int  // 0=IP, 1=timestamp, 2=method, 3=URI, 4=status, 5=bytes, 6=user-agent, 7=referer, -1=skip
	Delimiter byte // delimiter to find (space, quote, bracket)
	Quoted    bool // whether field is in quotes
	Brackets  bool // whether field is in brackets
}

// CompiledFormat represents a pre-compiled log format for fast parsing
type CompiledFormat struct {
	extractors []FieldExtractor
	pattern    string
	counters   *parseCounters
}

// parseCounters holds malformed-field tallies shared by all parse workers.
// Heap-allocated separately from CompiledFormat so the write-on-failure
// counters never share a cache line with the read-only hot fields.
type parseCounters struct {
	malformedStatus atomic.Uint64
	malformedBytes  atomic.Uint64
}

// ParseStats is a snapshot of malformed-field counters, cumulative across
// all ParseFile* calls on the same Parser.
type ParseStats struct {
	MalformedStatus uint64
	MalformedBytes  uint64
}

// Parser provides high-performance log parsing with adaptive I/O strategies
// Combines parallel processing, object pooling, and minimal-allocation field extraction
type Parser struct {
	format           string
	compiled         *CompiledFormat
	workers          int
	SkipStringFields bool // When true, skip URI and UserAgent string allocations
	SkipNonIPFields  bool // When true, skip all non-IP field extraction (timestamp, method, status, bytes, strings)
}

// NewParser creates a high-performance log parser (recommended constructor)
func NewParser(format string) (*Parser, error) {
	// Optimize worker count for maximum parsing throughput
	workerCount := runtime.NumCPU()
	// For log parsing, fewer workers often perform better due to memory bandwidth
	if workerCount > 8 {
		workerCount = 8 // Cap at 8 workers for optimal performance
	}

	p := &Parser{
		format:  format,
		workers: workerCount,
	}

	// Compile format string into optimized extractors
	compiled, err := compileFormat(format)
	if err != nil {
		return nil, err
	}
	p.compiled = compiled

	return p, nil
}

// Stats returns a snapshot of the malformed-field counters, cumulative across
// all ParseFile* calls on this Parser. The snapshot is valid (complete) once a
// ParseFile* call has returned: every parse path joins its workers via a
// WaitGroup before returning, which provides the happens-before edge for the
// atomic loads here.
func (pp *Parser) Stats() ParseStats {
	return ParseStats{
		MalformedStatus: pp.compiled.counters.malformedStatus.Load(),
		MalformedBytes:  pp.compiled.counters.malformedBytes.Load(),
	}
}

// ParseFile parses a log file using adaptive I/O strategy (primary interface)
// Automatically chooses between streaming I/O (small files) and chunked I/O (large files)
// This is the recommended method for all file parsing operations.
func (pp *Parser) ParseFile(filename string) ([]ingestor.Request, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size to decide on optimal parsing strategy
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()

	// For files smaller than 500MB, use streaming I/O (better performance)
	const largeFileThreshold = 500 * 1024 * 1024 // 500MB
	if fileSize < largeFileThreshold {
		return pp.parseFileWithStreamingIO(filename)
	}

	// For large files, use chunked concurrent I/O
	return pp.parseFileWithConcurrentIO(file, fileSize)
}

// ParseFileIPs parses a log file extracting ONLY the IPv4 address of each line
// as a uint32, skipping all other field work and never allocating an
// ingestor.Request. It uses the same adaptive streaming/concurrent I/O
// structure as ParseFile (same slab+batch line readers).
//
// Returns the slice of nonzero IPs (lines whose IP parsed successfully) and
// invalidCount = the number of lines whose IP failed to parse (extractIPOnly
// returned 0). This matches the downstream "invalid/missing IP" semantics:
// nonzero IPs flow into the trie, zero IPs are counted invalid. Order is not
// preserved (downstream radix-sorts), but the multiset of nonzero IPs and the
// invalid count are identical to ParseFile's req.IPUint32 stream.
func (pp *Parser) ParseFileIPs(filename string) (ips []uint32, invalidCount int, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	fileSize := stat.Size()

	const largeFileThreshold = 500 * 1024 * 1024 // 500MB
	if fileSize < largeFileThreshold {
		return pp.parseFileIPsStreamingIO(filename)
	}
	return pp.parseFileIPsConcurrentIO(file, fileSize)
}

// ipResult carries an IP-only worker batch plus its invalid count back to the
// collector, so invalid lines are counted without shipping zero IPs.
type ipResult struct {
	ips     []uint32
	invalid int
}

// parseFileIPsStreamingIO mirrors parseFileWithStreamingIO but the worker stage
// calls extractIPOnly and accumulates []uint32 (skipping/counting zero IPs).
func (pp *Parser) parseFileIPsStreamingIO(filename string) ([]uint32, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	estimatedLines := 1000
	if stat, err := file.Stat(); err == nil {
		estimatedLines = int(stat.Size() / 200)
		if estimatedLines < 1000 {
			estimatedLines = 1000
		}
	}

	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan ipResult, pp.workers*2)

	var wg sync.WaitGroup
	cf := pp.compiled
	for i := 0; i < pp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range linesChan {
				res := make([]uint32, 0, len(batch))
				invalid := 0
				for _, line := range batch {
					ip := cf.extractIPOnly(line)
					if ip != 0 {
						res = append(res, ip)
					} else {
						invalid++
					}
				}
				if len(res) > 0 || invalid > 0 {
					resultsChan <- ipResult{ips: res, invalid: invalid}
				}
			}
		}()
	}

	ips := make([]uint32, 0, estimatedLines)
	invalidCount := 0
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for r := range resultsChan {
			ips = append(ips, r.ips...)
			invalidCount += r.invalid
		}
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 256*1024), 2*1024*1024)

	const slabSize = 256 * 1024
	batch := make([][]byte, 0, parseBatchSize)
	slab := make([]byte, 0, slabSize)
	for scanner.Scan() {
		scanBytes := scanner.Bytes()
		lineLen := len(scanBytes)

		if len(slab)+lineLen > cap(slab) {
			newCap := slabSize
			if lineLen > newCap {
				newCap = lineLen
			}
			slab = make([]byte, 0, newCap)
		}

		start := len(slab)
		slab = append(slab, scanBytes...)
		batch = append(batch, slab[start:start+lineLen])

		if len(batch) >= parseBatchSize {
			linesChan <- batch
			batch = make([][]byte, 0, parseBatchSize)
			slab = make([]byte, 0, slabSize)
		}
	}
	if len(batch) > 0 {
		linesChan <- batch
	}

	close(linesChan)
	wg.Wait()
	close(resultsChan)
	collectorWG.Wait()

	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}

	return ips, invalidCount, nil
}

// parseFileIPsConcurrentIO mirrors parseFileWithConcurrentIO but extracts only
// IPs. It reuses readChunkBatched verbatim for the I/O stage.
func (pp *Parser) parseFileIPsConcurrentIO(file *os.File, fileSize int64) ([]uint32, int, error) {
	return pp.parseFileIPsConcurrentIOChunked(file, fileSize, defaultConcurrentChunkSize)
}

// defaultConcurrentChunkSize is the production chunk size (64MB) for the
// concurrent I/O path. Extracted as a constant so tests can drive the concurrent
// path with a small chunk size on a normal-sized file (many chunks + boundary
// crossings) without allocating a >=500MB file.
const defaultConcurrentChunkSize = 64 * 1024 * 1024

// parseFileIPsConcurrentIOChunked is the chunk-size-parameterized implementation
// of parseFileIPsConcurrentIO. Production callers use defaultConcurrentChunkSize;
// tests override chunkSize to exercise boundary handling on small files.
func (pp *Parser) parseFileIPsConcurrentIOChunked(file *os.File, fileSize int64, chunkSize int64) ([]uint32, int, error) {
	numChunks := int(fileSize / chunkSize)
	if fileSize%chunkSize != 0 {
		numChunks++
	}

	maxConcurrentChunks := runtime.NumCPU()
	if maxConcurrentChunks > 8 {
		maxConcurrentChunks = 8
	}

	estimatedLines := int(fileSize / 150)
	if estimatedLines < 1000 {
		estimatedLines = 1000
	}

	chunkJobs := make(chan chunkJob, numChunks)
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan ipResult, pp.workers*2)

	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range chunkJobs {
				pp.readChunkBatched(file, job, fileSize, linesChan)
			}
		}()
	}

	cf := pp.compiled
	var parserWG sync.WaitGroup
	for i := 0; i < pp.workers; i++ {
		parserWG.Add(1)
		go func() {
			defer parserWG.Done()
			for batch := range linesChan {
				res := make([]uint32, 0, len(batch))
				invalid := 0
				for _, line := range batch {
					ip := cf.extractIPOnly(line)
					if ip != 0 {
						res = append(res, ip)
					} else {
						invalid++
					}
				}
				if len(res) > 0 || invalid > 0 {
					resultsChan <- ipResult{ips: res, invalid: invalid}
				}
			}
		}()
	}

	ips := make([]uint32, 0, estimatedLines)
	invalidCount := 0
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for r := range resultsChan {
			ips = append(ips, r.ips...)
			invalidCount += r.invalid
		}
	}()

	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize
		if end > fileSize {
			end = fileSize
		}
		chunkJobs <- chunkJob{start: start, end: end, index: i}
	}
	close(chunkJobs)

	wg.Wait()
	close(linesChan)
	parserWG.Wait()
	close(resultsChan)
	collectorWG.Wait()

	return ips, invalidCount, nil
}

// parseBatchSize is the number of lines per batch sent through channels.
// Batching amortizes channel lock/unlock overhead: 1M lines = ~1K channel ops instead of 1M.
const parseBatchSize = 1024

// parseFileWithStreamingIO uses streaming I/O with batched parallel parsing workers (internal method)
func (pp *Parser) parseFileWithStreamingIO(filename string) ([]ingestor.Request, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get file size for pre-allocation estimate
	estimatedLines := 1000
	if stat, err := file.Stat(); err == nil {
		estimatedLines = int(stat.Size() / 200) // ~200 bytes per log line estimate
		if estimatedLines < 1000 {
			estimatedLines = 1000
		}
	}

	// Batched channels — each send/receive moves parseBatchSize items at once,
	// reducing channel operations from O(lines) to O(lines/batchSize).
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan []ingestor.Request, pp.workers*2)

	var wg sync.WaitGroup

	// Capture skip flags for use in worker goroutines
	skipStrings := pp.SkipStringFields
	skipNonIP := pp.SkipNonIPFields

	// Start parser workers — each worker reuses a single Request for parsing
	for i := 0; i < pp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &ingestor.Request{}
			for batch := range linesChan {
				resBatch := make([]ingestor.Request, 0, len(batch))
				for _, line := range batch {
					*req = ingestor.Request{}
					if err := pp.compiled.parseLineReuseOpt(line, req, skipStrings, skipNonIP); err == nil {
						resBatch = append(resBatch, *req)
					}
				}
				if len(resBatch) > 0 {
					resultsChan <- resBatch
				}
			}
		}()
	}

	// Start result collector with pre-allocated slice
	results := make([]ingestor.Request, 0, estimatedLines)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)

	go func() {
		defer collectorWG.Done()
		for batch := range resultsChan {
			results = append(results, batch...)
		}
	}()

	// I/O reader — accumulate lines into batches before sending
	// Uses a slab allocator: one contiguous []byte per batch instead of one per line.
	// Reduces allocations from O(lines) to O(lines/batchSize).
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 256*1024), 2*1024*1024) // 256KB initial, 2MB max

	const slabSize = 256 * 1024 // 256KB slab per batch (~250 bytes/line * 1024 lines)
	batch := make([][]byte, 0, parseBatchSize)
	slab := make([]byte, 0, slabSize)
	for scanner.Scan() {
		scanBytes := scanner.Bytes()
		lineLen := len(scanBytes)

		// If this line won't fit in the current slab, allocate a new one
		if len(slab)+lineLen > cap(slab) {
			newCap := slabSize
			if lineLen > newCap {
				newCap = lineLen // handle lines larger than slab
			}
			slab = make([]byte, 0, newCap)
		}

		// Sub-allocate from slab: append line bytes, then slice out the line
		start := len(slab)
		slab = append(slab, scanBytes...)
		batch = append(batch, slab[start:start+lineLen])

		if len(batch) >= parseBatchSize {
			linesChan <- batch
			batch = make([][]byte, 0, parseBatchSize)
			slab = make([]byte, 0, slabSize)
		}
	}
	// Send remaining lines
	if len(batch) > 0 {
		linesChan <- batch
	}

	// Shutdown pipeline
	close(linesChan)   // Signal workers to stop
	wg.Wait()          // Wait for all workers to finish
	close(resultsChan) // Signal collector to stop
	collectorWG.Wait() // Wait for collector to finish

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// parseFileWithConcurrentIO implements concurrent chunked file reading.
// Uses ReadAt for thread-safe parallel reads, batched channels matching the
// streaming path, and per-worker Request reuse (no sync.Pool needed).
func (pp *Parser) parseFileWithConcurrentIO(file *os.File, fileSize int64) ([]ingestor.Request, error) {
	return pp.parseFileConcurrentIOChunked(file, fileSize, defaultConcurrentChunkSize)
}

// parseFileConcurrentIOChunked is the chunk-size-parameterized implementation of
// parseFileWithConcurrentIO. Production callers use defaultConcurrentChunkSize
// (64MB); tests override chunkSize to exercise the concurrent path on small files.
func (pp *Parser) parseFileConcurrentIOChunked(file *os.File, fileSize int64, chunkSize int64) ([]ingestor.Request, error) {
	numChunks := int(fileSize / chunkSize)
	if fileSize%chunkSize != 0 {
		numChunks++
	}

	// Limit concurrent chunk readers
	maxConcurrentChunks := runtime.NumCPU()
	if maxConcurrentChunks > 8 {
		maxConcurrentChunks = 8
	}

	// Estimate total lines for pre-allocation
	estimatedLines := int(fileSize / 150)
	if estimatedLines < 1000 {
		estimatedLines = 1000
	}

	// Batched channels — same pattern as streaming path
	chunkJobs := make(chan chunkJob, numChunks)
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan []ingestor.Request, pp.workers*2)

	var wg sync.WaitGroup

	// Start chunk readers — use ReadAt (pread64) for thread-safe parallel reads
	// on the same file descriptor. No file handle pool needed.
	for i := 0; i < maxConcurrentChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range chunkJobs {
				pp.readChunkBatched(file, job, fileSize, linesChan)
			}
		}()
	}

	// Start parser workers — per-worker Request reuse (matches streaming path)
	skipStrings := pp.SkipStringFields
	skipNonIP := pp.SkipNonIPFields
	var parserWG sync.WaitGroup
	for i := 0; i < pp.workers; i++ {
		parserWG.Add(1)
		go func() {
			defer parserWG.Done()
			req := &ingestor.Request{}
			for batch := range linesChan {
				resBatch := make([]ingestor.Request, 0, len(batch))
				for _, line := range batch {
					*req = ingestor.Request{}
					if err := pp.compiled.parseLineReuseOpt(line, req, skipStrings, skipNonIP); err == nil {
						resBatch = append(resBatch, *req)
					}
				}
				if len(resBatch) > 0 {
					resultsChan <- resBatch
				}
			}
		}()
	}

	// Start result collector with pre-allocated slice
	results := make([]ingestor.Request, 0, estimatedLines)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for batch := range resultsChan {
			results = append(results, batch...)
		}
	}()

	// Enqueue chunk jobs
	for i := 0; i < numChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize
		if end > fileSize {
			end = fileSize
		}
		chunkJobs <- chunkJob{start: start, end: end, index: i}
	}
	close(chunkJobs)

	// Shutdown pipeline
	wg.Wait()
	close(linesChan)
	parserWG.Wait()
	close(resultsChan)
	collectorWG.Wait()

	return results, nil
}

// chunkJob represents a file chunk to be read
type chunkJob struct {
	start int64
	end   int64
	index int
}

// readChunkBatched reads a file chunk using ReadAt and sends batched line slices.
//
// Lines are zero-copy sub-slices of the chunk's freshly-allocated `buffer`: one
// allocation per chunk is shared by all of that chunk's line slices. No slab copy
// is performed (unlike the streaming path, which must copy because bufio.Scanner
// reuses its internal buffer). The buffer is never mutated or reused after ReadAt,
// so the sub-slices remain valid for the lifetime of the resulting Requests.
//
// Lifetime: in full-Request mode, parseUsingCompiledFormatOpt stores URI/UserAgent
// as unsafe.String views aliasing the line bytes; those strings keep `buffer`
// reachable so the GC retains it as long as any Request lives. In IP-only mode
// nothing aliases the bytes, so the buffer is freed once the chunk is parsed.
func (pp *Parser) readChunkBatched(file *os.File, job chunkJob, fileSize int64, linesChan chan<- [][]byte) {
	chunkLen := job.end - job.start
	if chunkLen <= 0 {
		return
	}

	// Read the chunk with overlap for line boundary handling. For non-first
	// chunks we additionally read ONE byte before job.start (the "sentinel"): it
	// lets us tell whether a line begins exactly at the chunk boundary (sentinel
	// == '\n') versus the boundary falling mid-line. Without this, a line whose
	// start offset equals job.start would be owned by neither chunk (the previous
	// chunk stops at job.end; this chunk would skip it as a leading partial line).
	overlap := int64(8192)
	readEnd := job.end + overlap
	if readEnd > fileSize {
		readEnd = fileSize
	}

	// readStart is the absolute file offset of buffer[0]. `pad` is the number of
	// sentinel bytes prepended (1 for non-first chunks, 0 for chunk 0).
	readStart := job.start
	pad := 0
	if job.index > 0 {
		readStart = job.start - 1
		pad = 1
	}
	readSize := readEnd - readStart

	buffer := make([]byte, readSize)
	n, err := file.ReadAt(buffer, readStart)
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "readChunkBatched: ReadAt offset %d: %v\n", readStart, err)
		return
	}
	buffer = buffer[:n]
	if len(buffer) < pad {
		return
	}

	// Ownership rule (must exactly partition the file so every physical line is
	// emitted by exactly one chunk, with no loss or duplication):
	//
	//   A chunk owns a line iff that line's START offset lies in the half-open
	//   absolute range [job.start, job.end).
	//
	// A line "starts" at file offset 0, or at the byte immediately following a
	// newline. The line may extend (its terminating newline may fall) beyond
	// job.end into the overlap region — we read `overlap` extra bytes precisely
	// so a boundary-straddling line owned by THIS chunk can be completed here.
	//
	// Disjointness: the line straddling the boundary (start < job.end <= newline)
	// is owned by chunk N because its start is in chunk N's range. Chunk N+1 skips
	// exactly that line via the leading-newline scan below, so it is emitted once.
	//
	// `start` is the buffer-relative offset of the first line owned by this chunk.
	// The chunk boundary job.start sits at buffer offset `pad`.
	//
	//   - Chunk 0: pad == 0, start == 0 (== job.start).
	//   - Later chunks: if the sentinel byte buffer[0] (== file byte job.start-1)
	//     is a newline, a line begins exactly AT the boundary; that line's start
	//     is in [job.start, job.end) so THIS chunk owns it — start = pad.
	//     Otherwise the byte at job.start is mid-line (owned by the previous
	//     chunk); skip to just after the first newline.
	start := 0
	if job.index > 0 {
		if buffer[0] == '\n' {
			// Line starts exactly at the boundary; own it.
			start = pad
		} else {
			idx := bytes.IndexByte(buffer, '\n')
			if idx < 0 {
				// No newline in this chunk's window: the single line covering this
				// chunk started in a previous chunk and is owned there.
				return
			}
			start = idx + 1
		}
	}

	// chunkEnd is job.end expressed as a buffer-relative offset. A line is owned
	// when its START offset `start` satisfies start < chunkEnd.
	chunkEnd := pad + int(job.end-job.start)

	// Extract lines as zero-copy sub-slices of `buffer`. The whole chunk is one
	// allocation shared by every line slice; no per-line slab copy is done.
	batch := make([][]byte, 0, parseBatchSize)

	for i := start; i < len(buffer); i++ {
		if buffer[i] == '\n' {
			// Stop once the CURRENT line started at/after the chunk boundary: that
			// line is owned by the next chunk.
			if start >= chunkEnd {
				break
			}

			lineData := buffer[start:i]
			start = i + 1

			// Strip a trailing '\r' (CRLF line endings) to match the streaming
			// path's bufio.Scanner behavior.
			if n := len(lineData); n > 0 && lineData[n-1] == '\r' {
				lineData = lineData[:n-1]
			}

			if len(lineData) == 0 {
				continue
			}

			// Zero-copy: append the sub-slice of buffer directly.
			batch = append(batch, lineData)

			if len(batch) >= parseBatchSize {
				linesChan <- batch
				batch = make([][]byte, 0, parseBatchSize)
			}
		}
	}

	// Handle a final line with no terminating newline. This is the very last line
	// of a file with no trailing '\n'. It is owned by whichever chunk's read
	// reached EOF and whose range contains the line's start (start < chunkEnd).
	if readEnd == fileSize && start < len(buffer) && start < chunkEnd {
		lineData := buffer[start:]
		// Strip a trailing '\r' (file ending in "...\r" with no final '\n').
		if n := len(lineData); n > 0 && lineData[n-1] == '\r' {
			lineData = lineData[:n-1]
		}
		if len(lineData) > 0 {
			batch = append(batch, lineData)
		}
	}

	// Send remaining lines
	if len(batch) > 0 {
		linesChan <- batch
	}
}

// validateFormat ensures format string doesn't have duplicate non-skippable fields
func validateFormat(format string) error {
	fieldCounts := make(map[byte]int)

	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			field := format[i+1]

			// Skip validation for skip field (%^)
			if field == '^' {
				continue
			}

			// Count occurrences of each field type
			fieldCounts[field]++

			// Validate supported field types and check for duplicates
			switch field {
			case 'h': // IP - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate IP field (%%h) found in format string - only one IP field is allowed")
				}
			case 't': // Timestamp - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate timestamp field (%%t) found in format string - only one timestamp field is allowed")
				}
			case 'r': // Request - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate request field (%%r) found in format string - only one request field is allowed")
				}
			case 'm': // Method - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate method field (%%m) found in format string - only one method field is allowed")
				}
			case 's': // Status - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate status field (%%s) found in format string - only one status field is allowed")
				}
			case 'b': // Bytes - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate bytes field (%%b) found in format string - only one bytes field is allowed")
				}
			case 'U': // URI standalone - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate URI field (%%U) found in format string - only one URI field is allowed")
				}
			case 'u': // User agent - should only appear once
				if fieldCounts[field] > 1 {
					return fmt.Errorf("duplicate user agent field (%%u) found in format string - only one user agent field is allowed")
				}
			default:
				return fmt.Errorf("unsupported format code %%%c - supported codes are: %%h (IP), %%t (timestamp), %%r (request), %%m (method), %%s (status), %%b (bytes), %%U (URI), %%u (user-agent), %%^ (skip)", field)
			}
		}
	}

	// Ensure at least one IP field is present
	if fieldCounts['h'] == 0 {
		return fmt.Errorf("no IP field (%%h) found in format string - at least one IP field is required")
	}

	return nil
}

// compileFormat converts a format string into optimized field extractors
//
// Supported format codes:
//
//	%h - IP address (required) - maps to Request.IP
//	%t - Timestamp in brackets [DD/MMM/YYYY:HH:mm:ss +zone] - maps to Request.Timestamp
//	%r - Request line "METHOD URI HTTP/VERSION" - extracts Method and URI (ignores HTTP version)
//	%m - HTTP method standalone - maps to Request.Method
//	%U - URI standalone - maps to Request.URI
//	%s - Status code - maps to Request.Status
//	%b - Response bytes - maps to Request.Bytes
//	%u - User-Agent - maps to Request.UserAgent
//	%^ - Skip this field (ignore)
//
// Notes:
//   - %r extracts both Method and URI from quoted request line, HTTP version is ignored
//   - Fields in quotes ("") or brackets ([]) are automatically detected
//   - Delimiter-aware parsing respects comma, space, and other separators
//   - At least one %h (IP) field is required
func compileFormat(format string) (*CompiledFormat, error) {
	// Validate format first
	if err := validateFormat(format); err != nil {
		return nil, err
	}

	var extractors []FieldExtractor

	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			extractor := FieldExtractor{}

			// Determine field type
			switch format[i+1] {
			case 'h':
				extractor.FieldType = 0 // IP
			case 't':
				extractor.FieldType = 1 // Timestamp
				extractor.Brackets = true
			case 'm':
				extractor.FieldType = 2 // Method
			case 'r':
				extractor.FieldType = 3 // URI (request)
			case 's':
				extractor.FieldType = 4 // Status
			case 'b':
				extractor.FieldType = 5 // Bytes
			case 'U':
				extractor.FieldType = 7 // URI (standalone)
			case 'u':
				extractor.FieldType = 6 // User agent
				extractor.Quoted = true
			case '^':
				extractor.FieldType = -1 // Skip
			default:
				continue
			}

			// Determine delimiter and quoted status by looking ahead
			if i+2 < len(format) {
				nextChar := format[i+2]
				extractor.Delimiter = nextChar
				if nextChar == '"' {
					extractor.Quoted = true
				}
			} else {
				extractor.Delimiter = ' ' // default
			}

			extractors = append(extractors, extractor)
			i++ // Skip format character
		}
	}

	return &CompiledFormat{
		extractors: extractors,
		pattern:    format,
		counters:   &parseCounters{}, // never nil: hot path may Add without a nil check
	}, nil
}

// parseLineReuseOpt parses a log line with optional string field skipping
func (cf *CompiledFormat) parseLineReuseOpt(line []byte, req *ingestor.Request, skipStrings, skipNonIP bool) error {
	// Use compiled format extractors for optimized parsing
	if len(cf.extractors) > 0 {
		return cf.parseUsingCompiledFormatOpt(line, req, skipStrings, skipNonIP)
	}

	// If no extractors configured, skip parsing
	return nil
}

// parseUsingCompiledFormatOpt applies extractors with optional string field skipping
// When skipNonIP is true, only the IP field is extracted (all others are skipped but positions still advance)
func (cf *CompiledFormat) parseUsingCompiledFormatOpt(line []byte, req *ingestor.Request, skipStrings, skipNonIP bool) error {
	pos := 0

	for _, extractor := range cf.extractors {
		if pos >= len(line) {
			break
		}

		// Skip whitespace
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}

		start := pos

		// Handle quoted/bracketed fields
		// bytes.IndexByte uses SIMD (SSE2/AVX2) on amd64 for 8-16x faster scanning
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++ // skip opening quote
			start = pos
			if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				if idx > 0 && line[pos+idx-1] == '\\' {
					pos = scanQuotedClose(line, pos, pos+idx) // rare slow path: escaped quote
				} else {
					pos += idx
				}
			} else {
				pos = len(line)
			}
			// Don't skip closing quote yet - we'll handle it after field extraction
		} else if extractor.Brackets && pos < len(line) && line[pos] == '[' {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			// Don't skip closing bracket yet
		} else {
			// Regular field - scan until delimiter or space
			delimiter := extractor.Delimiter
			if delimiter == 0 {
				delimiter = ' ' // default to space
			}
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
		}

		// Extract and parse field if not skipped
		if extractor.FieldType >= 0 && start < pos {
			// IP is always extracted; other fields are skipped when skipNonIP is true
			if extractor.FieldType == 0 {
				req.IPUint32 = parseIPv4ToUint32(line, start, pos)
			} else if !skipNonIP {
				fieldData := line[start:pos]

				switch extractor.FieldType {
				case 1: // Timestamp
					req.Timestamp = parseTimestamp(line, start, pos)
				case 2: // Method (standalone)
					req.Method = parseMethod(line, start, pos)
				case 3: // Request line (%r) - extracts METHOD and URI, ignores HTTP version
					if extractor.Quoted {
						// Parse "METHOD URI HTTP/VERSION" format efficiently
						methodEnd := start
						for methodEnd < pos && line[methodEnd] != ' ' {
							methodEnd++
						}

						// Extract method if not already set and method field exists
						if methodEnd > start && req.Method == 0 {
							req.Method = parseMethod(line, start, methodEnd)
						}

						// Extract URI only if strings are needed
						if !skipStrings {
							// Skip spaces after method
							uriStart := methodEnd
							for uriStart < pos && line[uriStart] == ' ' {
								uriStart++
							}

							// Find end of URI (next space before HTTP version)
							uriEnd := uriStart
							for uriEnd < pos && line[uriEnd] != ' ' {
								uriEnd++
							}

							// Extract URI
							if uriEnd > uriStart {
								req.URI = bytesToString(line[uriStart:uriEnd])
							}
						}
						// HTTP version is intentionally ignored as Request struct has no field for it
					} else if !skipStrings {
						// If not quoted, treat entire field as URI
						req.URI = bytesToString(fieldData)
					}
				case 4: // Status
					if pos-start == 3 {
						_ = line[start+2] // BCE hint: eliminate 3 individual bounds checks below
						d0 := line[start] - '0'
						d1 := line[start+1] - '0'
						d2 := line[start+2] - '0'
						// Do NOT or-fold these checks: (d0|d1|d2)<=9 is wrong (2|9==11).
						// Each d<=9 byte compare exploits unsigned wraparound for non-digits.
						if d0 <= 9 && d1 <= 9 && d2 <= 9 {
							req.Status = uint16(d0)*100 + uint16(d1)*10 + uint16(d2)
						} else {
							cf.counters.malformedStatus.Add(1)
						}
					} else if !(pos-start == 1 && line[start] == '-') {
						// "-" = absent (Apache convention): silent zero. Anything else: malformed.
						cf.counters.malformedStatus.Add(1)
					}
				case 5: // Bytes
					if len(fieldData) > 0 && fieldData[0] != '-' {
						b, ok := parseBytes(line, start, pos)
						req.Bytes = b
						if !ok {
							cf.counters.malformedBytes.Add(1)
						}
					}
				case 6: // User agent
					if !skipStrings {
						req.UserAgent = bytesToString(fieldData)
					}
				case 7: // URI (standalone)
					if !skipStrings {
						req.URI = bytesToString(fieldData)
					}
				}
			}
		}

		// Advance past closing quotes/brackets/delimiters
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++
		} else if extractor.Brackets && pos < len(line) && line[pos] == ']' {
			pos++
		} else if pos < len(line) && line[pos] == extractor.Delimiter {
			pos++ // Skip the delimiter
		}
	}

	return nil
}

// extractIPOnly walks the compiled extractors exactly like
// parseUsingCompiledFormatOpt (same quoted/bracketed/delimited field
// boundary handling) but performs NO field stores, builds NO Request, and
// returns as soon as the IP field (FieldType==0) has been parsed — it never
// scans fields that come after the IP. It returns the same uint32 that
// parseUsingCompiledFormatOpt would write to req.IPUint32 (0 on a failed or
// missing IP parse).
//
// This is the dominant fast path for clustering / static analysis where only
// the IP is needed.
//
// Malformed-field counters (cf.counters) are structurally zero on this path:
// status/bytes fields are never scanned here, so IP-only parses contribute no
// malformedStatus/malformedBytes counts by design.
func (cf *CompiledFormat) extractIPOnly(line []byte) uint32 {
	pos := 0

	for ei := range cf.extractors {
		extractor := &cf.extractors[ei]
		if pos >= len(line) {
			break
		}

		// Skip whitespace
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}

		start := pos

		// Handle quoted/bracketed fields — identical boundary logic to
		// parseUsingCompiledFormatOpt so that pos lands on the same offsets.
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++ // skip opening quote
			start = pos
			if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				if idx > 0 && line[pos+idx-1] == '\\' {
					pos = scanQuotedClose(line, pos, pos+idx) // rare slow path: escaped quote
				} else {
					pos += idx
				}
			} else {
				pos = len(line)
			}
		} else if extractor.Brackets && pos < len(line) && line[pos] == '[' {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
		} else {
			delimiter := extractor.Delimiter
			if delimiter == 0 {
				delimiter = ' '
			}
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
		}

		// IP field: parse and return immediately. The guard `start < pos`
		// matches the original (only fields with content are parsed); when the
		// IP field has no content we fall through and return 0 below, which is
		// exactly what req.IPUint32 would remain (zero value).
		if extractor.FieldType == 0 {
			if start < pos {
				return parseIPv4ToUint32(line, start, pos)
			}
			return 0
		}

		// Advance past closing quotes/brackets/delimiters — identical to
		// parseUsingCompiledFormatOpt so subsequent field boundaries align.
		if extractor.Quoted && pos < len(line) && line[pos] == '"' {
			pos++
		} else if extractor.Brackets && pos < len(line) && line[pos] == ']' {
			pos++
		} else if pos < len(line) && line[pos] == extractor.Delimiter {
			pos++
		}
	}

	return 0
}

// scanQuotedClose resumes a quoted-field scan when the quote found at
// firstQuote is preceded by a backslash. A quote is escaped iff preceded by
// an ODD number of consecutive backslashes (Apache escapes `"` -> `\"` and
// `\` -> `\\`). Returns the index of the first unescaped quote at/after
// firstQuote, or len(line). Only called when an escape candidate was seen,
// so the no-escape common case never pays for this loop. The field content
// keeps its raw escape bytes — this fixes field ALIGNMENT, not unescaping.
func scanQuotedClose(line []byte, contentStart, firstQuote int) int {
	i := firstQuote
	for {
		bs := 0
		for j := i - 1; j >= contentStart && line[j] == '\\'; j-- {
			bs++
		}
		if bs%2 == 0 {
			return i
		}
		next := bytes.IndexByte(line[i+1:], '"')
		if next < 0 {
			return len(line)
		}
		i += 1 + next
	}
}

// bytesToString converts byte slice to string without copying.
// Safe when the backing byte slice is not mutated after this call (e.g., lineCopy
// allocated per-line in parseFileWithStreamingIO is never reused).
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// parseIPv4ToUint32 extracts IPv4 address directly as uint32 — zero allocation
//
// Performance optimizations:
//   - Single-pass parsing with dot counting
//   - Bit masking for digit extraction: (b & 0x0F) converts ASCII digit to int
//   - Returns uint32 directly — NO net.IP heap allocation
//   - Bounds checking for IPv4 format (7-15 characters)
//
// Input: line[start:end] should contain IPv4 like "192.168.1.1"
// Returns: uint32 IP or 0 if invalid format
func parseIPv4ToUint32(line []byte, start, end int) uint32 {
	n := end - start
	if n < 7 || n > 15 {
		return 0
	}
	// BCE hint: prove line[start:end] is fully in bounds, eliminating the
	// per-iteration bounds check in the loop below.
	if start < 0 || end > len(line) {
		return 0
	}

	// Single-pass parse. We accumulate each octet into current and commit it on
	// a dot. The loop is branch-light: the dot test and the digit test are the
	// only data-dependent branches, and any deviation funnels into a single
	// `return 0`.
	//
	// Correctness contract (identical to the previous implementation):
	//   - exactly 3 dots, exactly 4 parts
	//   - every non-dot byte must be an ASCII digit
	//   - each committed octet (current at a dot, and the final part) must be <=255
	//   - leading zeros are accepted (current = current*10 + digit, no rejection)
	//   - any violation -> 0
	//
	// We never need partIdx>=3 as a guard the way the old loop did: with the
	// dots!=3 check at the end, a 4th dot would push dots to 4 and be rejected,
	// but the old code returned 0 *immediately* on the 4th dot (partIdx>=3).
	// To preserve that exact early-out semantics for the >255-then-extra-dot
	// edge, we cap commits at 4 parts via partIdx and reject a 4th dot.
	current := 0
	partIdx := 0
	var result uint32
	dots := 0

	sub := line[start:end]
	for i := 0; i < len(sub); i++ {
		b := sub[i]
		d := b - '0'
		if d <= 9 {
			// ASCII digit fast path (b in '0'..'9' => b-'0' in 0..9, unsigned).
			current = current*10 + int(d)
			continue
		}
		if b != '.' {
			return 0
		}
		// Dot: commit the current octet. Identical guard order to the original:
		// reject if the octet overflows 255 or we already have 3 committed parts.
		if current > 255 || partIdx >= 3 {
			return 0
		}
		result |= uint32(current) << (24 - 8*partIdx)
		partIdx++
		current = 0
		dots++
	}

	if dots != 3 || current > 255 || partIdx != 3 {
		return 0
	}
	result |= uint32(current)

	return result
}

// parseTimestamp extracts timestamp from Apache Common Log format with maximum performance
//
// Expected format: "06/Jul/2025:19:57:26 +0000" within line[start:end], where
// end is the field's exclusive end (e.g. the position of the closing ']').
// Only the first 20 bytes (date and time) are read; a trailing timezone offset
// is ignored and the wall-clock time is returned as UTC.
//
// Performance optimizations:
//   - Direct byte-to-int conversion using bit masking: (b & 0x0F)
//   - 3-byte month lookup using bitwise operations
//   - Hardcoded month codes eliminate string comparisons
//   - Single bounds check, then direct array access for all fields
//
// Month encoding: ASCII bytes packed into uint32 for fast switch lookup
// Example: "Jul" = 0x4A756C = uint32('J')<<16 | uint32('u')<<8 | uint32('l')
func parseTimestamp(line []byte, start, end int) time.Time {
	if end-start < 20 || end > len(line) { // fast path reads line[start..start+19]
		return time.Time{}
	}

	// BCE hint: prove all accesses up to line[start+19] are in bounds,
	// eliminating 14 individual bounds checks in the code below.
	_ = line[start+19]

	// Parse "06/Jul/2025:19:57:26 +0000" directly from line buffer
	// Use bit operations for faster digit parsing
	day := int(line[start]&0x0F)*10 + int(line[start+1]&0x0F)

	// Month lookup using 3-byte comparison
	var month time.Month
	m1, m2, m3 := line[start+3], line[start+4], line[start+5]
	monthCode := uint32(m1)<<16 | uint32(m2)<<8 | uint32(m3)
	switch monthCode {
	case 0x4A616E: // "Jan"
		month = 1
	case 0x466562: // "Feb"
		month = 2
	case 0x4D6172: // "Mar"
		month = 3
	case 0x417072: // "Apr"
		month = 4
	case 0x4D6179: // "May"
		month = 5
	case 0x4A756E: // "Jun"
		month = 6
	case 0x4A756C: // "Jul"
		month = 7
	case 0x417567: // "Aug"
		month = 8
	case 0x536570: // "Sep"
		month = 9
	case 0x4F6374: // "Oct"
		month = 10
	case 0x4E6F76: // "Nov"
		month = 11
	case 0x446563: // "Dec"
		month = 12
	default:
		return time.Time{}
	}

	// Use bit masking for faster digit extraction
	year := int(line[start+7]&0x0F)*1000 + int(line[start+8]&0x0F)*100 + int(line[start+9]&0x0F)*10 + int(line[start+10]&0x0F)
	hour := int(line[start+12]&0x0F)*10 + int(line[start+13]&0x0F)
	minute := int(line[start+15]&0x0F)*10 + int(line[start+16]&0x0F)
	second := int(line[start+18]&0x0F)*10 + int(line[start+19]&0x0F)

	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// parseMethod extracts HTTP method using first-character optimization
//
// Performance optimizations:
//   - First-byte lookup eliminates string comparisons
//   - Only checks second byte when needed (POST vs PUT disambiguation)
//   - Direct enum return avoids string allocations
//   - Covers all common HTTP methods: GET, POST, PUT, DELETE, HEAD, OPTIONS
//
// Returns: HTTPMethod enum or UNKNOWN for unrecognized methods
func parseMethod(line []byte, start, end int) ingestor.HTTPMethod {
	if end <= start {
		return ingestor.UNKNOWN
	}

	// Use first byte for lookup
	switch line[start] {
	case 'G':
		return ingestor.GET
	case 'P':
		if end > start+1 {
			switch line[start+1] {
			case 'O':
				return ingestor.POST
			case 'A':
				return ingestor.PATCH
			}
		}
		return ingestor.PUT
	case 'D':
		return ingestor.DELETE
	case 'H':
		return ingestor.HEAD
	case 'O':
		return ingestor.OPTIONS
	default:
		return ingestor.UNKNOWN
	}
}

// parseBytes extracts numeric byte count from line[start:end].
//
// Returns (value, true) when every byte in the field is an ASCII digit, or
// (0, false) when any non-digit appears — the field is then malformed and the
// caller counts it. The single d<=9 unsigned-wraparound compare per byte keeps
// the all-digit fast path branch-predictable and inlineable.
//
// Known pre-existing limitation (intentionally unchanged): values with >=10
// digits silently wrap around uint32.
func parseBytes(line []byte, start, end int) (uint32, bool) {
	if start >= end {
		return 0, false
	}
	// BCE hint: prove line[end-1] is in bounds, eliminating per-iteration bounds check
	if end > len(line) {
		end = len(line)
	}

	result := uint32(0)
	for i := start; i < end; i++ {
		d := line[i] - '0'
		if d > 9 {
			return 0, false // any non-digit invalidates the field
		}
		result = result*10 + uint32(d)
	}
	return result, true
}
