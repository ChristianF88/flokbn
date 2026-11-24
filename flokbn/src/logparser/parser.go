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

	"github.com/ChristianF88/flokbn/accesslog"
)

// FieldExtractor represents a compiled field extraction operation
type FieldExtractor struct {
	FieldType int  // 0=IP, 1=timestamp, 2=method, 3=URI, 4=status, 5=bytes, 6=user-agent, 7=URI(standalone), -1=skip
	Delimiter byte // delimiter to find (space, quote, bracket)
	Quoted    bool // whether field is in quotes
	Brackets  bool // whether field is in brackets
	// autoQuote: scan the value as a quoted string whenever it starts with a
	// double quote, whether or not the format quotes this slot. It is false only
	// for the first field of a quoted GROUP ("%^ %r %^"), where the leading quote
	// is a format literal and the value is a bare token. Computed at compile time
	// so the per-field cost is the same single flag test as before.
	autoQuote bool
	// after is the separator that follows this field once its closing quote or
	// bracket has been consumed: for a slot the format closes ("%u"| or [%t]|)
	// the literal behind the closer, for a bare slot (%^|) the slot's own
	// delimiter, which is what follows a value that turned out to be quoted. It
	// is consumed together with the closer so the next field does not start on
	// it. A space (also used when there is no such literal) is harmless: the
	// next field skips leading spaces anyway.
	after byte
	// resync says what to do when a bare value in this slot stops at a space
	// although the format ends the slot with something else (resyncNone:
	// nothing, the value ends there). Set by enableRealign only - see
	// realign.go.
	resync uint8
}

// CompiledFormat represents a pre-compiled log format for fast parsing
type CompiledFormat struct {
	extractors []FieldExtractor
	pattern    string
	counters   *parseCounters
	// hasMethodField is true iff the format contains a standalone %m extractor.
	// When set, the %m-parsed method is authoritative and the %r request-line
	// arm must NOT overwrite Method (it only fills Method as a fallback when no
	// standalone %m exists). Computed once at compile time so the per-line hot
	// path pays a single bool check instead of treating the zero value (GET==0)
	// as an "unset" sentinel - which silently clobbered a %m-parsed GET.
	hasMethodField bool
	// anchors is what the format literally puts around each slot, recorded at
	// compile time for enableRealign.
	anchors []slotAnchor
}

// parseCounters holds malformed-field tallies shared by all parse workers.
// Heap-allocated separately from CompiledFormat so the write-on-failure
// counters never share a cache line with the read-only hot fields.
type parseCounters struct {
	malformedStatus atomic.Uint64
	malformedBytes  atomic.Uint64
	oversizedLines  atomic.Uint64
}

// ParseStats is a snapshot of malformed-field counters, cumulative across
// all ParseFile* calls on the same Parser.
type ParseStats struct {
	MalformedStatus uint64
	MalformedBytes  uint64
	// OversizedLines is the number of lines longer than MaxLineLen. Such a line
	// is skipped by every I/O path: it is not a request and is not part of the
	// invalid-IP count either.
	OversizedLines uint64
}

// MaxLineLen is the longest line, in bytes before its "\n" terminator, that
// the file parsers accept (2 MiB). A longer line is skipped and counted in
// ParseStats.OversizedLines; the rest of the file is parsed normally. The
// limit bounds the memory one line can pin and is the same on the streaming
// (<500MB) and the chunked (>=500MB) reader.
const MaxLineLen = 2 * 1024 * 1024

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
	// The file parser re-aligns a line on the literals of the format.
	compiled.enableRealign()
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
		OversizedLines:  pp.compiled.counters.oversizedLines.Load(),
	}
}

// ParseFile parses a log file using adaptive I/O strategy (primary interface)
// Automatically chooses between streaming I/O (small files) and chunked I/O (large files)
// This is the recommended method for all file parsing operations.
//
// Both strategies frame lines identically: "\n" or "\r\n" terminated, blank
// lines skipped, lines longer than MaxLineLen skipped and counted in
// Stats().OversizedLines.
func (pp *Parser) ParseFile(filename string) ([]accesslog.Request, error) {
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

	// For files smaller than 500MB, use streaming I/O (better performance).
	// Pass the already-open file (positioned at offset 0; only Stat has run) so
	// the streaming path reuses this single fd instead of opening a second one.
	const largeFileThreshold = 500 * 1024 * 1024 // 500MB
	if fileSize < largeFileThreshold {
		return pp.parseFileWithStreamingIO(file, fileSize)
	}

	// For large files, use chunked concurrent I/O
	return pp.parseFileWithConcurrentIO(file, fileSize)
}

// ParseFileIPs parses a log file extracting ONLY the IPv4 address of each line
// as a uint32, skipping all other field work and never allocating an
// accesslog.Request. It uses the same adaptive streaming/concurrent I/O
// structure as ParseFile (same slab+batch line readers).
//
// Returns the slice of nonzero IPs (lines whose IP parsed successfully) and
// invalidCount = the number of lines whose IP failed to parse (extractIPOnly
// returned 0). Blank lines and lines longer than MaxLineLen are not lines in
// this sense: they are skipped (the latter counted in Stats().OversizedLines)
// and appear in neither number. This matches the downstream "invalid/missing IP" semantics:
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

	// Pass the already-open file (positioned at offset 0; only Stat has run) so
	// the streaming path reuses this single fd instead of opening a second one.
	const largeFileThreshold = 500 * 1024 * 1024 // 500MB
	if fileSize < largeFileThreshold {
		return pp.parseFileIPsStreamingIO(file, fileSize)
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
//
// The caller owns `file` (and closes it); it must be positioned at offset 0.
// fileSize is the caller's Stat size, used only for the line-count estimate.
func (pp *Parser) parseFileIPsStreamingIO(file *os.File, fileSize int64) ([]uint32, int, error) {
	estimatedLines := int(fileSize / 200)
	if estimatedLines < 1000 {
		estimatedLines = 1000
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

	scanner, splitter := newLineScanner(file)

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

	pp.compiled.counters.oversizedLines.Add(splitter.oversized)

	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}

	return ips, invalidCount, nil
}

// parseFileIPsConcurrentIO mirrors parseFileWithConcurrentIO but extracts only
// IPs. It reuses readChunkBatched verbatim for the I/O stage.
func (pp *Parser) parseFileIPsConcurrentIO(file *os.File, fileSize int64) ([]uint32, int, error) {
	return pp.parseFileIPsConcurrentIOChunked(file, file.Name(), fileSize, defaultConcurrentChunkSize)
}

// defaultConcurrentChunkSize is the production chunk size (64MB) for the
// concurrent I/O path. Extracted as a constant so tests can drive the concurrent
// path with a small chunk size on a normal-sized file (many chunks + boundary
// crossings) without allocating a >=500MB file.
const defaultConcurrentChunkSize = 64 * 1024 * 1024

// parseFileIPsConcurrentIOChunked is the chunk-size-parameterized implementation
// of parseFileIPsConcurrentIO. Production callers use defaultConcurrentChunkSize;
// tests override chunkSize to exercise boundary handling on small files.
// The read source is io.ReaderAt (forwarded to readChunkBatched, which uses only
// ReadAt) so a test can drive the chunked path with a fault-injecting reader on a
// small file. Production callers pass *os.File, which satisfies io.ReaderAt;
// Stat/Close stay at the ParseFile* entry points, so file ownership is unchanged.
//
// name is the source file's name (file.Name() at the production entry point); it
// is stored on the error-capture seam so a non-EOF ReadAt failure names the file
// in its error. It is io.ReaderAt-typed callers' responsibility to pass it (the
// reader itself is not always an *os.File, by design).
func (pp *Parser) parseFileIPsConcurrentIOChunked(file io.ReaderAt, name string, fileSize int64, chunkSize int64) ([]uint32, int, error) {
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

	readErr := chunkErrCapture{name: name}
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrentChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range chunkJobs {
				pp.readChunkBatched(file, job, fileSize, linesChan, &readErr)
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

	// Surface any chunk-read I/O error (parity with the streaming path's
	// scanner.Err() check). A failed read previously left a truncated result with
	// a nil error (silent under-banning); now ParseFileIPs returns a non-nil error
	// and analysis.Static fails loud. The full shutdown sequence above already ran,
	// so no goroutine leaks - only the return value changes. A partial result must
	// not be published, so return nil on error.
	if err := readErr.load(); err != nil {
		return nil, 0, err
	}

	return ips, invalidCount, nil
}

// lineSplitter is the bufio.SplitFunc state of the streaming readers. It frames
// lines exactly like the chunked reader (readChunkBatched), so a file parses
// the same way on either side of the 500MB switch:
//
//   - a line ends at "\n"; one trailing "\r" is stripped (CRLF);
//   - a blank line is skipped: it is not a request and not an invalid line;
//   - a line longer than MaxLineLen is skipped and counted in oversized, and the
//     scan resumes after its newline. bufio.ScanLines would instead fail the
//     whole parse with ErrTooLong once the line outgrew the buffer.
//
// It is used by one goroutine (the reader loop), so it needs no locking.
type lineSplitter struct {
	discarding bool   // inside an oversized line: drop bytes up to its newline
	oversized  uint64 // lines skipped for exceeding MaxLineLen
}

// newLineScanner returns a Scanner over r that yields the non-blank lines of at
// most MaxLineLen bytes, plus the splitter holding its oversized-line count.
// The buffer may grow to MaxLineLen+1 bytes: enough to hold a line of exactly
// MaxLineLen with its newline, and enough for split to see that a longer line
// has passed the limit before the Scanner would give up on it.
func newLineScanner(r io.Reader) (*bufio.Scanner, *lineSplitter) {
	ls := &lineSplitter{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 256*1024), MaxLineLen+1) // 256KB initial
	// The split function runs once per line, so the ordinary case is handled
	// right here in the closure the Scanner calls (no second call): a non-empty
	// LF-terminated line within the limit, not inside an oversized line.
	// Everything else - CRLF, blank, oversized, end of input - goes to
	// ls.split, which handles the ordinary case identically.
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i > 0 && i <= MaxLineLen && data[i-1] != '\r' && !ls.discarding {
			return i + 1, data[:i], nil
		}
		return ls.split(data, atEOF)
	})
	return scanner, ls
}

// split implements bufio.SplitFunc in full (newLineScanner short-circuits the
// ordinary line before calling it). It returns the next acceptable line and
// advances past any blank or oversized lines in front of it.
//
// Skipped lines are consumed inside this call, by looping, instead of being
// returned as a nil token with a positive advance: once the Scanner has seen
// EOF it stops at the first nil token even when more data is still buffered,
// which would silently drop every line after a blank one in the last buffer.
// A nil token is therefore only returned when more input is needed or all of
// data has been consumed.
func (ls *lineSplitter) split(data []byte, atEOF bool) (advance int, token []byte, err error) {
	pos := 0 // start of the line under inspection; everything before it is consumed
	for {
		rest := data[pos:]
		i := bytes.IndexByte(rest, '\n')

		if ls.discarding {
			// Tail of an oversized line that was already counted.
			if i < 0 {
				return len(data), nil, nil
			}
			ls.discarding = false
			pos += i + 1
			continue
		}

		end := i // exclusive end of the line within rest
		next := pos + i + 1
		if i < 0 {
			if len(rest) > MaxLineLen {
				// No newline within the limit: oversized however long it turns
				// out to be. Drop what is buffered and keep dropping to its end.
				ls.oversized++
				ls.discarding = true
				return len(data), nil, nil
			}
			if !atEOF || len(rest) == 0 {
				return pos, nil, nil // need more data, or nothing left
			}
			end = len(rest) // final line without a newline
			next = len(data)
		} else if i > MaxLineLen {
			ls.oversized++
			pos = next
			continue
		}

		if end > 0 && rest[end-1] == '\r' {
			end--
		}
		if end == 0 {
			pos = next // blank line
			continue
		}
		return next, rest[:end], nil
	}
}

// parseBatchSize is the number of lines per batch sent through channels.
// Batching amortizes channel lock/unlock overhead: 1M lines = ~1K channel ops instead of 1M.
const parseBatchSize = 1024

// requestBatchPool recycles the per-batch []Request buffers that workers fill
// and the collector drains, so the batches cycle instead of being freshly
// allocated. The single pre-sized collector slice still owns the final result;
// the pool only removes the per-batch allocation churn.
var requestBatchPool = sync.Pool{
	New: func() any {
		s := make([]accesslog.Request, 0, parseBatchSize)
		return &s
	},
}

// parseFileWithStreamingIO uses streaming I/O with batched parallel parsing
// workers (internal method).
//
// The caller owns `file` (and closes it); it must be positioned at offset 0.
// fileSize is the caller's Stat size, used only for the line-count estimate.
func (pp *Parser) parseFileWithStreamingIO(file *os.File, fileSize int64) ([]accesslog.Request, error) {
	// Pre-allocation estimate (~200 bytes per log line).
	estimatedLines := int(fileSize / 200)
	if estimatedLines < 1000 {
		estimatedLines = 1000
	}

	// Batched channels - each send/receive moves parseBatchSize items at once,
	// reducing channel operations from O(lines) to O(lines/batchSize).
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan *[]accesslog.Request, pp.workers*2)

	var wg sync.WaitGroup

	// Capture skip flags for use in worker goroutines
	skipStrings := pp.SkipStringFields
	skipNonIP := pp.SkipNonIPFields

	// Start parser workers - each reuses a single Request for parsing and fills a
	// pooled batch buffer, shipped to the collector which drains it and returns it
	// to the pool (so the buffers cycle instead of being freshly allocated).
	for i := 0; i < pp.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &accesslog.Request{}
			for batch := range linesChan {
				bp := requestBatchPool.Get().(*[]accesslog.Request)
				resBatch := (*bp)[:0]
				for _, line := range batch {
					*req = accesslog.Request{}
					if err := pp.compiled.parseLineReuseOpt(line, req, skipStrings, skipNonIP); err == nil {
						resBatch = append(resBatch, *req)
					}
				}
				*bp = resBatch
				if len(resBatch) > 0 {
					resultsChan <- bp
				} else {
					requestBatchPool.Put(bp)
				}
			}
		}()
	}

	// Start result collector with pre-allocated slice. It copies each pooled
	// batch out, then returns the buffer to the pool for a worker to refill.
	results := make([]accesslog.Request, 0, estimatedLines)
	var collectorWG sync.WaitGroup
	collectorWG.Add(1)

	go func() {
		defer collectorWG.Done()
		for bp := range resultsChan {
			results = append(results, (*bp)...)
			requestBatchPool.Put(bp)
		}
	}()

	// I/O reader - accumulate lines into batches before sending
	// Uses a slab allocator: one contiguous []byte per batch instead of one per line.
	// Reduces allocations from O(lines) to O(lines/batchSize).
	scanner, splitter := newLineScanner(file)

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

	pp.compiled.counters.oversizedLines.Add(splitter.oversized)

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// parseFileWithConcurrentIO implements concurrent chunked file reading.
// Uses ReadAt for thread-safe parallel reads, batched channels matching the
// streaming path, and per-worker Request reuse (no sync.Pool needed).
func (pp *Parser) parseFileWithConcurrentIO(file *os.File, fileSize int64) ([]accesslog.Request, error) {
	return pp.parseFileConcurrentIOChunked(file, file.Name(), fileSize, defaultConcurrentChunkSize)
}

// parseFileConcurrentIOChunked is the chunk-size-parameterized implementation of
// parseFileWithConcurrentIO. Production callers use defaultConcurrentChunkSize
// (64MB); tests override chunkSize to exercise the concurrent path on small files.
// The read source is io.ReaderAt (forwarded to readChunkBatched, which uses only
// ReadAt) so a test can drive the chunked path with a fault-injecting reader on a
// small file. Production callers pass *os.File, which satisfies io.ReaderAt;
// Stat/Close stay at the ParseFile* entry points, so file ownership is unchanged.
//
// name is the source file's name (file.Name() at the production entry point); it
// is stored on the error-capture seam so a non-EOF ReadAt failure names the file
// in its error. It is io.ReaderAt-typed callers' responsibility to pass it (the
// reader itself is not always an *os.File, by design).
func (pp *Parser) parseFileConcurrentIOChunked(file io.ReaderAt, name string, fileSize int64, chunkSize int64) ([]accesslog.Request, error) {
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

	// Batched channels - same pattern as streaming path
	chunkJobs := make(chan chunkJob, numChunks)
	linesChan := make(chan [][]byte, pp.workers*2)
	resultsChan := make(chan []accesslog.Request, pp.workers*2)

	readErr := chunkErrCapture{name: name}
	var wg sync.WaitGroup

	// Start chunk readers - use ReadAt (pread64) for thread-safe parallel reads
	// on the same file descriptor. No file handle pool needed.
	for i := 0; i < maxConcurrentChunks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range chunkJobs {
				pp.readChunkBatched(file, job, fileSize, linesChan, &readErr)
			}
		}()
	}

	// Start parser workers - per-worker Request reuse (matches streaming path)
	skipStrings := pp.SkipStringFields
	skipNonIP := pp.SkipNonIPFields
	var parserWG sync.WaitGroup
	for i := 0; i < pp.workers; i++ {
		parserWG.Add(1)
		go func() {
			defer parserWG.Done()
			req := &accesslog.Request{}
			for batch := range linesChan {
				resBatch := make([]accesslog.Request, 0, len(batch))
				for _, line := range batch {
					*req = accesslog.Request{}
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
	results := make([]accesslog.Request, 0, estimatedLines)
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

	// Surface any chunk-read I/O error (parity with the streaming path's
	// scanner.Err() check). A failed read previously left a truncated result with
	// a nil error (silent under-banning); now ParseFile returns a non-nil error and
	// analysis.Static fails loud. The full shutdown sequence above already ran, so
	// no goroutine leaks - only the return value changes. A partial result must not
	// be published, so return nil on error.
	if err := readErr.load(); err != nil {
		return nil, err
	}

	return results, nil
}

// chunkJob represents a file chunk to be read
type chunkJob struct {
	start int64
	end   int64
	index int
}

// chunkErrCapture is the store-once first-error seam shared by the chunk-reader
// goroutines of the concurrent (chunked, >=500MB) parse paths. A non-EOF ReadAt
// failure in readChunkBatched / recoverLongLine records the FIRST such error
// here (sync.Once, so concurrent failing readers are race-free and first-wins),
// instead of printing-and-returning and silently truncating the result.
//
// Cost on the success path is zero: record is only ever called on a failed
// ReadAt, never per line/byte. The orchestrator checks load() once after its
// chunk readers join (post wg.Wait()), mirroring the streaming path's
// scanner.Err() check, and returns the error so ParseFile* surface a non-nil
// error (parity with streaming) instead of a short result + nil error.
type chunkErrCapture struct {
	once sync.Once
	err  error
	// name is the source file's name, set once by the orchestrator before any
	// chunk reader starts, so readChunkBatched / recoverLongLine can name the
	// file in the ReadAt error without taking file.Name() (their read source is
	// io.ReaderAt, not *os.File, for fault-injection tests). Written before the
	// reader goroutines launch and read only on the cold ReadAt-failure branch,
	// so it adds no work to the success/hot path.
	name string
}

// record stores err as the first error iff none has been recorded yet. Safe to
// call from multiple chunk-reader goroutines concurrently.
func (c *chunkErrCapture) record(err error) {
	c.once.Do(func() { c.err = err })
}

// load returns the first recorded error (nil if none). Read only after the
// chunk-reader goroutines have joined, which provides the happens-before edge.
func (c *chunkErrCapture) load() error {
	return c.err
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
//
// errCap is the shared store-once error seam: on a non-EOF ReadAt failure the
// chunk's lines are dropped (as before) but the error is recorded so the
// orchestrator can surface it after the readers join, instead of silently
// truncating the result. io.EOF stays a normal (success) terminator.
//
// The read source is typed as io.ReaderAt (only ReadAt is used here) so a test
// can inject a failing reader without a >=500MB file; *os.File already satisfies
// io.ReaderAt and ReadAt is called once per chunk (cold I/O stage), never per
// line, so the interface dispatch is off the per-line hot path.
func (pp *Parser) readChunkBatched(file io.ReaderAt, job chunkJob, fileSize int64, linesChan chan<- [][]byte, errCap *chunkErrCapture) {
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
		// Record the error (store-once) instead of swallowing it; the orchestrator
		// surfaces it after the readers join so ParseFile* return a non-nil error
		// rather than a silently truncated result. io.EOF is the normal terminator
		// and is excluded above.
		errCap.record(fmt.Errorf("readChunkBatched: ReadAt %q offset %d: %w", errCap.name, readStart, err))
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
	// job.end into the overlap region - we read `overlap` extra bytes precisely
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
	//     is in [job.start, job.end) so THIS chunk owns it - start = pad.
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
	oversized := uint64(0)

	for i := start; i < len(buffer); i++ {
		if buffer[i] == '\n' {
			// Stop once the CURRENT line started at/after the chunk boundary: that
			// line is owned by the next chunk.
			if start >= chunkEnd {
				break
			}

			lineData := buffer[start:i]
			start = i + 1

			// Same limit as the streaming reader (lineSplitter): skip and count.
			if len(lineData) > MaxLineLen {
				oversized++
				continue
			}

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
		if len(lineData) > MaxLineLen {
			oversized++
			lineData = nil
		}
		// Strip a trailing '\r' (file ending in "...\r" with no final '\n').
		if n := len(lineData); n > 0 && lineData[n-1] == '\r' {
			lineData = lineData[:n-1]
		}
		if len(lineData) > 0 {
			batch = append(batch, lineData)
		}
	}

	// Cold recovery branch: an OWNED line was longer than the overlap window so
	// its terminating '\n' fell beyond `readEnd`. The emit loop above scanned to
	// the end of `buffer` without finding it, leaving `start` pointing at that
	// owned line's first byte (start < chunkEnd) with bytes still pending
	// (start < len(buffer)), and we are NOT at EOF (the EOF handler above would
	// otherwise have emitted it as the final line).
	//
	// This branch is entered ONLY for such a boundary-straddling long line. In
	// the common case every owned line terminates within `buffer`, so the loop
	// leaves `start` at or past chunkEnd (or at len(buffer)); the guard below is
	// false and the hot path does ZERO extra work / allocations. Lines shorter
	// than the 8192 overlap can never reach here.
	if readEnd != fileSize && start < chunkEnd && start < len(buffer) {
		if recovered, ok := pp.recoverLongLine(file, readStart+int64(start), fileSize, errCap); ok {
			batch = append(batch, recovered)
		}
	}

	// Cold: only touched when this chunk actually held an oversized line.
	if oversized > 0 {
		pp.compiled.counters.oversizedLines.Add(oversized)
	}

	// Send remaining lines
	if len(batch) > 0 {
		linesChan <- batch
	}
}

// recoverLongLine re-reads, starting at the absolute file offset `lineStart` of an
// owned line whose terminating '\n' fell beyond this chunk's overlap window, with
// a GROWING window (doubling from the default overlap) until the '\n' is found,
// EOF is reached, or the line is known to exceed MaxLineLen. It returns the line
// bytes (trailing '\r' stripped to match the streaming path) and ok=true when a
// complete owned line was recovered.
//
// Cold path only: invoked at most once per chunk (a single physical line can
// straddle a boundary at most once for the owning chunk), so the extra ReadAt and
// fresh allocation here do not touch the common-case parse cost. The returned
// slice aliases the freshly allocated `buf`; that alias keeps `buf` reachable, so
// the zero-copy unsafe.String lifetime invariant documented on readChunkBatched
// still holds (the recovery buffer is never reused or mutated after this read).
//
// PARITY with the streaming reader (lineSplitter) is exact, including at the
// limit: a line of up to MaxLineLen bytes before its '\n' is recovered, a longer
// one is skipped and counted in ParseStats.OversizedLines, and the parse goes on.
// The window therefore grows to at most MaxLineLen+1 bytes - one more than the
// longest acceptable line, so its newline (or the proof that there is none) is
// always inside the window.
//
// ok=false has three causes: a blank line, an oversized line (counted), and a
// genuine non-EOF ReadAt failure, which is recorded on errCap (the shared
// store-once error seam) so the orchestrator fails the parse loud. The read
// source is io.ReaderAt for the same test-injection reason as readChunkBatched
// (cold path, one ReadAt per grow step).
func (pp *Parser) recoverLongLine(file io.ReaderAt, lineStart, fileSize int64, errCap *chunkErrCapture) ([]byte, bool) {
	const maxWindow = MaxLineLen + 1
	window := int64(8192) // current overlap; double until '\n' found or capped
	for {
		window *= 2
		if window > maxWindow {
			window = maxWindow
		}
		readEnd := lineStart + window
		atEOF := false
		if readEnd >= fileSize {
			readEnd = fileSize
			atEOF = true
		}
		readSize := readEnd - lineStart
		if readSize <= 0 {
			return nil, false
		}

		buf := make([]byte, readSize)
		n, err := file.ReadAt(buf, lineStart)
		if err != nil && err != io.EOF {
			// Genuine I/O failure (distinct from the oversized-line skip below):
			// record it (store-once) so the orchestrator surfaces a non-nil error,
			// then drop this line. io.EOF is normal end-of-file and excluded above.
			errCap.record(fmt.Errorf("recoverLongLine: ReadAt %q offset %d: %w", errCap.name, lineStart, err))
			return nil, false
		}
		buf = buf[:n]

		lineData := buf
		if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
			// Found the terminating newline: this is the complete owned line.
			lineData = buf[:idx]
		} else if !atEOF {
			if window >= maxWindow {
				// MaxLineLen+1 bytes without a newline: oversized. Skip just
				// this line; the chunk that owns the next line picks up after
				// its newline.
				pp.compiled.counters.oversizedLines.Add(1)
				return nil, false
			}
			continue // grow the window and re-read
		}
		// else: no trailing '\n' before EOF - the file's final line; the whole
		// remaining tail is the line (matches the EOF handler).

		if len(lineData) > MaxLineLen {
			pp.compiled.counters.oversizedLines.Add(1)
			return nil, false
		}
		if m := len(lineData); m > 0 && lineData[m-1] == '\r' {
			lineData = lineData[:m-1]
		}
		if len(lineData) == 0 {
			return nil, false
		}
		return lineData, true
	}
}

// codeFieldNames maps a supported format code byte to its human-readable field
// name, used to build the duplicate-field error message and to validate that a
// code is supported. The skip code (%^) is intentionally absent: it is handled
// before the lookup and may repeat freely. Keep this in sync with the field
// types compiled in compileFormat.
var codeFieldNames = map[byte]string{
	'h': "IP",
	't': "timestamp",
	'r': "request",
	'm': "method",
	's': "status",
	'b': "bytes",
	'U': "URI",
	'u': "user agent",
}

// DefaultLogFormat is the canonical combined-log format used when no logFormat
// is configured. It is the SINGLE source of truth referenced by the static
// analysis entry points (analysis/static.go), the CLI --logFormat flag default,
// and config.Validate's empty->default fallback, so the three cannot drift.
// %h is last (the static default convention). Every slot that a combined log
// quotes (request, referer, User-Agent, client IP) is quoted here too.
const DefaultLogFormat = `%^ %^ %^ [%t] "%r" %s %b "%^" "%u" "%h"`

// ValidateFormat is the exported, side-effect-free precondition check for a log
// format string. It is a THIN wrapper over the unexported validateFormat, which
// compileFormat (and therefore NewParser) calls FIRST and which is a TOTAL
// precondition for compileFormat/NewParser success: compileFormat returns an
// error ONLY from validateFormat (its build loop merely `continue`s on unknown
// codes and otherwise returns nil). So ValidateFormat(f)==nil is equivalent to
// NewParser(f) succeeding w.r.t. the format string - config.Validate can gate a
// barrier-passed format and never have the downstream NewParser reject it.
func ValidateFormat(format string) error {
	return validateFormat(format)
}

// validateFormat ensures format string doesn't have duplicate non-skippable fields
func validateFormat(format string) error {
	fieldCounts := make(map[byte]int)

	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			field := format[i+1]

			// A quote that closes a GROUP of fields ("%^ %r %^") is consumed by a
			// bare token scan, which does not also consume a delimiter behind
			// it. With a space that does not matter; with any other delimiter
			// every later field would be off by one, so refuse the format.
			if groupDelimiterAt(format, i) {
				return fmt.Errorf("the quoted group ending in %%%c\" is followed by %q - a quoted group of several fields must be followed by a space (or quote each field on its own, e.g. \"%%r\"%c)",
					field, format[i+3], format[i+3])
			}

			// Skip validation for skip field (%^)
			if field == '^' {
				continue
			}

			name, ok := codeFieldNames[field]
			if !ok {
				return fmt.Errorf("unsupported format code %%%c - supported codes are: %%h (IP), %%t (timestamp), %%r (request), %%m (method), %%s (status), %%b (bytes), %%U (URI), %%u (user-agent), %%^ (skip)", field)
			}

			// Count occurrences and reject duplicates - each non-skip field may
			// appear at most once.
			fieldCounts[field]++
			if fieldCounts[field] > 1 {
				return fmt.Errorf("duplicate %s field (%%%c) found in format string - only one %s field is allowed", name, field, name)
			}
		}
	}

	// Ensure at least one IP field is present
	if fieldCounts['h'] == 0 {
		return fmt.Errorf("no IP field (%%h) found in format string - at least one IP field is required")
	}

	return nil
}

// groupDelimiterAt reports whether the specifier at format[i] is the LAST field
// of a quoted group (closing quote behind it, no opening quote in front of it)
// that is directly followed by a literal other than a space.
func groupDelimiterAt(format string, i int) bool {
	if format[i] != '%' || i+3 >= len(format) || format[i+2] != '"' {
		return false
	}
	if i > 0 && format[i-1] == '"' {
		return false // a self-contained quoted slot: "%r"
	}
	return format[i+3] != ' ' && format[i+3] != '%'
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
	var anchors []slotAnchor
	hasMethodField := false

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
				hasMethodField = true
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
				if nextChar == 0 {
					// A NUL after the specifier never worked as a delimiter (the
					// scan fell back to space); normalise here so the hot loop
					// does not have to.
					extractor.Delimiter = ' '
				}
			} else {
				extractor.Delimiter = ' ' // default
			}

			// A value that starts with a double quote is a quoted string even when
			// the format leaves the slot bare (`%^` for a referer): scanning it as
			// a bare token would split it at the first space and shift every later
			// field, letting a client-controlled Referer or User-Agent supply %h.
			// The one exception is a format literal quote that opens a group of
			// fields (`"%^ %r %^"`): there the quote belongs to the format, not to
			// this field's value.
			opensGroup := i > 0 && format[i-1] == '"' && extractor.Delimiter != '"'
			extractor.autoQuote = extractor.Quoted || !opensGroup

			// Separator behind the closing quote/bracket (see FieldExtractor.after).
			extractor.after = extractor.Delimiter
			if extractor.Delimiter == '"' || (extractor.Delimiter == ']' && extractor.Brackets) {
				extractor.after = ' '
				if i+3 < len(format) {
					extractor.after = format[i+3]
				}
			}
			if extractor.after == '%' {
				extractor.after = ' ' // the next specifier follows directly: no separator
			}

			anchors = append(anchors, slotAnchor{
				selfQuoted:  i > 0 && format[i-1] == '"' && extractor.Delimiter == '"',
				bracketed:   i > 0 && format[i-1] == '[' && extractor.Delimiter == ']',
				spaceBefore: i > 1 && format[i-2] == ' ',
				specifierOn: extractor.Delimiter == '%' && i+2 < len(format),
			})
			extractors = append(extractors, extractor)
			i++ // Skip format character
		}
	}

	return &CompiledFormat{
		extractors:     extractors,
		pattern:        format,
		counters:       &parseCounters{}, // never nil: hot path may Add without a nil check
		hasMethodField: hasMethodField,
		anchors:        anchors,
	}, nil
}

// parseLineReuseOpt parses a log line with optional string field skipping
func (cf *CompiledFormat) parseLineReuseOpt(line []byte, req *accesslog.Request, skipStrings, skipNonIP bool) error {
	// Use compiled format extractors for optimized parsing
	if len(cf.extractors) > 0 {
		return cf.parseUsingCompiledFormatOpt(line, req, skipStrings, skipNonIP)
	}

	// If no extractors configured, skip parsing
	return nil
}

// parseUsingCompiledFormatOpt applies extractors with optional string field skipping
// When skipNonIP is true, only the IP field is extracted (all others are skipped but positions still advance)
func (cf *CompiledFormat) parseUsingCompiledFormatOpt(line []byte, req *accesslog.Request, skipStrings, skipNonIP bool) error {
	pos := 0

	for _, extractor := range cf.extractors {
		// Skip whitespace; a line that ends here leaves the remaining fields unset.
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		if pos >= len(line) {
			break
		}

		start := pos

		// Scan the field. Each arm leaves pos on the field's exclusive end and
		// sets next to where the following field starts (past the closing quote,
		// bracket or delimiter). The first byte is tested before the per-format
		// flag so a bare token pays two byte compares and nothing else.
		// bytes.IndexByte uses SIMD (SSE2/AVX2) on amd64 for 8-16x faster scanning
		var next int
		quoted := false
		if c := line[pos]; c == '"' && extractor.autoQuote {
			quoted = true
			pos++ // skip opening quote
			start = pos
			if pos+1 < len(line) && line[pos] == '-' && line[pos+1] == '"' {
				pos++ // "-" (absent value): cheaper than the IndexByte call
			} else if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				if idx > 0 && line[pos+idx-1] == '\\' {
					pos = scanQuotedClose(line, pos, pos+idx) // rare slow path: escaped quote
				} else {
					pos += idx
				}
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing quote
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else if c == '[' && extractor.Brackets {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing bracket
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else {
			// Regular field - scan until delimiter or space
			delimiter := extractor.Delimiter
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
			next = pos
			if pos < len(line) {
				if line[pos] == delimiter {
					next++ // the delimiter itself
				} else if extractor.resync != resyncNone {
					// Slow path (realign.go): the value stopped at a space although
					// the format ends this slot with something else. A line that
					// follows its format never gets here.
					var ts *time.Time
					if !skipNonIP {
						ts = &req.Timestamp
					}
					start, pos, next = realignBare(line, start, pos, delimiter, extractor.after, extractor.resync, ts)
				}
			}
		}

		// Extract and parse field if not skipped
		if extractor.FieldType >= 0 && start < pos {
			// IP is always extracted; other fields are skipped when skipNonIP is true
			if extractor.FieldType == 0 {
				ip := parseIPv4ToUint32(line, start, pos)
				if ip == 0 {
					ip = forwardedTailIP(line, start, pos) // slow path: address list
				}
				req.IPUint32 = ip
			} else if !skipNonIP {
				fieldData := line[start:pos]

				switch extractor.FieldType {
				case 1: // Timestamp
					req.Timestamp = parseTimestamp(line, start, pos)
				case 2: // Method (standalone)
					req.Method = parseMethod(line, start, pos)
				case 3: // Request line (%r) - extracts METHOD and URI, ignores HTTP version
					if extractor.Quoted || quoted {
						// Parse "METHOD URI HTTP/VERSION" format efficiently
						methodEnd := start
						for methodEnd < pos && line[methodEnd] != ' ' {
							methodEnd++
						}

						// Fill Method from the request line ONLY when the format has no
						// standalone %m. When a %m extractor exists it is authoritative,
						// so %r must not overwrite it. Using the zero value (GET==0) as
						// an "unset" sentinel would silently clobber a %m-parsed GET.
						if methodEnd > start && !cf.hasMethodField {
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
		pos = next
	}

	return nil
}

// extractIPOnly walks the compiled extractors exactly like
// parseUsingCompiledFormatOpt (same quoted/bracketed/delimited field
// boundary handling) but performs NO field stores, builds NO Request, and
// returns as soon as the IP field (FieldType==0) has been parsed - it never
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

		// Skip whitespace; a line that ends here has no IP field.
		for pos < len(line) && line[pos] == ' ' {
			pos++
		}
		if pos >= len(line) {
			break
		}

		start := pos

		// Scan the field - identical boundary logic to
		// parseUsingCompiledFormatOpt so that pos and next land on the same
		// offsets.
		var next int
		if c := line[pos]; c == '"' && extractor.autoQuote {
			pos++ // skip opening quote
			start = pos
			if pos+1 < len(line) && line[pos] == '-' && line[pos+1] == '"' {
				pos++ // "-" (absent value): cheaper than the IndexByte call
			} else if idx := bytes.IndexByte(line[pos:], '"'); idx >= 0 {
				if idx > 0 && line[pos+idx-1] == '\\' {
					pos = scanQuotedClose(line, pos, pos+idx) // rare slow path: escaped quote
				} else {
					pos += idx
				}
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing quote
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else if c == '[' && extractor.Brackets {
			pos++ // skip opening bracket
			start = pos
			if idx := bytes.IndexByte(line[pos:], ']'); idx >= 0 {
				pos += idx
			} else {
				pos = len(line)
			}
			next = pos
			if pos < len(line) {
				next++ // closing bracket
				if next < len(line) && line[next] == extractor.after {
					next++ // and the delimiter behind it
				}
			}
		} else {
			delimiter := extractor.Delimiter
			for pos < len(line) && line[pos] != delimiter && line[pos] != ' ' {
				pos++
			}
			next = pos
			if pos < len(line) {
				if line[pos] == delimiter {
					next++ // the delimiter itself
				} else if extractor.resync != resyncNone {
					// Slow path - see parseUsingCompiledFormatOpt.
					start, pos, next = extractor.realignIP(line, start, pos)
				}
			}
		}

		// IP field: parse and return immediately. The guard `start < pos`
		// matches the original (only fields with content are parsed); when the
		// IP field has no content we fall through and return 0 below, which is
		// exactly what req.IPUint32 would remain (zero value).
		if extractor.FieldType == 0 {
			if start < pos {
				if ip := parseIPv4ToUint32(line, start, pos); ip != 0 {
					return ip
				}
				return forwardedTailIP(line, start, pos) // slow path: address list
			}
			return 0
		}

		// Advance past closing quotes/brackets/delimiters - identical to
		// parseUsingCompiledFormatOpt so subsequent field boundaries align.
		pos = next
	}

	return 0
}

// scanQuotedClose resumes a quoted-field scan when the quote found at
// firstQuote is preceded by a backslash. A quote is escaped iff preceded by
// an ODD number of consecutive backslashes (Apache escapes `"` -> `\"` and
// `\` -> `\\`). Returns the index of the first unescaped quote at/after
// firstQuote, or len(line). Only called when an escape candidate was seen,
// so the no-escape common case never pays for this loop. The field content
// keeps its raw escape bytes - this fixes field ALIGNMENT, not unescaping.
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
//
// Safe because the backing buffer is never mutated for the lifetime of the
// returned string. The streaming path (parseFileWithStreamingIO) sub-slices
// each line out of a per-batch slab that is replaced - never overwritten in
// place - once full. The concurrent path (readChunkBatched) sub-slices each
// line out of a per-chunk ReadAt buffer that is read once and never reused.
// In both cases the returned string keeps its backing buffer reachable, so the
// GC retains it as long as any aliasing Request lives.
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// forwardedTailIP is the slow path for a %h value that is not a single IPv4
// address: when the value is a comma-separated list (an X-Forwarded-For
// header) it returns the RIGHTMOST element, or 0 when that element is not a
// valid IPv4 address or there is no comma at all.
//
// Rightmost is the only defensible choice: every proxy appends the address it
// received the connection from, so the last element is the one written by the
// proxy nearest to the logging server, while everything to its left arrived in
// the request and is whatever the client chose to send. There is deliberately
// no fallback to an earlier element when the last one is unusable ("unknown",
// IPv6, empty) - that would hand the choice back to the client.
//
// Callers reach this only after parseIPv4ToUint32 returned 0, so a log of
// plain addresses never pays for it.
func forwardedTailIP(line []byte, start, end int) uint32 {
	if start < 0 || end > len(line) || start >= end {
		return 0
	}
	comma := bytes.LastIndexByte(line[start:end], ',')
	if comma < 0 {
		return 0
	}
	start += comma + 1
	for start < end && (line[start] == ' ' || line[start] == '\t') {
		start++
	}
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t') {
		end--
	}
	return parseIPv4ToUint32(line, start, end)
}

// parseIPv4ToUint32 extracts IPv4 address directly as uint32 - zero allocation
//
// Contract:
//   - exactly 4 octets separated by exactly 3 dots, nothing before or after
//   - every octet has 1 to 3 ASCII digits: an empty octet ("1.2..34",
//     "1.2.34.") is malformed, not a zero
//   - every octet is <= 255
//   - leading zeros within those 3 digits are accepted ("010" is 10)
//   - any violation -> 0
//
// Performance: the four octets are parsed by one unrolled "digit, optional
// digit, optional digit" sequence, so the strictness costs no per-byte state
// (no digit counter, no dot counter). One compare per digit, a constant shift
// per octet, no heap allocation. Measured faster than the previous lenient
// single loop on both uniform and mixed-width addresses.
//
// Input: line[start:end] should contain IPv4 like "192.168.1.1"
// Returns: uint32 IP or 0 if invalid format
func parseIPv4ToUint32(line []byte, start, end int) uint32 {
	n := end - start
	if n < 7 || n > 15 {
		return 0
	}
	// BCE hint: prove line[start:end] is fully in bounds.
	if start < 0 || end > len(line) {
		return 0
	}

	sub := line[start:end]
	var result uint32
	i := 0
	for part := 0; part < 4; part++ {
		// First digit of the octet is mandatory.
		if i >= len(sub) {
			return 0
		}
		d := sub[i] - '0' // unsigned: any non-digit wraps above 9
		if d > 9 {
			return 0
		}
		v := uint32(d)
		i++
		// Second and third digits are optional.
		if i < len(sub) {
			if d = sub[i] - '0'; d <= 9 {
				v = v*10 + uint32(d)
				i++
				if i < len(sub) {
					if d = sub[i] - '0'; d <= 9 {
						v = v*10 + uint32(d)
						i++
					}
				}
			}
		}
		if v > 255 {
			return 0
		}
		result = result<<8 | v
		// Octets 0..2 must be followed by a dot; a 4th digit lands here and is
		// rejected because it is not one.
		if part < 3 {
			if i >= len(sub) || sub[i] != '.' {
				return 0
			}
			i++
		}
	}
	if i != len(sub) {
		return 0 // trailing bytes after the 4th octet
	}

	return result
}

// notDigitBits returns a value with a bit set in its high nibble iff d, a byte
// minus '0', is NOT in 0..9. For a digit both d and d+6 stay below 16; any
// other value has a high-nibble bit in d itself (16..255) or in d+6 (10..15).
// OR-ing the results of several bytes and testing & 0xF0 once validates them
// all with a single branch.
func notDigitBits(d byte) byte {
	return d | (d + 6)
}

// daysInMonth is indexed by time.Month; February holds 29 and the leap-year
// rule is applied separately.
var daysInMonth = [13]uint8{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// parseTimestamp extracts timestamp from Apache Common Log format with maximum performance
//
// Expected format: "06/Jul/2025:19:57:26 +0000" within line[start:end], where
// end is the field's exclusive end (e.g. the position of the closing ']').
// The first 20 bytes (date and time) are the wall-clock fields. When a trailing
// "+HHMM"/"-HHMM" zone offset is present (end-start >= 26), that offset is
// RETAINED on the returned time: the wall-clock digits are unchanged (06:00
// stays 06:00) but the location reflects the log's real offset instead of being
// mislabeled UTC (URGENT-09). Live mode parses its lines with this same
// function, so both modes agree on the instant by construction. When no offset
// is present (the 20-byte EOL forms), the wall-clock is returned as UTC
// (unchanged behavior).
//
// Validation: the 12 digit positions must hold ASCII digits and the values must
// be in range (day valid for the month and year, hour <= 23, minute and second
// <= 59), which is what time.Parse accepts for the same text. Anything else
// yields the zero time instead of being masked or normalised into some other
// instant. The separators between the fields are not inspected.
//
// Performance optimizations:
//   - Digits validated together with one branch (see notDigitBits)
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
	// eliminating the individual bounds checks in the code below.
	_ = line[start+19]

	// Parse "06/Jul/2025:19:57:26 +0000" directly from line buffer. Load the 12
	// digits as byte-'0' and validate all of them with a single branch.
	d0, d1 := line[start]-'0', line[start+1]-'0'
	y0, y1, y2, y3 := line[start+7]-'0', line[start+8]-'0', line[start+9]-'0', line[start+10]-'0'
	h0, h1 := line[start+12]-'0', line[start+13]-'0'
	n0, n1 := line[start+15]-'0', line[start+16]-'0'
	s0, s1 := line[start+18]-'0', line[start+19]-'0'
	if (notDigitBits(d0)|notDigitBits(d1)|
		notDigitBits(y0)|notDigitBits(y1)|notDigitBits(y2)|notDigitBits(y3)|
		notDigitBits(h0)|notDigitBits(h1)|
		notDigitBits(n0)|notDigitBits(n1)|
		notDigitBits(s0)|notDigitBits(s1))&0xF0 != 0 {
		return time.Time{}
	}

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

	day := int(d0)*10 + int(d1)
	year := int(y0)*1000 + int(y1)*100 + int(y2)*10 + int(y3)
	hour := int(h0)*10 + int(h1)
	minute := int(n0)*10 + int(n1)
	second := int(s0)*10 + int(s1)

	// Range checks: time.Date would silently normalise 25:00 into the next day.
	if day == 0 || day > int(daysInMonth[month]) || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}
	}
	if month == 2 && day == 29 && (year%4 != 0 || (year%100 == 0 && year%400 != 0)) {
		return time.Time{}
	}

	// Retain the log's timezone offset when present (URGENT-09 parity). The
	// offset suffix is " +HHMM"/" -HHMM": space at start+20, sign at start+21,
	// four digits at start+22..25 - 6 bytes after the 20-byte core, so it is
	// in-bounds only when end-start >= 26. Shorter (20-byte EOL) fields keep the
	// historical UTC behavior.
	loc := time.UTC
	if end-start >= 26 {
		loc = offsetLocation(line[start+21 : start+26])
	}

	return time.Date(year, month, day, hour, minute, second, 0, loc)
}

// offsetCache memoizes *time.Location values keyed by the 5 offset bytes
// ("+HHMM"/"-HHMM"), so parseTimestamp stays allocation-free after warmup
// (time.FixedZone allocates and must never be called per line). Realistic logs
// use a single offset, so the cache holds a handful of entries. A sync.Map read
// for an existing key allocates nothing.
var offsetCache sync.Map // map[[5]byte]*time.Location

// offsetLocation returns a cached *time.Location for the "+HHMM"/"-HHMM" offset
// bytes. "+0000" fast-paths to time.UTC (no map hit, no alloc) so UTC logs -
// including the generated demo - see zero new allocations on the hot path. Any
// malformed offset falls back to UTC, preserving the wall-clock digits.
func offsetLocation(b []byte) *time.Location {
	// b is exactly 5 bytes: sign + HHMM.
	sign := b[0]
	h0, h1 := b[1]-'0', b[2]-'0'
	m0, m1 := b[3]-'0', b[4]-'0'
	// Validate digits and sign; on anything unexpected keep UTC wall-clock.
	if h0 > 9 || h1 > 9 || m0 > 9 || m1 > 9 || (sign != '+' && sign != '-') {
		return time.UTC
	}
	totalSec := (int(h0)*10+int(h1))*3600 + (int(m0)*10+int(m1))*60
	if totalSec == 0 {
		return time.UTC // +0000 / -0000: real UTC, fast path
	}
	var key [5]byte
	copy(key[:], b)
	if v, ok := offsetCache.Load(key); ok {
		return v.(*time.Location)
	}
	if sign == '-' {
		totalSec = -totalSec
	}
	loc := time.FixedZone(string(b), totalSec)
	actual, _ := offsetCache.LoadOrStore(key, loc)
	return actual.(*time.Location)
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
func parseMethod(line []byte, start, end int) accesslog.HTTPMethod {
	if end <= start {
		return accesslog.UNKNOWN
	}

	// Use first byte for lookup
	switch line[start] {
	case 'G':
		return accesslog.GET
	case 'P':
		if end > start+1 {
			switch line[start+1] {
			case 'O':
				return accesslog.POST
			case 'A':
				return accesslog.PATCH
			}
		}
		return accesslog.PUT
	case 'D':
		return accesslog.DELETE
	case 'H':
		return accesslog.HEAD
	case 'O':
		return accesslog.OPTIONS
	default:
		return accesslog.UNKNOWN
	}
}

// parseBytes extracts numeric byte count from line[start:end].
//
// Returns (value, true) when every byte in the field is an ASCII digit, or
// (0, false) when any non-digit appears - the field is then malformed and the
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
