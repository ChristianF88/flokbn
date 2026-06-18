package logparser

import (
	"errors"
	"io"
	"os"
	"sort"
	"testing"
)

// errInjectedReadAt is the sentinel returned by failingReaderAt for an injected
// read failure (a non-EOF error, distinct from io.EOF which is a normal
// terminator the parser must keep treating as success).
var errInjectedReadAt = errors.New("injected ReadAt failure")

// failingReaderAt wraps a real io.ReaderAt (an *os.File) and forces ReadAt to
// fail with errInjectedReadAt once the requested offset is at/after failAtOffset.
// Reads fully below the boundary are served by the delegate so the pipeline runs
// normally up to the failing chunk, exactly reproducing a mid-file partial-read
// fault on the concurrent (>=500MB) path without allocating a >=500MB file.
//
// This wraps an io.ReaderAt because the AUDIT-12 fix typed readChunkBatched /
// recoverLongLine's read source as io.ReaderAt (only ReadAt is used there);
// *os.File already satisfies it, so production behavior is unchanged.
type failingReaderAt struct {
	delegate     io.ReaderAt
	failAtOffset int64
}

func (f *failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= f.failAtOffset {
		return 0, errInjectedReadAt
	}
	return f.delegate.ReadAt(p, off)
}

// openSized opens path and returns the file plus its size; the caller closes it.
func openSized(t *testing.T, path string) (*os.File, int64) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		t.Fatalf("Stat: %v", err)
	}
	return f, st.Size()
}

// TestConcurrentReadAtError_FullModeSurfaces is the AUDIT-12 regression test for
// the full-Request concurrent path. A mid-file ReadAt failure on a later chunk
// previously produced a truncated result with a NIL error (silent under-banning).
// It must now surface a non-nil error from parseFileConcurrentIOChunked. A
// positive control (no injected failure) asserts the success path is unchanged
// (nil error + full result), so the change is pure error propagation.
func TestConcurrentReadAtError_FullModeSurfaces(t *testing.T) {
	const nLines = 5000
	content := genConcurrentTestLog(nLines, true)
	path := writeTempLog(t, content)

	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}

	// Small chunk size => many chunks; fail at a later chunk so earlier chunks
	// succeed and the fault is genuinely mid-file (matching a partial read on the
	// >=500MB production path).
	const chunkSize = 4 * 1024

	// Positive control: real file, no injected failure -> nil error + full result.
	func() {
		f, size := openSized(t, path)
		defer f.Close()
		reqs, perr := pp.parseFileConcurrentIOChunked(f, size, chunkSize)
		if perr != nil {
			t.Fatalf("success path returned unexpected error: %v", perr)
		}
		if len(reqs) == 0 {
			t.Fatalf("success path returned no requests")
		}
	}()

	// Failure injection: wrap the file so ReadAt fails at/after the 2nd chunk.
	f, size := openSized(t, path)
	defer f.Close()
	fr := &failingReaderAt{delegate: f, failAtOffset: chunkSize}
	reqs, perr := pp.parseFileConcurrentIOChunked(fr, size, chunkSize)
	if perr == nil {
		t.Fatalf("BUG: ReadAt failure swallowed — got nil error and %d requests (want non-nil error)", len(reqs))
	}
	if !errors.Is(perr, errInjectedReadAt) {
		t.Fatalf("error does not wrap injected failure: %v", perr)
	}
	// Partial result must not be published.
	if reqs != nil {
		t.Fatalf("expected nil result on error, got %d requests", len(reqs))
	}
}

// TestConcurrentReadAtError_IPModeSurfaces is the IP-only counterpart. The IP
// path shares readChunkBatched, so it must surface the same non-nil error
// (previously nil + a short IP set + understated invalid count). Positive control
// asserts the success path is unchanged.
func TestConcurrentReadAtError_IPModeSurfaces(t *testing.T) {
	const nLines = 5000
	content := genConcurrentTestLog(nLines, true)
	path := writeTempLog(t, content)

	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}
	pp.SkipNonIPFields = true

	const chunkSize = 4 * 1024

	// Positive control.
	func() {
		f, size := openSized(t, path)
		defer f.Close()
		ips, _, perr := pp.parseFileIPsConcurrentIOChunked(f, size, chunkSize)
		if perr != nil {
			t.Fatalf("success path returned unexpected error: %v", perr)
		}
		if len(ips) == 0 {
			t.Fatalf("success path returned no IPs")
		}
	}()

	// Failure injection.
	f, size := openSized(t, path)
	defer f.Close()
	fr := &failingReaderAt{delegate: f, failAtOffset: chunkSize}
	ips, invalid, perr := pp.parseFileIPsConcurrentIOChunked(fr, size, chunkSize)
	if perr == nil {
		t.Fatalf("BUG: ReadAt failure swallowed — got nil error, %d IPs, invalid=%d (want non-nil error)", len(ips), invalid)
	}
	if !errors.Is(perr, errInjectedReadAt) {
		t.Fatalf("error does not wrap injected failure: %v", perr)
	}
	if ips != nil || invalid != 0 {
		t.Fatalf("expected nil result + zero invalid on error, got %d IPs invalid=%d", len(ips), invalid)
	}
}

// TestConcurrentReadAtError_EOFStillSucceeds guards the edge the fix must NOT
// regress: io.EOF is the normal end-of-chunk/last-read terminator and must keep
// being treated as success. A reader that returns the real bytes plus io.EOF
// (the standard short-final-read contract) must still parse the full file with a
// nil error on both concurrent paths.
func TestConcurrentReadAtError_EOFStillSucceeds(t *testing.T) {
	const nLines = 4000
	content := genConcurrentTestLog(nLines, true)
	path := writeTempLog(t, content)

	pp, err := NewParser(concurrentZeroCopyFormat)
	if err != nil {
		t.Fatalf("NewParser: %v", err)
	}

	const chunkSize = 4 * 1024

	// eofReaderAt forwards to the file but always reports io.EOF alongside the
	// bytes it returns (a legal ReaderAt behavior). EOF must remain non-error.
	f, size := openSized(t, path)
	defer f.Close()
	eofR := &eofReaderAt{delegate: f}

	// Reference: streaming full-Request multiset.
	refReqs := parseStreamingFull(t, pp, path)

	reqs, perr := pp.parseFileConcurrentIOChunked(eofR, size, chunkSize)
	if perr != nil {
		t.Fatalf("io.EOF wrongly treated as error: %v", perr)
	}
	if len(reqs) != len(refReqs) {
		t.Fatalf("EOF-reader count mismatch: concurrent=%d streaming=%d", len(reqs), len(refReqs))
	}

	// IP-only path too.
	pp.SkipNonIPFields = true
	refIPs, refInvalid := parseStreamingIPs(t, pp, path)
	ips, invalid, perr := pp.parseFileIPsConcurrentIOChunked(eofR, size, chunkSize)
	if perr != nil {
		t.Fatalf("io.EOF wrongly treated as error (IP mode): %v", perr)
	}
	if len(ips) != len(refIPs) || invalid != refInvalid {
		t.Fatalf("EOF-reader IP mismatch: ips concurrent=%d streaming=%d, invalid concurrent=%d streaming=%d",
			len(ips), len(refIPs), invalid, refInvalid)
	}

	// Multiset equality as a stronger guard than counts alone.
	sortU32 := func(s []uint32) []uint32 {
		out := append([]uint32(nil), s...)
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	a, b := sortU32(ips), sortU32(refIPs)
	for i := range b {
		if a[i] != b[i] {
			t.Fatalf("EOF-reader IP multiset mismatch at %d: %d != %d", i, a[i], b[i])
		}
	}
}

// eofReaderAt forwards ReadAt to a delegate but always returns io.EOF as the
// error (with the real byte count). This is a legal io.ReaderAt: a caller must
// treat the returned n bytes as valid and io.EOF as a non-error terminator.
type eofReaderAt struct {
	delegate io.ReaderAt
}

func (e *eofReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := e.delegate.ReadAt(p, off)
	if err == nil {
		err = io.EOF
	}
	return n, err
}
