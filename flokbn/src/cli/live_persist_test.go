package cli

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/ChristianF88/flokbn/accesslog"
	"github.com/ChristianF88/flokbn/config"
	"github.com/ChristianF88/flokbn/jail"
)

// gatedIngestor parks the loop inside ReadBatch until the test releases one
// step, so the test can inspect the files on disk between iterations without
// racing the next one. Close unblocks a parked ReadBatch.
type gatedIngestor struct {
	*fakeIngestor
	gate   chan struct{}
	closed chan struct{}
}

func newGatedIngestor(batches ...[]accesslog.Request) *gatedIngestor {
	return &gatedIngestor{
		fakeIngestor: &fakeIngestor{batches: batches},
		gate:         make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (g *gatedIngestor) ReadBatch() ([]accesslog.Request, error) {
	select {
	case <-g.gate:
	case <-g.closed:
	}
	return g.fakeIngestor.ReadBatch()
}

func (g *gatedIngestor) Close() error {
	select {
	case <-g.closed:
	default:
		close(g.closed)
	}
	return g.fakeIngestor.Close()
}

// step releases exactly one ReadBatch and returns the resulting "iteration"
// record. When it returns, the loop is parked in the next ReadBatch (or about
// to be), so every file write of that iteration has already happened.
func (g *gatedIngestor) step(t *testing.T, h *loopHarness) logEvent {
	t.Helper()
	select {
	case g.gate <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("loop never asked for the next batch")
	}
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-h.events:
			if ev.rec.Message == "iteration" {
				return ev
			}
		case <-deadline:
			t.Fatal("timed out waiting for iteration log record")
		}
	}
}

// fileState is what the tests compare to tell "left alone" from "rewritten".
// Both files are written via temp file + rename, so a rewrite always yields a
// different inode even when the bytes are identical.
type fileState struct {
	info    os.FileInfo
	content string
}

func statFile(t *testing.T, path string) fileState {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return fileState{info: info, content: string(data)}
}

func (a fileState) untouched(b fileState) bool {
	return os.SameFile(a.info, b.info) && a.info.ModTime().Equal(b.info.ModTime()) && a.content == b.content
}

func writtenAttrs(t *testing.T, ev logEvent) (ban, jailFile bool) {
	t.Helper()
	attrs := recordAttrs(ev.rec)
	b, ok := attrs["ban_file_written"]
	if !ok {
		t.Fatalf("iteration record missing ban_file_written (attrs: %v)", attrs)
	}
	j, ok := attrs["jail_file_written"]
	if !ok {
		t.Fatalf("iteration record missing jail_file_written (attrs: %v)", attrs)
	}
	return b.Bool(), j.Bool()
}

// TestRunLiveLoop_IterationWritesFilesOnlyOnChange: the iteration path used to
// rewrite jail.json and the ban file (temp file, fsync, rename, fresh
// timestamp header) on every single iteration, even when nothing changed,
// while the heartbeat already used change detection. Both files must now be
// left alone when their content is unchanged, rewritten when it changes, and
// recreated when they went missing.
func TestRunLiveLoop_IterationWritesFilesOnlyOnChange(t *testing.T) {
	now := time.Now()
	ing := newGatedIngestor(
		hotBlock(10, 5, 5, now, "/api/item"), // 1: new ban
		hotBlock(10, 5, 5, now, "/api/item"), // 2: same range, ban still active: nothing changes
		hotBlock(10, 5, 5, now, "/api/item"), // 3: nothing changes, but the files were deleted
		hotBlock(10, 6, 6, now, "/api/item"), // 4: second range: both files change
	)
	cfg := newLiveConfig(t, map[string]*config.SlidingTrieConfig{
		"w": newWindowConfig(t, "", true),
	})
	banPath, jailPath := cfg.GetBanFile(), cfg.GetJailFile()

	h := startLoop(t, ing, cfg)

	// Iteration 1: first write of both files.
	ev1 := ing.step(t, h)
	if ban, jl := writtenAttrs(t, ev1); !ban || !jl {
		t.Fatalf("iteration 1 ban/jail written = %v/%v, want true/true", ban, jl)
	}
	ban1, jail1 := statFile(t, banPath), statFile(t, jailPath)
	if got := banCIDRs(t, banPath); !reflect.DeepEqual(got, []string{"10.5.5.0/24"}) {
		t.Fatalf("ban file after iteration 1 = %v, want [10.5.5.0/24]", got)
	}
	written1 := ev1.snap.Lists.BanFile.LastWritten

	// Iteration 2: identical outcome, neither file may be touched.
	ev2 := ing.step(t, h)
	if ban, jl := writtenAttrs(t, ev2); ban || jl {
		t.Errorf("iteration 2 ban/jail written = %v/%v, want false/false (nothing changed)", ban, jl)
	}
	if ban2 := statFile(t, banPath); !ban1.untouched(ban2) {
		t.Errorf("ban file was rewritten by an iteration that changed nothing")
	}
	if jail2 := statFile(t, jailPath); !jail1.untouched(jail2) {
		t.Errorf("jail file was rewritten by an iteration that changed nothing")
	}
	if got := ev2.snap.Lists.BanFile.LastWritten; !got.Equal(written1) {
		t.Errorf("lists.ban_file.last_written moved from %v to %v without a write", written1, got)
	}
	if got := ev2.snap.Lists.BanFile.Entries; got != 1 {
		t.Errorf("lists.ban_file.entries = %d, want 1", got)
	}

	// Iteration 3: still nothing to change, but both files are gone. They
	// must come back with the same content rather than stay missing until
	// the next ban change.
	if err := os.Remove(banPath); err != nil {
		t.Fatalf("removing ban file: %v", err)
	}
	if err := os.Remove(jailPath); err != nil {
		t.Fatalf("removing jail file: %v", err)
	}
	ev3 := ing.step(t, h)
	if ban, jl := writtenAttrs(t, ev3); !ban || !jl {
		t.Errorf("iteration 3 ban/jail written = %v/%v, want true/true (files were missing)", ban, jl)
	}
	if got := banCIDRs(t, banPath); !reflect.DeepEqual(got, []string{"10.5.5.0/24"}) {
		t.Errorf("recreated ban file = %v, want [10.5.5.0/24]", got)
	}
	if got := statFile(t, jailPath).content; got != jail1.content {
		t.Errorf("recreated jail file differs from the original:\n got %s\nwant %s", got, jail1.content)
	}

	// Iteration 4: a second range is banned, both files change.
	ev4 := ing.step(t, h)
	if ban, jl := writtenAttrs(t, ev4); !ban || !jl {
		t.Errorf("iteration 4 ban/jail written = %v/%v, want true/true (new ban)", ban, jl)
	}
	if got := banCIDRs(t, banPath); !reflect.DeepEqual(got, []string{"10.5.5.0/24", "10.6.6.0/24"}) {
		t.Errorf("ban file after iteration 4 = %v, want [10.5.5.0/24 10.6.6.0/24]", got)
	}
	for _, c := range []string{"10.5.5.0/24", "10.6.6.0/24"} {
		if _, active, found := findPrisoner(t, jailPath, c); !found || !active {
			t.Errorf("jail file after iteration 4: %s found/active = %v/%v, want true/true", c, found, active)
		}
	}
	if got := ev4.snap.Lists.BanFile.Entries; got != 2 {
		t.Errorf("lists.ban_file.entries = %d, want 2", got)
	}
}

// TestJailFileState_Save covers the change detection on its own: identical
// content is skipped, changed content and a missing file are written, and the
// bytes match what jail.Jail.Save produces.
func TestJailFileState_Save(t *testing.T) {
	path := t.TempDir() + "/jail.json"
	now := time.Now()
	j, err := jail.New(jail.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.UpdateCIDRs(now, []string{"10.5.5.0/24"}); err != nil {
		t.Fatalf("jail update: %v", err)
	}

	var st jailFileState
	if wrote, err := st.save(j, path); err != nil || !wrote {
		t.Fatalf("first save = %v, %v; want true, nil", wrote, err)
	}
	first := statFile(t, path)

	ref := t.TempDir() + "/ref.json"
	if err := j.Save(ref); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if want := statFile(t, ref); first.content != want.content || first.info.Mode() != want.info.Mode() {
		t.Errorf("saved jail differs from the output of Jail.Save (content or mode)")
	}

	// A round that only re-detects a banned range, and a ban that ran out,
	// leave the records as they are: nothing to write.
	if _, err := j.UpdateCIDRs(now.Add(time.Minute), []string{"10.5.5.0/24"}); err != nil {
		t.Fatalf("jail update: %v", err)
	}
	if _, err := j.UpdateCIDRs(now.Add(11*time.Minute), nil); err != nil {
		t.Fatalf("jail update: %v", err)
	}
	if wrote, err := st.save(j, path); err != nil || wrote {
		t.Errorf("unchanged save = %v, %v; want false, nil", wrote, err)
	}
	if !first.untouched(statFile(t, path)) {
		t.Errorf("unchanged save touched the file")
	}

	if _, err := j.UpdateCIDRs(now.Add(12*time.Minute), []string{"10.6.6.0/24"}); err != nil {
		t.Fatalf("jail update: %v", err)
	}
	if wrote, err := st.save(j, path); err != nil || !wrote {
		t.Errorf("changed save = %v, %v; want true, nil", wrote, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("removing jail file: %v", err)
	}
	if wrote, err := st.save(j, path); err != nil || !wrote {
		t.Errorf("save after the file was removed = %v, %v; want true, nil", wrote, err)
	}

	// A failed write must not be remembered as saved: the next call retries.
	bad := t.TempDir() + "/missing-dir/jail.json"
	var failing jailFileState
	if wrote, err := failing.save(j, bad); err == nil || wrote {
		t.Errorf("save into a missing directory = %v, %v; want false, error", wrote, err)
	}
	if wrote, err := failing.save(j, bad); err == nil || wrote {
		t.Errorf("retry into a missing directory = %v, %v; want false, error", wrote, err)
	}
}
