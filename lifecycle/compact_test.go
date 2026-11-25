package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"context"
)

// plainJournal is a FileJournal on an ordinary file, without the Windows
// storage adapter; plainReplace stands in for the atomic file replacement.
func plainJournal(t *testing.T, path string) *FileJournal {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	j := &FileJournal{file: f, state: emptyState(), token: make(chan struct{}, 1), unpin: func() {}}
	j.token <- struct{}{}
	t.Cleanup(func() { j.Close() })
	return j
}

func reopenPlain(t *testing.T, path string) State {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	j := &FileJournal{file: f, state: emptyState()}
	if err := j.readFrames(); err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	return j.state
}

type plainReplace struct {
	dir                   string
	paths                 []string
	failBefore, failAfter error
}

func (p *plainReplace) replace(current *os.File, frame []byte) (*os.File, bool, error) {
	if p.failBefore != nil {
		return nil, false, p.failBefore
	}
	path := filepath.Join(p.dir, fmt.Sprintf("journal-%d", len(p.paths)+1))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if _, err := f.Write(frame); err != nil {
		f.Close()
		return nil, false, err
	}
	if p.failAfter != nil {
		f.Close()
		return nil, true, p.failAfter
	}
	current.Close()
	p.paths = append(p.paths, path)
	return f, true, nil
}

type testArchiver struct {
	plans []Cleanup
	err   error
}

func (a *testArchiver) Archive(_ context.Context, plans []Cleanup) error {
	if a.err != nil {
		return a.err
	}
	a.plans = append(a.plans, plans...)
	return nil
}

var compactT0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

const retention90 = 90 * 24 * time.Hour

// seedJournal writes activation state and four cleanup plans:
// done (complete, closed at T0), incomplete, denied (retained CSR) and
// recent (complete, closed at T0+80d). Only done is purgeable at T0+91d.
func seedJournal(t *testing.T, j Journal) {
	t.Helper()
	a := Activator{Journal: j, Consumer: &testConsumer{}}
	for range 3 {
		if _, err := a.Reserve(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Apply(ctx, Activation{2, hashA}); err != nil {
		t.Fatal(err)
	}
	clock := compactT0
	run := func(id string, outcome Outcome, artifacts []Artifact, results ...error) {
		c := Cleaner{Journal: j, Deleter: &testDeleter{results: results}, Now: func() time.Time { return clock }}
		if err := c.Begin(ctx, id, outcome, artifacts); err != nil {
			t.Fatal(err)
		}
		_ = c.Resume(ctx, id)
	}
	run("done", Aborted, cleanupArtifacts())
	run("incomplete", Aborted, cleanupArtifacts(), ErrNotFound)
	run("denied", Denied, []Artifact{cleanupArtifacts()[0], {Kind: File, Name: "attempt.csr"}})
	clock = compactT0.Add(80 * 24 * time.Hour)
	run("recent", Aborted, cleanupArtifacts())
}

func stateJSON(t *testing.T, s State) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCompactPurgesOnlyEligiblePlansAndKeepsState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal")
	j := plainJournal(t, path)
	r := &plainReplace{dir: dir}
	j.replace = r.replace
	seedJournal(t, j)
	before := j.state
	arch := &testArchiver{}
	at := compactT0.Add(91 * 24 * time.Hour)
	purged, err := j.Compact(ctx, CompactOptions{Retention: retention90, Archive: arch, Now: func() time.Time { return at }})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(purged, []string{"done"}) || len(arch.plans) != 1 || arch.plans[0].ID != "done" {
		t.Fatalf("purged=%v archived=%+v", purged, arch.plans)
	}
	s := j.state
	if s.Revision != before.Revision+1 || s.Counter != 3 || s.Target != (Activation{2, hashA}) || s.Applied != s.Target {
		t.Fatalf("activation state changed: %+v", s)
	}
	if _, ok := s.Cleanups["done"]; ok || len(s.Cleanups) != 3 {
		t.Fatalf("cleanups after compaction: %v", s.Cleanups)
	}
	if c := s.Compaction; c == nil || c.Revision != s.Revision || !c.At.Equal(at) || c.Retention != retention90 || !slices.Equal(c.Purged, purged) {
		t.Fatalf("compaction record: %+v", c)
	}
	// The new file holds exactly one checkpoint frame, readable from scratch.
	frame, _ := encodeFrame(s)
	info, err := os.Stat(r.paths[0])
	if err != nil || info.Size() != int64(len(frame)) {
		t.Fatalf("compacted file: %v size=%d want %d", err, info.Size(), len(frame))
	}
	if got := reopenPlain(t, r.paths[0]); stateJSON(t, got) != stateJSON(t, s) {
		t.Fatal("reopened checkpoint differs from committed state")
	}
	// Appends continue on the new file and reopen across the checkpoint.
	g, err := (Activator{Journal: j}).Reserve(ctx)
	if err != nil || g != 4 {
		t.Fatalf("reserve after compaction: %d %v", g, err)
	}
	if got := reopenPlain(t, r.paths[0]); got.Counter != 4 || got.Revision != s.Revision+1 {
		t.Fatalf("append after checkpoint: %+v", got)
	}
	// Compacting again keeps the record count and drops nothing new.
	purged, err = j.Compact(ctx, CompactOptions{Retention: retention90, Archive: arch, Now: func() time.Time { return at }})
	if err != nil || len(purged) != 0 || len(j.state.Cleanups) != 3 {
		t.Fatalf("second compaction: %v %v", purged, err)
	}
}

// Without retention, compaction only rewrites the file: no record is removed
// and no archiver is needed. Latches and unfinished operations survive.
func TestCompactWithoutRetentionKeepsEverything(t *testing.T) {
	dir := t.TempDir()
	j := plainJournal(t, filepath.Join(dir, "journal"))
	r := &plainReplace{dir: dir}
	j.replace = r.replace
	seedJournal(t, j)
	latchCleanup(t, j, "latched")
	if err := (ProcessGuard{Journal: j}).Run(ctx, "native-op", nil, func() error { return ErrQuiescence }); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	before := j.state
	purged, err := j.Compact(ctx, CompactOptions{Now: func() time.Time { return compactT0.Add(1000 * 24 * time.Hour) }})
	if err != nil || len(purged) != 0 {
		t.Fatalf("%v %v", purged, err)
	}
	after := j.state
	after.Revision, after.Compaction = before.Revision, before.Compaction
	if stateJSON(t, after) != stateJSON(t, before) {
		t.Fatal("compaction without retention changed state")
	}
	if err := (Cleaner{Journal: j, Deleter: &testDeleter{}}).Resume(ctx, "recent"); err != nil {
		t.Fatal(err) // terminal complete plan still reports its outcome
	}
	if err := (ProcessGuard{Journal: j}).Run(ctx, "native-op", nil, func() error { return nil }); !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("latch lost by compaction: %v", err)
	}
}

func TestCompactFailuresLeaveJournalConsistent(t *testing.T) {
	at := func() time.Time { return compactT0.Add(91 * 24 * time.Hour) }
	t.Run("archive", func(t *testing.T) {
		dir := t.TempDir()
		j := plainJournal(t, filepath.Join(dir, "journal"))
		r := &plainReplace{dir: dir}
		j.replace = r.replace
		seedJournal(t, j)
		before := stateJSON(t, j.state)
		boom := errors.New("archive unavailable")
		if _, err := j.Compact(ctx, CompactOptions{Retention: retention90, Archive: &testArchiver{err: boom}, Now: at}); !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if len(r.paths) != 0 || stateJSON(t, j.state) != before || j.poison != nil {
			t.Fatal("failed archive changed the journal")
		}
	})
	t.Run("before replacement", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "journal")
		j := plainJournal(t, path)
		boom := errors.New("cannot create temporary file")
		j.replace = (&plainReplace{dir: dir, failBefore: boom}).replace
		seedJournal(t, j)
		before := stateJSON(t, j.state)
		if _, err := j.Compact(ctx, CompactOptions{Now: at}); !errors.Is(err, boom) || errors.Is(err, ErrCompactionInterrupted) {
			t.Fatal(err)
		}
		if stateJSON(t, j.state) != before || j.poison != nil {
			t.Fatal("uncommitted replacement changed the journal")
		}
		if _, err := (Activator{Journal: j}).Reserve(ctx); err != nil {
			t.Fatalf("journal unusable after uncommitted failure: %v", err)
		}
		if got := reopenPlain(t, path); got.Counter != 4 {
			t.Fatalf("append after failed compaction: %+v", got)
		}
	})
	t.Run("after replacement started", func(t *testing.T) {
		dir := t.TempDir()
		j := plainJournal(t, filepath.Join(dir, "journal"))
		boom := errors.New("rename failed")
		j.replace = (&plainReplace{dir: dir, failAfter: boom}).replace
		seedJournal(t, j)
		if _, err := j.Compact(ctx, CompactOptions{Now: at}); !errors.Is(err, ErrCompactionInterrupted) || !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if _, err := (Activator{Journal: j}).Reserve(ctx); !errors.Is(err, ErrCompactionInterrupted) {
			t.Fatalf("journal not poisoned: %v", err)
		}
	})
}

func TestCompactRefusals(t *testing.T) {
	dir := t.TempDir()
	j := plainJournal(t, filepath.Join(dir, "journal"))
	if _, err := j.Compact(ctx, CompactOptions{}); !errors.Is(err, ErrJournal) {
		t.Fatalf("compaction without adapter: %v", err)
	}
	j.replace = (&plainReplace{dir: dir}).replace
	if _, err := j.Compact(ctx, CompactOptions{Retention: retention90}); err == nil {
		t.Fatal("purge without archiver accepted")
	}
	if _, err := j.Compact(ctx, CompactOptions{Retention: -1}); err == nil {
		t.Fatal("negative retention accepted")
	}
	j.activationOnly = true
	if _, err := j.Compact(ctx, CompactOptions{}); !errors.Is(err, ErrJournal) {
		t.Fatalf("consumer journal compacted: %v", err)
	}
}

// Only Compact writes compaction records; the journal validates purges and
// accepts a checkpoint, and nothing else, as the first frame of a file.
func TestJournalValidatesCompactionRecords(t *testing.T) {
	j := newTestJournal()
	seedJournal(t, j)
	prev := cloneState(j.state)
	at := compactT0.Add(91 * 24 * time.Hour)
	checkpoint := func(retention time.Duration, purged ...string) State {
		next := cloneState(prev)
		next.Revision++
		next.Compaction = &Compaction{Revision: next.Revision, At: at, Retention: retention, Purged: purged}
		for _, id := range purged {
			if p, ok := next.Cleanups[id]; ok {
				if next.Purged == nil {
					next.Purged = map[string]PurgedCleanup{}
				}
				next.Purged[id] = purgedIdentity(p)
			}
			delete(next.Cleanups, id)
		}
		return next
	}
	if err := validateState(checkpoint(retention90, "done"), prev); err != nil {
		t.Fatalf("valid purge rejected: %v", err)
	}
	for name, next := range map[string]State{
		"incomplete plan":      checkpoint(retention90, "incomplete"),
		"retained CSR":         checkpoint(retention90, "denied"),
		"retention not over":   checkpoint(retention90, "recent"),
		"purge without period": checkpoint(0, "done"),
		"duplicate":            checkpoint(retention90, "done", "done"),
		"unknown plan":         checkpoint(retention90, "missing"),
	} {
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: purge accepted", name)
		}
	}
	unlisted := checkpoint(retention90)
	delete(unlisted.Cleanups, "done")
	if err := validateState(unlisted, prev); err == nil {
		t.Error("unlisted removal accepted")
	}
	wrongRevision := checkpoint(0)
	wrongRevision.Compaction.Revision--
	if err := validateState(wrongRevision, prev); err == nil {
		t.Error("compaction record outside its checkpoint accepted")
	}
	// fileTransaction.Save refuses compaction records from callers.
	fj := &FileJournal{state: prev}
	forged := cloneState(prev)
	forged.Compaction = &Compaction{Revision: prev.Revision + 1, At: at}
	if err := (fileTransaction{fj}).Save(forged); !errors.Is(err, ErrJournal) {
		t.Fatalf("caller wrote a compaction record: %v", err)
	}
	// First frame of a file: revision 1 or a checkpoint at any revision.
	cp := checkpoint(retention90, "done")
	if err := validateState(cp, emptyState()); err != nil {
		t.Fatalf("checkpoint rejected as first frame: %v", err)
	}
	plain := cloneState(prev)
	plain.Revision++
	if err := validateState(plain, emptyState()); err == nil {
		t.Fatal("non-checkpoint frame accepted as first frame at a later revision")
	}
	after := cloneState(cp)
	after.Revision++
	if err := validateState(after, emptyState()); err == nil {
		t.Fatal("frame following a checkpoint accepted as first frame")
	}
}

// A purged plan keeps its identity across compactions; a late
// identical Begin is a no-op, a different plan under the ID a conflict, and
// Resume never calls the deleter again.
func TestPurgedPlanIsNotReplayed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal")
	j := plainJournal(t, path)
	r := &plainReplace{dir: dir}
	j.replace = r.replace
	seedJournal(t, j)
	at := func() time.Time { return compactT0.Add(91 * 24 * time.Hour) }
	opts := CompactOptions{Retention: retention90, Archive: &testArchiver{}, Now: at}
	if purged, err := j.Compact(ctx, opts); err != nil || !slices.Equal(purged, []string{"done"}) {
		t.Fatalf("%v %v", purged, err)
	}
	// A second compaction replaces Compaction.Purged; the identity stays.
	if _, err := j.Compact(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if len(j.state.Compaction.Purged) != 0 || j.state.Purged["done"].Digest == "" {
		t.Fatalf("purged identity: %+v / %+v", j.state.Compaction, j.state.Purged)
	}
	d := &testDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "done", Aborted, cleanupArtifacts()); err != nil {
		t.Fatalf("identical replay: %v", err)
	}
	if _, ok := j.state.Cleanups["done"]; ok {
		t.Fatal("purged plan recreated")
	}
	if err := c.Resume(ctx, "done"); err != nil {
		t.Fatalf("resume of a purged complete plan: %v", err)
	}
	if err := c.Begin(ctx, "done", Denied, cleanupArtifacts()); !errors.Is(err, ErrConflict) {
		t.Fatalf("different outcome: %v", err)
	}
	if err := c.Begin(ctx, "done", Aborted, cleanupArtifacts()[:1]); !errors.Is(err, ErrConflict) {
		t.Fatalf("different artifacts: %v", err)
	}
	if len(d.calls) != 0 {
		t.Fatalf("deleter called for a purged plan: %+v", d.calls)
	}
	if got := reopenPlain(t, r.paths[len(r.paths)-1]); got.Purged["done"].Digest != j.state.Purged["done"].Digest {
		t.Fatal("purged identity not durable across reopen")
	}
}

func TestJournalProtectsPurgedIdentities(t *testing.T) {
	j := newTestJournal()
	seedJournal(t, j)
	j.state.Purged = map[string]PurgedCleanup{"old": {Outcome: Aborted, Digest: hashA, ClosedAt: compactT0}}
	prev := cloneState(j.state)
	for name, mutate := range map[string]func(*State){
		"dropped": func(s *State) { delete(s.Purged, "old") },
		"changed": func(s *State) { s.Purged["old"] = PurgedCleanup{Outcome: Denied, Digest: hashA, ClosedAt: compactT0} },
		"added outside a purge": func(s *State) {
			s.Purged["new"] = PurgedCleanup{Outcome: Aborted, Digest: hashB, ClosedAt: compactT0}
		},
		"ID reused": func(s *State) {
			s.Cleanups["old"] = Cleanup{ID: "old", Outcome: Aborted, Items: []CleanupItem{{Artifact: cleanupArtifacts()[0]}}}
		},
	} {
		next := cloneState(prev)
		mutate(&next)
		next.Revision++
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A purge must leave the matching identity.
	next := cloneState(prev)
	next.Revision++
	next.Compaction = &Compaction{Revision: next.Revision, At: compactT0.Add(91 * 24 * time.Hour), Retention: retention90, Purged: []string{"done"}}
	delete(next.Cleanups, "done")
	if err := validateState(next, prev); err == nil {
		t.Error("purge without identity accepted")
	}
	next.Purged["done"] = PurgedCleanup{Outcome: Aborted, Digest: hashB, ClosedAt: compactT0}
	if err := validateState(next, prev); err == nil {
		t.Error("purge with a wrong identity accepted")
	}
	next.Purged["done"] = purgedIdentity(prev.Cleanups["done"])
	if err := validateState(next, prev); err != nil {
		t.Errorf("valid purge rejected: %v", err)
	}
}

// The consumer journal reader rejects a checkpoint frame.
func TestConsumerReaderRejectsCheckpoint(t *testing.T) {
	s := emptyState()
	s.Revision = 5
	s.Compaction = &Compaction{Revision: 5, At: compactT0}
	frame, err := encodeFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "journal")
	if err := os.WriteFile(path, frame, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := (&FileJournal{file: f, state: emptyState(), activationOnly: true}).readFrames(); err == nil {
		t.Fatal("consumer journal accepted a checkpoint")
	}
}

// A checkpoint read at restart has no predecessor, so its
// purged identities get structural checks.
func TestCheckpointRejectsMalformedPurgedIdentity(t *testing.T) {
	base := emptyState()
	base.Revision = 7
	base.Compaction = &Compaction{Revision: 7, At: compactT0}
	valid := PurgedCleanup{Outcome: Aborted, Digest: hashA, ClosedAt: compactT0}
	for name, p := range map[string]PurgedCleanup{
		"valid":            valid,
		"uppercase digest": {Outcome: Aborted, Digest: strings.ToUpper(hashA), ClosedAt: compactT0},
		"non-hex digest":   {Outcome: Aborted, Digest: strings.Repeat("z", 64), ClosedAt: compactT0},
		"no closure":       {Outcome: Aborted, Digest: hashA},
		"unknown outcome":  {Outcome: "PURGED", Digest: hashA, ClosedAt: compactT0},
	} {
		s := cloneState(base)
		s.Purged = map[string]PurgedCleanup{"old": p}
		err := validateState(s, emptyState())
		if (err == nil) != (name == "valid") {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}
