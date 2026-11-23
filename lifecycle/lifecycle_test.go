package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()
var hashA = strings.Repeat("a", 64)
var hashB = strings.Repeat("b", 64)

// Failpoints model a crash before or after a durable write. Snapshots are
// deep-copied so uncommitted mutations cannot accidentally reach the journal.
type testJournal struct {
	mu             sync.Mutex
	state          State
	saves          int
	failAt         int
	commitThenFail bool
	history        []State // every committed state, in order
}

func newTestJournal() *testJournal { return &testJournal{state: emptyState()} }
func (j *testJournal) WithLock(c context.Context, f func(Transaction) error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := c.Err(); err != nil {
		return err
	}
	return f(j)
}
func cloneState(s State) State {
	b, _ := json.Marshal(s)
	var copy State
	_ = json.Unmarshal(b, &copy)
	return copy
}
func (j *testJournal) Load() (State, error) { return cloneState(j.state), nil }

var diskFailure = errors.New("injected flush failure")

func (j *testJournal) Save(s State) error {
	j.saves++
	if s.Revision != j.state.Revision {
		return ErrJournal
	}
	s.Revision++
	if err := validateState(s, j.state); err != nil {
		return err
	}
	fail := j.saves == j.failAt
	if !fail || j.commitThenFail {
		j.state = cloneState(s)
		j.history = append(j.history, cloneState(s))
	}
	if fail {
		return diskFailure
	}
	return nil
}

type testConsumer struct {
	mu         sync.Mutex
	current    Activation
	swaps      []Activation
	entered    chan struct{}
	release    chan struct{}
	checkLease func() error
}

func (c *testConsumer) Verify(_ context.Context, a Activation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != a {
		return errors.New("pointer/handshake mismatch")
	}
	return nil
}
func (c *testConsumer) Swap(_ context.Context, a Activation) error {
	if c.checkLease != nil {
		if err := c.checkLease(); err != nil {
			return err
		}
	}
	if c.entered != nil && a.Generation == 1 {
		close(c.entered)
		<-c.release
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = a
	c.swaps = append(c.swaps, a)
	return nil
}

func TestActivationHoldsLeaseAcrossActualSwap(t *testing.T) {
	j := newTestJournal()
	c := &testConsumer{checkLease: func() error {
		if j.mu.TryLock() {
			j.mu.Unlock()
			return errors.New("swap outside the journal lease")
		}
		return nil
	}}
	a := Activator{j, c}
	g, err := a.Reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, Activation{g, hashA}); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupBlocksOnUnfinishedNativeOperation(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "attempt", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	g := ProcessGuard{Journal: j}
	if err := g.Run(ctx, "certreq", nil, func() error { return ErrQuiescence }); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if len(d.calls) != 0 {
		t.Fatal("cleanup raced an unfinished mutator")
	}
}

func TestCleanupStopsAndLatchesUncertainDeleter(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{results: []error{ErrQuiescence}}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "attempt", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if len(d.calls) != 1 {
		t.Fatal("deletion continued after loss of quiescence")
	}
}

func TestActivationSerializesEffectNotOnlyComparison(t *testing.T) {
	j := newTestJournal()
	consumer := &testConsumer{entered: make(chan struct{}), release: make(chan struct{})}
	a := Activator{Journal: j, Consumer: consumer}
	g1, _ := a.Reserve(ctx)
	g2, _ := a.Reserve(ctx)
	done1, done2 := make(chan error, 1), make(chan error, 1)
	go func() { done1 <- a.Apply(ctx, Activation{g1, hashA}) }()
	<-consumer.entered
	go func() { done2 <- a.Apply(ctx, Activation{g2, hashB}) }()
	select {
	case err := <-done2:
		t.Fatalf("new activation escaped old swap's lease: %v", err)
	default:
	}
	close(consumer.release)
	if err := <-done1; err != nil {
		t.Fatal(err)
	}
	if err := <-done2; err != nil {
		t.Fatal(err)
	}
	if consumer.current != (Activation{g2, hashB}) {
		t.Fatal("late old swap replaced new activation")
	}
	if err := a.Apply(ctx, Activation{g1, hashA}); !errors.Is(err, ErrSuperseded) {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, Activation{g2, hashA}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, Activation{g2, hashB}); err != nil {
		t.Fatal(err)
	}
	if len(consumer.swaps) != 2 {
		t.Fatal("equal replay caused another swap")
	}
}

func TestActivationRecoveryAfterLostAcknowledgmentAndConsumerRestart(t *testing.T) {
	j := newTestJournal()
	consumer := &testConsumer{}
	a := Activator{j, consumer}
	g, _ := a.Reserve(ctx)
	j.failAt = 3 // reservation, intent, then acknowledgment
	if err := a.Apply(ctx, Activation{g, hashA}); !errors.Is(err, diskFailure) {
		t.Fatal(err)
	}
	if j.state.Applied.Generation != 0 || j.state.Target.Generation != g {
		t.Fatal("intent was lost")
	}
	// Recreate the consumer: a persisted Applied field would not prove its
	// in-memory pointer. Recovery must restore and verify the durable target.
	a.Consumer = &testConsumer{}
	if err := a.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if j.state.Applied != j.state.Target {
		t.Fatal("recovery not acknowledged")
	}
	g2, err := a.Reserve(ctx)
	if err != nil || g2 <= g {
		t.Fatal("counter was reused after restart")
	}
	// Rollback to the same certificate is a new operation, never generation g.
	if err := a.Apply(ctx, Activation{g2, hashA}); err != nil {
		t.Fatal(err)
	}
}

func TestActivationDoesNotSwapBeforeDurableIntent(t *testing.T) {
	for _, committed := range []bool{false, true} {
		j := newTestJournal()
		c := &testConsumer{}
		a := Activator{j, c}
		g, _ := a.Reserve(ctx)
		j.failAt, j.commitThenFail = 2, committed
		if err := a.Apply(ctx, Activation{g, hashA}); !errors.Is(err, diskFailure) {
			t.Fatal(err)
		}
		if len(c.swaps) != 0 {
			t.Fatal("swap followed uncertain intent write")
		}
		if committed {
			if err := a.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			if c.current.Generation != g {
				t.Fatal("durable intent not recovered")
			}
		}
	}
}

type testDeleter struct {
	calls   []Artifact
	results []error
}

func (d *testDeleter) Delete(_ context.Context, a Artifact) error {
	d.calls = append(d.calls, a)
	if len(d.results) == 0 {
		return nil
	}
	err := d.results[0]
	d.results = d.results[1:]
	return err
}
func cleanupArtifacts() []Artifact {
	return []Artifact{
		{Kind: Key, Name: "key", Provider: "KSP", Container: "container", SPKI: hashA},
		{Kind: Request, Name: "request", Hash: hashB, SPKI: hashA},
	}
}

func TestCleanupCrashAfterDeleteBeforeAcknowledgmentRemainsIncomplete(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{results: []error{nil, ErrNotFound, nil}}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "attempt", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	j.failAt = 2
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, diskFailure) {
		t.Fatal(err)
	}
	if len(d.calls) != 1 {
		t.Fatal("effects continued after checkpoint failure")
	}
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatal(err)
	}
	plan := j.state.Cleanups["attempt"]
	if plan.Complete || !plan.Terminal || plan.Items[0].Result != NotFound {
		t.Fatal("absence became deletion success")
	}
	n := len(d.calls)
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatal(err)
	}
	if len(d.calls) != n {
		t.Fatal("terminal incomplete cleanup retried automatically")
	}
}

func TestCleanupDoesNotRepeatDurablyAcknowledgedDelete(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "attempt", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	j.failAt, j.commitThenFail = 2, true
	if err := c.Resume(ctx, "attempt"); !errors.Is(err, diskFailure) {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "attempt"); err != nil {
		t.Fatal(err)
	}
	if len(d.calls) != 2 || d.calls[0].Kind != Key || d.calls[1].Kind != Request {
		t.Fatalf("repeated delete: %+v", d.calls)
	}
	if !j.state.Cleanups["attempt"].Complete {
		t.Fatal("cleanup not completed")
	}
}

func TestCleanupMatrixAndRetention(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, outcome := range []Outcome{Abandoned, Aborted, Denied, CAUnknown, BlockedPKI, Inconclusive, Retired} {
		t.Run(string(outcome), func(t *testing.T) {
			j := newTestJournal()
			d := &testDeleter{}
			c := Cleaner{Journal: j, Deleter: d, Now: func() time.Time { return now }}
			arts := append(cleanupArtifacts(), Artifact{Kind: File, Name: "request.csr", Hash: hashA})
			if err := c.Begin(ctx, "attempt", outcome, arts); err != nil {
				t.Fatal(err)
			}
			if err := c.Resume(ctx, "attempt"); err != nil {
				t.Fatal(err)
			}
			p := j.state.Cleanups["attempt"]
			wantKey := Deleted
			if outcome == Abandoned || outcome == BlockedPKI || outcome == Inconclusive {
				wantKey = Retained
			}
			if p.Items[0].Result != wantKey {
				t.Fatal("wrong key policy")
			}
			wantREQ := Deleted
			if outcome == Denied || outcome == CAUnknown || outcome == BlockedPKI || outcome == Inconclusive {
				wantREQ = Retained
			}
			if p.Items[2].Result != wantREQ {
				t.Fatal("wrong CSR policy")
			}
			eligible := p.AuditExpiry(now.Add(365*24*time.Hour), 90*24*time.Hour)
			if eligible != (outcome == Aborted || outcome == Retired) {
				t.Fatal("unresolved/retained artifact became purgeable")
			}
			if p.AuditExpiry(now.Add(-time.Hour), time.Hour) {
				t.Fatal("backward clock enabled purge")
			}
			bad := append([]Artifact(nil), arts...)
			bad[0].Container = "other"
			if err := c.Begin(ctx, "attempt", outcome, bad); !errors.Is(err, ErrConflict) {
				t.Fatal("intent replaced", err)
			}
		})
	}
}

func TestCleanupIntentFailureNeverDeletes(t *testing.T) {
	j := newTestJournal()
	j.failAt = 1
	d := &testDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "attempt", Aborted, cleanupArtifacts()); !errors.Is(err, diskFailure) {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "attempt"); err == nil {
		t.Fatal("missing intent accepted")
	}
	if len(d.calls) != 0 {
		t.Fatal("deleted without durable intent")
	}
}

type testQuiescer struct {
	err   error
	calls int
}

func (q *testQuiescer) Wait(context.Context, Operation) error { q.calls++; return q.err }

func TestProcessGuardBlocksAfterCrashWithoutTreeEvidence(t *testing.T) {
	j := newTestJournal()
	g := ProcessGuard{Journal: j}
	calls := 0
	effect := func() error { calls++; return ErrQuiescence }
	if err := g.Run(ctx, "certreq", []string{"-new"}, effect); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if err := g.Run(ctx, "certreq", []string{"-accept"}, effect); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("new mutator started without quiescence")
	}
	q := &testQuiescer{err: context.DeadlineExceeded}
	g.Recovery = q
	if err := g.Run(ctx, "certreq", nil, effect); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if j.state.Operation.Quiescent {
		t.Fatal("timeout certified quiescence")
	}
	q.err = nil
	if err := g.Run(ctx, "certreq", nil, effect); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if calls != 1 || !j.state.Operation.Quiescent {
		t.Fatal("replayed after interrupted operation")
	}
	// Reconciliation is a separate caller action. Only the next explicit
	// invocation can start a new operation.
	if err := g.Run(ctx, "certreq", nil, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || j.state.Operation.Sequence != 2 {
		t.Fatal("bad operation sequence")
	}
}

func TestProcessGuardIntentAndAcknowledgmentFailures(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		j := newTestJournal()
		j.failAt = failAt
		g := ProcessGuard{Journal: j}
		calls := 0
		err := g.Run(ctx, "certreq", nil, func() error { calls++; return nil })
		if !errors.Is(err, ErrQuiescence) || !errors.Is(err, diskFailure) {
			t.Fatal(err)
		}
		if calls != failAt-1 {
			t.Fatal("wrong effect ordering")
		}
	}
}

func TestJournalFramesFailClosedAtEveryTruncation(t *testing.T) {
	s := emptyState()
	s.Revision = 1
	frame, err := encodeFrame(s)
	if err != nil {
		t.Fatal(err)
	}
	for end := 1; end < len(frame); end++ {
		if _, err := readFrame(bytes.NewReader(frame[:end]), emptyState()); err == nil || err == io.EOF {
			t.Fatalf("truncated frame accepted at %d", end)
		}
	}
	if _, err := readFrame(bytes.NewReader(frame), emptyState()); err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] ^= 1
	if _, err := readFrame(bytes.NewReader(frame), emptyState()); err == nil {
		t.Fatal("corruption accepted")
	}
	for _, mutate := range []func(*State){
		func(s *State) { s.Schema++ },
		func(s *State) { s.Revision++ },
		func(s *State) { s.Target = Activation{2, hashA} },
		func(s *State) { s.Applied = Activation{1, hashA} },
	} {
		copy := cloneState(s)
		mutate(&copy)
		b, _ := encodeFrame(copy)
		if _, err := readFrame(bytes.NewReader(b), emptyState()); err == nil {
			t.Fatal("invalid state accepted")
		}
	}
}

// Exercise actual writes/flush/reopen with ordinary test files. This does not
// qualify the Windows directory ACL adapter or power-loss durability.
func TestFileJournalRoundTripAndPoisonedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	j := &FileJournal{file: f, state: emptyState(), token: make(chan struct{}, 1), unpin: func() {}}
	j.token <- struct{}{}
	a := Activator{Journal: j, Consumer: &testConsumer{}}
	g, err := a.Reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, Activation{g, hashA}); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	f, err = os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	reopened := &FileJournal{file: f, state: emptyState()}
	if err := reopened.readFrames(); err != nil {
		t.Fatal(err)
	}
	if reopened.state.Applied != (Activation{g, hashA}) {
		t.Fatal("lost durable state")
	}
	f.Close()
	s, _ := (fileTransaction{reopened}).Load()
	if err := (fileTransaction{reopened}).Save(s); !errors.Is(err, ErrJournal) {
		t.Fatal(err)
	}
	if reopened.poison == nil {
		t.Fatal("write failure did not poison journal")
	}
}

// Uncertain quiescence latched by one plan blocks every other plan on
// the same journal, even one that lists the same artifact.
func TestUncertainCleanupBlocksOtherPlans(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{results: []error{ErrQuiescence}}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "A", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	if err := c.Begin(ctx, "B", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "B"); !errors.Is(err, ErrQuiescence) || !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("plan B ignored A's latch: %v", err)
	}
	if len(d.calls) != 1 {
		t.Fatalf("deleter called %d times after uncertain quiescence, want 1", len(d.calls))
	}
}

// An uncertain cleanup also blocks the process guard. A Quiescer
// cannot clear it: it proves operations, not cleanup effects.
func TestUncertainCleanupBlocksProcessGuard(t *testing.T) {
	j := newTestJournal()
	c := Cleaner{Journal: j, Deleter: &testDeleter{results: []error{ErrQuiescence}}}
	if err := c.Begin(ctx, "A", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	q := &testQuiescer{}
	effects := 0
	g := ProcessGuard{Journal: j, Recovery: q}
	err := g.Run(ctx, "certreq", nil, func() error { effects++; return nil })
	if !errors.Is(err, ErrQuiescence) || !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("guard ignored uncertain cleanup: %v", err)
	}
	if effects != 0 || q.calls != 0 {
		t.Fatalf("effects=%d quiescer calls=%d, want 0/0", effects, q.calls)
	}
}

// A terminal plan performs no effect and still reports its own outcome while
// another plan is latched.
func TestTerminalPlanReportsOutcomeDespiteOtherLatch(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "done", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "done"); err != nil {
		t.Fatal(err)
	}
	d.results = []error{ErrQuiescence}
	if err := c.Begin(ctx, "A", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	calls := len(d.calls)
	if err := c.Resume(ctx, "done"); err != nil {
		t.Fatalf("terminal complete plan: %v", err)
	}
	if len(d.calls) != calls {
		t.Fatal("terminal plan performed an effect")
	}
}

// latchCleanup records uncertain quiescence for a fresh plan on j.
func latchCleanup(t *testing.T, j Journal, id string) {
	t.Helper()
	c := Cleaner{Journal: j, Deleter: &testDeleter{results: []error{ErrQuiescence}}}
	if err := c.Begin(ctx, id, Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, id); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
}

// An Activator wired to a journal shared with a latched
// broker must neither persist a new target nor Verify/Swap.
func TestActivationRespectsSharedJournalLatch(t *testing.T) {
	j := newTestJournal()
	c := &testConsumer{}
	a := Activator{j, c}
	g1, err := a.Reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, Activation{g1, hashA}); err != nil {
		t.Fatal(err)
	}
	g2, err := a.Reserve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	latchCleanup(t, j, "A")
	if err := a.Apply(ctx, Activation{g2, hashB}); !errors.Is(err, ErrQuiescence) || !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("Apply under latch: %v", err)
	}
	if got := j.state.Target; got != (Activation{g1, hashA}) {
		t.Fatalf("target persisted under latch: %+v", got)
	}
	// Recover must not repair a drifted pointer while latched.
	c.current = Activation{}
	if err := a.Recover(ctx); !errors.Is(err, ErrQuiescence) {
		t.Fatalf("Recover under latch: %v", err)
	}
	if len(c.swaps) != 1 {
		t.Fatalf("swaps under latch: %d, want only the pre-latch one", len(c.swaps))
	}
}

// A terminal incomplete plan reports ErrCleanupIncomplete under another
// plan's latch and performs no effect.
func TestTerminalIncompletePlanUnderLatch(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{results: []error{ErrNotFound}}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "inc", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "inc"); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatal(err)
	}
	calls := len(d.calls)
	latchCleanup(t, j, "A")
	if err := c.Resume(ctx, "inc"); !errors.Is(err, ErrCleanupIncomplete) || errors.Is(err, ErrQuiescence) {
		t.Fatalf("terminal incomplete under latch: %v", err)
	}
	if len(d.calls) != calls {
		t.Fatal("terminal plan performed an effect")
	}
}

// Both latches at once (possible in a journal written before the barrier):
// every blocked entry point names ErrUncertainCleanup, not only ErrQuiescence,
// and performs no effect.
func TestMixedLatchesReportUncertainCleanup(t *testing.T) {
	j := newTestJournal()
	latchCleanup(t, j, "A")
	d := &testDeleter{}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "B", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	// Inject the pre-barrier state directly: an unfinished operation recorded
	// after the cleanup latch.
	j.state.Operation = &Operation{Sequence: 1, Name: "certreq"}

	consumer := &testConsumer{}
	a := Activator{j, consumer}
	q := &testQuiescer{}
	effects := 0
	for name, run := range map[string]func() error{
		"resume":  func() error { return c.Resume(ctx, "B") },
		"apply":   func() error { return a.Apply(ctx, Activation{1, hashA}) },
		"recover": func() error { return a.Recover(ctx) },
		"guard": func() error {
			return ProcessGuard{Journal: j, Recovery: q}.Run(ctx, "certreq", nil, func() error { effects++; return nil })
		},
	} {
		if err := run(); !errors.Is(err, ErrQuiescence) || !errors.Is(err, ErrUncertainCleanup) {
			t.Errorf("%s: want ErrQuiescence+ErrUncertainCleanup, got %v", name, err)
		}
	}
	if len(d.calls) != 0 || len(consumer.swaps) != 0 || effects != 0 || q.calls != 0 {
		t.Fatalf("effects under mixed latches: deletes=%d swaps=%d runs=%d waits=%d",
			len(d.calls), len(consumer.swaps), effects, q.calls)
	}
}

// A plan cannot be both terminal and latched: Cleaner never produces it and
// the journal rejects such a record.
func TestJournalRejectsTerminalLatchedCleanup(t *testing.T) {
	prev := emptyState()
	next := emptyState()
	next.Revision = 1
	items := []CleanupItem{}
	for _, a := range cleanupArtifacts() {
		items = append(items, CleanupItem{Artifact: a, Result: NotFound})
	}
	next.Cleanups["A"] = Cleanup{ID: "A", Outcome: Aborted, Items: items, Terminal: true,
		ClosedAt: time.Unix(1, 0).UTC(), QuiescenceUnknown: true}
	if err := validateState(next, prev); err == nil {
		t.Fatal("terminal latched cleanup accepted")
	}
}
