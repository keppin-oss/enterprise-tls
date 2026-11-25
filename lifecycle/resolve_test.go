package lifecycle

import (
	"errors"
	"testing"
	"time"
)

var resolvedAt = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func testResolver(j Journal) Resolver {
	return Resolver{Journal: j, Now: func() time.Time { return resolvedAt }}
}

var adminStatement = Resolution{Actor: `EXAMPLE\admin`, Reason: "host rebooted; no enrollment process", Evidence: "ticket 42"}

// A resolution clears exactly the named latch; the plan then closes
// incomplete without repeating the uncertain delete, and other plans run.
func TestResolveCleanupLiftsLatchWithoutReplay(t *testing.T) {
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
	r := testResolver(j)
	if err := r.ResolveCleanup(ctx, "B", 0, adminStatement); !errors.Is(err, ErrNothingToResolve) {
		t.Fatalf("resolved an unlatched plan: %v", err)
	}
	if err := r.ResolveCleanup(ctx, "A", 0, Resolution{Reason: "no actor"}); err == nil {
		t.Fatal("resolution without actor accepted")
	}
	if err := r.ResolveCleanup(ctx, "A", 0, adminStatement); err != nil {
		t.Fatal(err)
	}
	plan := j.state.Cleanups["A"]
	if plan.QuiescenceUnknown || len(plan.Resolutions) != 1 || !plan.Resolutions[0].At.Equal(resolvedAt) ||
		plan.Resolutions[0].Actor != adminStatement.Actor {
		t.Fatalf("resolution not recorded: %+v", plan)
	}
	// Lost acknowledgment: the same statement is idempotent, another is not.
	if err := r.ResolveCleanup(ctx, "A", 0, adminStatement); err != nil {
		t.Fatalf("repeated statement: %v", err)
	}
	if len(j.state.Cleanups["A"].Resolutions) != 1 {
		t.Fatal("repeated statement recorded twice")
	}
	if err := r.ResolveCleanup(ctx, "A", 0, Resolution{Actor: "other", Reason: "x"}); !errors.Is(err, ErrNothingToResolve) {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "B"); err != nil {
		t.Fatalf("plan B still blocked: %v", err)
	}
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatalf("resolved plan: %v", err)
	}
	plan = j.state.Cleanups["A"]
	if !plan.Terminal || plan.Complete || plan.Items[0].Result != Failed || plan.Items[1].Result != Deleted {
		t.Fatalf("resolved plan items: %+v", plan.Items)
	}
	// Key of A once (uncertain), B's two artifacts, then A's request.
	if len(d.calls) != 4 || d.calls[3].Kind != Request {
		t.Fatalf("uncertain delete repeated or skipped: %+v", d.calls)
	}
}

// Resolving one plan does not unblock the journal while another is latched.
func TestResolveCleanupIsPerPlan(t *testing.T) {
	j := newTestJournal()
	latchCleanup(t, j, "A")
	// A second latched plan cannot arise through Cleaner (A's latch blocks
	// it); inject one as a journal written before the barrier could hold.
	b := j.state.Cleanups["A"]
	b.ID = "B"
	j.state.Cleanups["B"] = b
	if err := testResolver(j).ResolveCleanup(ctx, "A", 0, adminStatement); err != nil {
		t.Fatal(err)
	}
	g := ProcessGuard{Journal: j}
	if err := g.Run(ctx, "native-op", nil, func() error { return nil }); !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("guard ran with plan B latched: %v", err)
	}
}

// An administrator's statement replaces a missing Quiescer for one exact
// operation; the guard then starts the next operation without replay.
func TestResolveOperationUnblocksGuard(t *testing.T) {
	j := newTestJournal()
	g := ProcessGuard{Journal: j}
	calls := 0
	if err := g.Run(ctx, "native-op", []string{"-submit"}, func() error { calls++; return ErrQuiescence }); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	r := testResolver(j)
	if err := r.ResolveOperation(ctx, 2, adminStatement); !errors.Is(err, ErrNothingToResolve) {
		t.Fatalf("resolved the wrong sequence: %v", err)
	}
	if err := r.ResolveOperation(ctx, 1, adminStatement); err != nil {
		t.Fatal(err)
	}
	op := j.state.Operation
	if !op.Quiescent || op.Resolution == nil || op.Resolution.Actor != adminStatement.Actor {
		t.Fatalf("operation resolution not recorded: %+v", op)
	}
	if err := r.ResolveOperation(ctx, 1, adminStatement); err != nil {
		t.Fatalf("repeated statement: %v", err)
	}
	if err := r.ResolveOperation(ctx, 1, Resolution{Actor: "other", Reason: "x"}); !errors.Is(err, ErrNothingToResolve) {
		t.Fatal(err)
	}
	if err := g.Run(ctx, "native-op", []string{"-retrieve"}, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || j.state.Operation.Sequence != 2 || j.state.Operation.Resolution != nil {
		t.Fatalf("next operation: calls=%d op=%+v", calls, j.state.Operation)
	}
}

// Resolving the operation leaves an uncertain cleanup latched.
func TestResolveOperationKeepsCleanupLatch(t *testing.T) {
	j := newTestJournal()
	latchCleanup(t, j, "A")
	j.state.Operation = &Operation{Sequence: 1, Name: "native-op"}
	if err := testResolver(j).ResolveOperation(ctx, 1, adminStatement); err != nil {
		t.Fatal(err)
	}
	if err := (ProcessGuard{Journal: j}).Run(ctx, "native-op", nil, func() error { return nil }); !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("cleanup latch cleared by operation resolution: %v", err)
	}
}

func TestJournalRejectsForgedResolutions(t *testing.T) {
	j := newTestJournal()
	latchCleanup(t, j, "A")
	j.state.Operation = &Operation{Sequence: 1, Name: "native-op"}
	prev := cloneState(j.state)
	res := adminStatement
	res.At = resolvedAt
	for name, mutate := range map[string]func(*State){
		"unlatch without resolution": func(s *State) {
			p := s.Cleanups["A"]
			p.QuiescenceUnknown = false
			s.Cleanups["A"] = p
		},
		"resolution naming another item": func(s *State) {
			p := s.Cleanups["A"]
			other := res
			other.Item = 1
			p.QuiescenceUnknown, p.Resolutions = false, []Resolution{other}
			s.Cleanups["A"] = p
		},
		"operation resolution naming an item": func(s *State) {
			r := res
			r.Item = 1
			s.Operation.Quiescent, s.Operation.Resolution = true, &r
		},
		"resolution without unlatch": func(s *State) {
			p := s.Cleanups["A"]
			p.Resolutions = []Resolution{res}
			s.Cleanups["A"] = p
		},
		"two resolutions": func(s *State) {
			p := s.Cleanups["A"]
			p.QuiescenceUnknown, p.Resolutions = false, []Resolution{res, res}
			s.Cleanups["A"] = p
		},
		"resolution without actor": func(s *State) {
			p := s.Cleanups["A"]
			bad := res
			bad.Actor = ""
			p.QuiescenceUnknown, p.Resolutions = false, []Resolution{bad}
			s.Cleanups["A"] = p
		},
		"new plan with resolution": func(s *State) {
			s.Cleanups["N"] = Cleanup{ID: "N", Outcome: Aborted, Resolutions: []Resolution{res},
				Items: []CleanupItem{{Artifact: cleanupArtifacts()[0]}}}
		},
		"operation resolution while not quiescent": func(s *State) {
			s.Operation.Resolution = &res
		},
	} {
		next := cloneState(prev)
		mutate(&next)
		next.Revision++
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A recorded resolution can be neither changed nor dropped.
	if err := testResolver(j).ResolveCleanup(ctx, "A", 0, adminStatement); err != nil {
		t.Fatal(err)
	}
	if err := testResolver(j).ResolveOperation(ctx, 1, adminStatement); err != nil {
		t.Fatal(err)
	}
	prev = cloneState(j.state)
	for name, mutate := range map[string]func(*State){
		"cleanup resolution dropped": func(s *State) {
			p := s.Cleanups["A"]
			p.Resolutions = nil
			s.Cleanups["A"] = p
		},
		"cleanup resolution changed": func(s *State) {
			s.Cleanups["A"].Resolutions[0].Actor = "someone else"
		},
		"operation resolution dropped": func(s *State) { s.Operation.Resolution = nil },
		"operation resolution changed": func(s *State) { s.Operation.Resolution.Reason = "other" },
		"new operation with resolution": func(s *State) {
			s.Operation = &Operation{Sequence: 2, Name: "native-op", Quiescent: true, Resolution: &res}
		},
	} {
		next := cloneState(prev)
		mutate(&next)
		next.Revision++
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A retried resolution for the first latch, after Resume latched
// again on a later item, must not clear the newer latch.
func TestRetriedResolutionLeavesNewerLatch(t *testing.T) {
	j := newTestJournal()
	d := &testDeleter{results: []error{ErrQuiescence, ErrQuiescence}}
	c := Cleaner{Journal: j, Deleter: d}
	if err := c.Begin(ctx, "A", Aborted, cleanupArtifacts()); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	r := testResolver(j)
	if err := r.ResolveCleanup(ctx, "A", 1, adminStatement); !errors.Is(err, ErrNothingToResolve) {
		t.Fatalf("resolved an item that did not latch: %v", err)
	}
	if err := r.ResolveCleanup(ctx, "A", 0, adminStatement); err != nil {
		t.Fatal(err)
	}
	// The acknowledgment is lost; Resume proceeds and latches on item 1.
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrQuiescence) {
		t.Fatal(err)
	}
	// The retry of the first request is a no-op: the second latch stays.
	if err := r.ResolveCleanup(ctx, "A", 0, adminStatement); err != nil {
		t.Fatalf("retry: %v", err)
	}
	plan := j.state.Cleanups["A"]
	if !plan.QuiescenceUnknown || len(plan.Resolutions) != 1 {
		t.Fatalf("retry cleared the newer latch: %+v", plan)
	}
	if err := (ProcessGuard{Journal: j}).Run(ctx, "native-op", nil, func() error { return nil }); !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("barrier lifted by retry: %v", err)
	}
	if err := r.ResolveCleanup(ctx, "A", 0, Resolution{Actor: "other", Reason: "x"}); !errors.Is(err, ErrNothingToResolve) {
		t.Fatalf("other statement for the resolved item: %v", err)
	}
	if err := r.ResolveCleanup(ctx, "A", 1, adminStatement); err != nil {
		t.Fatal(err)
	}
	if err := c.Resume(ctx, "A"); !errors.Is(err, ErrCleanupIncomplete) {
		t.Fatal(err)
	}
	if len(d.calls) != 2 {
		t.Fatalf("uncertain deletes repeated: %d", len(d.calls))
	}
}

// The first ordinary frame of a journal gets no history
// exception; only a real checkpoint does.
func TestFirstOrdinaryFrameCannotCarryResolutions(t *testing.T) {
	res := adminStatement
	res.At = resolvedAt
	op := emptyState()
	op.Revision = 1
	op.Operation = &Operation{Sequence: 1, Name: "native-op", Quiescent: true, Resolution: &res}
	plan := emptyState()
	plan.Revision = 1
	plan.Cleanups["A"] = Cleanup{ID: "A", Outcome: Aborted, Resolutions: []Resolution{res},
		Items: []CleanupItem{{Artifact: cleanupArtifacts()[0]}}}
	for name, s := range map[string]State{"operation": op, "cleanup": plan} {
		if err := validateState(s, emptyState()); err == nil {
			t.Errorf("%s: resolution accepted in the first ordinary frame", name)
		}
		fj := &FileJournal{state: emptyState()}
		first := cloneState(s)
		first.Revision = 0
		if err := (fileTransaction{fj}).Save(first); !errors.Is(err, ErrJournal) {
			t.Errorf("%s: first Save accepted a resolution: %v", name, err)
		}
	}
}
