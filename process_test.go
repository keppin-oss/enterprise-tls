package enterprise

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

type quiescenceFailureRunner struct {
	requestDir string
	native     error
}

func (r *quiescenceFailureRunner) Run(_ context.Context, _ string, args ...string) (string, string, int, error) {
	r.requestDir = filepath.Dir(args[len(args)-1])
	return "", "", -1, errors.Join(ErrProcessQuiescence, r.native)
}

func TestEnrollPreservesArtifactsAndCauseWhenTreeIsNotQuiescent(t *testing.T) {
	native := errors.New("native job accounting failed")
	r := &quiescenceFailureRunner{native: native}
	p := New(Config{CA: "ca\\issuer"})
	p.runner = r
	keys := &fakeKeyRemover{}
	p.keys = keys
	result, err := p.Enroll(context.Background())
	if !errors.Is(err, ErrProcessQuiescence) || !errors.Is(err, native) {
		t.Fatal(err)
	}
	defer os.RemoveAll(r.requestDir)
	if result.KeyState != KeyStateUnproven || len(keys.deleted) != 0 {
		t.Fatal("unproven key was cleaned")
	}
	if result.ArtifactDirectory != r.requestDir {
		t.Fatal("preserved artifact directory not reported")
	}
	if _, err := os.Stat(filepath.Join(r.requestDir, "request.inf")); err != nil {
		t.Fatal("artifacts lost", err)
	}
}

func TestOwnedFailureDoesNotDeleteAfterQuiescenceFailure(t *testing.T) {
	keys := &fakeKeyRemover{}
	p := New(Config{})
	p.keys = keys
	res := &Result{Status: StatusEnrollmentFailed, Err: errors.Join(ErrEnrollmentFailed, ErrProcessQuiescence)}
	result, err := p.finishOwnedFailure(res, "owned")
	if len(keys.deleted) != 0 || result.KeyState != KeyStateUnproven ||
		!errors.Is(err, ErrProcessQuiescence) || !errors.Is(result.KeyCleanupErr, ErrProcessQuiescence) {
		t.Fatal("cleanup authorized before quiescence")
	}
}

// memJournal is a single-process lifecycle.Journal for guard tests.
type memJournal struct{ state lifecycle.State }

type memTx struct{ j *memJournal }

func (j *memJournal) WithLock(ctx context.Context, fn func(lifecycle.Transaction) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(memTx{j})
}

func (t memTx) Load() (lifecycle.State, error) {
	s := t.j.state
	if s.Operation != nil {
		op := *s.Operation
		op.Arguments = append([]string(nil), op.Arguments...)
		s.Operation = &op
	}
	return s, nil
}

func (t memTx) Save(s lifecycle.State) error { t.j.state = s; return nil }

type countingRunner struct {
	calls int
	err   error
}

func (r *countingRunner) Run(context.Context, string, ...string) (string, string, int, error) {
	r.calls++
	return "", "", -1, r.err
}

func interruptedJournal() *memJournal {
	return &memJournal{state: lifecycle.State{Operation: &lifecycle.Operation{Sequence: 1, Name: "certreq.exe"}}}
}

// An interrupted earlier operation blocks the guard before certreq starts.
// This call made no native effect: the error is ErrOperationBlocked (keeping
// lifecycle.ErrInterrupted), not uncertain quiescence of this call.
func TestGuardedRunnerBlockedBeforeInvocationIsNotQuiescence(t *testing.T) {
	native := &countingRunner{}
	r := guardedRunner{guard: lifecycle.ProcessGuard{Journal: interruptedJournal()}, native: native}
	_, _, _, err := r.Run(context.Background(), "certreq.exe", "-new")
	if native.calls != 0 {
		t.Fatal("native runner invoked despite interrupted operation")
	}
	if !errors.Is(err, ErrOperationBlocked) || !errors.Is(err, lifecycle.ErrInterrupted) || errors.Is(err, ErrProcessQuiescence) {
		t.Fatalf("want blocked+interrupted without quiescence, got %v", err)
	}
}

// After invocation, an uncertain quiescence keeps ErrProcessQuiescence and is
// never reported as blocked.
func TestGuardedRunnerQuiescenceAfterInvocationIsKept(t *testing.T) {
	native := &countingRunner{err: errors.Join(ErrProcessQuiescence, errors.New("job accounting failed"))}
	r := guardedRunner{guard: lifecycle.ProcessGuard{Journal: &memJournal{}}, native: native}
	_, _, _, err := r.Run(context.Background(), "certreq.exe", "-new")
	if native.calls != 1 || !errors.Is(err, ErrProcessQuiescence) || errors.Is(err, ErrOperationBlocked) {
		t.Fatalf("want quiescence error after one invocation, got calls=%d err=%v", native.calls, err)
	}
}

// Enroll blocked at -new: no key was created, nothing is deleted and the
// attempt files are not retained as quiescence evidence.
func TestEnrollBlockedAtNewReportsNoKey(t *testing.T) {
	p, err := NewWithProcessJournal(Config{CA: "ca\\issuer"}, lifecycle.ProcessGuard{Journal: interruptedJournal()})
	if err != nil {
		t.Fatal(err)
	}
	keys := &fakeKeyRemover{}
	p.keys = keys
	result, err := p.Enroll(context.Background())
	if !errors.Is(err, ErrOperationBlocked) || errors.Is(err, ErrProcessQuiescence) {
		t.Fatalf("want blocked without quiescence, got %v", err)
	}
	if result.KeyState != KeyStateNone || len(keys.deleted) != 0 || result.ArtifactDirectory != "" {
		t.Fatalf("blocked -new: state=%s deleted=%v dir=%q", result.KeyState, keys.deleted, result.ArtifactDirectory)
	}
	if result.Status != StatusEnrollmentFailed {
		t.Fatalf("want enrollment-failed, got %s", result.Status)
	}
}

// A block after -new (for example another attempt left an operation
// unfinished) still allows exact cleanup of this attempt's own key, whose
// creating process was observed to completion.
func TestOwnedFailureCleansWhenLaterPhaseIsBlocked(t *testing.T) {
	keys := &fakeKeyRemover{}
	p := New(Config{})
	p.keys = keys
	blocked := &blockedError{cause: errors.Join(ErrProcessQuiescence, lifecycle.ErrInterrupted)}
	res := &Result{Status: StatusEnrollmentFailed, Err: errors.Join(ErrEnrollmentFailed, blocked)}
	result, _ := p.finishOwnedFailure(res, "owned")
	if result.KeyState != KeyStateRemoved || len(keys.deleted) != 1 {
		t.Fatalf("want owned key removed, got state=%s deleted=%v", result.KeyState, keys.deleted)
	}
}

type failingQuiescer struct{ err error }

func (q failingQuiescer) Wait(context.Context, lifecycle.Operation) error { return q.err }

type lockFailJournal struct{ err error }

func (j lockFailJournal) WithLock(context.Context, func(lifecycle.Transaction) error) error {
	return j.err
}

type causeError struct{ code int }

func (e *causeError) Error() string { return "adapter cause" }

// Every guard refusal before invocation is blocked, never quiescence, and
// keeps its cause matchable through errors.Is and errors.As.
func TestGuardedRunnerRefusalsKeepCauses(t *testing.T) {
	journalErr := errors.New("journal unavailable")
	recoveryErr := &causeError{code: 7}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		name  string
		ctx   context.Context
		guard lifecycle.ProcessGuard
		cause error
	}{
		{"interrupted", context.Background(), lifecycle.ProcessGuard{Journal: interruptedJournal()}, lifecycle.ErrInterrupted},
		{"recovery failed", context.Background(), lifecycle.ProcessGuard{Journal: interruptedJournal(), Recovery: failingQuiescer{err: recoveryErr}}, recoveryErr},
		{"journal error", context.Background(), lifecycle.ProcessGuard{Journal: lockFailJournal{err: journalErr}}, journalErr},
		{"canceled before lease", canceled, lifecycle.ProcessGuard{Journal: &memJournal{}}, context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			native := &countingRunner{}
			_, _, _, err := guardedRunner{guard: tt.guard, native: native}.Run(tt.ctx, "certreq.exe", "-new")
			if native.calls != 0 {
				t.Fatal("native runner invoked")
			}
			if !errors.Is(err, ErrOperationBlocked) || errors.Is(err, ErrProcessQuiescence) || !errors.Is(err, tt.cause) {
				t.Fatalf("want blocked with cause %v and without quiescence, got %v", tt.cause, err)
			}
		})
	}
	_, _, _, err := guardedRunner{
		guard:  lifecycle.ProcessGuard{Journal: interruptedJournal(), Recovery: failingQuiescer{err: recoveryErr}},
		native: &countingRunner{},
	}.Run(context.Background(), "certreq.exe", "-new")
	var ce *causeError
	if !errors.As(err, &ce) || ce.code != 7 {
		t.Fatalf("errors.As lost the adapter cause: %v", err)
	}
}

// A guard refusal whose cause wraps exec.ErrNotFound (for example a
// missing recovery helper) never ran certreq and must not become Unavailable.
func TestEnrollBlockedWithNotFoundCauseIsNotUnavailable(t *testing.T) {
	native := &countingRunner{}
	p := New(Config{CA: "ca\\issuer"})
	p.runner = guardedRunner{
		guard:  lifecycle.ProcessGuard{Journal: interruptedJournal(), Recovery: failingQuiescer{err: fmt.Errorf("recovery helper: %w", exec.ErrNotFound)}},
		native: native,
	}
	p.keys = &fakeKeyRemover{}
	result, err := p.Enroll(context.Background())
	if native.calls != 0 {
		t.Fatal("certreq invoked despite guard refusal")
	}
	if result.Status != StatusEnrollmentFailed || errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("want enrollment-failed without ErrUnavailable, got status=%s err=%v", result.Status, err)
	}
	if !errors.Is(err, ErrOperationBlocked) || !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("diagnostic causes lost: %v", err)
	}
}
