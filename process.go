package enterprise

import (
	"context"
	"errors"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

// ErrProcessQuiescence means the runner could not establish that all local
// job members have exited. No cleanup or replay is authorized by this error.
var ErrProcessQuiescence = lifecycle.ErrQuiescence

// NewWithProcessJournal adds a durable native-operation latch to the existing
// Enroll API. A broker crash blocks later native operations until a qualified
// Recovery adapter establishes quiescence; it never blindly replays certreq.
// This is process recovery, not the full enrollment state machine (lifecycle.Enrollment).
// The caller owns and closes guard.Journal after all Enroll calls complete.
//
// Deprecated: use lifecycle.Enrollment with the native adapters, which keeps
// the whole attempt in the journal; see Provider.
func NewWithProcessJournal(cfg Config, guard lifecycle.ProcessGuard) (*Provider, error) {
	if guard.Journal == nil {
		return nil, errors.New("process journal required")
	}
	p := New(cfg)
	p.runner = guardedRunner{guard: guard, native: execRunner{}}
	return p, nil
}

type guardedRunner struct {
	guard  lifecycle.ProcessGuard
	native runner
}

func (r guardedRunner) Run(ctx context.Context, name string, args ...string) (out, stderr string, code int, err error) {
	code = -1
	invoked := false
	err = r.guard.Run(ctx, name, args, func() error {
		invoked = true
		var nativeErr error
		out, stderr, code, nativeErr = r.native.Run(ctx, name, args...)
		return nativeErr
	})
	// When the guard refused before starting the executable (an interrupted
	// earlier operation, failed recovery, journal error or cancellation before
	// the lease), this call had no native effect. Report it as blocked rather
	// than as uncertain quiescence of this call. Errors after invocation keep
	// their chain unchanged, including ErrProcessQuiescence.
	if err != nil && !invoked {
		err = &blockedError{cause: err}
	}
	return
}

// ErrOperationBlocked means the process guard refused to start a native
// operation, so this call produced no native effect. The cause (for example
// lifecycle.ErrInterrupted or a journal error) stays matchable. It does not
// match ErrProcessQuiescence: that uncertainty concerns an earlier operation
// and must be reconciled through the journal, not by this call's cleanup.
var ErrOperationBlocked = errors.New("native operation blocked by process guard")

type blockedError struct{ cause error }

func (e *blockedError) Error() string { return ErrOperationBlocked.Error() + ": " + e.cause.Error() }

func (e *blockedError) Is(target error) bool {
	if target == ErrOperationBlocked {
		return true
	}
	return target != ErrProcessQuiescence && errors.Is(e.cause, target)
}

func (e *blockedError) As(target any) bool { return errors.As(e.cause, target) }
