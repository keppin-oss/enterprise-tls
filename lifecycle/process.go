package lifecycle

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrQuiescence  = errors.New("process tree quiescence not established")
	ErrInterrupted = errors.New("previous native operation interrupted; reconcile its effects")
	// ErrUncertainCleanup means a cleanup plan in this journal recorded
	// uncertain quiescence. It blocks every new effect on the journal, not
	// only that plan, until Resolver.ResolveCleanup records an administrative
	// resolution for every latched plan.
	ErrUncertainCleanup = errors.New("a cleanup left uncertain quiescence; administrative resolution required")
	// ErrBrokerBusy means an enrollment launch awaits reconciliation by
	// Enrollment.Step. No effect was started; retry after the attempt step.
	ErrBrokerBusy = errors.New("broker journal busy: an enrollment launch awaits reconciliation")
)

// pendingLaunch returns the ID of an attempt whose launch is not consumed.
func pendingLaunch(s State) string {
	for id, a := range s.Attempts {
		if a.Launch != nil {
			return id
		}
	}
	return ""
}

// uncertainCleanup reports whether any cleanup plan latched uncertain
// quiescence. Together with an unfinished Operation it forms the single
// journal-wide barrier checked before every new native effect.
func uncertainCleanup(s State) bool {
	for _, plan := range s.Cleanups {
		if plan.QuiescenceUnknown {
			return true
		}
	}
	return false
}

// quiescenceBarrier is checked inside the lease before any effect that does
// not itself resolve an unfinished operation (cleanup deletes, activation
// swaps). ProcessGuard checks uncertainCleanup and then applies its own
// Quiescer-based handling of an unfinished Operation.
//
// The cleanup latch is checked first so that, when both latches coexist (for
// example in a journal written before the barrier existed), the error names
// ErrUncertainCleanup, the cause a Quiescer cannot resolve.
func quiescenceBarrier(s State) error {
	if uncertainCleanup(s) {
		return errors.Join(ErrQuiescence, ErrUncertainCleanup)
	}
	if s.Operation != nil && !s.Operation.Quiescent {
		return ErrQuiescence
	}
	return nil
}

// Operation is durable before the first external effect. Quiescent records
// mean local mutators stopped, NOT that enrollment/accept/cleanup succeeded.
type Operation struct {
	Sequence  uint64   `json:"sequence"`
	Name      string   `json:"name"`
	Arguments []string `json:"arguments"`
	Quiescent bool     `json:"quiescent"`
	// Resolution is set when an administrator, not the guard or a Quiescer,
	// established quiescence (Resolver.ResolveOperation).
	Resolution *Resolution `json:"resolution,omitempty"`
}

// Quiescer must establish completion of ALL mutators associated with the
// operation, including indirect descendants. A timeout, broker lock, inherited
// file handle or request to terminate a job is not a successful Wait.
// No default adapter guesses quiescence after a broker crash.
type Quiescer interface {
	Wait(context.Context, Operation) error
}

type ProcessGuard struct {
	Journal  Journal
	Recovery Quiescer
}

// Run persists intention, executes synchronously while holding the lease, and
// records quiescence only when effect returns without ErrQuiescence. The
// effect must retain this sentinel if it cannot prove local completion.
// When a previous operation was interrupted, Run NEVER invokes the new effect.
// It is RunIn under its own lease.
func (g ProcessGuard) Run(ctx context.Context, name string, args []string, effect func() error) error {
	if g.Journal == nil || name == "" || effect == nil {
		return errors.New("process guard adapters required")
	}
	entered := false
	err := g.Journal.WithLock(ctx, func(tx Transaction) error {
		entered = true
		return g.RunIn(ctx, tx, name, args, nil, effect)
	})
	if err != nil && !entered {
		return errors.Join(ErrQuiescence, err)
	}
	return err
}

// RunIn is Run inside a transaction the caller already holds, so that the
// caller's intent, the operation, its quiescence acknowledgment and the
// caller's result share one lease. mark, when non-nil, is applied to the state
// saved together with the operation intent and receives that operation's
// sequence: a caller's launch record therefore exists exactly when the effect
// may have started. The three saves are not one atomic write; after RunIn the
// caller must reload the state before saving its result. RunIn never takes a
// lock and must not be called from inside an effect.
func (g ProcessGuard) RunIn(ctx context.Context, tx Transaction, name string, args []string,
	mark func(s *State, seq uint64), effect func() error) error {
	if tx == nil || name == "" || effect == nil {
		return errors.New("process guard adapters required")
	}
	s, recovered, err := g.settle(ctx, tx)
	if err != nil {
		return err
	}
	if recovered {
		// Quiescence never implies replay is safe. When the interrupted
		// operation is an enrollment launch the refusal also names the busy
		// broker journal, so the first concurrent caller can recognize it.
		if id := pendingLaunch(s); id != "" {
			return errors.Join(ErrInterrupted, fmt.Errorf("%w: attempt %s", ErrBrokerBusy, id))
		}
		return ErrInterrupted
	}
	// The journal has one operation slot: an enrollment launch keeps it until
	// its result is reconciled, so every other operation waits, even after
	// quiescence.
	if id := pendingLaunch(s); id != "" {
		return fmt.Errorf("%w: attempt %s", ErrBrokerBusy, id)
	}
	var seq uint64 = 1
	if s.Operation != nil {
		if s.Operation.Sequence == ^uint64(0) {
			return errors.New("operation sequence exhausted")
		}
		seq = s.Operation.Sequence + 1
	}
	s.Operation = &Operation{Sequence: seq, Name: name, Arguments: append([]string(nil), args...)}
	if mark != nil {
		mark(&s, seq)
	}
	if err := tx.Save(s); err != nil {
		return errors.Join(ErrQuiescence, err)
	}
	if err := ctx.Err(); err != nil {
		// No external effect started, but still checkpoint quiescence.
		return g.complete(tx, err)
	}
	effectErr := effect()
	if errors.Is(effectErr, ErrQuiescence) {
		return effectErr
	}
	return g.complete(tx, effectErr)
}

// settle applies the journal-wide barrier before a new effect. An uncertain
// cleanup always refuses. An unfinished operation refuses without a Quiescer;
// with one, a successful Wait is acknowledged durably and recovered is true:
// the caller must reconcile the interrupted operation, never replay it.
// s is the state settle loaded, so the caller needs no second Load. When
// recovered is true, s is the content just saved; the journal advanced its
// Revision, so s may be read but never saved again.
func (g ProcessGuard) settle(ctx context.Context, tx Transaction) (s State, recovered bool, err error) {
	s, err = tx.Load()
	if err != nil {
		return s, false, errors.Join(ErrQuiescence, err)
	}
	// A Quiescer proves completion of a native operation, not of an
	// uncertain cleanup: that latch is never cleared automatically.
	if uncertainCleanup(s) {
		return s, false, errors.Join(ErrQuiescence, ErrUncertainCleanup)
	}
	if s.Operation == nil || s.Operation.Quiescent {
		return s, false, nil
	}
	if g.Recovery == nil {
		return s, false, errors.Join(ErrQuiescence, ErrInterrupted)
	}
	prior := *s.Operation
	prior.Arguments = append([]string(nil), prior.Arguments...)
	if err := g.Recovery.Wait(ctx, prior); err != nil {
		return s, false, errors.Join(ErrQuiescence, err)
	}
	s.Operation.Quiescent = true
	if err := tx.Save(s); err != nil {
		return s, false, errors.Join(ErrQuiescence, err)
	}
	return s, true, nil
}

func (g ProcessGuard) complete(tx Transaction, effectErr error) error {
	s, err := tx.Load()
	if err != nil {
		return errors.Join(ErrQuiescence, effectErr, err)
	}
	if s.Operation == nil {
		return errors.Join(ErrQuiescence, fmt.Errorf("%w: missing operation intent", ErrJournal))
	}
	s.Operation.Quiescent = true
	if err := tx.Save(s); err != nil {
		return errors.Join(ErrQuiescence, effectErr, err)
	}
	return effectErr
}
