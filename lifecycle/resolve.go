package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Resolution is an administrator's durable statement, recorded in the journal,
// that every local mutator of a latched operation or cleanup has stopped (for
// example after a reboot or an inspection of the process tree). It is an
// attestation, not proof produced by the module, and it says nothing about
// whether the native effects happened: the caller still reconciles them.
type Resolution struct {
	// Actor identifies the administrator (for example DOMAIN\user or a SID).
	Actor string `json:"actor"`
	// Reason states why quiescence is considered established.
	Reason string `json:"reason"`
	// Evidence optionally references the supporting record (ticket, log).
	Evidence string `json:"evidence,omitempty"`
	// At is set by the Resolver when the resolution is recorded.
	At time.Time `json:"at"`
	// Item is, for a cleanup resolution, the index of the item whose uncertain
	// result set the latch; zero for an operation resolution.
	Item int `json:"item,omitempty"`
}

func (r Resolution) valid() error {
	if r.Actor == "" || r.Reason == "" || r.At.IsZero() {
		return errors.New("resolution requires actor, reason and time")
	}
	return nil
}

func (r Resolution) sameStatement(o Resolution) bool {
	return r.Actor == o.Actor && r.Reason == o.Reason && r.Evidence == o.Evidence && r.Item == o.Item
}

func (r Resolution) equal(o Resolution) bool { return r.sameStatement(o) && r.At.Equal(o.At) }

// ErrNothingToResolve means the named operation or cleanup is not latched, or
// it is not the one currently recorded.
var ErrNothingToResolve = errors.New("no matching latch to resolve")

// Resolver records administrative resolutions. It never performs a native
// effect and never deletes a record: it is the only path that clears a latch
// that a Quiescer cannot clear. Expose it only to administrators of the broker
// journal (SYSTEM/BA); the journal does not authenticate Actor.
type Resolver struct {
	Journal Journal
	Now     func() time.Time
}

func (r Resolver) stamp(res Resolution) (Resolution, error) {
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	res.At = now().UTC()
	if r.Journal == nil {
		return res, errors.New("resolution journal required")
	}
	return res, res.valid()
}

// ResolveOperation marks the unfinished native operation with this exact
// sequence as quiescent on the administrator's statement. The next
// ProcessGuard.Run proceeds; nothing is replayed and no effect is reconciled.
// It does not clear an uncertain cleanup. Repeating the same statement after
// a lost acknowledgment succeeds without a new record.
func (r Resolver) ResolveOperation(ctx context.Context, sequence uint64, res Resolution) error {
	res, err := r.stamp(res)
	if err != nil {
		return err
	}
	return r.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		op := s.Operation
		if op == nil || op.Sequence != sequence {
			return fmt.Errorf("%w: operation %d is not the recorded operation", ErrNothingToResolve, sequence)
		}
		if op.Quiescent {
			if op.Resolution != nil && op.Resolution.sameStatement(res) {
				return nil
			}
			return fmt.Errorf("%w: operation %d is already quiescent", ErrNothingToResolve, sequence)
		}
		op.Quiescent, op.Resolution = true, &res
		return tx.Save(s)
	})
}

// ResolveCleanup clears the uncertain-quiescence latch of one cleanup plan on
// the administrator's statement. item is the index of the plan item whose
// uncertain result set the latch (the last acknowledged item); a resolution
// clears only that occurrence. The plan stays non-terminal: a later Resume
// continues with the items not yet acknowledged and never repeats one. The
// resolved item keeps its FAILED result, so the plan closes incomplete and
// still needs an administrative handoff. Other latched plans, and a later
// latch on another item of the same plan, need their own resolution.
// Repeating a recorded statement for the same item after a lost
// acknowledgment succeeds without a new record and never clears a newer latch.
func (r Resolver) ResolveCleanup(ctx context.Context, id string, item int, res Resolution) error {
	res, err := r.stamp(res)
	if err != nil {
		return err
	}
	res.Item = item
	return r.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		plan, ok := s.Cleanups[id]
		if !ok {
			return fmt.Errorf("%w: no cleanup %q", ErrNothingToResolve, id)
		}
		for _, done := range plan.Resolutions {
			if done.Item == item && done.sameStatement(res) {
				return nil
			}
		}
		if !plan.QuiescenceUnknown {
			return fmt.Errorf("%w: cleanup %q is not latched", ErrNothingToResolve, id)
		}
		if latched := latchedItem(plan); item != latched {
			return fmt.Errorf("%w: cleanup %q is latched on item %d, not %d", ErrNothingToResolve, id, latched, item)
		}
		plan.QuiescenceUnknown = false
		plan.Resolutions = append(plan.Resolutions, res)
		s.Cleanups[id] = plan
		return tx.Save(s)
	})
}

// latchedItem is the item whose result set the plan's latch: Resume stops
// right after acknowledging it, so it is the last item with a result.
func latchedItem(plan Cleanup) int {
	for i := len(plan.Items) - 1; i >= 0; i-- {
		if plan.Items[i].Result != "" {
			return i
		}
	}
	return -1
}

// ResolveAttempt records an administrator's decision on a BLOCKED_PKI,
// INCONCLUSIVE or CA_UNKNOWN attempt (AttemptResolution). It is not a quiescence
// attestation: a Resolution of an operation or cleanup never unblocks Start,
// and a statement without a decision about the attempt's RequestId is
// rejected. It does not reopen the attempt and performs no effect; it only
// lets Enrollment.Start create a new attempt. Repeating the same statement
// succeeds without a new record.
func (r Resolver) ResolveAttempt(ctx context.Context, id string, res AttemptResolution) error {
	if r.Journal == nil {
		return errors.New("resolution journal required")
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	res.At = now().UTC()
	return r.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		a, ok := s.Attempts[id]
		if !ok || a.State != AttemptDone || !awaitsResolution(a.Outcome) {
			return fmt.Errorf("%w: attempt %q is not BLOCKED_PKI, INCONCLUSIVE or CA_UNKNOWN", ErrNothingToResolve, id)
		}
		if a.Resolution != nil {
			if a.Resolution.sameStatement(res) {
				return nil
			}
			return fmt.Errorf("%w: attempt %q is already resolved", ErrNothingToResolve, id)
		}
		if err := res.validFor(a); err != nil {
			return err
		}
		a.Resolution = &res
		s.Attempts[id] = a
		return tx.Save(s)
	})
}
