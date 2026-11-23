package lifecycle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
)

// Activation.Generation orders operations, not certificate ages or broker
// leases. A rollback uses a NEW generation and the previous fingerprint.
type Activation struct {
	Generation  uint64 `json:"generation"`
	Fingerprint string `json:"fingerprint"`
}

// Consumer must perform synchronous swaps. Returning while a queued operation
// can still change the pointer violates this interface. Verify checks the
// pointer, binding, key policy and TLS handshake against this exact target.
// Every writer of the consumer pointer must use the same Journal lease.
type Consumer interface {
	Swap(context.Context, Activation) error
	Verify(context.Context, Activation) error
}

type Activator struct {
	// Run the Activator IN the consumer process, using its own journal.
	// A broker-side mutex around an asynchronous/RPC swap is not fencing:
	// that RPC could survive the broker's death. Swap must change local
	// consumer state synchronously; all local pointer writers use this lease.
	Journal  Journal
	Consumer Consumer
}

// Reserve increments a durable counter independently of broker restarts.
// Reservations may be skipped, but never reused, including after rollback.
func (a Activator) Reserve(ctx context.Context) (uint64, error) {
	if a.Journal == nil {
		return 0, errors.New("activation journal required")
	}
	var generation uint64
	err := a.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		if s.Counter == ^uint64(0) {
			return errors.New("activation counter exhausted")
		}
		s.Counter++
		generation = s.Counter
		return tx.Save(s)
	})
	if err != nil {
		return 0, err
	}
	return generation, nil
}

// Apply linearizes comparison, durable intent, swap, verification and durable
// acknowledgment under one lease. Failed acknowledgment leaves Target intact
// for recovery. A stale request never causes a swap, even if it arrives late.
func (a Activator) Apply(ctx context.Context, target Activation) error {
	if a.Journal == nil || a.Consumer == nil {
		return errors.New("activation adapters required")
	}
	if err := validActivation(target); err != nil {
		return err
	}
	return a.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		// Refuse before persisting a new target, not only before the swap.
		if err := quiescenceBarrier(s); err != nil {
			return err
		}
		if target.Generation > s.Counter {
			return fmt.Errorf("%w: unreserved generation", ErrConflict)
		}
		if target.Generation < s.Target.Generation {
			return ErrSuperseded
		}
		if target.Generation == s.Target.Generation && target != s.Target {
			return ErrConflict
		}
		if target.Generation > s.Target.Generation {
			s.Target = target
			if err := tx.Save(s); err != nil {
				return err
			}
		}
		return a.finish(ctx, tx)
	})
}

// Recover re-establishes the durable target after consumer restart. It does
// not trust Applied alone as evidence of the current runtime pointer.
func (a Activator) Recover(ctx context.Context) error {
	if a.Journal == nil || a.Consumer == nil {
		return errors.New("activation adapters required")
	}
	return a.Journal.WithLock(ctx, func(tx Transaction) error { return a.finish(ctx, tx) })
}

func (a Activator) finish(ctx context.Context, tx Transaction) error {
	s, err := tx.Load()
	if err != nil {
		return err
	}
	// The consumer journal is normally separate and carries no broker
	// records, but Journal is an interface: if it is shared with a latched
	// broker, no Verify/Swap may run.
	if err := quiescenceBarrier(s); err != nil {
		return err
	}
	if s.Target.Generation == 0 {
		return nil
	}
	if err := validActivation(s.Target); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.Consumer.Verify(ctx, s.Target); err != nil {
		if err := a.Consumer.Swap(ctx, s.Target); err != nil {
			return err
		}
		if err := a.Consumer.Verify(ctx, s.Target); err != nil {
			return err
		}
	}
	if s.Applied == s.Target {
		return nil
	}
	s.Applied = s.Target
	return tx.Save(s)
}

func validActivation(a Activation) error {
	b, err := hex.DecodeString(a.Fingerprint)
	if a.Generation == 0 || err != nil || len(b) != 32 ||
		hex.EncodeToString(b) != a.Fingerprint {
		return errors.New("activation requires nonzero generation and lowercase SHA-256 fingerprint")
	}
	return nil
}
