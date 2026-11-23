package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"
)

// Compaction is recorded in the checkpoint frame that starts a compacted
// journal file. Purged lists the cleanup plans removed by that compaction
// after they were handed to the Archiver; it is replaced by the next one.
type Compaction struct {
	Revision  uint64        `json:"revision"`
	At        time.Time     `json:"at"`
	Retention time.Duration `json:"retention,omitempty"`
	Purged    []string      `json:"purged,omitempty"`
}

// PurgedCleanup is the identity a purged plan leaves in the journal so that a
// late Begin with the same ID is recognised (no-op or ErrConflict) instead of
// recreating the plan and repeating its deletes. Entries are never removed.
type PurgedCleanup struct {
	Outcome  Outcome   `json:"outcome"`
	Digest   string    `json:"digest"`
	ClosedAt time.Time `json:"closed_at"`
}

// planDigest is the SHA-256 of the ordered artifact identities and retention
// decisions of a plan, independent of later acknowledgments.
func planDigest(items []CleanupItem) string {
	type identity struct {
		Artifact     Artifact `json:"artifact"`
		Keep         bool     `json:"keep"`
		Unidentified bool     `json:"unidentified,omitempty"`
	}
	ids := make([]identity, len(items))
	for i, item := range items {
		ids[i] = identity{item.Artifact, item.Keep, item.Unidentified}
	}
	b, _ := json.Marshal(ids)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func purgedIdentity(p Cleanup) PurgedCleanup {
	return PurgedCleanup{Outcome: p.Outcome, Digest: planDigest(p.Items), ClosedAt: p.ClosedAt}
}

func samePurged(a, b PurgedCleanup) bool {
	return a.Outcome == b.Outcome && a.Digest == b.Digest && a.ClosedAt.Equal(b.ClosedAt)
}

func sameCompaction(a, b *Compaction) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Revision == b.Revision && a.At.Equal(b.At) && a.Retention == b.Retention && slices.Equal(a.Purged, b.Purged)
}

// Archiver durably hands audit-expired cleanup plans to the administrator's
// archive before Compact removes them from the journal. Archive must return
// nil only after the plans are stored durably, must be idempotent by plan ID
// (a crash after Archive and before the checkpoint repeats the call) and must
// not reenter the journal.
type Archiver interface {
	Archive(context.Context, []Cleanup) error
}

// CompactOptions configures FileJournal.Compact.
type CompactOptions struct {
	// Retention enables purging when positive: cleanup plans for which
	// AuditExpiry(now, Retention) holds are archived and then removed. The
	// recommended value is 90 days from complete terminal closure. Zero compacts the
	// file without removing any record.
	Retention time.Duration
	// Archive is required when Retention is positive.
	Archive Archiver
	// Now defaults to time.Now.
	Now func() time.Time
}

// ErrCompactionInterrupted means the journal file was being replaced when an
// error occurred. The instance is poisoned: close it and reopen the directory,
// which completes or discards the interrupted replacement.
var ErrCompactionInterrupted = errors.New("journal compaction interrupted; close and reopen the journal")

// Compact rewrites the broker journal as a single checkpoint frame holding the
// current state, optionally without audit-expired cleanup plans. It is an
// administrative operation: it performs no native effect and never removes an
// operation record, an unresolved or retained cleanup, a latch, a resolution,
// the activation counter or the target. It is allowed while a latch is set.
//
// The replacement keeps the exclusive lease: the new file is written and
// flushed under a temporary name, the live file is renamed aside through its
// own handle, the new file takes its name, and the old one is deleted. If the
// process stops in between, OpenJournal completes or discards the replacement.
// Consumer activation journals cannot be compacted by the runtime, which has
// no right to create or rename files in its directory.
func (j *FileJournal) Compact(ctx context.Context, opts CompactOptions) (purged []string, err error) {
	if opts.Retention < 0 || opts.Retention > 0 && opts.Archive == nil {
		return nil, errors.New("compaction requires a non-negative retention and an archiver to purge")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-j.token:
	}
	defer func() { j.token <- struct{}{} }()
	if j.poison != nil {
		return nil, j.poison
	}
	if j.activationOnly || j.replace == nil {
		return nil, fmt.Errorf("%w: compaction unsupported for this journal", ErrJournal)
	}
	tx := fileTransaction{j}
	next, err := tx.Load()
	if err != nil {
		return nil, err
	}
	at := now().UTC()
	var plans []Cleanup
	if opts.Retention > 0 {
		for id, plan := range next.Cleanups {
			if plan.AuditExpiry(at, opts.Retention) {
				purged = append(purged, id)
			}
		}
		sort.Strings(purged)
		for _, id := range purged {
			plans = append(plans, next.Cleanups[id])
		}
	}
	if next.Revision == ^uint64(0) {
		return nil, fmt.Errorf("%w: revision exhausted", ErrJournal)
	}
	next.Revision++
	next.Compaction = &Compaction{Revision: next.Revision, At: at, Retention: opts.Retention, Purged: purged}
	for _, id := range purged {
		if next.Purged == nil {
			next.Purged = make(map[string]PurgedCleanup)
		}
		next.Purged[id] = purgedIdentity(next.Cleanups[id])
		delete(next.Cleanups, id)
	}
	if err := validateState(next, j.state); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJournal, err)
	}
	frame, err := encodeFrame(next)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(plans) > 0 {
		if err := opts.Archive.Archive(ctx, plans); err != nil {
			return nil, fmt.Errorf("archive before purge: %w", err)
		}
	}
	file, committed, err := j.replace(j.file, frame)
	if file != nil {
		j.file = file
	}
	if err != nil {
		if committed {
			j.poison = fmt.Errorf("%w: %w", ErrCompactionInterrupted, err)
			return nil, j.poison
		}
		return nil, fmt.Errorf("%w: compaction not applied: %w", ErrJournal, err)
	}
	if err := j.commit(frame); err != nil {
		return nil, err
	}
	return purged, nil
}

func validOutcome(o Outcome) bool {
	switch o {
	case Abandoned, Aborted, Denied, CAUnknown, BlockedPKI, Inconclusive, Retired:
		return true
	}
	return false
}
