package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

type Outcome string

const (
	Abandoned    Outcome = "ABANDONED_UNVERIFIED"
	Aborted      Outcome = "ABORTED_PRE_SUBMIT"
	Denied       Outcome = "DENIED"
	CAUnknown    Outcome = "CA_UNKNOWN"
	BlockedPKI   Outcome = "BLOCKED_PKI"
	Inconclusive Outcome = "INCONCLUSIVE"
	Retired      Outcome = "RETIRED"
)

type ArtifactKind string

const (
	Key         ArtifactKind = "K"
	File        ArtifactKind = "F"
	Request     ArtifactKind = "R"
	Certificate ArtifactKind = "M"
)

type CleanupResult string

const (
	Deleted  CleanupResult = "DELETED"
	NotFound CleanupResult = "NOT_FOUND_UNVERIFIED"
	Failed   CleanupResult = "FAILED"
	NotOwned CleanupResult = "SKIPPED_NOT_OWNED"
	Retained CleanupResult = "RETAINED"
)

var (
	ErrNotFound          = errors.New("artifact not found or inaccessible")
	ErrNotOwned          = errors.New("artifact ownership not established")
	ErrCleanupIncomplete = errors.New("cleanup incomplete; administrative handoff required")
)

// Artifact identifies one local object. Hash is the exact SHA-256 for F/R/M;
// K requires Provider+Container+SPKI. File.Name is relative to the protected
// attempt directory, never an arbitrary absolute path. PublicKey is the
// base64 DER SubjectPublicKeyInfo of an enrollment key (SHA-256 = SPKI): the
// cng deleter verifies it on the handle it deletes.
type Artifact struct {
	Kind      ArtifactKind `json:"kind"`
	Name      string       `json:"name"`
	Hash      string       `json:"hash,omitempty"`
	Provider  string       `json:"provider,omitempty"`
	Container string       `json:"container,omitempty"`
	SPKI      string       `json:"spki,omitempty"`
	PublicKey string       `json:"public_key,omitempty"`
}

type CleanupItem struct {
	Artifact Artifact `json:"artifact"`
	Keep     bool     `json:"keep"`
	// Unidentified marks an artifact the attempt may have created whose exact
	// identity was not established at intent time. It is independent of Keep:
	// a retained item can be unidentified too. Such an item is never deleted
	// and the plan never closes complete.
	Unidentified bool          `json:"unidentified,omitempty"`
	Result       CleanupResult `json:"result,omitempty"`
	Cause        string        `json:"cause,omitempty"`
}

// Cleanup holds the durable intent as well as per-artifact acknowledgments.
// Complete means the policy was satisfied, not that retained objects vanished.
type Cleanup struct {
	ID                string        `json:"id"`
	Outcome           Outcome       `json:"outcome"`
	Items             []CleanupItem `json:"items"`
	Terminal          bool          `json:"terminal"`
	Complete          bool          `json:"complete"`
	ClosedAt          time.Time     `json:"closed_at,omitempty"`
	QuiescenceUnknown bool          `json:"quiescence_unknown,omitempty"`
	// Resolutions is append-only: each entry cleared one latch
	// (Resolver.ResolveCleanup).
	Resolutions []Resolution `json:"resolutions,omitempty"`
}

// Deleter must verify ownership against Artifact on the same native object it
// deletes; name-only deletion is not an implementation.
// It must finish all effects before returning, including on cancellation.
type Deleter interface {
	Delete(context.Context, Artifact) error
}

// PlanDeleter is an optional Deleter extension for artifacts scoped by their
// plan, such as the files of an enrollment attempt directory: for enrollment
// plans the plan ID is the attempt ID. Cleaner prefers it when implemented.
// The Deleter contract above applies unchanged.
type PlanDeleter interface {
	DeletePlanned(ctx context.Context, plan string, a Artifact) error
}

func deleteArtifact(ctx context.Context, d Deleter, plan string, a Artifact) error {
	if pd, ok := d.(PlanDeleter); ok {
		return pd.DeletePlanned(ctx, plan, a)
	}
	return d.Delete(ctx, a)
}

type Cleaner struct {
	Journal Journal
	Deleter Deleter
	Now     func() time.Time
}

// Begin persists CLEANUP_INTENT. No effect occurs until Resume. The terminal
// outcome and exact list cannot be changed by replaying Begin with the same ID.
// CAUnknown callers must have durably recorded CA/CSR/SPKI/request metadata
// before calling Begin. Retired callers must have verified ACTIVE, drain and
// quarantine before authorizing this plan.
func (c Cleaner) Begin(ctx context.Context, id string, outcome Outcome, artifacts []Artifact) error {
	if c.Journal == nil || id == "" || len(artifacts) == 0 {
		return errors.New("cleanup identity and artifacts required")
	}
	planned := make([]PlannedArtifact, len(artifacts))
	for i, a := range artifacts {
		planned[i] = PlannedArtifact{Artifact: a}
	}
	plan, err := newCleanupPlan(id, outcome, planned)
	if err != nil {
		return err
	}
	return c.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		// A purged plan keeps its identity: an identical replay is a no-op, a
		// different plan under the same ID is a conflict, never a new plan.
		if gone, ok := s.Purged[id]; ok {
			if gone.Outcome != outcome || gone.Digest != planDigest(plan.Items) {
				return ErrConflict
			}
			return nil
		}
		if old, ok := s.Cleanups[id]; ok {
			if old.Outcome != outcome || len(old.Items) != len(plan.Items) {
				return ErrConflict
			}
			for i := range old.Items {
				if old.Items[i].Artifact != plan.Items[i].Artifact || old.Items[i].Keep != plan.Items[i].Keep ||
					old.Items[i].Unidentified != plan.Items[i].Unidentified {
					return ErrConflict
				}
			}
			return nil
		}
		s.Cleanups[id] = plan
		return tx.Save(s)
	})
}

func (c Cleaner) Resume(ctx context.Context, id string) error {
	if c.Journal == nil || c.Deleter == nil {
		return errors.New("cleanup adapters required")
	}
	return c.Journal.WithLock(ctx, func(tx Transaction) error { return c.resumeIn(ctx, tx, id) })
}

// resumeIn is Resume inside a transaction the caller holds.
func (c Cleaner) resumeIn(ctx context.Context, tx Transaction, id string) error {
	if c.Deleter == nil {
		return errors.New("cleanup adapters required")
	}
	{
		s, err := tx.Load()
		if err != nil {
			return err
		}
		if _, gone := s.Purged[id]; gone {
			return nil // only complete terminal plans are purged
		}
		plan, ok := s.Cleanups[id]
		if !ok {
			return errors.New("no cleanup intent")
		}
		// Terminal plans perform no effect, so report their outcome first.
		if plan.Terminal && !plan.QuiescenceUnknown {
			if plan.Complete {
				return nil
			}
			return ErrCleanupIncomplete
		}
		// Journal-wide barrier: an unfinished native operation or ANY plan
		// with uncertain quiescence blocks this plan's next effect.
		if err := quiescenceBarrier(s); err != nil {
			return err
		}
		var causes []error
		for i := range plan.Items {
			item := &plan.Items[i]
			if item.Result != "" {
				continue
			} // never repeat a checkpointed delete
			if err := ctx.Err(); err != nil {
				return err
			}
			if item.Keep {
				item.Result = Retained
			} else {
				err := deleteArtifact(ctx, c.Deleter, id, item.Artifact)
				switch {
				case err == nil:
					item.Result = Deleted
				case errors.Is(err, ErrNotFound):
					item.Result = NotFound
				case errors.Is(err, ErrNotOwned):
					item.Result = NotOwned
				default:
					item.Result = Failed
				}
				if err != nil {
					item.Cause = err.Error()
					causes = append(causes, err)
					if errors.Is(err, ErrQuiescence) {
						plan.QuiescenceUnknown = true
					}
				}
			}
			s.Cleanups[id] = plan
			if err := tx.Save(s); err != nil {
				return errors.Join(append(causes, err)...)
			}
			if plan.QuiescenceUnknown {
				return errors.Join(append(causes, ErrQuiescence)...)
			}
			// Every save advances the revision; reload before the next effect.
			s, err = tx.Load()
			if err != nil {
				return err
			}
			plan = s.Cleanups[id]
		}
		plan.Terminal, plan.Complete = true, true
		for _, item := range plan.Items {
			if item.Result != Deleted && item.Result != Retained || item.Unidentified {
				plan.Complete = false
			}
		}
		now := time.Now
		if c.Now != nil {
			now = c.Now
		}
		plan.ClosedAt = now().UTC()
		s.Cleanups[id] = plan
		if err := tx.Save(s); err != nil {
			return errors.Join(append(causes, err)...)
		}
		if !plan.Complete {
			causes = append(causes, ErrCleanupIncomplete)
		}
		return errors.Join(causes...)
	}
}

// AuditExpiry is eligibility only: it does not erase operational records or
// retained artifacts. Unresolved outcomes never become purgeable with age.
// FileJournal.Compact archives and removes eligible plans; physical cleanup of
// a retained CSR still needs its own authorized cleanup.
func (p Cleanup) AuditExpiry(now time.Time, retention time.Duration) bool {
	if retention <= 0 || !p.Terminal || !p.Complete || p.ClosedAt.IsZero() ||
		now.Before(p.ClosedAt) || now.Sub(p.ClosedAt) < retention {
		return false
	}
	switch p.Outcome {
	case Abandoned, BlockedPKI, Inconclusive:
		return false
	}
	for _, item := range p.Items {
		if item.Result == Retained {
			return false
		}
	}
	return true
}

func keepArtifact(outcome Outcome, a Artifact) (bool, error) {
	switch outcome {
	case BlockedPKI, Inconclusive:
		return true, nil
	case Abandoned:
		if a.Kind == Certificate {
			return false, errors.New("unexpected My certificate before submit")
		}
		return a.Kind == Key, nil
	case Aborted:
		if a.Kind == Certificate {
			return false, errors.New("unexpected My certificate before submit")
		}
		return false, nil
	case Denied, CAUnknown:
		if a.Kind == Certificate {
			return false, errors.New("unexpected My certificate before install")
		}
		return a.Kind == File && strings.EqualFold(path.Ext(a.Name), ".csr"), nil
	case Retired:
		return false, nil
	default:
		return false, errors.New("unknown terminal outcome")
	}
}

func validArtifact(a Artifact, deleting bool) error {
	if a.Name == "" {
		return errors.New("artifact name required")
	}
	switch a.Kind {
	case Key:
		if a.Provider == "" || a.Container == "" {
			return errors.New("key provider and container required")
		}
		if deleting && !validHash(a.SPKI) {
			return errors.New("key SPKI required before deletion")
		}
	case File:
		if strings.ContainsAny(a.Name, "\\:\x00") || path.Clean(a.Name) != a.Name ||
			path.IsAbs(a.Name) || a.Name == "." || a.Name == ".." || strings.HasPrefix(a.Name, "../") {
			return errors.New("file must be relative to the protected attempt directory")
		}
		if deleting && !validHash(a.Hash) {
			return errors.New("file hash required before deletion")
		}
	case Request, Certificate:
		if deleting && !validHash(a.Hash) {
			return errors.New("store object fingerprint required")
		}
		if a.Kind == Request && deleting && !validHash(a.SPKI) {
			return errors.New("REQUEST SPKI cross-check required")
		}
	default:
		return fmt.Errorf("unknown artifact kind %q", a.Kind)
	}
	return nil
}

func validHash(h string) bool {
	return validActivation(Activation{Generation: 1, Fingerprint: h}) == nil
}

// PlannedArtifact is one item of a cleanup intent. Unattributed marks an
// artifact the attempt may have created but whose exact identity could not be
// established (unreadable file or directory listing, REQUEST object not
// uniquely attributed, key without SPKI). The item keeps its retention
// decision and is recorded as unidentified: never deleted (if policy would
// delete it, it is SKIPPED_NOT_OWNED at intent time), never omitted as absent,
// and the plan closes incomplete whether the item is retained or not.
type PlannedArtifact struct {
	Artifact     Artifact
	Unattributed bool
}

func newCleanupPlan(id string, outcome Outcome, artifacts []PlannedArtifact) (Cleanup, error) {
	if id == "" || len(artifacts) == 0 {
		return Cleanup{}, errors.New("cleanup identity and artifacts required")
	}
	plan := Cleanup{ID: id, Outcome: outcome}
	seen := map[Artifact]bool{}
	for _, p := range artifacts {
		if seen[p.Artifact] {
			return Cleanup{}, errors.New("duplicate cleanup artifact")
		}
		seen[p.Artifact] = true
		keep, err := keepArtifact(outcome, p.Artifact)
		if err != nil {
			return Cleanup{}, err
		}
		item := CleanupItem{Artifact: p.Artifact, Keep: keep, Unidentified: p.Unattributed}
		if p.Unattributed && !keep {
			item.Result, item.Cause = NotOwned, "identity not established at cleanup intent"
		}
		if err := validArtifact(item.Artifact, deletes(item)); err != nil {
			return Cleanup{}, err
		}
		plan.Items = append(plan.Items, item)
	}
	return plan, nil
}

// deletes reports whether the plan may delete this item, which requires its
// exact identity.
func deletes(item CleanupItem) bool { return !item.Keep && !item.Unidentified }
