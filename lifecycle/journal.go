// Package lifecycle implements the durable activation and terminal-cleanup
// portions of the Enterprise renewal protocol. Native enrollment, key policy,
// and consumer TLS swaps are supplied by explicitly trusted adapters.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

var (
	ErrJournal    = errors.New("invalid or unavailable lifecycle journal")
	ErrConflict   = errors.New("lifecycle identity conflict")
	ErrSuperseded = errors.New("activation superseded")
)

// schema 2: native enrollment records. A
// schema 1 journal, written by the certreq machine, is refused, not migrated.
const schema = 2
const maxFrame = 16 << 20

// State contains operational metadata, not private keys. Counter and Target
// are never subject to audit retention. Schema/version/checksum errors stop
// recovery rather than selecting an older state.
type State struct {
	Schema    int                `json:"schema"`
	Revision  uint64             `json:"revision"`
	Counter   uint64             `json:"counter"`
	Target    Activation         `json:"target"`
	Applied   Activation         `json:"applied"`
	Operation *Operation         `json:"operation,omitempty"`
	Cleanups  map[string]Cleanup `json:"cleanups"`
	// Compaction describes the last physical compaction. Only
	// FileJournal.Compact changes it, in the checkpoint frame that starts the
	// compacted file.
	Compaction *Compaction `json:"compaction,omitempty"`
	// Purged keeps the identity of every cleanup plan removed by compaction.
	// It only grows, and only in a checkpoint frame.
	Purged map[string]PurgedCleanup `json:"purged,omitempty"`
	// Attempts holds the durable enrollment attempts (see Enrollment); at most
	// one is open. Pace is journal-wide pacing of new attempts.
	Attempts map[string]Attempt `json:"attempts,omitempty"`
	Pace     *Pace              `json:"pace,omitempty"`
}

func emptyState() State { return State{Schema: schema, Cleanups: make(map[string]Cleanup)} }

// Transaction is valid only inside WithLock. Save must commit durably before
// returning nil; after any failure the caller must stop before the next effect.
type Transaction interface {
	Load() (State, error)
	Save(State) error
}

// Journal serializes all effects, not just writes. Implementations must also
// exclude other processes and return independent snapshots from Load.
type Journal interface {
	WithLock(context.Context, func(Transaction) error) error
}

// FileJournal is an append-only, checksummed, flush-before-effect journal.
// Its stable file handle is also the exclusive interprocess lease. A torn or
// corrupt final frame blocks recovery; it is never silently discarded.
type FileJournal struct {
	file           *os.File
	unpin          func()
	token          chan struct{}
	state          State
	poison         error
	activationOnly bool
	// replace is nil when the platform adapter cannot compact.
	replace journalReplacer
}

// journalReplacer atomically substitutes the journal file with one holding
// only frame (see Compact). committed reports whether the current file was
// already moved aside. It closes current only when it returns a non-nil next.
type journalReplacer func(current *os.File, frame []byte) (next *os.File, committed bool, err error)

// OpenJournal opens journal.log in an existing protected local NTFS directory.
// It fails immediately if another process holds the lease. Provision the
// directory with a protected DACL granting full control only to SYSTEM and BA.
// The caller must establish quiescence of previous native mutators before
// calling lifecycle operations; possession of this lease alone is not proof.
func OpenJournal(dir string) (*FileJournal, error) {
	return openJournal(dir, "")
}

// OpenActivationJournal opens a separate consumer-owned activation journal.
// The installer must precreate journal.log with owner SYSTEM/BA and a protected
// DACL: SYSTEM/BA full control, the service SID file read+write (0x12019f).
// The directory grants that SID read+execute (0x1200a9), not write-DAC/delete.
// No cleanup or broker-operation records are accepted in this journal.
func OpenActivationJournal(dir, serviceSID string) (*FileJournal, error) {
	if serviceSID == "" {
		return nil, errors.New("consumer service SID required")
	}
	return openJournal(dir, serviceSID)
}

func openJournal(dir, serviceSID string) (*FileJournal, error) {
	f, unpin, replace, err := openJournalFile(dir, serviceSID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJournal, err)
	}
	j := &FileJournal{file: f, unpin: unpin, replace: replace, token: make(chan struct{}, 1), state: emptyState(), activationOnly: serviceSID != ""}
	if err := j.readFrames(); err != nil {
		f.Close()
		unpin()
		return nil, fmt.Errorf("%w: %w", ErrJournal, err)
	}
	j.token <- struct{}{}
	return j, nil
}

func (j *FileJournal) WithLock(ctx context.Context, fn func(Transaction) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-j.token:
	}
	defer func() { j.token <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if j.poison != nil {
		return j.poison
	}
	return fn(fileTransaction{j})
}

// Close waits for an in-flight operation. Call only after native adapters have
// completed; closing the lease does not terminate external processes.
func (j *FileJournal) Close() error {
	<-j.token
	defer func() { j.token <- struct{}{} }()
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	j.unpin()
	j.poison = fmt.Errorf("%w: closed", ErrJournal)
	return err
}

type fileTransaction struct{ j *FileJournal }

func (t fileTransaction) Load() (State, error) {
	// Marshal/unmarshal produces independent maps/slices, including artifacts.
	data, err := json.Marshal(t.j.state)
	if err != nil {
		return State{}, err
	}
	var s State
	err = json.Unmarshal(data, &s)
	return s, err
}

func (t fileTransaction) Save(s State) error {
	j := t.j
	if j.poison != nil {
		return j.poison
	}
	if j.activationOnly && (s.Operation != nil || len(s.Cleanups) != 0 || len(s.Purged) != 0 || len(s.Attempts) != 0 || s.Pace != nil) {
		return fmt.Errorf("%w: broker records forbidden in consumer journal", ErrJournal)
	}
	if s.Schema != schema || s.Revision != j.state.Revision || s.Counter < j.state.Counter {
		return fmt.Errorf("%w: schema, revision or counter", ErrJournal)
	}
	if !sameCompaction(s.Compaction, j.state.Compaction) {
		return fmt.Errorf("%w: compaction records are written only by Compact", ErrJournal)
	}
	if s.Revision == ^uint64(0) {
		return fmt.Errorf("%w: revision exhausted", ErrJournal)
	}
	s.Revision++
	if err := validateState(s, j.state); err != nil {
		return fmt.Errorf("%w: %w", ErrJournal, err)
	}
	frame, err := encodeFrame(s)
	if err != nil {
		return err
	}
	if _, err = j.file.Write(frame); err == nil {
		err = j.file.Sync()
	}
	if err != nil {
		j.poison = fmt.Errorf("%w: commit: %w", ErrJournal, err)
		return j.poison
	}
	// Never keep caller-owned slices or maps as committed state. Decode into a
	// fresh value: decoding into j.state would merge maps and keep omitted
	// pointers from the previous state.
	return j.commit(frame)
}

func (j *FileJournal) commit(frame []byte) error {
	var next State
	if err := json.Unmarshal(frame[36:], &next); err != nil {
		j.poison = fmt.Errorf("%w: decode committed frame: %w", ErrJournal, err)
		return j.poison
	}
	j.state = next
	return nil
}

func encodeFrame(s State) ([]byte, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxFrame {
		return nil, fmt.Errorf("%w: frame too large", ErrJournal)
	}
	sum := sha256.Sum256(payload)
	frame := make([]byte, 36, 36+len(payload))
	binary.LittleEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], sum[:])
	return append(frame, payload...), nil
}

func readFrame(r io.Reader, previous State) (State, error) {
	var header [36]byte
	n, err := io.ReadFull(r, header[:])
	if n == 0 && err == io.EOF {
		return State{}, io.EOF
	}
	if err != nil {
		return State{}, fmt.Errorf("incomplete header: %w", err)
	}
	size := binary.LittleEndian.Uint32(header[:4])
	if size == 0 || size > maxFrame {
		return State{}, errors.New("invalid frame size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return State{}, fmt.Errorf("incomplete payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	if string(sum[:]) != string(header[4:]) {
		return State{}, errors.New("checksum mismatch")
	}
	var s State
	if err := json.Unmarshal(payload, &s); err != nil {
		return State{}, err
	}
	if s.Schema != schema {
		return State{}, fmt.Errorf("journal schema %d, this version reads only schema %d (no migration)", s.Schema, schema)
	}
	if err := validateState(s, previous); err != nil {
		return State{}, err
	}
	return s, nil
}

// validateState checks s as the successor of previous. A previous state with
// Revision 0 means s is the first frame of a file: either revision 1, or the
// checkpoint frame written by Compact, whose history is no longer on disk.
func validateState(s, previous State) error {
	// restart: s is the checkpoint that starts a compacted file. Its history is
	// no longer on disk, so history-dependent checks cannot apply. An ordinary
	// first Save is never a checkpoint (Save rejects Compaction changes).
	base := previous.Revision == 0
	checkpoint := s.Compaction != nil && s.Compaction.Revision == s.Revision
	restart := base && checkpoint
	if previous.Revision == ^uint64(0) || s.Schema != schema ||
		s.Revision != previous.Revision+1 && !(restart && s.Revision != 0) ||
		s.Counter < previous.Counter || s.Target.Generation > s.Counter ||
		s.Target.Generation < previous.Target.Generation ||
		s.Applied.Generation < previous.Applied.Generation ||
		s.Applied.Generation > s.Target.Generation || s.Cleanups == nil {
		return errors.New("invalid schema, sequence or state")
	}
	for _, a := range []Activation{s.Target, s.Applied} {
		if a.Generation == 0 && a.Fingerprint != "" {
			return errors.New("fingerprint without generation")
		}
		if a.Generation != 0 {
			if err := validActivation(a); err != nil {
				return err
			}
		}
	}
	if s.Target.Generation == previous.Target.Generation && s.Target != previous.Target ||
		s.Applied.Generation == previous.Applied.Generation && s.Applied != previous.Applied ||
		s.Applied.Generation == s.Target.Generation && s.Applied != s.Target {
		return errors.New("fingerprint changed at same generation")
	}
	purged := map[string]bool{}
	if !sameCompaction(s.Compaction, previous.Compaction) {
		c := s.Compaction
		if !checkpoint || c.At.IsZero() || c.Retention < 0 || len(c.Purged) > 0 && c.Retention == 0 {
			return errors.New("invalid compaction record")
		}
		for _, id := range c.Purged {
			if purged[id] {
				return errors.New("duplicate purged cleanup")
			}
			purged[id] = true
			if restart {
				continue // the purged plans are no longer on disk
			}
			old, ok := previous.Cleanups[id]
			if _, kept := s.Cleanups[id]; !ok || kept || !old.AuditExpiry(c.At, c.Retention) {
				return errors.New("purged cleanup not eligible for audit expiry")
			}
		}
	}
	// Purged identities only grow, exactly by this checkpoint's purge, and
	// an ID that left a purged identity never becomes an active plan again.
	for id, gone := range previous.Purged {
		if kept, ok := s.Purged[id]; !ok || !samePurged(gone, kept) {
			return errors.New("purged cleanup identity lost or changed")
		}
	}
	for id := range purged {
		if _, ok := s.Purged[id]; !ok {
			return errors.New("purged cleanup without identity")
		}
	}
	for id, gone := range s.Purged {
		if _, active := s.Cleanups[id]; active {
			return errors.New("purged cleanup identity reused")
		}
		if !validOutcome(gone.Outcome) || !validHash(gone.Digest) || gone.ClosedAt.IsZero() {
			return errors.New("invalid purged cleanup identity")
		}
		if _, had := previous.Purged[id]; had || restart {
			continue
		}
		if !purged[id] || !samePurged(gone, purgedIdentity(previous.Cleanups[id])) {
			return errors.New("purged cleanup identity does not match the plan")
		}
	}
	if previous.Operation != nil {
		if s.Operation == nil || s.Operation.Sequence < previous.Operation.Sequence {
			return errors.New("native operation sequence lost")
		}
		old, next := previous.Operation, s.Operation
		if old.Sequence == next.Sequence {
			if old.Name != next.Name || !slices.Equal(old.Arguments, next.Arguments) || old.Quiescent && !next.Quiescent {
				return errors.New("native operation identity or acknowledgment changed")
			}
			if old.Resolution != nil && (next.Resolution == nil || !old.Resolution.equal(*next.Resolution)) ||
				old.Resolution == nil && next.Resolution != nil && old.Quiescent {
				return errors.New("operation resolution changed or added after quiescence")
			}
		} else if !old.Quiescent || old.Sequence == ^uint64(0) || next.Sequence != old.Sequence+1 {
			return errors.New("unfinished operation replaced")
		} else if next.Resolution != nil {
			return errors.New("new operation carries a resolution")
		}
	} else if s.Operation != nil && s.Operation.Resolution != nil && !restart {
		return errors.New("new operation carries a resolution")
	}
	if s.Operation != nil && (s.Operation.Sequence == 0 || s.Operation.Name == "") {
		return errors.New("invalid native operation")
	}
	if r := s.Operation; r != nil && r.Resolution != nil && (!r.Quiescent || r.Resolution.Item != 0 || r.Resolution.valid() != nil) {
		return errors.New("invalid operation resolution")
	}
	for id, old := range previous.Cleanups {
		next, ok := s.Cleanups[id]
		if !ok && purged[id] {
			continue
		}
		if !ok || next.ID != old.ID || next.Outcome != old.Outcome || len(next.Items) != len(old.Items) {
			return errors.New("cleanup identity lost or replaced")
		}
		for i, item := range old.Items {
			n := next.Items[i]
			if n.Artifact != item.Artifact || n.Keep != item.Keep || n.Unidentified != item.Unidentified ||
				item.Result != "" && (n.Result != item.Result || n.Cause != item.Cause) {
				return errors.New("cleanup identity or acknowledgment changed")
			}
		}
		if old.Terminal && (!next.Terminal || old.Complete != next.Complete || !old.ClosedAt.Equal(next.ClosedAt)) {
			return errors.New("terminal cleanup reopened")
		}
		n := len(old.Resolutions)
		if len(next.Resolutions) < n || len(next.Resolutions) > n+1 {
			return errors.New("cleanup resolutions lost or added in bulk")
		}
		for i := range old.Resolutions {
			if !old.Resolutions[i].equal(next.Resolutions[i]) {
				return errors.New("cleanup resolution changed")
			}
		}
		// Exactly one new administrative resolution clears exactly one latch.
		resolved := len(next.Resolutions) == n+1
		if resolved != (old.QuiescenceUnknown && !next.QuiescenceUnknown) {
			return errors.New("uncertain cleanup automatically unblocked")
		}
		// The resolution names the occurrence it clears: the latched item.
		if item := latchedItem(old); resolved && (item < 0 || next.Resolutions[n].Item != item || old.Items[item].Result != Failed) {
			return errors.New("cleanup resolution does not name the latched item")
		}
	}
	for id, plan := range s.Cleanups {
		if id == "" || id != plan.ID || len(plan.Items) == 0 {
			return errors.New("invalid cleanup identity")
		}
		if _, existed := previous.Cleanups[id]; !existed && !restart && len(plan.Resolutions) != 0 {
			return errors.New("new cleanup carries resolutions")
		}
		for _, r := range plan.Resolutions {
			if r.valid() != nil {
				return errors.New("invalid cleanup resolution")
			}
		}
		allDone, allSuccessful := true, true
		for _, item := range plan.Items {
			keep, err := keepArtifact(plan.Outcome, item.Artifact)
			if err != nil || keep != item.Keep {
				return errors.New("invalid cleanup policy")
			}
			if err := validArtifact(item.Artifact, deletes(item)); err != nil {
				return err
			}
			if item.Unidentified {
				// Fixed at intent: never deleted, never a complete plan.
				if !keep && item.Result != NotOwned {
					return errors.New("unidentified artifact not skipped at intent")
				}
				allSuccessful = false
			}
			switch item.Result {
			case "":
				allDone, allSuccessful = false, false
			case Deleted:
				if keep {
					return errors.New("retained artifact marked deleted")
				}
			case Retained:
				if !keep {
					return errors.New("delete replaced by retention")
				}
			case NotFound, NotOwned, Failed:
				if keep {
					return errors.New("retained artifact was mutated")
				}
				allSuccessful = false
			default:
				return errors.New("unknown cleanup result")
			}
		}
		if plan.Terminal && plan.QuiescenceUnknown {
			// Cleaner never closes a latched plan; reject such a record.
			return errors.New("terminal cleanup with uncertain quiescence")
		}
		if plan.Terminal {
			if !allDone || plan.Complete != allSuccessful || plan.ClosedAt.IsZero() {
				return errors.New("invalid cleanup terminal")
			}
		} else if plan.Complete || !plan.ClosedAt.IsZero() {
			return errors.New("nonterminal cleanup marked complete")
		}
	}
	return validateAttempts(s, previous, restart)
}

func (j *FileJournal) readFrames() error {
	for {
		s, err := readFrame(j.file, j.state)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if j.activationOnly && (s.Operation != nil || len(s.Cleanups) != 0 || len(s.Purged) != 0 || len(s.Attempts) != 0 || s.Pace != nil || s.Compaction != nil) {
			return errors.New("broker records in consumer journal")
		}
		j.state = s
	}
}

// scanFrames validates every frame from r and returns the final state and the
// frame count. The storage adapter uses it to validate a journal file before
// it removes the copy left by an interrupted compaction.
func scanFrames(r io.Reader) (State, int, error) {
	s, n := emptyState(), 0
	for {
		next, err := readFrame(r, s)
		if err == io.EOF {
			return s, n, nil
		}
		if err != nil {
			return s, n, err
		}
		s, n = next, n+1
	}
}

// isCheckpointFile reports whether r holds exactly one complete checkpoint.
func isCheckpointFile(r io.Reader) error {
	s, n, err := scanFrames(r)
	if err != nil {
		return err
	}
	if n != 1 || s.Compaction == nil || s.Compaction.Revision != s.Revision {
		return errors.New("not a single complete checkpoint frame")
	}
	return nil
}
