package lifecycle

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// sameAttempt reports whether two records are identical in every field, as
// they are persisted.
func sameAttempt(a, b Attempt) bool {
	x, errX := json.Marshal(a)
	y, errY := json.Marshal(b)
	return errX == nil && errY == nil && bytes.Equal(x, y)
}

// AttemptState is the last durable record of an enrollment attempt.
type AttemptState string

const (
	AttemptPrepare   AttemptState = "PREPARE"
	AttemptKeyReady  AttemptState = "KEY_READY"
	AttemptSubmitted AttemptState = "SUBMITTED"
	AttemptIssued    AttemptState = "ISSUED"
	// AttemptDone is terminal; Attempt.Outcome says how it ended.
	AttemptDone AttemptState = "DONE"
)

// Accepted is the successful terminal outcome of an attempt. It is not a
// cleanup outcome: an accepted attempt writes no cleanup plan.
const Accepted Outcome = "ACCEPTED"

// Phase names the native call a launch record refers to.
type Phase string

const (
	PhaseCreate   Phase = "create"
	PhaseSubmit   Phase = "submit"
	PhaseRetrieve Phase = "retrieve"
	PhaseInstall  Phase = "install"
)

// Launch records that a native call of Phase may have started under the
// ProcessGuard operation Seq. It is written in the same frame as that
// operation's intent and cleared with the call's result.
type Launch struct {
	Phase Phase  `json:"phase"`
	Seq   uint64 `json:"seq"`
}

// Disposition is the last CA disposition observed for an attempt.
type Disposition string

const (
	DispositionIssued  Disposition = "issued"
	DispositionUnknown Disposition = "unknown"
)

// Attempt is the durable record of one enrollment attempt. Identity fields
// are immutable once set; the record's TargetSID and Profile, not the current
// configuration, drive every step.
type Attempt struct {
	ID        string `json:"id"`
	CA        string `json:"ca"`
	Template  string `json:"template"`
	Provider  string `json:"provider"`
	Container string `json:"container"`
	TargetSID string `json:"target_sid"`
	Profile   string `json:"profile"`

	CSRHash string `json:"csr_hash,omitempty"`
	// SPKI is the lowercase SHA-256 of PublicKey, the DER
	// SubjectPublicKeyInfo of the key this attempt created. Both are set
	// together when the create result is consumed (KEY_READY).
	SPKI      string `json:"spki,omitempty"`
	PublicKey []byte `json:"public_key,omitempty"`
	RequestID int    `json:"request_id,omitempty"`
	CertHash  string `json:"cert_hash,omitempty"`
	// OutOfBand records that the CA answered CR_DISP_ISSUED_OUT_OF_BAND. It
	// is never cleared: the PKI contact sees that the CA claimed an issuance
	// even when no certificate was obtained.
	OutOfBand bool `json:"out_of_band,omitempty"`

	State         AttemptState       `json:"state"`
	Disposition   Disposition        `json:"disposition,omitempty"`
	CertFile      string             `json:"cert_file,omitempty"`
	Launch        *Launch            `json:"launch,omitempty"`
	Retrieves     int                `json:"retrieves,omitempty"`
	NextRetrieve  time.Time          `json:"next_retrieve,omitempty"`
	Reconstructed bool               `json:"reconstructed,omitempty"`
	Outcome       Outcome            `json:"outcome,omitempty"`
	Reason        string             `json:"reason,omitempty"`
	Started       time.Time          `json:"started"`
	Updated       time.Time          `json:"updated"`
	Resolution    *AttemptResolution `json:"resolution,omitempty"`
}

// AttemptDecision is what an administrator decided about a blocked attempt.
type AttemptDecision string

const (
	// The CA denied the pending request.
	DecisionCADenied AttemptDecision = "CA_DENIED"
	// The CA issued the request; this attempt never installs it (completing a
	// pending request is out of scope).
	DecisionCAIssued AttemptDecision = "CA_ISSUED_NOT_INSTALLED"
	// The request was removed from the CA database.
	DecisionCARemoved AttemptDecision = "CA_REQUEST_REMOVED"
	// INCONCLUSIVE only: the attempt's artifacts were inspected and settled.
	DecisionArtifactsSettled AttemptDecision = "ARTIFACTS_SETTLED"
	// CA_UNKNOWN only: the operator explicitly accepts the risk of a new
	// submit without a proven CA outcome. Missing CA rows are never a CA
	// decision.
	DecisionRiskAccepted AttemptDecision = "RISK_ACCEPTED"
)

// awaitsResolution reports whether an outcome blocks new attempts until an
// AttemptResolution is recorded. CA_UNKNOWN is a barrier.
func awaitsResolution(o Outcome) bool {
	return o == BlockedPKI || o == Inconclusive || o == CAUnknown
}

// AttemptResolution is an administrator's decision on a BLOCKED_PKI,
// INCONCLUSIVE or CA_UNKNOWN attempt. Unlike Resolution, it is not a quiescence statement:
// it names a decision and the RequestId it is about, which must be the
// attempt's (0 only when the attempt never learned one), and it needs
// evidence (CA record, ticket).
type AttemptResolution struct {
	Actor     string          `json:"actor"`
	Decision  AttemptDecision `json:"decision"`
	RequestID int             `json:"request_id"`
	Reason    string          `json:"reason"`
	Evidence  string          `json:"evidence"`
	At        time.Time       `json:"at"`
}

func (r AttemptResolution) sameStatement(o AttemptResolution) bool {
	return r.Actor == o.Actor && r.Decision == o.Decision && r.RequestID == o.RequestID &&
		r.Reason == o.Reason && r.Evidence == o.Evidence
}

func (r AttemptResolution) validFor(a Attempt) error {
	if r.Actor == "" || r.Reason == "" || r.Evidence == "" || r.At.IsZero() {
		return errors.New("attempt resolution requires actor, reason, evidence and time")
	}
	if r.RequestID != a.RequestID {
		return errors.New("attempt resolution must name the attempt's RequestId")
	}
	switch r.Decision {
	case DecisionCADenied, DecisionCAIssued, DecisionCARemoved:
		if a.Outcome == CAUnknown && a.RequestID == 0 {
			return errors.New("a CA_UNKNOWN attempt without a RequestId is resolved only by an explicit risk acceptance")
		}
	case DecisionArtifactsSettled:
		if a.Outcome != Inconclusive {
			return errors.New("a pending request is resolved only by a CA decision")
		}
	case DecisionRiskAccepted:
		if a.Outcome != CAUnknown {
			return errors.New("risk acceptance resolves only CA_UNKNOWN")
		}
	default:
		return errors.New("attempt resolution requires a decision")
	}
	if !awaitsResolution(a.Outcome) {
		return errors.New("only BLOCKED_PKI, INCONCLUSIVE and CA_UNKNOWN attempts are resolved")
	}
	return nil
}

// Pace is journal-wide pacing state for new attempts. It is not part of any
// attempt, so compaction keeps it. MaxSeen is the highest time ever recorded:
// a clock moved backwards never shortens a wait.
type Pace struct {
	LastStart   time.Time `json:"last_start,omitempty"`
	WindowStart time.Time `json:"window_start,omitempty"`
	WindowCount int       `json:"window_count,omitempty"`
	Failures    int       `json:"failures,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	MaxSeen     time.Time `json:"max_seen,omitempty"`
}

var attemptOrder = map[AttemptState]int{
	AttemptPrepare: 0, AttemptKeyReady: 1, AttemptSubmitted: 2, AttemptIssued: 3, AttemptDone: 4,
}

// attemptEdges whitelists state changes; a self-edge allows progress fields
// only. Terminal outcomes reachable from each state are in terminalFrom.
var attemptEdges = map[AttemptState][]AttemptState{
	AttemptPrepare:   {AttemptPrepare, AttemptKeyReady, AttemptDone},
	AttemptKeyReady:  {AttemptKeyReady, AttemptSubmitted, AttemptDone},
	AttemptSubmitted: {AttemptSubmitted, AttemptIssued, AttemptDone},
	AttemptIssued:    {AttemptIssued, AttemptDone},
	AttemptDone:      {AttemptDone},
}

var terminalFrom = map[AttemptState][]Outcome{
	AttemptPrepare:   {Abandoned, Inconclusive},
	AttemptKeyReady:  {Aborted, Inconclusive, CAUnknown, BlockedPKI, Denied},
	AttemptSubmitted: {BlockedPKI, Denied, CAUnknown, Inconclusive},
	AttemptIssued:    {Accepted, Inconclusive},
}

func contains[T comparable](list []T, v T) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// setOnce reports whether an identity field kept its value or was set from
// empty.
func setOnce[T comparable](old, next T) bool {
	var zero T
	return old == zero || old == next
}

// launchPhases lists the native calls each open state may launch.
var launchPhases = map[AttemptState][]Phase{
	AttemptPrepare:   {PhaseCreate},
	AttemptKeyReady:  {PhaseSubmit},
	AttemptSubmitted: {PhaseRetrieve},
	AttemptIssued:    {PhaseRetrieve, PhaseInstall},
}

// stateChangingPhases are not repeatable: consuming their launch must leave
// the state it was recorded in, so the record never again looks like the one
// before the first launch. A retrieve result keeps SUBMITTED or ISSUED and
// its budget was consumed with the launch.
var stateChangingPhases = []Phase{PhaseCreate, PhaseSubmit, PhaseInstall}

// reachedBy names the launch that a state change into each state consumes.
var reachedBy = map[AttemptState]Phase{AttemptKeyReady: PhaseCreate, AttemptSubmitted: PhaseSubmit}

func validAttemptShape(a Attempt) error {
	if a.ID == "" || a.CA == "" || a.Template == "" || a.Provider == "" || a.Container == "" ||
		a.TargetSID == "" || a.Profile == "" || a.Started.IsZero() || a.Updated.Before(a.Started) {
		return errors.New("attempt identity incomplete")
	}
	if _, ok := attemptOrder[a.State]; !ok {
		return errors.New("unknown attempt state")
	}
	order := attemptOrder[a.State]
	for _, h := range []string{a.CSRHash, a.SPKI, a.CertHash} {
		if h != "" && !validHash(h) {
			return errors.New("attempt hash must be lowercase SHA-256")
		}
	}
	if (a.SPKI == "") != (len(a.PublicKey) == 0) || len(a.PublicKey) > 0 && sha256Hex(a.PublicKey) != a.SPKI {
		return errors.New("attempt SPKI must be the SHA-256 of its public key")
	}
	if len(a.PublicKey) > 0 {
		if _, err := x509.ParsePKIXPublicKey(a.PublicKey); err != nil {
			return errors.New("attempt public key is not a DER SubjectPublicKeyInfo")
		}
	}
	// What each state or terminal outcome proves on its own, so that a
	// checkpoint without its history cannot drop it.
	needKey := a.State != AttemptDone && order >= attemptOrder[AttemptKeyReady] ||
		contains([]Outcome{Aborted, Denied, CAUnknown, BlockedPKI, Accepted}, a.Outcome)
	needCSR := a.State != AttemptDone && order >= attemptOrder[AttemptSubmitted] ||
		contains([]Outcome{Denied, CAUnknown, BlockedPKI, Accepted}, a.Outcome)
	if needKey && a.SPKI == "" {
		return errors.New("attempt past PREPARE without its key identity")
	}
	if needCSR && a.CSRHash == "" {
		return errors.New("attempt past KEY_READY without its CSR")
	}
	if a.State == AttemptIssued && a.CertHash == "" || a.Outcome == Accepted && a.CertHash == "" {
		return errors.New("issued attempt without certificate hash")
	}
	if (a.State == AttemptDone) != (a.Outcome != "") {
		return errors.New("attempt outcome must accompany the terminal state")
	}
	if a.State == AttemptDone && a.Launch != nil {
		return errors.New("terminal attempt with a launch record")
	}
	if a.Launch != nil && (a.Launch.Seq == 0 || !contains(launchPhases[a.State], a.Launch.Phase)) {
		return errors.New("invalid launch record for this state")
	}
	if a.RequestID < 0 || a.Retrieves < 0 {
		return errors.New("invalid attempt counters")
	}
	if a.Resolution != nil && a.Resolution.validFor(a) != nil {
		return errors.New("invalid attempt resolution")
	}
	return nil
}

// validateAttempts checks the attempt records of s against previous. The
// snapshot properties hold in every frame, including the checkpoint that
// starts a compacted file (restart); the step properties need the
// predecessor, which a checkpoint does not have.
func validateAttempts(s, previous State, restart bool) error {
	if err := validateAttemptSnapshot(s); err != nil {
		return err
	}
	if err := validatePace(s.Pace, previous.Pace, restart); err != nil {
		return err
	}
	if restart {
		return nil
	}
	for id, old := range previous.Attempts {
		next, ok := s.Attempts[id]
		if !ok {
			return errors.New("attempt record removed")
		}
		if err := validateAttemptStep(old, next, s, previous); err != nil {
			return err
		}
	}
	for id, a := range s.Attempts {
		if _, existed := previous.Attempts[id]; existed {
			continue
		}
		if a.State != AttemptPrepare || a.Launch != nil || a.CSRHash != "" || a.SPKI != "" || len(a.PublicKey) != 0 ||
			a.RequestID != 0 || a.Retrieves != 0 || a.Reconstructed || a.OutOfBand || a.Resolution != nil {
			return errors.New("new attempt must start empty at PREPARE")
		}
	}
	return nil
}

// validateAttemptSnapshot checks what a single frame proves on its own.
func validateAttemptSnapshot(s State) error {
	open := 0
	containers := map[string]bool{}
	for id, a := range s.Attempts {
		if id != a.ID {
			return errors.New("attempt keyed by another ID")
		}
		if err := validAttemptShape(a); err != nil {
			return err
		}
		key := a.Provider + "\x00" + a.Container
		if containers[key] {
			return errors.New("key container used by two attempts")
		}
		containers[key] = true
		plan, planned := s.Cleanups[id]
		gone, purged := s.Purged[id]
		switch {
		case a.State != AttemptDone:
			open++
			if planned || purged {
				return errors.New("open attempt with a cleanup plan or a used ID")
			}
		case a.Outcome == Accepted:
			if planned || purged {
				return errors.New("accepted attempt with a cleanup plan")
			}
		default:
			if !(planned && plan.Outcome == a.Outcome || purged && gone.Outcome == a.Outcome) {
				return errors.New("terminal attempt without its cleanup plan")
			}
			if planned {
				if err := planMatchesAttempt(plan, a); err != nil {
					return err
				}
			}
		}
		// A launch is always the journal's current guard operation: while it
		// is pending no other operation can start.
		if l := a.Launch; l != nil {
			op := s.Operation
			if op == nil || op.Sequence != l.Seq || op.Name != "enroll-"+string(l.Phase) ||
				len(op.Arguments) == 0 || op.Arguments[0] != a.ID {
				return errors.New("launch record does not match the current guard operation")
			}
		}
		if s.Pace == nil || a.Started.After(s.Pace.LastStart) || a.Updated.After(s.Pace.MaxSeen) {
			return errors.New("attempt times beyond the pacing record")
		}
	}
	if open > 1 {
		return errors.New("more than one open attempt")
	}
	return nil
}

// planMatchesAttempt binds an enrollment cleanup plan to the identity its
// attempt recorded: exactly one key item, which is the attempt's own key (or
// unidentified when the attempt never recorded one), and an installed
// certificate only as the attempt's certificate. A plan item never names an
// object of its own choosing.
func planMatchesAttempt(plan Cleanup, a Attempt) error {
	keys := 0
	for _, item := range plan.Items {
		art := item.Artifact
		switch art.Kind {
		case Key:
			keys++
			want := Artifact{Kind: Key, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: a.SPKI}
			if len(a.PublicKey) > 0 {
				want.PublicKey = base64.StdEncoding.EncodeToString(a.PublicKey)
			}
			if art != want || item.Unidentified != (a.SPKI == "") {
				return errors.New("cleanup key item is not the attempt's key")
			}
		case Certificate:
			if a.CertHash == "" || art.Hash != a.CertHash {
				return errors.New("cleanup certificate item is not the attempt's certificate")
			}
		case Request:
			return errors.New("REQUEST item in a native enrollment plan")
		}
	}
	if keys != 1 {
		return errors.New("enrollment cleanup plan must list the attempt's key once")
	}
	return nil
}

func validateAttemptStep(old, next Attempt, s, previous State) error {
	if old.ID != next.ID || old.CA != next.CA || old.Template != next.Template ||
		old.Provider != next.Provider || old.Container != next.Container ||
		old.TargetSID != next.TargetSID || old.Profile != next.Profile || !old.Started.Equal(next.Started) ||
		!setOnce(old.CSRHash, next.CSRHash) || !setOnce(old.SPKI, next.SPKI) ||
		len(old.PublicKey) != 0 && !bytes.Equal(old.PublicKey, next.PublicKey) ||
		!setOnce(old.RequestID, next.RequestID) || !setOnce(old.CertHash, next.CertHash) ||
		old.Reconstructed && !next.Reconstructed || old.OutOfBand && !next.OutOfBand {
		return errors.New("attempt identity changed")
	}
	if next.Updated.Before(old.Updated) || next.Retrieves < old.Retrieves {
		return errors.New("attempt progress went backwards")
	}
	if old.State == AttemptDone {
		// A terminal record is frozen; the only change is its first
		// resolution, judged against the identity the attempt acquired.
		if old.Resolution == nil {
			next.Resolution = nil
		}
		if !sameAttempt(old, next) {
			return errors.New("terminal attempt reopened or changed")
		}
		return nil
	}
	if next.Resolution != nil {
		return errors.New("resolution on an open attempt")
	}
	if !contains(attemptEdges[old.State], next.State) {
		return errors.New("attempt transition not allowed")
	}
	if err := validateLaunchStep(old, next, s, previous); err != nil {
		return err
	}
	if next.State != old.State {
		if phase, ok := reachedBy[next.State]; ok && (old.Launch == nil || old.Launch.Phase != phase) {
			return errors.New("state reached without the launch of its effect")
		}
	}
	if next.State == AttemptDone {
		if !contains(terminalFrom[old.State], next.Outcome) {
			return errors.New("terminal outcome not allowed from this state")
		}
		if next.Outcome == Aborted && old.Launch != nil {
			return errors.New("abort with a pending launch")
		}
		if next.Outcome == Accepted && (old.Launch == nil || old.Launch.Phase != PhaseInstall) {
			return errors.New("accepted without an install launch")
		}
		if next.Outcome != Accepted {
			plan, ok := s.Cleanups[next.ID]
			if _, existed := previous.Cleanups[next.ID]; existed || !ok || plan.Outcome != next.Outcome {
				return errors.New("terminal attempt without its cleanup intent in the same frame")
			}
		}
	}
	return nil
}

// validateLaunchStep enforces the life of a launch record: written only with a
// new guard operation of the same sequence and with exactly its own budget,
// never replaced, the attempt frozen while it is pending, and consumed only
// once that operation is quiescent, by a transition its phase allows.
func validateLaunchStep(old, next Attempt, s, previous State) error {
	pending, now := old.Launch, next.Launch
	switch {
	case pending == nil && now != nil:
		op := s.Operation
		if op == nil || op.Sequence != now.Seq || op.Quiescent ||
			previous.Operation != nil && previous.Operation.Sequence >= now.Seq {
			return errors.New("launch without a new guard operation")
		}
		retrieve := now.Phase == PhaseRetrieve
		reconstruct := retrieve && old.State == AttemptIssued
		budget := old.Retrieves
		if retrieve {
			budget++
		}
		if next.State != old.State || next.Retrieves != budget || reconstruct && old.Reconstructed ||
			next.Reconstructed != (old.Reconstructed || reconstruct) {
			return errors.New("launch recorded without exactly its own progress")
		}
		// The launch frame records the launch and its budget, nothing else:
		// a RequestId or disposition written before the effect could make
		// the real result look discordant.
		same := next
		same.Launch, same.Retrieves, same.Reconstructed = nil, old.Retrieves, old.Reconstructed
		if !sameAttempt(old, same) {
			return errors.New("attempt changed together with its launch")
		}
	case pending != nil && now != nil:
		if *pending != *now {
			return errors.New("launch replaced without a result")
		}
		// Frozen: no field may change while the result is unknown, so
		// nothing (RequestId, disposition, certificate file) is recorded
		// without consuming the launch.
		if !sameAttempt(old, next) {
			return errors.New("attempt changed with a pending launch")
		}
	case pending != nil:
		op := s.Operation
		if op == nil || op.Sequence != pending.Seq || !op.Quiescent {
			return errors.New("launch consumed before its operation is quiescent")
		}
		if next.Retrieves != old.Retrieves || next.Reconstructed != old.Reconstructed {
			return errors.New("launch consumed with budget changes")
		}
		// Evidence fields are first set only by the result that proves them.
		if old.SPKI == "" && next.SPKI != "" && (pending.Phase != PhaseCreate || next.State != AttemptKeyReady) {
			return errors.New("key identity recorded without a create result")
		}
		if !old.OutOfBand && next.OutOfBand && pending.Phase != PhaseSubmit && pending.Phase != PhaseRetrieve {
			return errors.New("out-of-band disposition recorded without a CA result")
		}
		if contains(stateChangingPhases, pending.Phase) && next.State == old.State {
			return errors.New("launch consumed without leaving its state")
		}
	default:
		if next.Retrieves != old.Retrieves || next.Reconstructed != old.Reconstructed {
			return errors.New("retrieve budget changed without a launch")
		}
		if old.SPKI == "" && next.SPKI != "" || !old.OutOfBand && next.OutOfBand {
			return errors.New("evidence recorded without the result of a launch")
		}
	}
	return nil
}

// validatePace checks the pacing record. Its snapshot properties hold in every
// frame; MaxSeen and the start times never decrease, and the window count never
// decreases while the window is unchanged.
func validatePace(next, old *Pace, restart bool) error {
	if next == nil {
		if old != nil && !restart {
			return errors.New("pacing record removed")
		}
		return nil
	}
	if next.WindowCount < 0 || next.Failures < 0 || next.LastStart.After(next.MaxSeen) ||
		!next.WindowStart.IsZero() && (next.WindowStart.After(next.LastStart) || next.WindowCount < 1) {
		return errors.New("invalid pacing record")
	}
	if old == nil || restart {
		return nil
	}
	if next.MaxSeen.Before(old.MaxSeen) || next.LastStart.Before(old.LastStart) || next.WindowStart.Before(old.WindowStart) ||
		next.WindowStart.Equal(old.WindowStart) && next.WindowCount < old.WindowCount {
		return errors.New("pacing record went backwards")
	}
	return nil
}
