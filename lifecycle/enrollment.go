package lifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// KeyHandle is an open handle on an attempt's key. Close releases it.
type KeyHandle interface {
	crypto.Signer
	Close() error
}

// ErrKeyExists is returned by KeyStore.Create when the name is already taken:
// nothing was created and the existing key is not the attempt's.
var ErrKeyExists = errors.New("a key with the attempt's container name already exists")

// KeyStore creates and opens the attempt's key with the access policy for the
// attempt's TargetSID and Profile (cng v0.4.0 adapter). The adapter refuses
// an attempt whose TargetSID is not the one of its configured policy.
type KeyStore interface {
	// Create creates the key create-only; it never opens an existing one.
	Create(ctx context.Context, a Attempt) (KeyHandle, error)
	// Open opens the key with the record's policy. An error means the key
	// could not be opened; it is never proof of absence.
	Open(ctx context.Context, a Attempt) (KeyHandle, error)
}

// CADisposition is the disposition returned by ICertRequest::Submit or
// RetrievePending (certcli.h values).
type CADisposition int32

const (
	DispIncomplete      CADisposition = 0
	DispError           CADisposition = 1
	DispDenied          CADisposition = 2
	DispIssued          CADisposition = 3
	DispIssuedOutOfBand CADisposition = 4
	DispUnderSubmission CADisposition = 5
	DispRevoked         CADisposition = 6
)

// CAResult is the raw outcome of a Submit or RetrievePending call. Err is the
// failed HRESULT or a refusal (ErrQuiescence when local completion cannot be
// proven); Disposition is meaningful only when Err is nil. Stat is the result
// of writing the issued certificate to its file after CR_DISP_ISSUED. Status
// (GetLastStatus) and Text are diagnostic only and never used for decisions.
type CAResult struct {
	Err         error
	Disposition CADisposition
	RequestID   int
	Stat        error
	Status      uint32
	Text        string
}

// CertStore installs certificates into LocalMachine\My and proves their
// binding.
type CertStore interface {
	// Install adds the certificate to My and sets its CRYPT_KEY_PROV_INFO for
	// the attempt's provider and container with the machine flag. A
	// certificate already present is not an error by itself.
	Install(ctx context.Context, a Attempt, cert []byte) error
	// VerifyBinding re-reads a.CertHash from My, checks its
	// CRYPT_KEY_PROV_INFO, acquires the key through it with no cache and no
	// repair, compares the public keys and verifies a test signature. It
	// returns the SHA-256 SPKI of the acquired key. An error is never proof of
	// absence.
	VerifyBinding(ctx context.Context, a Attempt) (spki string, err error)
}

// AttemptFile is a file found in the attempt directory. Err marks a file whose
// identity could not be established.
type AttemptFile struct {
	Name string
	Hash string
	Err  error
}

// Requester builds the CSR, calls the CA and reads files inside the protected
// attempt directory. A call that cannot prove local completion must return an
// error matching ErrQuiescence (in CAResult.Err for Submit/Retrieve).
type Requester interface {
	// WriteCSR builds the PKCS #10 request for a signed by key, verifies its
	// signature, writes request.csr (replacing an earlier one: it is called
	// only while CSRHash is empty) and returns its SHA-256.
	WriteCSR(ctx context.Context, a Attempt, key crypto.Signer) (hash string, err error)
	// ReadCSR returns the SHA-256 of request.csr and of its SPKI.
	ReadCSR(ctx context.Context, a Attempt) (hash, spki string, err error)
	// Submit and Retrieve write an issued certificate to certFile.
	Submit(ctx context.Context, a Attempt, certFile string) CAResult
	Retrieve(ctx context.Context, a Attempt, certFile string) CAResult
	ReadCert(ctx context.Context, a Attempt, certFile string) ([]byte, error)
	// Files lists every file of the attempt in a stable order.
	Files(ctx context.Context, a Attempt) ([]AttemptFile, error)
}

// PacePolicy limits new attempts and retrieves.
type PacePolicy struct {
	MinInterval     time.Duration
	Window          time.Duration
	MaxPerWindow    int
	Backoff         func(failures int) time.Duration
	RetrieveMax     int
	RetrieveBackoff func(done int) time.Duration
}

// Params identify a new attempt. Container must be new; ID is generated when
// empty.
type Params struct {
	ID        string
	CA        string
	Template  string
	Provider  string
	Container string
	TargetSID string
	Profile   string
}

var (
	ErrAttemptOpen     = errors.New("an enrollment attempt or its cleanup is still open")
	ErrAttemptBlocked  = errors.New("a BLOCKED_PKI, INCONCLUSIVE or CA_UNKNOWN attempt awaits administrative resolution")
	ErrPaced           = errors.New("new enrollment attempt not allowed yet by pacing")
	ErrNoOpenAttempt   = errors.New("no open enrollment attempt")
	ErrRetrieveNotDue  = errors.New("next retrieve not due yet")
	ErrAttemptNotFound = errors.New("enrollment attempt not found")
)

const (
	csrFile        = "request.csr"
	issuedCertFile = "issued.cer"
)

// Enrollment drives durable enrollment attempts. Guard and the cleanup must use
// the same Journal. Step is the only driver: the normal path and crash
// recovery are the same code, selected by the last record. Each Step performs
// at most one transition under one lease.
type Enrollment struct {
	Journal  Journal
	Guard    ProcessGuard
	Deleter  Deleter
	Requests Requester
	Keys     KeyStore
	Stores   CertStore
	// Validate performs the full validation of the certificate for a.
	Validate func(ctx context.Context, cert []byte, a Attempt) error
	Pace     PacePolicy
	Now      func() time.Time
}

func (e Enrollment) ready() error {
	if e.Journal == nil || e.Requests == nil || e.Keys == nil || e.Stores == nil || e.Validate == nil || e.Deleter == nil {
		return errors.New("enrollment adapters required")
	}
	return nil
}

// clock returns max(now, Pace.MaxSeen) and records it.
func (e Enrollment) clock(s *State) time.Time {
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	t := now().UTC()
	if s.Pace == nil {
		s.Pace = &Pace{}
	}
	if t.Before(s.Pace.MaxSeen) {
		t = s.Pace.MaxSeen
	}
	s.Pace.MaxSeen = t
	return t
}

func newAttemptID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Start records a new attempt at PREPARE. It refuses under a latch, while an
// attempt or its cleanup is open, while a BLOCKED_PKI, INCONCLUSIVE or CA_UNKNOWN attempt is
// unresolved, and when pacing does not allow it.
func (e Enrollment) Start(ctx context.Context, p Params) (Attempt, error) {
	if err := e.ready(); err != nil {
		return Attempt{}, err
	}
	if p.ID == "" {
		id, err := newAttemptID()
		if err != nil {
			return Attempt{}, err
		}
		p.ID = id
	}
	var out Attempt
	err := e.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		if err := quiescenceBarrier(s); err != nil {
			return err
		}
		for id, a := range s.Attempts {
			if a.State != AttemptDone {
				return ErrAttemptOpen
			}
			if plan, ok := s.Cleanups[id]; ok && !plan.Terminal {
				return ErrAttemptOpen
			}
			if awaitsResolution(a.Outcome) && a.Resolution == nil {
				return ErrAttemptBlocked
			}
		}
		now := e.clock(&s)
		pace := s.Pace
		if now.Before(pace.NotBefore) || !pace.LastStart.IsZero() && now.Before(pace.LastStart.Add(e.Pace.MinInterval)) {
			return ErrPaced
		}
		if pace.WindowStart.IsZero() || e.Pace.Window <= 0 || !now.Before(pace.WindowStart.Add(e.Pace.Window)) {
			pace.WindowStart, pace.WindowCount = now, 0
		}
		if e.Pace.MaxPerWindow > 0 && pace.WindowCount >= e.Pace.MaxPerWindow {
			return ErrPaced
		}
		pace.LastStart = now
		pace.WindowCount++
		out = Attempt{ID: p.ID, CA: p.CA, Template: p.Template, Provider: p.Provider, Container: p.Container,
			TargetSID: p.TargetSID, Profile: p.Profile, State: AttemptPrepare, Started: now, Updated: now}
		if s.Attempts == nil {
			s.Attempts = map[string]Attempt{}
		}
		s.Attempts[out.ID] = out
		return tx.Save(s)
	})
	if err != nil {
		return Attempt{}, err
	}
	return out, nil
}

// Step advances or recovers the open attempt by one transition. With no open
// attempt it resumes the cleanup plan of a terminal attempt, if any, and
// otherwise returns ErrNoOpenAttempt.
func (e Enrollment) Step(ctx context.Context) (Attempt, error) {
	if err := e.ready(); err != nil {
		return Attempt{}, err
	}
	var out Attempt
	err := e.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		id := ""
		for aid, a := range s.Attempts {
			if a.State != AttemptDone {
				id = aid
			}
		}
		if id == "" {
			pending := []string{}
			for aid := range s.Attempts {
				if plan, ok := s.Cleanups[aid]; ok && !plan.Terminal {
					pending = append(pending, aid)
				}
			}
			if len(pending) == 0 {
				return ErrNoOpenAttempt
			}
			sort.Strings(pending)
			out = s.Attempts[pending[0]]
			return Cleaner{Deleter: e.Deleter, Now: e.Now}.resumeIn(ctx, tx, pending[0])
		}
		out = s.Attempts[id]
		// Evidence is read only once quiescence is established or resolved.
		if _, _, err := e.Guard.settle(ctx, tx); err != nil {
			return err
		}
		out, err = e.advance(ctx, tx, id)
		return err
	})
	return out, err
}

// Abort closes an attempt at KEY_READY with no pending launch as
// ABORTED_PRE_SUBMIT: ownership is proven and no submit was ever launched.
func (e Enrollment) Abort(ctx context.Context, reason string) (Attempt, error) {
	if err := e.ready(); err != nil {
		return Attempt{}, err
	}
	var out Attempt
	err := e.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		// No evidence is read and nothing is closed under a latch: another
		// unfinished operation or an uncertain cleanup may still change the
		// artifacts the inventory would freeze.
		if err := quiescenceBarrier(s); err != nil {
			return err
		}
		for _, a := range s.Attempts {
			if a.State == AttemptKeyReady {
				if a.Launch != nil {
					return errors.New("abort refused: a native call may be in progress")
				}
				out, err = e.finish(ctx, tx, s, a, Aborted, "aborted: "+reason)
				return err
			}
		}
		return errors.New("no attempt can be aborted before submit")
	})
	return out, err
}

// Report returns an attempt and its cleanup plan: the report fields
// (attempt ID, CA, RequestId, CSR hash, SPKI, outcome, reason and the
// per-artifact cleanup results).
func (e Enrollment) Report(ctx context.Context, id string) (Attempt, *Cleanup, error) {
	if e.Journal == nil {
		return Attempt{}, nil, errors.New("enrollment journal required")
	}
	var a Attempt
	var plan *Cleanup
	err := e.Journal.WithLock(ctx, func(tx Transaction) error {
		s, err := tx.Load()
		if err != nil {
			return err
		}
		var ok bool
		if a, ok = s.Attempts[id]; !ok {
			return ErrAttemptNotFound
		}
		if p, ok := s.Cleanups[id]; ok {
			plan = &p
		}
		return nil
	})
	return a, plan, err
}

func (e Enrollment) reload(tx Transaction, id string) (State, Attempt, error) {
	s, err := tx.Load()
	if err != nil {
		return State{}, Attempt{}, err
	}
	return s, s.Attempts[id], nil
}

func (e Enrollment) save(tx Transaction, s State, a Attempt) (Attempt, error) {
	a.Updated = e.clock(&s)
	s.Attempts[a.ID] = a
	if err := tx.Save(s); err != nil {
		return a, err
	}
	return a, nil
}

// finish closes the attempt and, except for ACCEPTED, writes its cleanup
// intent in the same frame.
func (e Enrollment) finish(ctx context.Context, tx Transaction, s State, a Attempt, outcome Outcome, reason string) (Attempt, error) {
	var items []PlannedArtifact
	if outcome != Accepted {
		items = e.inventory(ctx, a) // from the last open record
	}
	if a.OutOfBand && outcome != Accepted {
		reason = "the CA reported CR_DISP_ISSUED_OUT_OF_BAND; " + reason
	}
	now := e.clock(&s)
	a.State, a.Outcome, a.Reason, a.Launch, a.Updated = AttemptDone, outcome, reason, nil, now
	if outcome == Accepted {
		s.Pace.Failures = 0
	} else {
		plan, err := newCleanupPlan(a.ID, outcome, items)
		if err != nil {
			return a, err
		}
		s.Cleanups[a.ID] = plan
		s.Pace.Failures++
		if e.Pace.Backoff != nil {
			s.Pace.NotBefore = now.Add(e.Pace.Backoff(s.Pace.Failures))
		}
	}
	s.Attempts[a.ID] = a
	return a, tx.Save(s)
}

// expectedFiles names every file an attempt in state a may have created
// in its directory: the CSR always, the submit output once a submit may have
// launched, and one output per retrieve launch.
func expectedFiles(a Attempt) []string {
	names := []string{csrFile}
	if attemptOrder[a.State] >= attemptOrder[AttemptKeyReady] {
		names = append(names, issuedCertFile)
	}
	for n := 1; n <= a.Retrieves; n++ {
		names = append(names, retrieveFile(n))
	}
	return names
}

func retrieveFile(n int) string { return fmt.Sprintf("retrieve-%d.cer", n) }

// inventory lists every artifact the attempt may have created, in a stable
// order: key, files, installed certificate. A successful listing of the
// protected attempt directory establishes which files exist; a file that is
// listed but unreadable, a name listed twice with different identities, and
// every expected or returned file when the listing fails are unidentified,
// never omitted. A key without a recorded SPKI (PREPARE) has no identity and
// is never deleted.
func (e Enrollment) inventory(ctx context.Context, a Attempt) []PlannedArtifact {
	key := Artifact{Kind: Key, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: a.SPKI}
	if len(a.PublicKey) > 0 {
		key.PublicKey = base64.StdEncoding.EncodeToString(a.PublicKey)
	}
	items := []PlannedArtifact{{Artifact: key, Unattributed: a.SPKI == ""}}
	files, err := e.Requests.Files(ctx, a)
	// One item per file name. A failed listing makes every name uncertain,
	// including names it returned (a partial list is not proof), and an
	// uncertain entry always prevails over an identified one of the same name.
	var names []string
	byName := map[string]PlannedArtifact{}
	add := func(name, hash string, uncertain bool) {
		art := Artifact{Kind: File, Name: name}
		if !uncertain {
			art.Hash = hash
		}
		p, seen := byName[name]
		if !seen {
			names = append(names, name)
		} else if p.Unattributed || p.Artifact.Hash != art.Hash {
			art, uncertain = Artifact{Kind: File, Name: name}, true
		}
		byName[name] = PlannedArtifact{Artifact: art, Unattributed: uncertain}
	}
	if err != nil {
		for _, name := range expectedFiles(a) {
			add(name, "", true)
		}
	}
	for _, f := range files {
		add(f.Name, f.Hash, err != nil || f.Err != nil || !validHash(f.Hash))
	}
	for _, name := range names {
		items = append(items, byName[name])
	}
	// Certificate item: an install may have run without a proven binding.
	if a.Launch != nil && a.Launch.Phase == PhaseInstall {
		items = append(items, PlannedArtifact{Artifact: Artifact{Kind: Certificate, Name: "My", Hash: a.CertHash}})
	}
	return items
}

// run launches a native call under the guard inside tx. The launch record (and
// extra progress) is saved with the operation intent. It returns stop=true
// with the error when the step must end without evaluating results: the guard
// refused before writing the intent, the intent frame failed, or quiescence is
// uncertain. Once the intent with its launch record is durable, a refusal
// returned by the Requester itself is NOT distinguished from a failed call:
// the launch record stands and its result is evaluated, so a refused
// submit closes as CA_UNKNOWN and is never resubmitted. Adapter refusals
// (directory not pinnable, missing input) therefore cost the attempt; this
// is the conservative reading of a launch record.
func (e Enrollment) run(ctx context.Context, tx Transaction, a Attempt, phase Phase, args []string,
	extra func(*Attempt), effect func() error) (stop bool, err error) {
	invoked := false
	err = e.Guard.RunIn(ctx, tx, "enroll-"+string(phase), append([]string{a.ID}, args...),
		func(s *State, seq uint64) {
			at := s.Attempts[a.ID]
			at.Launch = &Launch{Phase: phase, Seq: seq}
			if extra != nil {
				extra(&at)
			}
			s.Attempts[a.ID] = at
		},
		func() error { invoked = true; return effect() })
	if err != nil && (!invoked || errors.Is(err, ErrQuiescence)) {
		return true, err
	}
	return false, err
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (e Enrollment) advance(ctx context.Context, tx Transaction, id string) (Attempt, error) {
	s, a, err := e.reload(tx, id)
	if err != nil {
		return a, err
	}
	switch a.State {
	case AttemptPrepare:
		return e.stepPrepare(ctx, tx, s, a)
	case AttemptKeyReady:
		return e.stepKeyReady(ctx, tx, s, a)
	case AttemptSubmitted:
		return e.stepSubmitted(ctx, tx, s, a)
	case AttemptIssued:
		return e.stepIssued(ctx, tx, s, a)
	}
	return a, fmt.Errorf("attempt %s in unexpected state %s", a.ID, a.State)
}

// publicKeyOf returns the DER SubjectPublicKeyInfo of an open key.
func publicKeyOf(k crypto.Signer) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.Public())
}

// stepPrepare launches create. A create result that was lost is never
// recovered by opening the key: a key that opens may predate the attempt, and
// the lost result cannot tell a successful create from ErrKeyExists. Such an
// attempt ends ABANDONED_UNVERIFIED and its key, without a recorded SPKI, is
// kept.
func (e Enrollment) stepPrepare(ctx context.Context, tx Transaction, s State, a Attempt) (Attempt, error) {
	if a.Launch != nil {
		return e.finish(ctx, tx, s, a, Abandoned, "create result lost; the key is never adopted")
	}
	var key KeyHandle
	var createErr error
	stop, err := e.run(ctx, tx, a, PhaseCreate, nil, nil, func() error {
		key, createErr = e.Keys.Create(ctx, a)
		return createErr
	})
	if stop {
		if key != nil {
			key.Close()
		}
		return a, err
	}
	if s, a, err = e.reload(tx, a.ID); err != nil {
		if key != nil {
			key.Close()
		}
		return a, err
	}
	switch {
	case errors.Is(createErr, ErrKeyExists):
		return e.finish(ctx, tx, s, a, Inconclusive, "key container name already in use: "+createErr.Error())
	case createErr != nil:
		if key != nil {
			key.Close()
		}
		return e.finish(ctx, tx, s, a, Abandoned, "create failed: "+createErr.Error())
	case key == nil:
		return e.finish(ctx, tx, s, a, Inconclusive, "create reported success without a key handle")
	}
	pub, perr := publicKeyOf(key)
	if cerr := key.Close(); perr == nil && cerr != nil {
		perr = cerr
	}
	if perr != nil {
		return e.finish(ctx, tx, s, a, Inconclusive, "created key without a readable public key: "+perr.Error())
	}
	a.State, a.Launch, a.PublicKey, a.SPKI = AttemptKeyReady, nil, pub, sha256Hex(pub)
	return e.save(tx, s, a)
}

// openOwnKey opens the attempt's key and checks that it is the recorded one.
func (e Enrollment) openOwnKey(ctx context.Context, a Attempt) (KeyHandle, error) {
	key, err := e.Keys.Open(ctx, a)
	if err != nil {
		return nil, fmt.Errorf("key not openable: %w", err)
	}
	pub, err := publicKeyOf(key)
	if err != nil || !bytes.Equal(pub, a.PublicKey) {
		key.Close()
		return nil, fmt.Errorf("key is not the recorded one (%v)", err)
	}
	return key, nil
}

// stepKeyReady writes the CSR once, then launches submit. A lost submit
// result is CA_UNKNOWN, never a resubmit.
func (e Enrollment) stepKeyReady(ctx context.Context, tx Transaction, s State, a Attempt) (Attempt, error) {
	if a.Launch != nil {
		return e.finish(ctx, tx, s, a, CAUnknown, "submit may have reached the CA; its result was lost")
	}
	key, err := e.openOwnKey(ctx, a)
	if err != nil {
		return e.finish(ctx, tx, s, a, Inconclusive, err.Error()+" before submit")
	}
	if a.CSRHash == "" {
		h, err := e.Requests.WriteCSR(ctx, a, key)
		key.Close()
		if err != nil {
			return a, err // nothing was submitted: the CSR may be written again
		}
		a.CSRHash = h
		return e.save(tx, s, a)
	}
	key.Close()
	csrHash, csrSPKI, err := e.Requests.ReadCSR(ctx, a)
	if err != nil || csrHash != a.CSRHash || csrSPKI != a.SPKI {
		return e.finish(ctx, tx, s, a, Inconclusive, fmt.Sprintf("request.csr changed before submit (%v)", err))
	}
	var res CAResult
	if stop, err := e.run(ctx, tx, a, PhaseSubmit, nil, nil, func() error {
		res = e.Requests.Submit(ctx, a, issuedCertFile)
		return res.Err
	}); stop {
		return a, err
	}
	if s, a, err = e.reload(tx, a.ID); err != nil {
		return a, err
	}
	return e.applyCA(ctx, tx, s, a, res, issuedCertFile)
}

type caVerdict int

const (
	caIssued caVerdict = iota
	caPending
	caDenied
	caOutOfBand
	caOther
)

// classifyCA classifies the CA reply after quiescence was established: a failed
// HRESULT is never a PKI decision, then the disposition decides.
func classifyCA(r CAResult) caVerdict {
	if r.Err != nil {
		return caOther
	}
	switch r.Disposition {
	case DispIssued:
		if r.Stat == nil {
			return caIssued
		}
	case DispUnderSubmission:
		return caPending
	case DispDenied:
		return caDenied
	case DispIssuedOutOfBand:
		return caOutOfBand
	}
	return caOther
}

func (e Enrollment) retrieveMax() int {
	if e.Pace.RetrieveMax > 0 {
		return e.Pace.RetrieveMax
	}
	return 1
}

func (e Enrollment) applyCA(ctx context.Context, tx Transaction, s State, a Attempt, res CAResult, file string) (Attempt, error) {
	a.Launch = nil
	if res.RequestID > 0 {
		if a.RequestID != 0 && a.RequestID != res.RequestID {
			return e.finish(ctx, tx, s, a, Inconclusive, fmt.Sprintf("RequestId changed from %d to %d", a.RequestID, res.RequestID))
		}
		a.RequestID = res.RequestID
	}
	diag := fmt.Sprintf("disposition %d, status 0x%08X: %v; %s", res.Disposition, res.Status, res.Err, res.Text)
	switch classifyCA(res) {
	case caIssued:
		a.State, a.Disposition, a.CertFile, a.Reason = AttemptSubmitted, DispositionIssued, file, ""
		return e.save(tx, s, a)
	case caPending:
		return e.finish(ctx, tx, s, a, BlockedPKI, "pending at the CA, waiting for a PKI decision: "+res.Text)
	case caDenied:
		return e.finish(ctx, tx, s, a, Denied, "denied by the CA: "+diag)
	case caOutOfBand:
		// The CA claims an issuance but returned no certificate to
		// validate: recorded, never ISSUED without one.
		a.OutOfBand = true
	}
	if a.RequestID == 0 {
		return e.finish(ctx, tx, s, a, CAUnknown, "no durable RequestId after "+diag)
	}
	if a.Retrieves >= e.retrieveMax() {
		return e.finish(ctx, tx, s, a, CAUnknown, "retrieve budget exhausted after "+diag)
	}
	a.State, a.Disposition, a.Reason = AttemptSubmitted, DispositionUnknown, diag
	a.NextRetrieve = e.clock(&s)
	if e.Pace.RetrieveBackoff != nil && a.Retrieves > 0 {
		a.NextRetrieve = a.NextRetrieve.Add(e.Pace.RetrieveBackoff(a.Retrieves))
	}
	return e.save(tx, s, a)
}

func (e Enrollment) stepSubmitted(ctx context.Context, tx Transaction, s State, a Attempt) (Attempt, error) {
	if a.Launch != nil {
		// A retrieve may have run; its result was lost. The launch consumed
		// one budget unit; the next retrieve writes a new file.
		a.Launch, a.Disposition, a.Reason = nil, DispositionUnknown, "retrieve result lost"
		if a.Retrieves >= e.retrieveMax() {
			return e.finish(ctx, tx, s, a, CAUnknown, "retrieve budget exhausted after a lost result")
		}
		a.NextRetrieve = e.clock(&s)
		if e.Pace.RetrieveBackoff != nil {
			a.NextRetrieve = a.NextRetrieve.Add(e.Pace.RetrieveBackoff(a.Retrieves))
		}
		return e.save(tx, s, a)
	}
	if a.Disposition == DispositionIssued {
		cert, err := e.Requests.ReadCert(ctx, a, a.CertFile)
		if err != nil {
			if a.RequestID == 0 {
				return e.finish(ctx, tx, s, a, Inconclusive, "issued certificate file unreadable and no RequestId: "+err.Error())
			}
			a.Disposition, a.Reason = DispositionUnknown, "issued certificate file unreadable: "+err.Error()
			a.NextRetrieve = e.clock(&s)
			return e.save(tx, s, a)
		}
		if err := e.Validate(ctx, cert, a); err != nil {
			return e.finish(ctx, tx, s, a, Inconclusive, "certificate validation failed: "+err.Error())
		}
		a.State, a.CertHash, a.Reason = AttemptIssued, sha256Hex(cert), ""
		return e.save(tx, s, a)
	}
	if a.RequestID == 0 || a.Retrieves >= e.retrieveMax() {
		return e.finish(ctx, tx, s, a, CAUnknown, "no retrieve possible: "+a.Reason)
	}
	if e.clock(&s).Before(a.NextRetrieve) {
		return a, ErrRetrieveNotDue
	}
	n := a.Retrieves + 1
	file := retrieveFile(n)
	var res CAResult
	stop, err := e.run(ctx, tx, a, PhaseRetrieve, []string{file}, func(at *Attempt) { at.Retrieves = n }, func() error {
		res = e.Requests.Retrieve(ctx, a, file)
		return res.Err
	})
	if stop {
		return a, err
	}
	if s, a, err = e.reload(tx, a.ID); err != nil {
		return a, err
	}
	return e.applyCA(ctx, tx, s, a, res, file)
}

func (e Enrollment) stepIssued(ctx context.Context, tx Transaction, s State, a Attempt) (Attempt, error) {
	if a.Launch != nil {
		if a.Launch.Phase == PhaseInstall {
			return e.installEvidence(ctx, tx, s, a)
		}
		return e.finish(ctx, tx, s, a, Inconclusive, "reconstruction retrieve result lost")
	}
	cert, err := e.Requests.ReadCert(ctx, a, a.CertFile)
	if err != nil || sha256Hex(cert) != a.CertHash {
		if a.Reconstructed || a.RequestID == 0 || a.Retrieves >= e.retrieveMax() {
			return e.finish(ctx, tx, s, a, Inconclusive, fmt.Sprintf("issued certificate missing or changed (%v)", err))
		}
		n := a.Retrieves + 1
		file := retrieveFile(n)
		var res CAResult
		stop, err := e.run(ctx, tx, a, PhaseRetrieve, []string{file},
			func(at *Attempt) { at.Retrieves, at.Reconstructed = n, true },
			func() error { res = e.Requests.Retrieve(ctx, a, file); return res.Err })
		if stop {
			return a, err
		}
		if s, a, err = e.reload(tx, a.ID); err != nil {
			return a, err
		}
		a.Launch = nil
		if res.RequestID > 0 && res.RequestID != a.RequestID {
			return e.finish(ctx, tx, s, a, Inconclusive, fmt.Sprintf("reconstruction retrieve returned RequestId %d, recorded %d", res.RequestID, a.RequestID))
		}
		switch classifyCA(res) {
		case caIssued:
		case caOutOfBand:
			a.OutOfBand = true // recorded; never installed without the validated bytes
			return e.finish(ctx, tx, s, a, Inconclusive, "reconstruction retrieve returned no certificate")
		default:
			return e.finish(ctx, tx, s, a, Inconclusive, "reconstruction retrieve did not return the certificate")
		}
		again, err := e.Requests.ReadCert(ctx, a, file)
		if err != nil || sha256Hex(again) != a.CertHash {
			return e.finish(ctx, tx, s, a, Inconclusive, "reconstructed certificate differs from the validated one")
		}
		a.CertFile = file
		return e.save(tx, s, a)
	}
	if err := e.Validate(ctx, cert, a); err != nil {
		return e.finish(ctx, tx, s, a, Inconclusive, "certificate revalidation failed: "+err.Error())
	}
	if stop, err := e.run(ctx, tx, a, PhaseInstall, nil, nil, func() error { return e.Stores.Install(ctx, a, cert) }); stop {
		return a, err
	}
	if s, a, err = e.reload(tx, a.ID); err != nil {
		return a, err
	}
	return e.installEvidence(ctx, tx, s, a)
}

// installEvidence never repeats install: only the binding check
// on the certificate re-read from My proves success. ACCEPTED means installed
// with a proven binding, not in use: the consumer confirms use.
func (e Enrollment) installEvidence(ctx context.Context, tx Transaction, s State, a Attempt) (Attempt, error) {
	spki, err := e.Stores.VerifyBinding(ctx, a)
	if err != nil {
		return e.finish(ctx, tx, s, a, Inconclusive, "install may have run; binding not proven: "+err.Error())
	}
	if spki != a.SPKI {
		return e.finish(ctx, tx, s, a, Inconclusive, "install may have run; the key acquired through My is not the recorded one")
	}
	return e.finish(ctx, tx, s, a, Accepted, "")
}
