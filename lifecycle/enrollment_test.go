package lifecycle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// world simulates the KSP, the attempt directory, LocalMachine\My and the CA.
// Effects persist across simulated broker restarts; the driver keeps no
// memory between Steps.
type world struct {
	t            *testing.T
	own          *ecdsa.PrivateKey // the key a successful create makes
	key          *ecdsa.PrivateKey // the key under the container name, nil if none
	createErr    error             // create fails without creating a key
	csrSPKI      string
	files        map[string][]byte
	my           map[string]string // certificate hash -> SPKI of the key acquired through it
	cert         []byte
	submit       func(w *world, file string) CAResult
	retrieve     func(w *world, n int, file string) CAResult
	validate     error
	quiesce      map[Phase]bool // effect runs, then reports uncertain quiescence
	calls        map[string]int
	deleted      map[Artifact]int
	targets      map[string]bool
	retrieveN    int
	created      map[string]bool // every file name ever written
	filesErr     error           // the attempt directory cannot be listed
	filesPartial bool            // Files returns entries together with filesErr
	bindErr      error           // the binding check cannot read My
}

const (
	wProvider  = "Microsoft Software Key Storage Provider"
	wContainer = "keppin-attempt"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func spkiOfKey(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return sha256Hex(der)
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, own: newKey(t), files: map[string][]byte{}, my: map[string]string{},
		cert: []byte("certificate"), calls: map[string]int{}, deleted: map[Artifact]int{}, targets: map[string]bool{},
		created: map[string]bool{}}
	w.submit = func(w *world, file string) CAResult { return w.issue(file, 21) }
	w.retrieve = func(w *world, n int, file string) CAResult { return w.issue(file, 0) }
	return w
}

func (w *world) ownSPKI() string { return spkiOfKey(w.t, w.own) }

func (w *world) write(name string, b []byte) {
	w.files[name] = b
	w.created[name] = true
}

func (w *world) issue(file string, id int) CAResult {
	w.write(file, w.cert)
	return CAResult{Disposition: DispIssued, RequestID: id, Text: "Issued"}
}

func pendingResult(id int) CAResult {
	return CAResult{Disposition: DispUnderSubmission, RequestID: id, Status: 0, Text: "Taken under submission"}
}

func deniedResult(id int) CAResult {
	return CAResult{Disposition: DispDenied, RequestID: id, Status: 0x80094012, Text: "Denied by Policy Module"}
}

// failResult is a failed HRESULT: never a PKI decision.
func failResult(id int) CAResult {
	return CAResult{Err: errors.New("HRESULT 0x800706BA: RPC server unavailable"), RequestID: id}
}

func (w *world) effect(p Phase) error {
	w.calls[string(p)]++
	if w.quiesce[p] {
		delete(w.quiesce, p) // one uncertain call, then normal behaviour
		return fmt.Errorf("%w: job accounting failed", ErrQuiescence)
	}
	return nil
}

type fakeKey struct {
	*ecdsa.PrivateKey
	w *world
}

func (k fakeKey) Close() error { k.w.calls["close"]++; return nil }

func (w *world) handle(k *ecdsa.PrivateKey) KeyHandle {
	w.calls["open-handles"]++
	return fakeKey{PrivateKey: k, w: w}
}

func (w *world) Create(_ context.Context, a Attempt) (KeyHandle, error) {
	w.targets[a.TargetSID] = true
	var h KeyHandle
	var err error
	switch {
	case w.key != nil:
		err = fmt.Errorf("%w: NTE_EXISTS", ErrKeyExists)
	case w.createErr != nil:
		err = w.createErr
	default:
		w.key = w.own
		h = w.handle(w.key)
	}
	if qerr := w.effect(PhaseCreate); qerr != nil {
		err = qerr
	}
	return h, err
}

func (w *world) Open(_ context.Context, a Attempt) (KeyHandle, error) {
	w.targets[a.TargetSID] = true
	if w.key == nil {
		return nil, errors.New("NTE_BAD_KEYSET")
	}
	return w.handle(w.key), nil
}

func (w *world) WriteCSR(_ context.Context, a Attempt, key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	w.calls["csr"]++
	w.csrSPKI = sha256Hex(der)
	w.write(csrFile, []byte(fmt.Sprintf("csr:%s:%d", a.Container, w.calls["csr"])))
	return sha256Hex(w.files[csrFile]), nil
}

func (w *world) ReadCSR(context.Context, Attempt) (string, string, error) {
	b, ok := w.files[csrFile]
	if !ok {
		return "", "", fs.ErrNotExist
	}
	return sha256Hex(b), w.csrSPKI, nil
}

func (w *world) Submit(_ context.Context, a Attempt, file string) CAResult {
	res := w.submit(w, file)
	if err := w.effect(PhaseSubmit); err != nil {
		res.Err = err
	}
	return res
}

func (w *world) Retrieve(_ context.Context, a Attempt, file string) CAResult {
	w.retrieveN++
	res := w.retrieve(w, w.retrieveN, file)
	if res.RequestID == 0 {
		res.RequestID = a.RequestID
	}
	if err := w.effect(PhaseRetrieve); err != nil {
		res.Err = err
	}
	return res
}

func (w *world) ReadCert(_ context.Context, _ Attempt, file string) ([]byte, error) {
	b, ok := w.files[file]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}

func (w *world) Install(_ context.Context, a Attempt, cert []byte) error {
	if w.key != nil {
		w.my[sha256Hex(cert)] = spkiOfKey(w.t, w.key)
	}
	return w.effect(PhaseInstall)
}

func (w *world) VerifyBinding(_ context.Context, a Attempt) (string, error) {
	w.calls["verify"]++
	if w.bindErr != nil {
		return "", w.bindErr
	}
	spki, ok := w.my[a.CertHash]
	if !ok {
		return "", errors.New("CRYPT_E_NOT_FOUND")
	}
	return spki, nil
}

func (w *world) Files(context.Context, Attempt) ([]AttemptFile, error) {
	w.calls["files"]++
	var names []string
	for n := range w.files {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []AttemptFile
	for _, n := range names {
		out = append(out, AttemptFile{Name: n, Hash: sha256Hex(w.files[n])})
	}
	if w.filesErr != nil {
		if w.filesPartial {
			return out, w.filesErr // a partial list together with the error
		}
		return nil, w.filesErr
	}
	return out, nil
}

// Delete verifies the object exists before deleting it, like the strict
// adapters: a repeated call after a lost acknowledgment finds nothing. A key
// is deleted only when its SPKI and public key are the recorded ones.
func (w *world) Delete(_ context.Context, a Artifact) error {
	switch a.Kind {
	case Key:
		if w.key == nil {
			return ErrNotFound
		}
		if a.SPKI != spkiOfKey(w.t, w.key) || a.PublicKey == "" {
			return ErrNotOwned
		}
		w.key = nil
	case File:
		if _, ok := w.files[a.Name]; !ok {
			return ErrNotFound
		}
		delete(w.files, a.Name)
	default:
		return fmt.Errorf("unexpected deletion of %+v", a)
	}
	w.deleted[a]++ // successful deletions only
	return nil
}

type enrollRig struct {
	j     *testJournal
	w     *world
	e     Enrollment
	clock time.Time
}

func newRig(t *testing.T) *enrollRig {
	r := &enrollRig{j: newTestJournal(), w: newWorld(t), clock: compactT0}
	r.e = Enrollment{Journal: r.j, Guard: ProcessGuard{Journal: r.j, Recovery: &testQuiescer{}},
		Deleter: r.w, Requests: r.w, Keys: r.w, Stores: r.w,
		Validate: func(context.Context, []byte, Attempt) error { return r.w.validate },
		Pace:     PacePolicy{RetrieveMax: 3},
		Now:      func() time.Time { return r.clock }}
	return r
}

var testParams = Params{ID: "a1", CA: `ca\Root`, Template: "KeppinEnterpriseTLS", Provider: wProvider,
	Container: wContainer, TargetSID: "S-1-5-80-1-2-3-4-5", Profile: "GRGX"}

// drive steps until no attempt or cleanup is open; injected journal failures
// and retrieve waits behave like broker restarts.
func (r *enrollRig) drive(t *testing.T) Attempt {
	t.Helper()
	var last Attempt
	for i := 0; i < 100; i++ {
		a, err := r.e.Step(ctx)
		if a.ID != "" {
			last = a
		}
		switch {
		case errors.Is(err, ErrNoOpenAttempt):
			last = r.j.state.Attempts[last.ID]
			return last
		case errors.Is(err, ErrRetrieveNotDue):
			r.clock = r.clock.Add(time.Hour)
		case errors.Is(err, diskFailure):
			r.j.failAt = 0 // restart after the injected crash
		}
	}
	t.Fatalf("attempt did not settle: %+v", r.j.state.Attempts)
	return last
}

func (r *enrollRig) start(t *testing.T) {
	t.Helper()
	if _, err := r.e.Start(ctx, testParams); err != nil {
		t.Fatal(err)
	}
}

// stepUntil steps until cond holds for attempt a1.
func (r *enrollRig) stepUntil(t *testing.T, cond func(Attempt) bool) {
	t.Helper()
	for i := 0; !cond(r.j.state.Attempts["a1"]); i++ {
		if i > 50 {
			t.Fatalf("condition never reached: %+v", r.j.state.Attempts["a1"])
		}
		if _, err := r.e.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// csrReady is KEY_READY with the CSR written: the next Step submits.
func csrReady(a Attempt) bool { return a.State == AttemptKeyReady && a.CSRHash != "" }

func TestEnrollmentHappyPath(t *testing.T) {
	r := newRig(t)
	r.start(t)
	a := r.drive(t)
	if a.Outcome != Accepted || a.RequestID != 21 || a.CertHash != sha256Hex(r.w.cert) {
		t.Fatalf("attempt: %+v", a)
	}
	for _, p := range []Phase{PhaseCreate, PhaseSubmit, PhaseInstall} {
		if r.w.calls[string(p)] != 1 {
			t.Fatalf("%s ran %d times", p, r.w.calls[string(p)])
		}
	}
	if a.SPKI != r.w.ownSPKI() || !bytes.Equal(a.PublicKey, mustPKIX(t, r.w.own)) {
		t.Fatalf("recorded key identity: %s", a.SPKI)
	}
	if _, ok := r.j.state.Cleanups[a.ID]; ok {
		t.Fatal("accepted attempt wrote a cleanup plan")
	}
	if len(r.w.targets) != 1 || !r.w.targets[testParams.TargetSID] {
		t.Fatalf("steps used another target: %v", r.w.targets)
	}
	if r.w.my[a.CertHash] != a.SPKI {
		t.Fatalf("binding: %q", r.w.my[a.CertHash])
	}
	if r.w.calls["open-handles"] != r.w.calls["close"] {
		t.Fatalf("key handles leaked: %d opened, %d closed", r.w.calls["open-handles"], r.w.calls["close"])
	}
}

func mustPKIX(t *testing.T, k *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Core crash matrix: a crash before or after every journal write, then restarts.
// Each crash point has its own expected outcome, derived from what the failed
// write was (launch intent, quiescence acknowledgment, result) and the
// recovery rule for its phase. Non-idempotent effects run at most once, an
// artifact is successfully deleted at most once (a repeat after a lost
// acknowledgment finds nothing), and every plan matches the retention matrix independently.
func TestEnrollmentCrashAtEverySave(t *testing.T) {
	t.Run("accepted", func(t *testing.T) { crashMatrix(t, func(*enrollRig) {}) })
	// The denied path also crashes inside the cleanup (Resume) of the plan.
	t.Run("denied", func(t *testing.T) {
		crashMatrix(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return deniedResult(13) }
		})
	})
}

type saveKind int

const (
	saveOther   saveKind = iota
	saveIntent           // writes a launch record with its operation intent
	saveQuiesce          // acknowledges quiescence of the launched operation
	saveResult           // consumes the launch with its result
)

// labelSave says what the k-th write of a run (1-based) was.
func labelSave(history []State, k int) (saveKind, Phase) {
	prev := emptyState()
	if k > 1 {
		prev = history[k-2]
	}
	next := history[k-1]
	before, after := prev.Attempts["a1"].Launch, next.Attempts["a1"].Launch
	switch {
	case before == nil && after != nil:
		return saveIntent, after.Phase
	case before != nil && after == nil:
		return saveResult, before.Phase
	case before != nil && !prev.Operation.Quiescent && next.Operation.Quiescent:
		return saveQuiesce, before.Phase
	}
	return saveOther, ""
}

// expectedOutcome applies the recovery rules to a crash at a write: an intent
// committed with the effect never run, or an effect that ran with its result
// lost. A lost create is ABANDONED either way: the key is never adopted.
func expectedOutcome(kind saveKind, phase Phase, commit bool, base Outcome) Outcome {
	notRun := map[Phase]Outcome{PhaseCreate: Abandoned, PhaseSubmit: CAUnknown, PhaseInstall: Inconclusive}
	ranLost := map[Phase]Outcome{PhaseCreate: Abandoned, PhaseSubmit: CAUnknown, PhaseInstall: Accepted}
	switch {
	case kind == saveIntent && commit:
		return notRun[phase]
	case kind == saveQuiesce, kind == saveResult && !commit:
		return ranLost[phase]
	}
	return base
}

func crashMatrix(t *testing.T, setup func(*enrollRig)) {
	happy := newRig(t)
	setup(happy)
	happy.start(t)
	base := happy.drive(t).Outcome
	if len(happy.j.history) != happy.j.saves {
		t.Fatalf("happy run rejected a write: %d of %d", len(happy.j.history), happy.j.saves)
	}
	seen := map[saveKind]int{}
	for k := 1; k <= happy.j.saves; k++ {
		kind, phase := labelSave(happy.j.history, k)
		seen[kind]++
		for _, commit := range []bool{false, true} {
			want := expectedOutcome(kind, phase, commit, base)
			t.Run(fmt.Sprintf("save%d-%s-commit%t", k, phase, commit), func(t *testing.T) {
				r := newRig(t)
				setup(r)
				r.j.failAt, r.j.commitThenFail = k, commit
				if _, err := r.e.Start(ctx, testParams); err != nil {
					if !errors.Is(err, diskFailure) {
						t.Fatal(err)
					}
					r.j.failAt = 0
					if _, ok := r.j.state.Attempts["a1"]; !ok {
						r.start(t)
					}
				}
				a := r.drive(t)
				if a.Outcome != want {
					t.Fatalf("outcome %s (%s), want %s", a.Outcome, a.Reason, want)
				}
				for _, p := range []Phase{PhaseCreate, PhaseSubmit, PhaseInstall} {
					if r.w.calls[string(p)] > 1 {
						t.Fatalf("%s ran %d times", p, r.w.calls[string(p)])
					}
				}
				if want == Accepted && (r.w.calls["create"] != 1 || r.w.calls["submit"] != 1 || r.w.calls["install"] != 1) {
					t.Fatalf("accepted with calls %v", r.w.calls)
				}
				for art, n := range r.w.deleted {
					if n > 1 {
						t.Fatalf("%+v deleted %d times", art, n)
					}
				}
				if a.Outcome == Accepted {
					if r.w.my[a.CertHash] != a.SPKI {
						t.Fatal("accepted without binding")
					}
					return
				}
				for art := range r.w.deleted {
					if a.Outcome == Abandoned && art.Kind == Key {
						t.Fatal("abandoned attempt deleted a key")
					}
				}
				plan, ok := r.j.state.Cleanups[a.ID]
				if !ok || !plan.Terminal || plan.Outcome != a.Outcome {
					t.Fatalf("terminal attempt without a closed plan: %+v", plan)
				}
				// The report stays available after every crash point.
				if got, rp, err := r.e.Report(ctx, a.ID); err != nil || got.Outcome != a.Outcome || rp == nil || !rp.Terminal {
					t.Fatalf("report after the crash: %+v %v", rp, err)
				}
				checkMatrix(t, plan, r.w)
			})
		}
	}
	if seen[saveIntent] == 0 || seen[saveQuiesce] == 0 || seen[saveResult] == 0 {
		t.Fatalf("happy run did not exercise every write kind: %v", seen)
	}
}

// retentionMatrix is the retention matrix written out independently of keepArtifact: whether
// each kind of artifact (F.csr for request.csr, M for an installed
// certificate) is retained per outcome.
var retentionMatrix = map[Outcome]map[string]bool{
	Abandoned:    {"K": true, "F": false, "F.csr": false},
	Aborted:      {"K": false, "F": false, "F.csr": false},
	Denied:       {"K": false, "F": false, "F.csr": true},
	CAUnknown:    {"K": false, "F": false, "F.csr": true},
	BlockedPKI:   {"K": true, "F": true, "F.csr": true, "M": true},
	Inconclusive: {"K": true, "F": true, "F.csr": true, "M": true},
}

// checkMatrix compares a closed plan with the retention matrix and with the world: every
// artifact still present or deleted is in the plan (no omission), each item's
// retention and result follow the matrix and its identity, and completeness
// matches the items.
func checkMatrix(t *testing.T, plan Cleanup, w *world) {
	t.Helper()
	row, ok := retentionMatrix[plan.Outcome]
	if !ok {
		t.Fatalf("no retention matrix row for %s", plan.Outcome)
	}
	kinds := map[ArtifactKind]int{}
	names := map[string]bool{}
	complete := true
	for _, it := range plan.Items {
		kinds[it.Artifact.Kind]++
		col := string(it.Artifact.Kind)
		if it.Artifact.Kind == File {
			names[it.Artifact.Name] = true
			if strings.HasSuffix(it.Artifact.Name, ".csr") {
				col = "F.csr"
			}
		}
		if _, ok := row[col]; !ok {
			t.Fatalf("%s: unexpected artifact %+v", plan.Outcome, it)
		}
		if it.Keep != row[col] {
			t.Fatalf("%s: %+v violates the retention matrix (%s keep=%t)", plan.Outcome, it, col, row[col])
		}
		switch {
		case it.Keep:
			if it.Result != Retained {
				t.Fatalf("%s: retained artifact got %s", plan.Outcome, it.Result)
			}
		case it.Unidentified:
			if it.Result != NotOwned {
				t.Fatalf("%s: unidentified artifact got %s", plan.Outcome, it.Result)
			}
		case it.Result == Deleted:
			if it.Artifact.Kind == File && w.files[it.Artifact.Name] != nil {
				t.Fatalf("%s reported deleted but present", it.Artifact.Name)
			}
		case it.Result != NotFound:
			t.Fatalf("%s: %+v got %s", plan.Outcome, it, it.Result)
		}
		if it.Unidentified || it.Result != Deleted && it.Result != Retained {
			complete = false
		}
	}
	if kinds[Key] != 1 || kinds[Request] != 0 || kinds[Certificate] > 1 {
		t.Fatalf("plan must list the key once, no REQUEST object, at most one certificate: %v", kinds)
	}
	for name := range w.files {
		if !names[name] {
			t.Fatalf("%s: file %s omitted from the plan", plan.Outcome, name)
		}
	}
	if plan.Complete != complete {
		t.Fatalf("plan complete=%t, items say %t", plan.Complete, complete)
	}
}

// A failed HRESULT is never a PKI decision, whatever disposition
// accompanies it; then the disposition decides.
func TestClassifyCAPrecedence(t *testing.T) {
	rpc := errors.New("HRESULT 0x800706BA")
	for name, tc := range map[string]struct {
		r    CAResult
		want caVerdict
	}{
		"issued with file":         {CAResult{Disposition: DispIssued}, caIssued},
		"issued, file not written": {CAResult{Disposition: DispIssued, Stat: fs.ErrPermission}, caOther},
		"under submission":         {CAResult{Disposition: DispUnderSubmission}, caPending},
		"denied":                   {CAResult{Disposition: DispDenied, Status: 0x80094012}, caDenied},
		"issued out of band":       {CAResult{Disposition: DispIssuedOutOfBand}, caOutOfBand},
		"incomplete":               {CAResult{Disposition: DispIncomplete}, caOther},
		"error":                    {CAResult{Disposition: DispError}, caOther},
		"revoked":                  {CAResult{Disposition: DispRevoked}, caOther},
		"unknown value":            {CAResult{Disposition: 42}, caOther},
	} {
		if got := classifyCA(tc.r); got != tc.want {
			t.Errorf("%s: got %d want %d", name, got, tc.want)
		}
	}
	// A failed HRESULT with every disposition value, including pending and
	// an unknown one, and with or without a RequestId.
	for _, d := range []CADisposition{DispIncomplete, DispError, DispDenied, DispIssued,
		DispIssuedOutOfBand, DispUnderSubmission, DispRevoked, 42} {
		for _, id := range []int{0, 7} {
			r := CAResult{Err: rpc, Disposition: d, RequestID: id}
			if got := classifyCA(r); got != caOther {
				t.Errorf("failed HRESULT, disposition %d, RequestId %d: got %d want %d", d, id, got, caOther)
			}
		}
	}
}

func outcomeOf(t *testing.T, setup func(r *enrollRig)) (*enrollRig, Attempt) {
	t.Helper()
	r := newRig(t)
	setup(r)
	r.start(t)
	return r, r.drive(t)
}

func TestEnrollmentCADispositions(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return pendingResult(14) }
		})
		if a.Outcome != BlockedPKI || a.RequestID != 14 || r.w.calls["install"] != 0 {
			t.Fatalf("%+v", a)
		}
		plan := r.j.state.Cleanups[a.ID]
		checkMatrix(t, plan, r.w)
		if len(r.w.deleted) != 0 || !plan.Complete {
			t.Fatalf("pending deleted artifacts: %v", r.w.deleted)
		}
		if _, err := r.e.Start(ctx, Params{ID: "a2", CA: "x", Template: "t", Provider: wProvider, Container: "c2", TargetSID: "s", Profile: "p"}); !errors.Is(err, ErrAttemptBlocked) {
			t.Fatalf("new attempt while pending: %v", err)
		}
	})
	t.Run("denied", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return deniedResult(13) }
		})
		if a.Outcome != Denied {
			t.Fatalf("%+v", a)
		}
		plan := r.j.state.Cleanups[a.ID]
		checkMatrix(t, plan, r.w)
		for _, it := range plan.Items {
			if it.Artifact.Name == csrFile && it.Result != Retained || it.Artifact.Kind == Key && it.Result != Deleted {
				t.Fatalf("denied matrix: %+v", it)
			}
		}
		if r.w.key != nil {
			t.Fatal("denied attempt kept its key")
		}
	})
	t.Run("denied with a failed HRESULT is not a PKI decision", func(t *testing.T) {
		_, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult {
				res := deniedResult(0)
				res.Err = errors.New("HRESULT 0x80070005")
				return res
			}
		})
		if a.Outcome != CAUnknown {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("failed HRESULT without RequestId", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return failResult(0) }
		})
		if a.Outcome != CAUnknown || r.w.calls["submit"] != 1 || r.w.calls["retrieve"] != 0 {
			t.Fatalf("%+v calls=%v", a, r.w.calls)
		}
	})
	t.Run("failed HRESULT with RequestId then retrieve issued", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return failResult(22) }
		})
		if a.Outcome != Accepted || a.CertFile != "retrieve-1.cer" || r.w.calls["submit"] != 1 {
			t.Fatalf("%+v calls=%v", a, r.w.calls)
		}
	})
	for _, d := range []CADisposition{DispIncomplete, DispError, DispRevoked, 42} {
		t.Run(fmt.Sprintf("disposition %d is handled like a failed call", d), func(t *testing.T) {
			r, a := outcomeOf(t, func(r *enrollRig) {
				r.w.submit = func(*world, string) CAResult { return CAResult{Disposition: d} }
			})
			if a.Outcome != CAUnknown || r.w.calls["retrieve"] != 0 || r.w.calls["install"] != 0 {
				t.Fatalf("%+v calls=%v", a, r.w.calls)
			}
		})
	}
	t.Run("out of band without RequestId", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return CAResult{Disposition: DispIssuedOutOfBand} }
		})
		if a.Outcome != CAUnknown || !a.OutOfBand || !strings.Contains(a.Reason, "CR_DISP_ISSUED_OUT_OF_BAND") ||
			a.CertHash != "" || r.w.calls["install"] != 0 {
			t.Fatalf("%+v calls=%v", a, r.w.calls)
		}
		if _, err := r.e.Start(ctx, Params{ID: "a2", CA: "x", Template: "t", Provider: wProvider, Container: "c2",
			TargetSID: "s", Profile: "p"}); !errors.Is(err, ErrAttemptBlocked) {
			t.Fatal("CA_UNKNOWN is not a barrier")
		}
	})
	t.Run("out of band with RequestId then retrieve issued", func(t *testing.T) {
		_, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return CAResult{Disposition: DispIssuedOutOfBand, RequestID: 40} }
		})
		if a.Outcome != Accepted || !a.OutOfBand || a.CertFile != "retrieve-1.cer" {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("out of band then retrieve budget exhausted", func(t *testing.T) {
		_, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return CAResult{Disposition: DispIssuedOutOfBand, RequestID: 41} }
			r.w.retrieve = func(*world, int, string) CAResult { return failResult(0) }
		})
		if a.Outcome != CAUnknown || !a.OutOfBand || !strings.Contains(a.Reason, "CR_DISP_ISSUED_OUT_OF_BAND") {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("retrieve still pending", func(t *testing.T) {
		_, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return failResult(23) }
			r.w.retrieve = func(*world, int, string) CAResult { return pendingResult(23) }
		})
		if a.Outcome != BlockedPKI {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("retrieve budget exhausted", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.e.Pace.RetrieveBackoff = func(int) time.Duration { return 30 * time.Minute }
			r.w.submit = func(*world, string) CAResult { return failResult(25) }
			r.w.retrieve = func(*world, int, string) CAResult { return failResult(0) }
		})
		if a.Outcome != CAUnknown || r.w.calls["retrieve"] != 3 || r.w.calls["submit"] != 1 {
			t.Fatalf("%+v calls=%v", a, r.w.calls)
		}
	})
	t.Run("validation fails", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) { r.w.validate = errors.New("SAN mismatch") })
		if a.Outcome != Inconclusive || r.w.calls["install"] != 0 {
			t.Fatalf("%+v install=%d", a, r.w.calls["install"])
		}
	})
}

// The retrieve budget and schedule are durable: restarts do not reset them.
func TestRetrieveBudgetSurvivesRestart(t *testing.T) {
	r := newRig(t)
	r.e.Pace.RetrieveBackoff = func(int) time.Duration { return time.Hour }
	r.w.submit = func(*world, string) CAResult { return failResult(26) }
	r.w.retrieve = func(*world, int, string) CAResult { return failResult(0) }
	r.start(t)
	for range 4 {
		if _, err := r.e.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// Submitted with retrieve 1 done; the next one is not due for an hour.
	a := r.j.state.Attempts["a1"]
	if a.State != AttemptSubmitted || a.Retrieves != 1 {
		t.Fatalf("%+v", a)
	}
	restarted := r.e // a new broker: same journal, no memory
	if _, err := restarted.Step(ctx); !errors.Is(err, ErrRetrieveNotDue) {
		t.Fatalf("retrieve before backoff: %v", err)
	}
	r.clock = r.clock.Add(-24 * time.Hour) // clock moved backwards
	if _, err := restarted.Step(ctx); !errors.Is(err, ErrRetrieveNotDue) {
		t.Fatalf("backward clock shortened the wait: %v", err)
	}
	if r.w.calls["retrieve"] != 1 {
		t.Fatalf("retrieves: %d", r.w.calls["retrieve"])
	}
	// Past every deadline the restarted broker spends only what is left of
	// the original budget (RetrieveMax 3), then closes CA_UNKNOWN.
	for i := 0; ; i++ {
		if i == 200 {
			t.Fatal("attempt did not settle")
		}
		_, err := restarted.Step(ctx)
		if errors.Is(err, ErrNoOpenAttempt) {
			break
		}
		if errors.Is(err, ErrRetrieveNotDue) {
			r.clock = r.clock.Add(time.Hour)
			continue
		}
		if err != nil && !errors.Is(err, ErrCleanupIncomplete) {
			t.Fatal(err)
		}
	}
	a = r.j.state.Attempts["a1"]
	if a.Outcome != CAUnknown || a.Retrieves != 3 || r.w.calls["retrieve"] != 3 || r.w.calls["submit"] != 1 {
		t.Fatalf("%+v calls=%v", a, r.w.calls)
	}
}

// A key is adopted only from a create result that was recorded.
func TestPrepareNeverAdopts(t *testing.T) {
	t.Run("create result lost", func(t *testing.T) {
		r := newRig(t)
		r.w.quiesce = map[Phase]bool{PhaseCreate: true}
		r.start(t)
		if _, err := r.e.Step(ctx); !errors.Is(err, ErrQuiescence) {
			t.Fatal(err)
		}
		a := r.drive(t)
		if a.Outcome != Abandoned || a.SPKI != "" || r.w.calls["create"] != 1 || r.w.calls["submit"] != 0 {
			t.Fatalf("%+v calls=%v", a, r.w.calls)
		}
		plan := r.j.state.Cleanups[a.ID]
		checkMatrix(t, plan, r.w)
		if r.w.key == nil || len(r.w.deleted) != 0 || plan.Complete {
			t.Fatalf("lost create: key=%t deleted=%v complete=%t", r.w.key != nil, r.w.deleted, plan.Complete)
		}
		if k := plan.Items[0]; k.Artifact.Kind != Key || !k.Unidentified || k.Result != Retained {
			t.Fatalf("key item: %+v", k)
		}
	})
	t.Run("name already in use", func(t *testing.T) {
		foreign := newKey(t)
		r, a := outcomeOf(t, func(r *enrollRig) { r.w.key = foreign })
		if a.Outcome != Inconclusive || a.SPKI != "" || r.w.calls["submit"] != 0 {
			t.Fatalf("%+v", a)
		}
		if r.w.key != foreign || len(r.w.deleted) != 0 {
			t.Fatal("the existing key was touched")
		}
		checkMatrix(t, r.j.state.Cleanups[a.ID], r.w)
	})
	t.Run("create failed", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) { r.w.createErr = errors.New("NTE_PERM") })
		if a.Outcome != Abandoned || len(r.w.deleted) != 0 {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("key replaced before submit", func(t *testing.T) {
		r := newRig(t)
		r.start(t)
		r.stepUntil(t, csrReady)
		r.w.key = newKey(t)
		a := r.drive(t)
		if a.Outcome != Inconclusive || r.w.calls["submit"] != 0 || len(r.w.deleted) != 0 {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("key unopenable before the CSR", func(t *testing.T) {
		r := newRig(t)
		r.start(t)
		r.stepUntil(t, func(a Attempt) bool { return a.State == AttemptKeyReady })
		r.w.key = nil
		a := r.drive(t)
		if a.Outcome != Inconclusive || r.w.calls["csr"] != 0 || r.w.calls["submit"] != 0 {
			t.Fatalf("%+v calls=%v", a, r.w.calls)
		}
	})
	t.Run("CSR changed before submit", func(t *testing.T) {
		r := newRig(t)
		r.start(t)
		r.stepUntil(t, csrReady)
		r.w.files[csrFile] = []byte("other")
		if a := r.drive(t); a.Outcome != Inconclusive || r.w.calls["submit"] != 0 {
			t.Fatalf("%+v", a)
		}
	})
}

// Uncertain quiescence stops the step; recovery after the Quiescer never
// replays: a lost create is never adopted, a lost submit becomes CA_UNKNOWN
// even with a RequestId, an install is decided by the binding check.
func TestUncertainQuiescencePerPhase(t *testing.T) {
	for phase, want := range map[Phase]Outcome{
		PhaseCreate: Abandoned, PhaseSubmit: CAUnknown, PhaseRetrieve: Accepted, PhaseInstall: Accepted,
	} {
		t.Run(string(phase), func(t *testing.T) {
			r := newRig(t)
			r.w.quiesce = map[Phase]bool{phase: true}
			if phase == PhaseRetrieve {
				r.w.submit = func(*world, string) CAResult { return failResult(27) }
			}
			r.start(t)
			a := r.drive(t)
			if a.Outcome != want {
				t.Fatalf("outcome %s (%s), want %s", a.Outcome, a.Reason, want)
			}
			if phase != PhaseRetrieve && r.w.calls[string(phase)] != 1 {
				t.Fatalf("%s ran %d times", phase, r.w.calls[string(phase)])
			}
		})
	}
	// Without a Quiescer the latch holds until an administrator resolves it.
	r := newRig(t)
	r.e.Guard.Recovery = nil
	r.w.quiesce = map[Phase]bool{PhaseSubmit: true}
	r.start(t)
	for range 3 {
		r.e.Step(ctx)
	}
	if _, err := r.e.Step(ctx); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("step under latch: %v", err)
	}
	seq := r.j.state.Operation.Sequence
	if err := testResolver(r.j).ResolveOperation(ctx, seq, adminStatement); err != nil {
		t.Fatal(err)
	}
	if a := r.drive(t); a.Outcome != CAUnknown || r.w.calls["submit"] != 1 {
		t.Fatalf("%+v", a)
	}
}

// Install is never repeated; only the binding check on the
// certificate re-read from My proves it. An unproven install leaves the certificate item.
func TestInstallRecoveryNeverRepeats(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(r *enrollRig, certHash string)
		want   Outcome
	}{
		"bound exactly":         {func(*enrollRig, string) {}, Accepted},
		"bound to another key":  {func(r *enrollRig, h string) { r.w.my[h] = spkiOfKey(t, newKey(t)) }, Inconclusive},
		"missing":               {func(r *enrollRig, h string) { delete(r.w.my, h) }, Inconclusive},
		"binding check failing": {func(r *enrollRig, _ string) { r.w.bindErr = errors.New("NTE_BAD_PUBLIC_KEY") }, Inconclusive},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.w.quiesce = map[Phase]bool{PhaseInstall: true}
			r.start(t)
			for {
				_, err := r.e.Step(ctx)
				if errors.Is(err, ErrQuiescence) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			tc.mutate(r, sha256Hex(r.w.cert))
			a := r.drive(t)
			if a.Outcome != tc.want || r.w.calls["install"] != 1 {
				t.Fatalf("%+v install=%d", a, r.w.calls["install"])
			}
			if a.Outcome == Accepted {
				return
			}
			plan := r.j.state.Cleanups[a.ID]
			checkMatrix(t, plan, r.w)
			last := plan.Items[len(plan.Items)-1]
			if last.Artifact.Kind != Certificate || last.Artifact.Hash != a.CertHash || last.Result != Retained {
				t.Fatalf("certificate item: %+v", last)
			}
		})
	}
}

func TestReconstructionRetrieve(t *testing.T) {
	setup := func(r *enrollRig, same bool) {
		r.start(t)
		for r.j.state.Attempts["a1"].State != AttemptIssued {
			if _, err := r.e.Step(ctx); err != nil {
				t.Fatal(err)
			}
		}
		delete(r.w.files, issuedCertFile)
		if !same {
			r.w.cert = []byte("another certificate")
		}
	}
	r := newRig(t)
	setup(r, true)
	if a := r.drive(t); a.Outcome != Accepted || a.CertFile != "retrieve-1.cer" || !a.Reconstructed {
		t.Fatalf("%+v", a)
	}
	r = newRig(t)
	setup(r, false)
	if a := r.drive(t); a.Outcome != Inconclusive || r.w.calls["install"] != 0 {
		t.Fatalf("%+v", a)
	}
}

func TestStartRefusals(t *testing.T) {
	r := newRig(t)
	r.start(t)
	other := testParams
	other.ID, other.Container = "a2", "c2"
	if _, err := r.e.Start(ctx, other); !errors.Is(err, ErrAttemptOpen) {
		t.Fatalf("second open attempt: %v", err)
	}
	r.drive(t)
	reused := testParams
	reused.ID = "a3"
	if _, err := r.e.Start(ctx, reused); err == nil {
		t.Fatal("key container reused")
	}
	latchCleanup(t, r.j, "latched")
	if _, err := r.e.Start(ctx, other); !errors.Is(err, ErrUncertainCleanup) {
		t.Fatalf("start under latch: %v", err)
	}
}

func TestStartPacing(t *testing.T) {
	r := newRig(t)
	r.e.Pace = PacePolicy{MinInterval: time.Hour, Window: 24 * time.Hour, MaxPerWindow: 2,
		Backoff: func(n int) time.Duration { return time.Duration(n) * 2 * time.Hour }, RetrieveMax: 1}
	r.w.submit = func(*world, string) CAResult { return deniedResult(30) }
	next := func(i int) Params {
		p := testParams
		p.ID, p.Container = fmt.Sprintf("p%d", i), fmt.Sprintf("c%d", i)
		return p
	}
	if _, err := r.e.Start(ctx, next(1)); err != nil {
		t.Fatal(err)
	}
	r.drive(t)
	// Denied: backoff 2h from closure; min interval 1h.
	r.clock = r.clock.Add(90 * time.Minute)
	if _, err := r.e.Start(ctx, next(2)); !errors.Is(err, ErrPaced) {
		t.Fatalf("backoff ignored: %v", err)
	}
	r.clock = r.clock.Add(-48 * time.Hour) // clock moved backwards
	if _, err := r.e.Start(ctx, next(2)); !errors.Is(err, ErrPaced) {
		t.Fatalf("backward clock shortened backoff: %v", err)
	}
	r.clock = compactT0.Add(3 * time.Hour)
	if _, err := r.e.Start(ctx, next(2)); err != nil {
		t.Fatal(err)
	}
	r.drive(t)
	r.clock = compactT0.Add(10 * time.Hour)
	if _, err := r.e.Start(ctx, next(3)); !errors.Is(err, ErrPaced) {
		t.Fatalf("window limit ignored: %v", err)
	}
}

// reopenWritable opens a plain journal file again, as a restarted broker would.
func reopenWritable(t *testing.T, path string) *FileJournal {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	j := &FileJournal{file: f, state: emptyState(), token: make(chan struct{}, 1), unpin: func() {}}
	j.token <- struct{}{}
	if err := j.readFrames(); err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func fileEnrollment(j *FileJournal, w *world, clock *time.Time, pace PacePolicy) Enrollment {
	return Enrollment{Journal: j, Guard: ProcessGuard{Journal: j}, Deleter: w, Requests: w, Keys: w, Stores: w,
		Validate: func(context.Context, []byte, Attempt) error { return nil },
		Pace:     pace, Now: func() time.Time { return *clock }}
}

// An active pacing window survives compaction and a reopen of the file.
func TestPacingSurvivesCompaction(t *testing.T) {
	dir := t.TempDir()
	j := plainJournal(t, filepath.Join(dir, "journal"))
	j.replace = (&plainReplace{dir: dir}).replace
	clock := compactT0
	pace := PacePolicy{Window: 24 * time.Hour, MaxPerWindow: 2, RetrieveMax: 1}
	run := func(e Enrollment, id, container string) error {
		p := testParams
		p.ID, p.Container = id, container
		if _, err := e.Start(ctx, p); err != nil {
			return err
		}
		for {
			if _, err := e.Step(ctx); errors.Is(err, ErrNoOpenAttempt) {
				return nil
			} else if err != nil {
				t.Fatal(err)
			}
		}
	}
	e := fileEnrollment(j, newWorld(t), &clock, pace)
	if err := run(e, "a1", "c1"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Hour)
	if err := run(fileEnrollment(j, newWorld(t), &clock, pace), "a2", "c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Compact(ctx, CompactOptions{}); err != nil {
		t.Fatal(err)
	}
	path := j.file.Name()
	j.Close()
	reopened := reopenWritable(t, path)
	if p := reopened.state.Pace; p == nil || p.WindowCount != 2 || !p.WindowStart.Equal(compactT0) {
		t.Fatalf("pacing after compaction and reopen: %+v", p)
	}
	clock = compactT0.Add(10 * time.Hour)
	e = fileEnrollment(reopened, newWorld(t), &clock, pace)
	if err := run(e, "a3", "c3"); !errors.Is(err, ErrPaced) {
		t.Fatalf("active window lost by compaction: %v", err)
	}
	clock = compactT0.Add(25 * time.Hour)
	if err := run(e, "a3", "c3"); err != nil {
		t.Fatalf("new window refused: %v", err)
	}
	if reopened.state.Attempts["a1"].Outcome != Accepted || reopened.state.Pace.WindowCount != 1 {
		t.Fatalf("after the new window: %+v", reopened.state.Pace)
	}
}

// A quiescence statement or an acknowledgment never unblocks Start: only a
// decision about the attempt's own RequestId, with evidence, does.
func TestResolveAttemptRequiresDecision(t *testing.T) {
	r, a := outcomeOf(t, func(r *enrollRig) {
		r.w.submit = func(*world, string) CAResult { return pendingResult(31) }
	})
	other := testParams
	other.ID, other.Container = "a2", "c2"
	res := testResolver(r.j)
	decision := AttemptResolution{Actor: `EXAMPLE\pki`, Decision: DecisionCADenied, RequestID: 31,
		Reason: "denied in the CA console", Evidence: "CA request 31, ticket 77"}
	without := func(f func(*AttemptResolution)) AttemptResolution { d := decision; f(&d); return d }
	for name, bad := range map[string]AttemptResolution{
		"reboot statement": {Actor: adminStatement.Actor, Reason: adminStatement.Reason, Evidence: adminStatement.Evidence, RequestID: 31},
		"no evidence":      without(func(d *AttemptResolution) { d.Evidence = "" }),
		"other RequestId":  without(func(d *AttemptResolution) { d.RequestID = 32 }),
		"no RequestId":     without(func(d *AttemptResolution) { d.RequestID = 0 }),
		"artifacts only":   without(func(d *AttemptResolution) { d.Decision = DecisionArtifactsSettled }),
	} {
		if err := res.ResolveAttempt(ctx, a.ID, bad); err == nil {
			t.Fatalf("%s accepted as a resolution", name)
		}
		if _, err := r.e.Start(ctx, other); !errors.Is(err, ErrAttemptBlocked) {
			t.Fatalf("%s: start not blocked: %v", name, err)
		}
	}
	if err := res.ResolveAttempt(ctx, "missing", decision); !errors.Is(err, ErrNothingToResolve) {
		t.Fatal(err)
	}
	if err := res.ResolveAttempt(ctx, a.ID, decision); err != nil {
		t.Fatal(err)
	}
	if err := res.ResolveAttempt(ctx, a.ID, decision); err != nil {
		t.Fatalf("repeat: %v", err)
	}
	if err := res.ResolveAttempt(ctx, a.ID, without(func(d *AttemptResolution) { d.Decision = DecisionCARemoved })); !errors.Is(err, ErrNothingToResolve) {
		t.Fatalf("second decision: %v", err)
	}
	if got := r.j.state.Attempts[a.ID]; got.Outcome != BlockedPKI || got.Resolution == nil || got.Resolution.Decision != DecisionCADenied {
		t.Fatalf("resolution reopened or lost: %+v", got)
	}
	if _, err := r.e.Start(ctx, other); err != nil {
		t.Fatalf("start after resolution: %v", err)
	}
}

func TestAbortBeforeSubmit(t *testing.T) {
	r := newRig(t)
	r.start(t)
	for a := r.j.state.Attempts["a1"]; !csrReady(a); a = r.j.state.Attempts["a1"] {
		if _, err := r.e.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	a, err := r.e.Abort(ctx, "operator")
	if err != nil || a.Outcome != Aborted {
		t.Fatalf("%+v %v", a, err)
	}
	r.drive(t)
	plan := r.j.state.Cleanups["a1"]
	checkMatrix(t, plan, r.w)
	if !plan.Complete || r.w.calls["submit"] != 0 {
		t.Fatalf("abort: %+v submit=%d", plan, r.w.calls["submit"])
	}
	if _, _, err := r.e.Report(ctx, "a1"); err != nil {
		t.Fatal(err)
	}
}

func TestJournalRejectsForgedAttempts(t *testing.T) {
	r := newRig(t)
	r.start(t)
	for a := r.j.state.Attempts["a1"]; !csrReady(a); a = r.j.state.Attempts["a1"] {
		if _, err := r.e.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	prev := cloneState(r.j.state)
	edit := func(f func(a *Attempt)) func(*State) {
		return func(s *State) { a := s.Attempts["a1"]; f(&a); s.Attempts["a1"] = a }
	}
	for name, mutate := range map[string]func(*State){
		"identity changed": edit(func(a *Attempt) { a.TargetSID = "S-1-5-80-9" }),
		"hash changed":     edit(func(a *Attempt) { a.CSRHash = hashB }),
		"skipped edge":     edit(func(a *Attempt) { a.State, a.CertHash = AttemptIssued, hashA }),
		"public key changed": edit(func(a *Attempt) {
			a.PublicKey = append([]byte(nil), a.PublicKey...)
			a.PublicKey[len(a.PublicKey)-1] ^= 1
		}),
		"public key without its SPKI": edit(func(a *Attempt) { a.SPKI = hashB }),
		"key identity dropped":        edit(func(a *Attempt) { a.SPKI, a.PublicKey = "", nil }),
		"terminal without plan": edit(func(a *Attempt) {
			a.State, a.Outcome = AttemptDone, CAUnknown
		}),
		"launch without operation": edit(func(a *Attempt) { a.Launch = &Launch{Phase: PhaseSubmit, Seq: 99} }),
		"removed":                  func(s *State) { delete(s.Attempts, "a1") },
		"second open attempt": func(s *State) {
			b := s.Attempts["a1"]
			b.ID, b.Container, b.State = "b", "cb", AttemptPrepare
			b.CSRHash, b.SPKI, b.PublicKey = "", "", nil
			s.Attempts["b"] = b
		},
		"accepted without certificate": edit(func(a *Attempt) { a.State, a.Outcome = AttemptDone, Accepted }),
	} {
		next := cloneState(prev)
		mutate(&next)
		next.Revision++
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	r.drive(t)
	done := cloneState(r.j.state)
	next := cloneState(done)
	a := next.Attempts["a1"]
	a.State, a.Outcome = AttemptIssued, ""
	next.Attempts["a1"] = a
	next.Revision++
	if err := validateState(next, done); err == nil {
		t.Error("terminal attempt reopened")
	}
}

// Abort applies the journal-wide barrier before reading any evidence: under
// another unfinished operation or an uncertain cleanup it reads no files and
// changes nothing.
func TestAbortRespectsJournalBarrier(t *testing.T) {
	for name, latch := range map[string]func(t *testing.T, r *enrollRig){
		"unfinished operation": func(t *testing.T, r *enrollRig) {
			g := ProcessGuard{Journal: r.j}
			err := g.Run(ctx, "other", nil, func() error { return fmt.Errorf("%w: lost", ErrQuiescence) })
			if !errors.Is(err, ErrQuiescence) {
				t.Fatal(err)
			}
		},
		"uncertain cleanup": func(t *testing.T, r *enrollRig) { latchCleanup(t, r.j, "latched") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.start(t)
			for a := r.j.state.Attempts["a1"]; !csrReady(a); a = r.j.state.Attempts["a1"] {
				if _, err := r.e.Step(ctx); err != nil {
					t.Fatal(err)
				}
			}
			latch(t, r)
			before, files := cloneState(r.j.state), r.w.calls["files"]
			if _, err := r.e.Abort(ctx, "operator"); !errors.Is(err, ErrQuiescence) {
				t.Fatalf("abort under latch: %v", err)
			}
			if r.w.calls["files"] != files || r.j.state.Revision != before.Revision ||
				!csrReady(r.j.state.Attempts["a1"]) || len(r.w.deleted) != 0 {
				t.Fatalf("abort under latch had effects: files=%d state=%+v", r.w.calls["files"]-files, r.j.state.Attempts["a1"])
			}
		})
	}
}

// Two concurrent Starts: exactly one attempt is recorded.
func TestConcurrentStart(t *testing.T) {
	r := newRig(t)
	errs := make(chan error, 2)
	for i := range 2 {
		p := testParams
		p.ID, p.Container = fmt.Sprintf("c%d", i), fmt.Sprintf("container-%d", i)
		go func() { _, err := r.e.Start(ctx, p); errs <- err }()
	}
	var ok, open int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrAttemptOpen):
			open++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || open != 1 || len(r.j.state.Attempts) != 1 || r.j.state.Pace.WindowCount != 1 {
		t.Fatalf("concurrent starts: ok=%d open=%d attempts=%d", ok, open, len(r.j.state.Attempts))
	}
}

// An unlistable attempt directory: every expected file is listed by name as
// unidentified, retained items included, and the plan closes incomplete. The
// report survives a reopen of the journal file.
func TestInventoryKeepsUncertainty(t *testing.T) {
	for _, tc := range []struct {
		name    string
		submit  func(*world, string) CAResult
		outcome Outcome
	}{
		{"denied", func(*world, string) CAResult { return deniedResult(13) }, Denied},
		{"pending", func(*world, string) CAResult { return pendingResult(14) }, BlockedPKI},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			j := plainJournal(t, filepath.Join(dir, "journal"))
			w := newWorld(t)
			w.submit = func(w *world, file string) CAResult {
				w.filesErr = errors.New("ERROR_ACCESS_DENIED listing the attempt directory")
				return tc.submit(w, file)
			}
			clock := compactT0
			e := fileEnrollment(j, w, &clock, PacePolicy{RetrieveMax: 1})
			if _, err := e.Start(ctx, testParams); err != nil {
				t.Fatal(err)
			}
			for {
				_, err := e.Step(ctx)
				if errors.Is(err, ErrNoOpenAttempt) {
					break
				}
				if err != nil && !errors.Is(err, ErrCleanupIncomplete) {
					t.Fatal(err)
				}
			}
			s := reopenPlain(t, filepath.Join(dir, "journal"))
			a, plan := s.Attempts["a1"], s.Cleanups["a1"]
			if a.Outcome != tc.outcome || !plan.Terminal || plan.Complete {
				t.Fatalf("after reopen: %s terminal=%t complete=%t", a.Outcome, plan.Terminal, plan.Complete)
			}
			byName := map[string]CleanupItem{}
			for _, it := range plan.Items {
				byName[it.Artifact.Name] = it
			}
			for _, name := range []string{csrFile, issuedCertFile} {
				it, ok := byName[name]
				if !ok || !it.Unidentified || it.Artifact.Hash != "" {
					t.Fatalf("%s missing or identified: %+v", name, it)
				}
				want := NotOwned
				if it.Keep {
					want = Retained
				}
				if it.Result != want {
					t.Fatalf("%s: %s, want %s", name, it.Result, want)
				}
			}
			if !byName[csrFile].Keep || tc.outcome == Denied && byName["key"].Result != Deleted {
				t.Fatalf("matrix: %+v", plan.Items)
			}
			checkMatrix(t, plan, w)
		})
	}
}

// An unreadable My store after -accept gives INCONCLUSIVE, never a repeat.
func TestAcceptBindingUnreadable(t *testing.T) {
	r, a := outcomeOf(t, func(r *enrollRig) { r.w.bindErr = errors.New("store busy") })
	if a.Outcome != Inconclusive || r.w.calls["install"] != 1 {
		t.Fatalf("%+v install=%d", a, r.w.calls["install"])
	}
}

// A reconstruction retrieve that reports another RequestId is INCONCLUSIVE,
// with zero accept.
func TestReconstructionRequestIDConflict(t *testing.T) {
	r := newRig(t)
	r.start(t)
	for r.j.state.Attempts["a1"].State != AttemptIssued {
		if _, err := r.e.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	delete(r.w.files, issuedCertFile)
	r.w.retrieve = func(w *world, _ int, file string) CAResult { return w.issue(file, 99) }
	if a := r.drive(t); a.Outcome != Inconclusive || r.w.calls["install"] != 0 || a.RequestID != 21 {
		t.Fatalf("%+v install=%d", a, r.w.calls["install"])
	}
}

// Launch records cannot be dropped, forged or outlived, and a checkpoint is
// checked for every property a single frame can prove.
func TestJournalRejectsForgedLaunches(t *testing.T) {
	r := newRig(t)
	r.w.quiesce = map[Phase]bool{PhaseSubmit: true}
	r.start(t)
	for {
		_, err := r.e.Step(ctx)
		if errors.Is(err, ErrQuiescence) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	launched := cloneState(r.j.state) // NORMALIZED, submit launch, operation unfinished
	if l := launched.Attempts["a1"].Launch; l == nil || l.Phase != PhaseSubmit || launched.Operation.Quiescent {
		t.Fatalf("setup: %+v", launched.Attempts["a1"])
	}
	quiet := cloneState(launched)
	quiet.Operation.Quiescent = true
	quiet.Revision++
	if err := validateState(quiet, launched); err != nil {
		t.Fatalf("quiescence acknowledgment rejected: %v", err)
	}
	edit := func(base State, f func(s *State, a *Attempt)) func() (State, State) {
		return func() (State, State) {
			next := cloneState(base)
			a := next.Attempts["a1"]
			f(&next, &a)
			next.Attempts["a1"] = a
			next.Revision++
			return next, base
		}
	}
	for name, forge := range map[string]func() (State, State){
		"submit launch dropped in place": edit(quiet, func(_ *State, a *Attempt) { a.Launch = nil }),
		"launch consumed before quiescence": edit(launched, func(_ *State, a *Attempt) {
			a.Launch, a.State, a.Disposition, a.CertFile = nil, AttemptSubmitted, DispositionIssued, issuedCertFile
		}),
		"new operation while launch pending": edit(quiet, func(s *State, _ *Attempt) {
			s.Operation = &Operation{Sequence: s.Operation.Sequence + 1, Name: "other"}
		}),
		"launch of another phase":                edit(quiet, func(_ *State, a *Attempt) { a.Launch.Phase = PhaseInstall }),
		"RequestId recorded with launch pending": edit(quiet, func(_ *State, a *Attempt) { a.RequestID = 21 }),
		"disposition recorded with launch pending": edit(quiet, func(_ *State, a *Attempt) {
			a.Disposition, a.CertFile = DispositionIssued, issuedCertFile
		}),
		"advanced with launch pending": edit(quiet, func(_ *State, a *Attempt) {
			a.State, a.Disposition, a.CertFile = AttemptSubmitted, DispositionIssued, issuedCertFile
		}),
	} {
		next, prev := forge()
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// From NORMALIZED without a launch.
	n := newRig(t)
	n.start(t)
	for a := n.j.state.Attempts["a1"]; !csrReady(a); a = n.j.state.Attempts["a1"] {
		if _, err := n.e.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	norm := cloneState(n.j.state)
	newOp := func(name, id string) func(s *State, a *Attempt) {
		return func(s *State, a *Attempt) {
			seq := s.Operation.Sequence + 1
			s.Operation = &Operation{Sequence: seq, Name: name, Arguments: []string{id}}
			a.Launch = &Launch{Phase: PhaseSubmit, Seq: seq}
		}
	}
	if next, prev := edit(norm, newOp("enroll-submit", "a1"))(); validateState(next, prev) != nil {
		t.Fatalf("genuine submit launch rejected: %v", validateState(next, prev))
	}
	for name, forge := range map[string]func() (State, State){
		"launch with another operation name": edit(norm, newOp("enroll-install", "a1")),
		"launch for another attempt":         edit(norm, newOp("enroll-submit", "b")),
		"launch of a past operation": edit(norm, func(s *State, a *Attempt) {
			a.Launch = &Launch{Phase: PhaseSubmit, Seq: s.Operation.Sequence}
		}),
		"RequestId written with the launch": edit(norm, func(s *State, a *Attempt) {
			newOp("enroll-submit", "a1")(s, a)
			a.RequestID = 21
		}),
		"disposition written with the launch": edit(norm, func(s *State, a *Attempt) {
			newOp("enroll-submit", "a1")(s, a)
			a.Disposition = DispositionIssued
		}),
		"retrieve budget without launch": edit(norm, func(_ *State, a *Attempt) { a.Retrieves++ }),
		"submitted without submit launch": edit(norm, func(_ *State, a *Attempt) {
			a.State, a.Disposition, a.CertFile = AttemptSubmitted, DispositionIssued, issuedCertFile
		}),
	} {
		next, prev := forge()
		if err := validateState(next, prev); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The window count never decreases while the window is unchanged.
	two, one := *norm.Pace, *norm.Pace
	two.WindowCount, one.WindowCount = 2, 1
	if err := validatePace(&one, &two, false); err == nil {
		t.Error("window count decreased in the same window")
	}

	// Checkpoints: what a frame proves without its predecessor.
	checkpoint := func(base State, f func(s *State)) State {
		s := cloneState(base)
		f(&s)
		s.Compaction = &Compaction{Revision: s.Revision, At: compactT0}
		return s
	}
	for name, s := range map[string]State{
		"open attempt":   checkpoint(norm, func(*State) {}),
		"pending launch": checkpoint(quiet, func(*State) {}),
	} {
		if err := validateState(s, emptyState()); err != nil {
			t.Fatalf("valid checkpoint %s rejected: %v", name, err)
		}
	}
	for name, s := range map[string]State{
		"launch without operation": checkpoint(quiet, func(s *State) { s.Operation = nil }),
		"launch of a past operation": checkpoint(quiet, func(s *State) {
			s.Operation = &Operation{Sequence: s.Operation.Sequence + 1, Name: "other", Quiescent: true}
		}),
		"shared key container": checkpoint(norm, func(s *State) {
			b := s.Attempts["a1"]
			b.ID, b.State, b.Outcome, b.Launch = "b", AttemptDone, Aborted, nil
			s.Attempts["b"] = b
			s.Cleanups["b"] = Cleanup{ID: "b", Outcome: Aborted, Items: []CleanupItem{
				{Artifact: Artifact{Kind: File, Name: "x"}, Unidentified: true, Result: NotOwned}}}
		}),
		"terminal without plan": checkpoint(norm, func(s *State) {
			a := s.Attempts["a1"]
			a.State, a.Outcome = AttemptDone, Aborted
			s.Attempts["a1"] = a
		}),
		"pacing removed":       checkpoint(norm, func(s *State) { s.Pace = nil }),
		"attempt after clock":  checkpoint(norm, func(s *State) { s.Pace.MaxSeen = compactT0.Add(-time.Hour) }),
		"window without count": checkpoint(norm, func(s *State) { s.Pace.WindowCount = 0 }),
	} {
		if err := validateState(s, emptyState()); err == nil {
			t.Errorf("checkpoint %s: accepted", name)
		}
	}
}

// A terminal record is frozen: its only change is the first resolution, judged
// against the RequestId the attempt acquired, never one added afterwards.
func TestTerminalAttemptFrozen(t *testing.T) {
	r, a := outcomeOf(t, func(r *enrollRig) {
		r.w.submit = func(*world, string) CAResult { return pendingResult(0) }
	})
	if a.Outcome != BlockedPKI || a.RequestID != 0 {
		t.Fatalf("setup: %+v", a)
	}
	done := cloneState(r.j.state)
	resolve := func(id int, f func(a *Attempt)) State {
		next := cloneState(done)
		at := next.Attempts["a1"]
		f(&at)
		at.Resolution = &AttemptResolution{Actor: `EXAMPLE\pki`, Decision: DecisionCADenied, RequestID: id,
			Reason: "denied", Evidence: "CA row", At: resolvedAt}
		next.Attempts["a1"] = at
		next.Revision++
		return next
	}
	if err := validateState(resolve(0, func(*Attempt) {}), done); err != nil {
		t.Fatalf("first resolution on the acquired identity rejected: %v", err)
	}
	for name, next := range map[string]State{
		"RequestId acquired after DONE":  resolve(31, func(a *Attempt) { a.RequestID = 31 }),
		"certificate hash after DONE":    resolve(0, func(a *Attempt) { a.CertHash = hashA }),
		"disposition changed after DONE": resolve(0, func(a *Attempt) { a.Disposition = DispositionIssued }),
	} {
		if err := validateState(next, done); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := testResolver(r.j).ResolveAttempt(ctx, "a1", AttemptResolution{Actor: `EXAMPLE\pki`,
		Decision: DecisionCADenied, RequestID: 31, Reason: "denied", Evidence: "CA row"}); err == nil {
		t.Fatal("resolution naming a RequestId the attempt never acquired")
	}
}

// Files returning a partial list together with an error: one item per name,
// every one unidentified, nothing deleted by name.
func TestInventoryPartialListing(t *testing.T) {
	r, a := outcomeOf(t, func(r *enrollRig) {
		r.w.submit = func(w *world, file string) CAResult {
			w.filesErr, w.filesPartial = errors.New("listing interrupted"), true
			return deniedResult(13)
		}
	})
	plan := r.j.state.Cleanups[a.ID]
	if a.Outcome != Denied || plan.Complete {
		t.Fatalf("%s complete=%t", a.Outcome, plan.Complete)
	}
	seen := map[string]int{}
	for _, it := range plan.Items {
		if it.Artifact.Kind != File {
			continue
		}
		seen[it.Artifact.Name]++
		if !it.Unidentified || it.Artifact.Hash != "" || it.Result == Deleted {
			t.Fatalf("partial listing gave an identified item: %+v", it)
		}
	}
	for _, name := range []string{csrFile, issuedCertFile} {
		if seen[name] != 1 {
			t.Fatalf("%s appears %d times", name, seen[name])
		}
	}
	for art := range r.w.deleted {
		if art.Kind == File {
			t.Fatalf("file deleted from a partial listing: %+v", art)
		}
	}
	checkMatrix(t, plan, r.w)
}

// While a launch awaits reconciliation another guard operation is refused
// before its effect with ErrBrokerBusy, already by the run that acknowledges
// quiescence.
func TestBrokerBusyWhileLaunchPending(t *testing.T) {
	r := newRig(t)
	r.w.quiesce = map[Phase]bool{PhaseSubmit: true}
	r.start(t)
	for {
		_, err := r.e.Step(ctx)
		if errors.Is(err, ErrQuiescence) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	g := r.e.Guard
	ran := false
	effect := func() error { ran = true; return nil }
	if err := g.Run(ctx, "other", nil, effect); !errors.Is(err, ErrInterrupted) || !errors.Is(err, ErrBrokerBusy) || ran {
		t.Fatalf("first run must acknowledge quiescence and name the busy journal: %v ran=%t", err, ran)
	}
	if err := g.Run(ctx, "other", nil, effect); !errors.Is(err, ErrBrokerBusy) || ran {
		t.Fatalf("run with a pending launch: %v ran=%t", err, ran)
	}
	if a := r.drive(t); a.Outcome != CAUnknown || r.w.calls["submit"] != 1 {
		t.Fatalf("%+v", a)
	}
	if err := g.Run(ctx, "other", nil, effect); err != nil || !ran {
		t.Fatalf("run after reconciliation: %v", err)
	}
}

// reloadFails fails every Load after its first Save, as a disk that turns
// unreadable right after the quiescence acknowledgment is written.
type reloadFails struct {
	Transaction
	saved bool
}

func (t *reloadFails) Load() (State, error) {
	if t.saved {
		return State{}, errors.New("injected reload failure")
	}
	return t.Transaction.Load()
}

func (t *reloadFails) Save(s State) error {
	t.saved = true
	return t.Transaction.Save(s)
}

// The run that acknowledges quiescence of a pending launch decides on the
// state settle saved, without reloading: a failing reload cannot hide
// ErrInterrupted or ErrBrokerBusy.
func TestBrokerBusySurvivesReloadFailure(t *testing.T) {
	r := newRig(t)
	r.w.quiesce = map[Phase]bool{PhaseSubmit: true}
	r.start(t)
	for {
		_, err := r.e.Step(ctx)
		if errors.Is(err, ErrQuiescence) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	ran := false
	err := r.j.WithLock(ctx, func(tx Transaction) error {
		return r.e.Guard.RunIn(ctx, &reloadFails{Transaction: tx}, "other", nil, nil,
			func() error { ran = true; return nil })
	})
	if !errors.Is(err, ErrInterrupted) || !errors.Is(err, ErrBrokerBusy) || ran {
		t.Fatalf("recovery with a failing reload: %v ran=%t", err, ran)
	}
	if op := r.j.state.Operation; op == nil || !op.Quiescent {
		t.Fatalf("quiescence not acknowledged: %+v", op)
	}
}

// CA_UNKNOWN is a barrier. Without a RequestId only an
// explicit risk acceptance resolves it; with one, a CA decision about it does.
func TestCAUnknownIsABarrier(t *testing.T) {
	other := testParams
	other.ID, other.Container = "a2", "c2"
	decision := func(d AttemptDecision, id int) AttemptResolution {
		return AttemptResolution{Actor: `EXAMPLE\operator`, Decision: d, RequestID: id,
			Reason: "reviewed with the PKI contact", Evidence: "ticket 90"}
	}
	t.Run("without RequestId", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return failResult(0) }
		})
		if a.Outcome != CAUnknown || a.RequestID != 0 {
			t.Fatalf("setup: %+v", a)
		}
		if _, err := r.e.Start(ctx, other); !errors.Is(err, ErrAttemptBlocked) {
			t.Fatalf("new attempt after CA_UNKNOWN: %v", err)
		}
		res := testResolver(r.j)
		for _, d := range []AttemptDecision{DecisionCARemoved, DecisionCADenied, DecisionArtifactsSettled} {
			if err := res.ResolveAttempt(ctx, a.ID, decision(d, 0)); err == nil {
				t.Fatalf("%s accepted for CA_UNKNOWN without RequestId", d)
			}
		}
		if err := res.ResolveAttempt(ctx, a.ID, decision(DecisionRiskAccepted, 0)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.e.Start(ctx, other); err != nil {
			t.Fatalf("start after risk acceptance: %v", err)
		}
	})
	t.Run("with RequestId", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return failResult(50) }
			r.w.retrieve = func(*world, int, string) CAResult { return failResult(0) }
		})
		if a.Outcome != CAUnknown || a.RequestID != 50 {
			t.Fatalf("setup: %+v", a)
		}
		if err := testResolver(r.j).ResolveAttempt(ctx, a.ID, decision(DecisionCADenied, 50)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.e.Start(ctx, other); err != nil {
			t.Fatalf("start after the CA decision: %v", err)
		}
	})
	t.Run("risk acceptance only for CA_UNKNOWN", func(t *testing.T) {
		r, a := outcomeOf(t, func(r *enrollRig) {
			r.w.submit = func(*world, string) CAResult { return pendingResult(51) }
		})
		if err := testResolver(r.j).ResolveAttempt(ctx, a.ID, decision(DecisionRiskAccepted, 51)); err == nil {
			t.Fatal("risk acceptance resolved a pending request")
		}
	})
}

// An out-of-band issuance is sticky: a later record cannot drop it.
func TestOutOfBandIsNeverCleared(t *testing.T) {
	r := newRig(t)
	r.e.Pace.RetrieveBackoff = func(int) time.Duration { return time.Hour }
	r.w.submit = func(*world, string) CAResult { return CAResult{Disposition: DispIssuedOutOfBand, RequestID: 60} }
	r.start(t)
	r.stepUntil(t, func(a Attempt) bool { return a.State == AttemptSubmitted })
	prev := cloneState(r.j.state)
	if !prev.Attempts["a1"].OutOfBand {
		t.Fatalf("setup: %+v", prev.Attempts["a1"])
	}
	next := cloneState(prev)
	a := next.Attempts["a1"]
	a.OutOfBand = false
	next.Attempts["a1"] = a
	next.Revision++
	if err := validateState(next, prev); err == nil {
		t.Fatal("out-of-band flag cleared")
	}
}

// Abort at KEY_READY, before the CSR exists: the key is ours and is deleted
// with its recorded public key.
func TestAbortBeforeCSR(t *testing.T) {
	r := newRig(t)
	r.start(t)
	r.stepUntil(t, func(a Attempt) bool { return a.State == AttemptKeyReady })
	if _, err := r.e.Abort(ctx, "operator"); err != nil {
		t.Fatal(err)
	}
	r.drive(t)
	plan := r.j.state.Cleanups["a1"]
	checkMatrix(t, plan, r.w)
	if k := plan.Items[0]; k.Result != Deleted || k.Artifact.PublicKey == "" || r.w.key != nil {
		t.Fatalf("key item: %+v", k)
	}
	if r.w.calls["csr"] != 0 || r.w.calls["submit"] != 0 {
		t.Fatalf("calls: %v", r.w.calls)
	}
}

// A schema 1 journal (certreq machine) is refused with its version, never
// migrated.
func TestSchemaOneJournalRefused(t *testing.T) {
	old := emptyState()
	old.Schema, old.Revision = 1, 1
	frame, err := encodeFrame(old)
	if err != nil {
		t.Fatal(err)
	}
	_, err = readFrame(bytes.NewReader(frame), emptyState())
	if err == nil || !strings.Contains(err.Error(), "schema 1") {
		t.Fatalf("schema 1 frame: %v", err)
	}
}

// Review of f87f666, finding 1: the key identity and the out-of-band flag are
// first recorded only by the launch result that proves them, and the public
// key must be a DER SubjectPublicKeyInfo.
func TestEvidenceOnlyFromResults(t *testing.T) {
	r := newRig(t)
	r.start(t)
	prepare := cloneState(r.j.state) // PREPARE, no launch
	pub := mustPKIX(t, newKey(t))
	edit := func(base State, f func(a *Attempt)) State {
		next := cloneState(base)
		a := next.Attempts["a1"]
		f(&a)
		next.Attempts["a1"] = a
		next.Revision++
		return next
	}
	for name, next := range map[string]State{
		"key identity at PREPARE without create": edit(prepare, func(a *Attempt) { a.PublicKey, a.SPKI = pub, sha256Hex(pub) }),
		"out of band at PREPARE":                 edit(prepare, func(a *Attempt) { a.OutOfBand = true }),
	} {
		if err := validateState(next, prepare); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	notDER := []byte("not a SubjectPublicKeyInfo")
	if err := validAttemptShape(edit(prepare, func(a *Attempt) {
		a.State, a.PublicKey, a.SPKI = AttemptKeyReady, notDER, sha256Hex(notDER)
	}).Attempts["a1"]); err == nil {
		t.Error("non-DER public key with a matching digest accepted")
	}
	r.stepUntil(t, csrReady)
	ready := cloneState(r.j.state)
	if err := validateState(edit(ready, func(a *Attempt) { a.OutOfBand = true }), ready); err == nil {
		t.Error("out of band at KEY_READY without a CA result accepted")
	}
}

// Finding 2: what ACCEPTED (and every post-submit outcome) proves holds in an
// isolated checkpoint too.
func TestTerminalCheckpointKeepsIdentity(t *testing.T) {
	r := newRig(t)
	r.start(t)
	r.drive(t)
	done := cloneState(r.j.state)
	if done.Attempts["a1"].Outcome != Accepted {
		t.Fatalf("setup: %+v", done.Attempts["a1"])
	}
	checkpoint := func(f func(a *Attempt)) State {
		s := cloneState(done)
		a := s.Attempts["a1"]
		f(&a)
		s.Attempts["a1"] = a
		s.Compaction = &Compaction{Revision: s.Revision, At: compactT0}
		return s
	}
	if err := validateState(checkpoint(func(*Attempt) {}), emptyState()); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	for name, s := range map[string]State{
		"key identity dropped": checkpoint(func(a *Attempt) { a.PublicKey, a.SPKI = nil, "" }),
		"CSR dropped":          checkpoint(func(a *Attempt) { a.CSRHash = "" }),
		"all dropped":          checkpoint(func(a *Attempt) { a.PublicKey, a.SPKI, a.CSRHash = nil, "", "" }),
	} {
		if err := validateState(s, emptyState()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Finding 3: a cleanup plan item cannot name a key other than the attempt's.
func TestPlanKeyIsTheAttemptKey(t *testing.T) {
	r := newRig(t)
	r.start(t)
	r.stepUntil(t, func(a Attempt) bool { return a.State == AttemptKeyReady })
	if _, err := r.e.Abort(ctx, "operator"); err != nil {
		t.Fatal(err)
	}
	aborted := cloneState(r.j.state) // terminal, plan intent not yet resumed
	other := mustPKIX(t, newKey(t))
	swap := func(f func(art *Artifact)) State {
		s := cloneState(aborted)
		plan := s.Cleanups["a1"]
		plan.Items = append([]CleanupItem(nil), plan.Items...)
		f(&plan.Items[0].Artifact)
		s.Cleanups["a1"] = plan
		s.Compaction = &Compaction{Revision: s.Revision, At: compactT0}
		return s
	}
	if err := validateState(swap(func(*Artifact) {}), emptyState()); err != nil {
		t.Fatalf("genuine plan rejected: %v", err)
	}
	for name, s := range map[string]State{
		"other key":       swap(func(k *Artifact) { k.SPKI, k.PublicKey = sha256Hex(other), base64.StdEncoding.EncodeToString(other) }),
		"other container": swap(func(k *Artifact) { k.Container = "another-container" }),
		"public key gone": swap(func(k *Artifact) { k.PublicKey = "" }),
	} {
		if err := validateState(s, emptyState()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Finding 4: an out-of-band disposition returned by the reconstruction
// retrieve is recorded, and nothing is installed.
func TestReconstructionOutOfBandRecorded(t *testing.T) {
	r := newRig(t)
	r.start(t)
	r.stepUntil(t, func(a Attempt) bool { return a.State == AttemptIssued })
	delete(r.w.files, issuedCertFile)
	r.w.retrieve = func(*world, int, string) CAResult {
		return CAResult{Disposition: DispIssuedOutOfBand, RequestID: 21}
	}
	a := r.drive(t)
	if a.Outcome != Inconclusive || !a.OutOfBand || !strings.Contains(a.Reason, "CR_DISP_ISSUED_OUT_OF_BAND") ||
		r.w.calls["install"] != 0 {
		t.Fatalf("%+v install=%d", a, r.w.calls["install"])
	}
}

// A failed flush of a launch intent stops the step before
// the effect, for every non-repeatable phase.
func TestFailedIntentFlushRunsNoEffect(t *testing.T) {
	for phase, until := range map[Phase]func(Attempt) bool{
		PhaseCreate:  func(a Attempt) bool { return a.State == AttemptPrepare },
		PhaseSubmit:  csrReady,
		PhaseInstall: func(a Attempt) bool { return a.State == AttemptIssued },
	} {
		t.Run(string(phase), func(t *testing.T) {
			r := newRig(t)
			r.start(t)
			r.stepUntil(t, until)
			r.j.failAt = r.j.saves + 1 // the next save is the launch intent
			if _, err := r.e.Step(ctx); !errors.Is(err, diskFailure) {
				t.Fatalf("step with a failed intent flush: %v", err)
			}
			if r.w.calls[string(phase)] != 0 {
				t.Fatalf("%s ran without a durable intent", phase)
			}
			if l := r.j.state.Attempts["a1"].Launch; l != nil {
				t.Fatalf("launch recorded: %+v", l)
			}
		})
	}
}

// A poisoned journal refuses every step before reading
// evidence or running an effect.
func TestPoisonedJournalStopsTheStep(t *testing.T) {
	dir := t.TempDir()
	j := plainJournal(t, filepath.Join(dir, "journal"))
	w := newWorld(t)
	clock := compactT0
	e := fileEnrollment(j, w, &clock, PacePolicy{RetrieveMax: 1})
	if _, err := e.Start(ctx, testParams); err != nil {
		t.Fatal(err)
	}
	j.poison = fmt.Errorf("%w: injected", ErrJournal)
	before := fmt.Sprint(w.calls)
	if _, err := e.Step(ctx); !errors.Is(err, ErrJournal) {
		t.Fatalf("step on a poisoned journal: %v", err)
	}
	if _, err := e.Abort(ctx, "operator"); !errors.Is(err, ErrJournal) {
		t.Fatalf("abort on a poisoned journal: %v", err)
	}
	if fmt.Sprint(w.calls) != before {
		t.Fatalf("effects on a poisoned journal: %v", w.calls)
	}
}
