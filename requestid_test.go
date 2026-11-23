package enterprise

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

const issuedSubmitStdout = "RequestId: 11\r\nRequestId: \"11\"\r\nCertificato recuperato(Emesso) Emesso\r\n"

func issuedProvider(t *testing.T, fr *fakeRunner) *Provider {
	t.Helper()
	root, rootKey := rootCA(t)
	fr.root, fr.rootKey = root, rootKey
	p := New(Config{CA: "ca1\\RootCA", Template: "WebServer"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.store = enrollStore{kpi: keyProvInfo{provider: expectedCNGProvider, containerName: testKeyContainer}}
	p.keys = &fakeKeyRemover{}
	pinKeyContainer(p)
	return p
}

// An issued request that printed a RequestId carries CA + RequestID on success.
func TestEnroll_IssuedSuccessReportsRequestID(t *testing.T) {
	fr := &fakeRunner{t: t, key: mustRSAKey(t), submitStdout: issuedSubmitStdout}
	res, err := issuedProvider(t, fr).Enroll(context.Background())
	if err != nil || res.Status != StatusSuccess {
		t.Fatalf("want success, got status=%s err=%v", res.Status, err)
	}
	if res.CA != "ca1\\RootCA" || res.RequestID != 11 {
		t.Fatalf("request identity on success: CA=%q RequestID=%d", res.CA, res.RequestID)
	}
}

// A failure after an issued submit (here: -accept) keeps CA + RequestID.
func TestEnroll_AcceptFailureAfterIssueReportsRequestID(t *testing.T) {
	fr := &fakeRunner{t: t, key: mustRSAKey(t), submitStdout: issuedSubmitStdout,
		acceptErr: errors.New("accept failed"), acceptCode: int(uint32(0x80092004))}
	res, err := issuedProvider(t, fr).Enroll(context.Background())
	if res.Status != StatusEnrollmentFailed || !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("want enrollment-failed, got status=%s err=%v", res.Status, err)
	}
	if res.CA != "ca1\\RootCA" || res.RequestID != 11 {
		t.Fatalf("request identity after accept failure: CA=%q RequestID=%d", res.CA, res.RequestID)
	}
}

// blockSubmitRunner runs -new through the fake and refuses -submit as the
// process guard does, before any process starts.
type blockSubmitRunner struct{ fake *fakeRunner }

func (r blockSubmitRunner) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	if slices.Contains(args, "-submit") {
		return "", "", -1, &blockedError{cause: errors.Join(ErrProcessQuiescence, lifecycle.ErrInterrupted)}
	}
	return r.fake.Run(ctx, name, args...)
}

// A submit that never ran reports no CA or RequestID.
func TestEnroll_BlockedSubmitReportsNoRequestIdentity(t *testing.T) {
	fr := &fakeRunner{t: t, key: mustRSAKey(t)}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = blockSubmitRunner{fake: fr}
	p.keys = &fakeKeyRemover{}
	res, err := p.Enroll(context.Background())
	if !errors.Is(err, ErrOperationBlocked) {
		t.Fatalf("want blocked, got %v", err)
	}
	if res.CA != "" || res.RequestID != 0 {
		t.Fatalf("blocked submit must not report a request: CA=%q RequestID=%d", res.CA, res.RequestID)
	}
}

// A pending request whose ID cannot be read still carries CA, RequestID 0.
func TestEnroll_PendingWithoutRequestIDKeepsCA(t *testing.T) {
	fr := &fakeRunner{t: t, key: mustRSAKey(t), submitPending: true, submitStdout: "Richiesta di certificato in sospeso\r\n"}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	keys := &fakeKeyRemover{}
	p.keys = keys
	res, err := p.Enroll(context.Background())
	if !errors.Is(err, ErrEnrollmentPending) || res.CA != "ca1\\RootCA" || res.RequestID != 0 {
		t.Fatalf("want pending with CA and RequestID 0, got CA=%q RequestID=%d err=%v", res.CA, res.RequestID, err)
	}
	if len(keys.deleted) != 0 {
		t.Fatal("pending key deleted")
	}
}
