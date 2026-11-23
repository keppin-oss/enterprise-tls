package enterprise

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/keppin-oss/cng/windowscng"
)

type fakeRunner struct {
	t          *testing.T
	key        *rsa.PrivateKey
	root       *x509.Certificate
	rootKey    *rsa.PrivateKey
	leafTmpl   *x509.Certificate
	leafKey    *rsa.PrivateKey // overrides the key used for the issued leaf
	chainRaw   []byte          // overrides the chain file contents
	calls      []string
	newErr     error
	submitErr  error
	acceptErr  error
	newCode    int // exit code for a -new failure (default 1)
	submitCode int
	acceptCode int
	// submitPending makes -submit succeed without writing any output file, as
	// certreq does for a request left pending by the CA.
	submitPending bool
	submitStdout  string // stdout returned by -submit (success, pending or failure)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch {
	case slices.Contains(args, "-new"):
		if f.newErr != nil {
			return "", "new failed", failCode(f.newCode), f.newErr
		}
		reqPath := args[len(args)-1]
		csr := mustCSR(f.t, f.key)
		if err := os.WriteFile(reqPath, []byte(base64.StdEncoding.EncodeToString(csr)), 0o600); err != nil {
			return "", "", 1, err
		}
		return "", "", 0, nil
	case slices.Contains(args, "-submit"):
		if f.submitErr != nil {
			return f.submitStdout, "submit failed", failCode(f.submitCode), f.submitErr
		}
		if f.submitPending {
			return f.submitStdout, "", 0, nil
		}
		tmpl := f.leafTmpl
		if tmpl == nil {
			tmpl = leafTemplate()
		}
		leafKey := f.leafKey
		if leafKey == nil {
			leafKey = f.key
		}
		leaf := issueCert(f.t, tmpl, f.root, f.rootKey, &leafKey.PublicKey)
		certPath := args[len(args)-2]
		chainPath := args[len(args)-1]
		if err := os.WriteFile(certPath, []byte(base64.StdEncoding.EncodeToString(leaf.Raw)), 0o600); err != nil {
			return "", "", 1, err
		}
		chain := f.chainRaw
		if chain == nil {
			chain = certreqPEM(buildPKCS7(f.t, leaf))
		}
		if err := os.WriteFile(chainPath, chain, 0o600); err != nil {
			return "", "", 1, err
		}
		return f.submitStdout, "", 0, nil
	case slices.Contains(args, "-accept"):
		if f.acceptErr != nil {
			return "", "accept failed", failCode(f.acceptCode), f.acceptErr
		}
		return "", "", 0, nil
	}
	return "", "", 0, nil
}

// certreqPEM armors der the way certreq.exe -submit writes the chain file:
// PEM labelled "CERTIFICATE" with CRLF line endings.
func certreqPEM(der []byte) []byte {
	armored := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return bytes.ReplaceAll(armored, []byte("\n"), []byte("\r\n"))
}

// intermediateCA issues a CA certificate under root, for chains that need an
// intermediate.
func intermediateCA(t *testing.T, root *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := mustRSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return issueCert(t, tmpl, root, rootKey, &key.PublicKey), key
}

func failCode(c int) int {
	if c == 0 {
		return 1
	}
	return c
}

// enrollStore is a certStore seam for Enroll tests: it returns a fixed
// key-provider association for any fingerprint.
type enrollStore struct {
	kpi keyProvInfo
	err error
}

func (e enrollStore) FindLeafBySHA256([32]byte) ([]byte, error) { return nil, errCertNotFound }
func (e enrollStore) KeyProvInfo([32]byte) (keyProvInfo, error) { return e.kpi, e.err }
func (e enrollStore) DeleteLeafBySHA256([32]byte) error         { return nil }

const testKeyContainer = "keppin-enterprise-tls-test-0001"

// pinKeyContainer pins the deterministic key container for a test provider so
// the generated identity is predictable across the enrollment attempt.
func pinKeyContainer(p *Provider) {
	p.keyContainer = func() (string, error) { return testKeyContainer, nil }
}

func TestEnroll_Success(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey}

	p := New(Config{CA: "ca1\\RootCA", Template: "WebServer"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.store = enrollStore{kpi: keyProvInfo{provider: expectedCNGProvider, containerName: testKeyContainer}}
	p.keys = &fakeKeyRemover{}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	if res.Status != StatusSuccess {
		t.Fatalf("expected success, got %s", res.Status)
	}
	if res.Certificate == nil {
		t.Fatal("expected certificate")
	}
	if res.Thumbprint == "" {
		t.Fatal("expected thumbprint")
	}
	if res.KeyContainer != testKeyContainer {
		t.Fatalf("expected key container %q, got %q", testKeyContainer, res.KeyContainer)
	}
	if res.Cleanup == nil {
		t.Fatal("expected cleanup metadata")
	}
	if res.Cleanup.Provider != expectedCNGProvider || res.Cleanup.ContainerName != testKeyContainer {
		t.Fatalf("unexpected cleanup metadata: %+v", res.Cleanup)
	}
	if res.Cleanup.LeafSHA256 != sha256Hex(res.Certificate.Raw) {
		t.Fatal("cleanup leaf fingerprint does not match certificate")
	}
	if len(fr.calls) != 3 {
		t.Fatalf("expected 3 certreq calls, got %d: %v", len(fr.calls), fr.calls)
	}
	if !strings.Contains(fr.calls[0], "-new -machine -q") {
		t.Fatalf("first call should be -new: %s", fr.calls[0])
	}
	if !strings.Contains(fr.calls[1], "-submit -q -config ca1\\RootCA") {
		t.Fatalf("second call should be -submit with -config: %s", fr.calls[1])
	}
	// certreq.exe rejects -machine on -submit ("unexpected argument").
	if strings.Contains(fr.calls[1], "-machine") {
		t.Fatalf("-submit must not carry -machine: %s", fr.calls[1])
	}
	if !strings.Contains(fr.calls[2], "-accept -machine -q") {
		t.Fatalf("third call should be -accept: %s", fr.calls[2])
	}
}

// The leaf is issued by an intermediate that only the certreq-style PEM chain
// file carries: Enroll succeeds only if it reads that chain.
func TestEnroll_PEMChainSuppliesIntermediate(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	inter, interKey := intermediateCA(t, root, rootKey)
	fr := &fakeRunner{t: t, key: key, root: inter, rootKey: interKey, chainRaw: certreqPEM(buildPKCS7(t, inter))}

	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.store = enrollStore{kpi: keyProvInfo{provider: expectedCNGProvider, containerName: testKeyContainer}}
	p.keys = &fakeKeyRemover{}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err != nil {
		t.Fatalf("Enroll returned error: %v", err)
	}
	if res.Status != StatusSuccess {
		t.Fatalf("expected success, got %s", res.Status)
	}
}

// A PEM chain whose intermediate does not lead to a trusted root is rejected
// before -accept, and the key created for the attempt is removed.
func TestEnroll_PEMChainUntrusted(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	inter, interKey := intermediateCA(t, root, rootKey)
	otherRoot, _ := rootCA(t)
	fr := &fakeRunner{t: t, key: key, root: inter, rootKey: interKey, chainRaw: certreqPEM(buildPKCS7(t, inter))}

	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(otherRoot)
	p.store = enrollStore{kpi: keyProvInfo{provider: expectedCNGProvider, containerName: testKeyContainer}}
	keys := &fakeKeyRemover{}
	p.keys = keys
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	for _, c := range fr.calls {
		if strings.Contains(c, "-accept") {
			t.Fatalf("-accept must not run for an untrusted chain: %v", fr.calls)
		}
	}
	if res.KeyState != KeyStateRemoved || len(keys.deleted) != 1 || keys.deleted[0] != testKeyContainer {
		t.Fatalf("expected exact key %q removed, got state %s, deleted %v", testKeyContainer, res.KeyState, keys.deleted)
	}
}

// A chain file that breaks the PEM policy (here: a second block after a
// usable one) is invalid-certificate, not a partially read chain.
func TestEnroll_PEMChainTwoBlocks(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	inter, interKey := intermediateCA(t, root, rootKey)
	chain := append(certreqPEM(buildPKCS7(t, inter)), certreqPEM(buildPKCS7(t))...)
	fr := &fakeRunner{t: t, key: key, root: inter, rootKey: interKey, chainRaw: chain}

	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	// A fake store keeps the test off the native store even if a regression
	// lets the chain through to -accept and the key association lookup.
	p.store = enrollStore{kpi: keyProvInfo{provider: expectedCNGProvider, containerName: testKeyContainer}}
	keys := &fakeKeyRemover{}
	p.keys = keys
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate || !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected invalid-certificate, got %s (%v)", res.Status, err)
	}
	for _, c := range fr.calls {
		if strings.Contains(c, "-accept") {
			t.Fatalf("-accept must not run for a rejected chain file: %v", fr.calls)
		}
	}
	if res.KeyState != KeyStateRemoved || len(keys.deleted) != 1 || keys.deleted[0] != testKeyContainer {
		t.Fatalf("expected exact key %q removed, got state %s, deleted %v", testKeyContainer, res.KeyState, keys.deleted)
	}
}

func TestEnroll_CleanupMetadataFailure(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.store = enrollStore{err: errors.New("store read failed")}
	p.keys = &fakeKeyRemover{}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusEnrollmentIncomplete {
		t.Fatalf("expected enrollment-incomplete, got %s", res.Status)
	}
	if !errors.Is(err, ErrEnrollmentIncomplete) {
		t.Fatalf("expected ErrEnrollmentIncomplete, got %v", err)
	}
	if res.Certificate == nil {
		t.Fatal("certificate should still be returned so the caller can act on the orphan")
	}
	if res.KeyContainer != testKeyContainer {
		t.Fatalf("expected key container %q, got %q", testKeyContainer, res.KeyContainer)
	}
	if res.Cleanup == nil {
		t.Fatal("expected best-effort cleanup metadata for retry")
	}
	if res.Cleanup.ContainerName != testKeyContainer {
		t.Fatalf("expected retry cleanup to reference %q, got %q", testKeyContainer, res.Cleanup.ContainerName)
	}
}

func TestEnroll_NewFailureDoesNotDeleteKey(t *testing.T) {
	fr := &fakeRunner{t: t, newErr: errors.New("new failed")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	keys := &fakeKeyRemover{}
	p.keys = keys
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.KeyContainer != testKeyContainer {
		t.Fatalf("expected key container %q, got %q", testKeyContainer, res.KeyContainer)
	}
	if res.KeyState != KeyStateUnproven {
		t.Fatalf("expected KeyStateUnproven, got %s", res.KeyState)
	}
	if len(keys.deleted) != 0 {
		t.Fatalf("key must not be deleted when -new fails, got %v", keys.deleted)
	}
}

func TestEnroll_SubmitFailureCleansUpOwnedKey(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("submit failed")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	keys := &fakeKeyRemover{}
	p.keys = keys
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.KeyState != KeyStateRemoved {
		t.Fatalf("expected KeyStateRemoved, got %s", res.KeyState)
	}
	if res.KeyCleanupErr != nil {
		t.Fatalf("unexpected cleanup error: %v", res.KeyCleanupErr)
	}
	if len(keys.deleted) != 1 || keys.deleted[0] != testKeyContainer {
		t.Fatalf("expected exact key %q deleted, got %v", testKeyContainer, keys.deleted)
	}
}

// When the owned key cannot be removed, Result.KeyCleanupErr carries the native
// NCrypt cause: not-found or not accessible (NTE_BAD_KEYSET) is not removal.
func TestEnroll_KeyCleanupErrKeepsNativeCause(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("submit failed")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.keys = &fakeKeyRemover{err: fmt.Errorf("%w: %w", errKeyNotFound,
		&windowscng.NCryptError{Op: "NCryptOpenKey", Code: windowscng.NTEBadKeyset})}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.KeyState != KeyStatePresent {
		t.Fatalf("expected KeyStatePresent, got %s", res.KeyState)
	}
	if !errors.Is(res.KeyCleanupErr, errKeyNotFound) {
		t.Fatalf("expected errKeyNotFound in KeyCleanupErr, got %v", res.KeyCleanupErr)
	}
	var ne *windowscng.NCryptError
	if !errors.As(res.KeyCleanupErr, &ne) || ne.Code != windowscng.NTEBadKeyset {
		t.Fatalf("expected NCryptError NTE_BAD_KEYSET in KeyCleanupErr, got %v", res.KeyCleanupErr)
	}
}

func TestEnroll_ValidationFailureCleansUpOwnedKey(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	badTmpl := leafTemplate()
	badTmpl.DNSNames = []string{"server01.contoso.com"}
	badTmpl.IPAddresses = nil

	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, leafTmpl: badTmpl}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	keys := &fakeKeyRemover{}
	p.keys = keys
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	if res.KeyState != KeyStateRemoved {
		t.Fatalf("expected KeyStateRemoved, got %s", res.KeyState)
	}
	if len(keys.deleted) != 1 || keys.deleted[0] != testKeyContainer {
		t.Fatalf("expected exact key %q deleted, got %v", testKeyContainer, keys.deleted)
	}
}

func TestEnroll_AcceptFailureCleansUpOwnedKey(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, acceptErr: errors.New("accept failed")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	keys := &fakeKeyRemover{}
	p.keys = keys
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.KeyState != KeyStateRemoved {
		t.Fatalf("expected KeyStateRemoved, got %s", res.KeyState)
	}
	if len(keys.deleted) != 1 || keys.deleted[0] != testKeyContainer {
		t.Fatalf("expected exact key %q deleted, got %v", testKeyContainer, keys.deleted)
	}
}

func TestEnroll_CleanupFailureObservable(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("submit failed")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.keys = &fakeKeyRemover{err: errors.New("delete failed")}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.KeyState != KeyStatePresent {
		t.Fatalf("expected KeyStatePresent, got %s", res.KeyState)
	}
	if res.KeyCleanupErr == nil {
		t.Fatal("expected cleanup error to be observable")
	}
	if res.KeyContainer != testKeyContainer {
		t.Fatalf("expected key container %q for retry, got %q", testKeyContainer, res.KeyContainer)
	}
}

// errKeyNotFound means "not found or not accessible; nothing deleted", so the
// failure cleanup must not attest removal.
func TestEnroll_SubmitFailureKeyNotFoundIsNotRemoved(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("submit failed")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.keys = &fakeKeyRemover{err: errKeyNotFound}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.KeyState != KeyStatePresent {
		t.Fatalf("expected KeyStatePresent, got %s", res.KeyState)
	}
	if !errors.Is(res.KeyCleanupErr, errKeyNotFound) {
		t.Fatalf("expected KeyCleanupErr to preserve errKeyNotFound, got %v", res.KeyCleanupErr)
	}
	if res.KeyContainer != testKeyContainer {
		t.Fatalf("expected key container %q for retry, got %q", testKeyContainer, res.KeyContainer)
	}
}

func TestEnroll_ContainerMismatchFailsClosed(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	keys := &fakeKeyRemover{}
	p.keys = keys
	p.store = enrollStore{kpi: keyProvInfo{provider: expectedCNGProvider, containerName: "some-other-container"}}
	pinKeyContainer(p)

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusEnrollmentIncomplete {
		t.Fatalf("expected enrollment-incomplete, got %s", res.Status)
	}
	if !errors.Is(err, ErrEnrollmentIncomplete) {
		t.Fatalf("expected ErrEnrollmentIncomplete, got %v", err)
	}
	if len(keys.deleted) != 0 {
		t.Fatalf("key must not be deleted on association mismatch, got %v", keys.deleted)
	}
	if res.KeyState != KeyStatePresent {
		t.Fatalf("expected KeyStatePresent, got %s", res.KeyState)
	}
}

func TestEnroll_NotConfigured(t *testing.T) {
	p := New(Config{})
	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusNotConfigured {
		t.Fatalf("expected not-configured, got %s", res.Status)
	}
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestEnroll_ToolUnavailable(t *testing.T) {
	fr := &fakeRunner{t: t, newErr: exec.ErrNotFound}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusUnavailable {
		t.Fatalf("expected unavailable, got %s", res.Status)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

func TestEnroll_EnrollmentFailed(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("denied by policy")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusEnrollmentFailed {
		t.Fatalf("expected enrollment-failed, got %s", res.Status)
	}
	if !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_SubmitRPCDoesNotAuthorizeFallback(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("CA unreachable"), submitCode: int(uint32(0x800706BA))}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusEnrollmentFailed {
		t.Fatalf("expected enrollment-failed, got %s", res.Status)
	}
	if !errors.Is(err, ErrEnrollmentFailed) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected enrollment failure without fallback, got %v", err)
	}
}

func TestEnroll_NewReachabilityIsEnrollmentFailed(t *testing.T) {
	fr := &fakeRunner{t: t, newErr: errors.New("unreachable"), newCode: int(uint32(0x800706BA))}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusEnrollmentFailed {
		t.Fatalf("expected enrollment-failed, got %s", res.Status)
	}
	if !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_AcceptReachabilityIsEnrollmentFailed(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, acceptErr: errors.New("accept failed"), acceptCode: int(uint32(0x800706BA))}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusEnrollmentFailed {
		t.Fatalf("expected enrollment-failed, got %s", res.Status)
	}
	if !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_InvalidCertificate(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)
	badTmpl := leafTemplate()
	badTmpl.DNSNames = []string{"server01.contoso.com"}
	badTmpl.IPAddresses = nil

	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, leafTmpl: badTmpl}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestEnroll_KeyMismatch(t *testing.T) {
	key := mustRSAKey(t)
	otherKey := mustRSAKey(t)
	root, rootKey := rootCA(t)

	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, leafKey: otherKey}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestEnroll_UntrustedChain(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)

	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	// Trust a different root: the leaf (and its chain) will not verify.
	otherRoot, _ := rootCA(t)
	p.validateOpts.Roots = rootsPool(otherRoot)
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestEnroll_MalformedChain(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)

	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, chainRaw: []byte("not a pkcs7 blob")}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

func TestEnroll_ChainNoCertificates(t *testing.T) {
	key := mustRSAKey(t)
	root, rootKey := rootCA(t)

	// A well-formed SignedData chain with an empty certificate set.
	emptyChain := buildPKCS7(t)
	fr := &fakeRunner{t: t, key: key, root: root, rootKey: rootKey, chainRaw: emptyChain}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.validateOpts.Roots = rootsPool(root)
	p.keys = &fakeKeyRemover{}

	res, err := p.Enroll(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != StatusInvalidCertificate {
		t.Fatalf("expected invalid-certificate, got %s", res.Status)
	}
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}

// buildSignedDataDER builds the inner SignedData SEQUENCE (including its own
// SEQUENCE header) for the given certificates.
func buildSignedDataDER(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	var set bytes.Buffer
	for _, c := range certs {
		set.Write(c.Raw)
	}
	certField := append([]byte{0xA0}, asn1Len(set.Len())...)
	certField = append(certField, set.Bytes()...)

	encap := []byte{0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}
	digest := []byte{0x31, 0x00}
	signerInfos := []byte{0x31, 0x00}

	var sd bytes.Buffer
	sd.Write([]byte{0x02, 0x01, 0x01}) // version 1
	sd.Write(digest)
	sd.Write(encap)
	sd.Write(certField)
	sd.Write(signerInfos)

	sdSeq := append([]byte{0x30}, asn1Len(sd.Len())...)
	sdSeq = append(sdSeq, sd.Bytes()...)
	return sdSeq
}

// buildPKCS7 constructs a minimal PKCS#7 SignedData ContentInfo blob
// containing the given certificates, matching the certreq.exe
// "certchainfileout" format.
func buildPKCS7(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	sdSeq := buildSignedDataDER(t, certs...)
	return buildContentInfo(t, oidSignedDataDER, sdSeq)
}

// oidSignedDataDER and oidDataDER are the DER encodings of the SignedData and
// Data content-type OIDs respectively.
var (
	oidSignedDataDER = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02}
	oidDataDER       = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}
)

// buildContentInfo wraps an OID and an optional [0] EXPLICIT content in a
// ContentInfo SEQUENCE.
func buildContentInfo(t *testing.T, oid, content []byte) []byte {
	t.Helper()
	var ci bytes.Buffer
	ci.Write(oid)
	if len(content) > 0 {
		c := append([]byte{0xA0}, asn1Len(len(content))...)
		c = append(c, content...)
		ci.Write(c)
	}
	out := append([]byte{0x30}, asn1Len(ci.Len())...)
	out = append(out, ci.Bytes()...)
	return out
}

func asn1Len(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n & 0xFF)}, buf...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

func TestParsePKCS7Certificates(t *testing.T) {
	root, rootKey := rootCA(t)
	leafKey := mustRSAKey(t)
	leaf := issueCert(t, leafTemplate(), root, rootKey, &leafKey.PublicKey)
	blob := buildPKCS7(t, leaf)

	got, err := parsePKCS7Certificates(blob)
	if err != nil {
		t.Fatalf("parsePKCS7Certificates: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(got))
	}
	if !publicKeysEqual(got[0].PublicKey, leaf.PublicKey) {
		t.Fatal("public key mismatch")
	}
}

// certreq -submit output for a pending request, as observed on it-IT; the
// RequestId label is not localized.
const pendingSubmitStdout = "RequestId: 14\r\nRequestId: \"14\"\r\nRichiesta di certificato in sospeso: Accettato all'invio (0)\r\n"

// A pending request (submit exit 0, no certificate file) is not a failure:
// the key is retained, nothing is accepted, and CA + RequestId are reported.
func TestEnroll_PendingRetainsKeyAndReportsRequestID(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitPending: true, submitStdout: pendingSubmitStdout}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	keys := &fakeKeyRemover{}
	p.keys = keys

	res, err := p.Enroll(context.Background())
	if res.Status != StatusEnrollmentPending || !errors.Is(err, ErrEnrollmentPending) {
		t.Fatalf("want enrollment-pending, got status=%s err=%v", res.Status, err)
	}
	if errors.Is(err, ErrEnrollmentFailed) {
		t.Fatal("pending must not match ErrEnrollmentFailed")
	}
	if res.KeyState != KeyStateRetained || len(keys.deleted) != 0 {
		t.Fatalf("pending key must be retained, got state=%s deleted=%v", res.KeyState, keys.deleted)
	}
	if res.CA != "ca1\\RootCA" || res.RequestID != 14 || res.KeyContainer == "" {
		t.Fatalf("request identity: CA=%q RequestID=%d container=%q", res.CA, res.RequestID, res.KeyContainer)
	}
	for _, c := range fr.calls {
		if strings.Contains(c, "-accept") {
			t.Fatal("-accept invoked for a pending request")
		}
	}
	defer os.RemoveAll(res.ArtifactDirectory)
	if res.ArtifactDirectory == "" {
		t.Fatal("attempt files not retained for a pending request")
	}
	if _, err := os.Stat(filepath.Join(res.ArtifactDirectory, "request.req")); err != nil {
		t.Fatalf("request file not retained: %v", err)
	}
}

// A request denied by the CA keeps the failure path (exact key cleanup) and
// now carries CA + RequestId for the PKI report.
func TestEnroll_DeniedReportsRequestID(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("denied"), submitCode: int(uint32(0x80094012)),
		submitStdout: "RequestId: 13\r\nRequestId: \"13\"\r\nCertificato non emesso (Negato) Negato dal modulo criteri\r\n"}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	keys := &fakeKeyRemover{}
	p.keys = keys

	res, err := p.Enroll(context.Background())
	if res.Status != StatusEnrollmentFailed || !errors.Is(err, ErrEnrollmentFailed) || errors.Is(err, ErrEnrollmentPending) {
		t.Fatalf("want enrollment-failed, got status=%s err=%v", res.Status, err)
	}
	if res.CA != "ca1\\RootCA" || res.RequestID != 13 {
		t.Fatalf("request identity: CA=%q RequestID=%d", res.CA, res.RequestID)
	}
	if res.KeyState != KeyStateRemoved || len(keys.deleted) != 1 {
		t.Fatalf("denied: want owned key removed, got state=%s deleted=%v", res.KeyState, keys.deleted)
	}
}

func TestParseRequestID(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want int
	}{
		{pendingSubmitStdout, 14},
		{"RequestId: \"7\"\n", 7},
		{"  RequestId: 42  \r\n", 42},
		{"Certificato recuperato(Emesso) Emesso\r\n", 0},
		{"RequestId: abc\n", 0},
		{"RequestId: 0\n", 0},
		{"xRequestId: 5\n", 0},
		{"", 0},
		{"RequestId: 42", 42},                                      // last line without newline
		{"RequestId:\r\n42\r\n", 0},                                // ID on the next line is not accepted
		{"RequestId:\n\n42\n", 0},                                  // nor after a blank line
		{"RequestId: \"42\r\n", 0},                                 // unpaired opening quote
		{"RequestId: 42\"\r\n", 0},                                 // unpaired closing quote
		{"RequestId: 4 2\r\n", 0},                                  // embedded space
		{"RequestId: x\r\nRequestId: \"9\"\r\n", 9},                // first valid line wins
		{"Note\r\n RequestId:\t\"11\"\t\r\nRequestId: 12\r\n", 11}, // tabs, quoted, first match
	} {
		if got := parseRequestID(tt.in); got != tt.want {
			t.Errorf("parseRequestID(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
