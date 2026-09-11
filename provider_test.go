package enterprise

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
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
			return "", "submit failed", failCode(f.submitCode), f.submitErr
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
			chain = []byte(base64.StdEncoding.EncodeToString(buildPKCS7(f.t, leaf)))
		}
		if err := os.WriteFile(chainPath, chain, 0o600); err != nil {
			return "", "", 1, err
		}
		return "", "", 0, nil
	case slices.Contains(args, "-accept"):
		if f.acceptErr != nil {
			return "", "accept failed", failCode(f.acceptCode), f.acceptErr
		}
		return "", "", 0, nil
	}
	return "", "", 0, nil
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
	if !strings.Contains(fr.calls[1], "-config ca1\\RootCA") {
		t.Fatalf("second call should carry -config: %s", fr.calls[1])
	}
	if !strings.Contains(fr.calls[2], "-accept -machine -q") {
		t.Fatalf("third call should be -accept: %s", fr.calls[2])
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

func TestEnroll_SubmitUnavailable(t *testing.T) {
	key := mustRSAKey(t)
	fr := &fakeRunner{t: t, key: key, submitErr: errors.New("CA unreachable"), submitCode: int(uint32(0x800706BA))}
	p := New(Config{CA: "ca1\\RootCA"})
	p.runner = fr
	p.keys = &fakeKeyRemover{}

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
