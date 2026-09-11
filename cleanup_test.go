package enterprise

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

type fakeStore struct {
	certs   map[[32]byte][]byte
	kpi     map[[32]byte]keyProvInfo
	deleted []string
	findErr error
	keyErr  error
	delErr  error
}

func (f *fakeStore) FindLeafBySHA256(fp [32]byte) ([]byte, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	der, ok := f.certs[fp]
	if !ok {
		return nil, errCertNotFound
	}
	return der, nil
}

func (f *fakeStore) KeyProvInfo(fp [32]byte) (keyProvInfo, error) {
	if f.keyErr != nil {
		return keyProvInfo{}, f.keyErr
	}
	if _, ok := f.certs[fp]; !ok {
		return keyProvInfo{}, errCertNotFound
	}
	return f.kpi[fp], nil
}

func (f *fakeStore) DeleteLeafBySHA256(fp [32]byte) error {
	if f.delErr != nil {
		return f.delErr
	}
	if _, ok := f.certs[fp]; !ok {
		return errCertNotFound
	}
	delete(f.certs, fp)
	f.deleted = append(f.deleted, hex.EncodeToString(fp[:]))
	return nil
}

type fakeKeyRemover struct {
	deleted []string
	err     error
}

func (f *fakeKeyRemover) DeleteCNGKey(_, container string) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, container)
	return nil
}

func testLeafAndInfo(t *testing.T) (*x509.Certificate, CleanupInfo, [32]byte) {
	t.Helper()
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	leaf := issueCert(t, leafTemplate(), root, rootKey, &key.PublicKey)
	info := cleanupInfoForCert(leaf)
	info.Provider = expectedCNGProvider
	info.ContainerName = "test-container"
	info.ProviderType = 0
	info.KeySpec = 0
	return leaf, info, sha256Sum(leaf.Raw)
}

func populatedStore(leaf *x509.Certificate) (*fakeStore, [32]byte) {
	fp := sha256Sum(leaf.Raw)
	return &fakeStore{
		certs: map[[32]byte][]byte{fp: leaf.Raw},
		kpi:   map[[32]byte]keyProvInfo{fp: {provider: expectedCNGProvider, containerName: "test-container"}},
	}, fp
}

func TestRunCleanup_Success(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	keys := &fakeKeyRemover{}

	if err := runCleanup(store, keys, info); err != nil {
		t.Fatalf("runCleanup: %v", err)
	}
	if len(store.deleted) != 1 {
		t.Fatalf("expected 1 cert deleted, got %v", store.deleted)
	}
	if len(keys.deleted) != 1 || keys.deleted[0] != "test-container" {
		t.Fatalf("expected key deleted, got %v", keys.deleted)
	}
}

func TestRunCleanup_CertAbsentKeyPresent(t *testing.T) {
	_, info, _ := testLeafAndInfo(t)
	store := &fakeStore{certs: map[[32]byte][]byte{}}
	keys := &fakeKeyRemover{}

	if err := runCleanup(store, keys, info); err != nil {
		t.Fatalf("runCleanup: %v", err)
	}
	if len(store.deleted) != 0 {
		t.Fatalf("certificate should not be deleted, got %v", store.deleted)
	}
	if len(keys.deleted) != 1 || keys.deleted[0] != "test-container" {
		t.Fatalf("expected orphan key deleted, got %v", keys.deleted)
	}
}

func TestRunCleanup_CertAbsentKeyAbsent(t *testing.T) {
	_, info, _ := testLeafAndInfo(t)
	store := &fakeStore{certs: map[[32]byte][]byte{}}
	keys := &fakeKeyRemover{err: errKeyNotFound}

	if err := runCleanup(store, keys, info); err != nil {
		t.Fatalf("runCleanup should be idempotent success, got %v", err)
	}
	if len(keys.deleted) != 0 {
		t.Fatalf("no key should be deleted, got %v", keys.deleted)
	}
}

func TestRunCleanup_CertAbsentNoKeyMetadata(t *testing.T) {
	_, info, _ := testLeafAndInfo(t)
	info.ContainerName = ""
	info.Provider = ""
	store := &fakeStore{certs: map[[32]byte][]byte{}}
	keys := &fakeKeyRemover{}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(keys.deleted) != 0 {
		t.Fatalf("orphan key must not be deleted without metadata, got %v", keys.deleted)
	}
}

func TestRunCleanup_CertPresentKeyMissing(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	keys := &fakeKeyRemover{err: errKeyNotFound}

	if err := runCleanup(store, keys, info); err != nil {
		t.Fatalf("runCleanup should succeed when key already absent, got %v", err)
	}
	if len(store.deleted) != 1 {
		t.Fatalf("certificate should still be deleted, got %v", store.deleted)
	}
}

func TestRunCleanup_SerialMismatch(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	keys := &fakeKeyRemover{}

	info.SerialNumber = "00deadbeef"
	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(store.deleted) != 0 || len(keys.deleted) != 0 {
		t.Fatalf("nothing should be deleted on mismatch")
	}
}

func TestRunCleanup_IssuerMismatch(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	keys := &fakeKeyRemover{}

	info.Issuer = "CN=Something Else"
	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(store.deleted) != 0 || len(keys.deleted) != 0 {
		t.Fatalf("nothing should be deleted on mismatch")
	}
}

func TestRunCleanup_SPKIMismatch(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	keys := &fakeKeyRemover{}

	info.SPKISHA256 = sha256Hex([]byte("not the spki"))
	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(store.deleted) != 0 || len(keys.deleted) != 0 {
		t.Fatalf("nothing should be deleted on mismatch")
	}
}

func TestRunCleanup_ProviderMismatch(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, fp := populatedStore(leaf)
	store.kpi[fp] = keyProvInfo{provider: "Microsoft Base Smart Card Crypto Provider", containerName: "test-container"}
	keys := &fakeKeyRemover{}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(store.deleted) != 0 || len(keys.deleted) != 0 {
		t.Fatalf("certificate must not be deleted when provider mismatches")
	}
}

func TestRunCleanup_ContainerMismatch(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, fp := populatedStore(leaf)
	store.kpi[fp] = keyProvInfo{provider: expectedCNGProvider, containerName: "some-other-container"}
	keys := &fakeKeyRemover{}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(store.deleted) != 0 || len(keys.deleted) != 0 {
		t.Fatalf("certificate must not be deleted when container mismatches")
	}
}

func TestRunCleanup_ProviderTypeMismatch(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, fp := populatedStore(leaf)
	store.kpi[fp] = keyProvInfo{provider: expectedCNGProvider, containerName: "test-container", providerType: 1}
	keys := &fakeKeyRemover{}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrOwnershipMismatch) {
		t.Fatalf("expected ErrOwnershipMismatch, got %v", err)
	}
	if len(store.deleted) != 0 || len(keys.deleted) != 0 {
		t.Fatalf("nothing should be deleted on provider type mismatch")
	}
}

func TestRunCleanup_StoreFindError(t *testing.T) {
	_, info, _ := testLeafAndInfo(t)
	store := &fakeStore{findErr: errors.New("boom")}
	keys := &fakeKeyRemover{}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("expected ErrCleanupFailed, got %v", err)
	}
}

func TestRunCleanup_DeleteCertError(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	store.delErr = errors.New("boom")
	keys := &fakeKeyRemover{}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("expected ErrCleanupFailed, got %v", err)
	}
	if len(keys.deleted) != 0 {
		t.Fatalf("key must not be deleted when certificate deletion fails")
	}
}

func TestRunCleanup_DeleteKeyError(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	store, _ := populatedStore(leaf)
	keys := &fakeKeyRemover{err: errors.New("boom")}

	err := runCleanup(store, keys, info)
	if !errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("expected ErrCleanupFailed, got %v", err)
	}
	if len(store.deleted) != 1 {
		t.Fatalf("certificate should still be deleted, got %v", store.deleted)
	}
}

func TestCleanupInfo_matches(t *testing.T) {
	leaf, info, _ := testLeafAndInfo(t)
	if !info.matches(leaf) {
		t.Fatal("matching metadata should match")
	}

	bad := info
	bad.SerialNumber = "00"
	if bad.matches(leaf) {
		t.Fatal("serial mismatch should not match")
	}
	bad = info
	bad.Issuer = "CN=nope"
	if bad.matches(leaf) {
		t.Fatal("issuer mismatch should not match")
	}
	bad = info
	bad.LeafSHA256 = strings.Repeat("00", 32)
	if bad.matches(leaf) {
		t.Fatal("leaf sha256 mismatch should not match")
	}
	bad = info
	bad.SPKISHA256 = sha256Hex([]byte("x"))
	if bad.matches(leaf) {
		t.Fatal("spki mismatch should not match")
	}
}

func TestCaptureCleanupInfo_Success(t *testing.T) {
	leaf, _, fp := testLeafAndInfo(t)
	store := &fakeStore{
		certs: map[[32]byte][]byte{fp: leaf.Raw},
		kpi:   map[[32]byte]keyProvInfo{fp: {provider: expectedCNGProvider, containerName: "c1"}},
	}
	p := &Provider{store: store}

	info, err := p.captureCleanupInfo(leaf, "c1")
	if err != nil {
		t.Fatalf("captureCleanupInfo: %v", err)
	}
	if info.Provider != expectedCNGProvider || info.ContainerName != "c1" {
		t.Fatalf("unexpected key info: %+v", info)
	}
	if info.LeafSHA256 != sha256Hex(leaf.Raw) {
		t.Fatalf("unexpected leaf fingerprint")
	}
}

func TestCaptureCleanupInfo_ProviderMismatch(t *testing.T) {
	leaf, _, fp := testLeafAndInfo(t)
	store := &fakeStore{
		certs: map[[32]byte][]byte{fp: leaf.Raw},
		kpi:   map[[32]byte]keyProvInfo{fp: {provider: "legacy", containerName: "c1"}},
	}
	p := &Provider{store: store}

	_, err := p.captureCleanupInfo(leaf, "c1")
	if !errors.Is(err, ErrEnrollmentIncomplete) {
		t.Fatalf("expected ErrEnrollmentIncomplete, got %v", err)
	}
}

func TestCaptureCleanupInfo_ContainerMismatch(t *testing.T) {
	leaf, _, fp := testLeafAndInfo(t)
	store := &fakeStore{
		certs: map[[32]byte][]byte{fp: leaf.Raw},
		kpi:   map[[32]byte]keyProvInfo{fp: {provider: expectedCNGProvider, containerName: "other-container"}},
	}
	p := &Provider{store: store}

	_, err := p.captureCleanupInfo(leaf, "c1")
	if !errors.Is(err, ErrEnrollmentIncomplete) {
		t.Fatalf("expected ErrEnrollmentIncomplete, got %v", err)
	}
}

func TestCaptureCleanupInfo_StoreError(t *testing.T) {
	leaf, _, _ := testLeafAndInfo(t)
	p := &Provider{store: &fakeStore{keyErr: errors.New("boom")}}

	_, err := p.captureCleanupInfo(leaf, "c1")
	if !errors.Is(err, ErrEnrollmentIncomplete) {
		t.Fatalf("expected ErrEnrollmentIncomplete, got %v", err)
	}
}
