//go:build windows

package enterprise

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

var (
	procNCryptOpenStorageProvider = modNCrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = modNCrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptFinalizeKey         = modNCrypt.NewProc("NCryptFinalizeKey")
	procNCryptDeleteKey           = modNCrypt.NewProc("NCryptDeleteKey")
)

// userKey creates a persisted per-user ECDSA P-256 key in the Software KSP and
// removes it at the end of the test.
func userKey(t *testing.T, name string) *ecdsa.PublicKey {
	t.Helper()
	provName, _ := windows.UTF16PtrFromString(expectedCNGProvider)
	alg, _ := windows.UTF16PtrFromString("ECDSA_P256")
	kn, _ := windows.UTF16PtrFromString(name)
	var prov, key uintptr
	if r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&prov)), uintptr(unsafe.Pointer(provName)), 0); r != 0 {
		t.Fatalf("open provider: 0x%08X", uint32(r))
	}
	t.Cleanup(func() { procNCryptFreeObject.Call(prov) })
	if r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(alg)),
		uintptr(unsafe.Pointer(kn)), 0, 0); r != 0 {
		t.Fatalf("create key: 0x%08X", uint32(r))
	}
	if r, _, _ := procNCryptFinalizeKey.Call(key, 0); r != 0 {
		procNCryptDeleteKey.Call(key, 0)
		t.Fatalf("finalize key: 0x%08X", uint32(r))
	}
	pub, err := exportECCPublic(windows.Handle(key))
	if err != nil {
		procNCryptDeleteKey.Call(key, 0)
		t.Fatal(err)
	}
	t.Cleanup(func() { procNCryptDeleteKey.Call(key, 0) })
	return pub
}

// leafFor issues a certificate for pub, signed by a throwaway Go CA key.
func leafFor(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "keppin-store-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, ca)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func removeFromUserMy(t *testing.T, m MachineMy, certHash string) {
	store, err := m.open(false)
	if err != nil {
		t.Errorf("cleanup: open: %v", err)
		return
	}
	defer windows.CertCloseStore(store, 0)
	c, _, err := findBySHA256(store, certHash)
	if err != nil {
		return
	}
	// CertDeleteCertificateFromStore frees the context.
	if r, _, e := procCertDeleteCertificateFromStore.Call(uintptr(unsafe.Pointer(c))); r == 0 {
		t.Errorf("cleanup: delete certificate: %v", e)
	}
}

// TestMyStoreBindingLive runs Install and VerifyBinding against the current
// user's My store with a per-user key, which needs no elevation. It writes to
// the store and the KSP and removes both, so it runs only with
// KEPPIN_STORE_LIVE=1.
func TestMyStoreBindingLive(t *testing.T) {
	if os.Getenv("KEPPIN_STORE_LIVE") != "1" {
		t.Skip("set KEPPIN_STORE_LIVE=1 to run against CurrentUser\\My")
	}
	m := MachineMy{location: storeCurrentUser, keyFlags: 0}
	var b [8]byte
	_, _ = rand.Read(b[:])
	name := "keppin-store-test-" + hex.EncodeToString(b[:])
	pub := userKey(t, name)
	leaf := leafFor(t, pub)
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	a := lifecycle.Attempt{Provider: expectedCNGProvider, Container: name, CertHash: sha256Hex(leaf), SPKI: sha256Hex(spkiDER)}
	t.Cleanup(func() { removeFromUserMy(t, m, a.CertHash) })

	if err := m.Install(actx, a, leaf); err != nil {
		t.Fatalf("install: %v", err)
	}
	spki, err := m.VerifyBinding(actx, a)
	if err != nil || spki != a.SPKI {
		t.Fatalf("binding: %s %v", spki, err)
	}
	if err := m.Install(actx, a, leaf); err != nil {
		t.Fatalf("second install of the same certificate: %v", err)
	}

	// A certificate bound to the container but issued for another key fails
	// the comparison.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := leafFor(t, &other.PublicKey)
	b2 := a
	b2.CertHash = sha256Hex(wrong)
	t.Cleanup(func() { removeFromUserMy(t, m, b2.CertHash) })
	if err := m.Install(actx, b2, wrong); err != nil {
		t.Fatalf("install of the mismatched certificate: %v", err)
	}
	if _, err := m.VerifyBinding(actx, b2); err == nil {
		t.Fatal("certificate for another key reported as bound")
	}
	// Another container name in the attempt is not the binding.
	b3 := a
	b3.Container = name + "-other"
	if _, err := m.VerifyBinding(actx, b3); err == nil {
		t.Fatal("binding accepted for another container")
	}
}
