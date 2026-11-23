package enterprise

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/keppin-oss/cng/windowscng"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

type ecSigner struct{ *ecdsa.PrivateKey }

func (ecSigner) Close() error { return nil }

// fakeKSP records the calls CNGKeys makes and returns scripted results.
type fakeKSP struct {
	key       *ecdsa.PrivateKey
	createErr error
	openErr   error
	deleteErr error
	calls     []string
	deleted   []byte
}

func (f *fakeKSP) CreateForService(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
	f.calls = append(f.calls, "create "+name+" "+p.SID())
	if f.createErr != nil {
		return nil, f.createErr
	}
	return ecSigner{f.key}, nil
}

func (f *fakeKSP) OpenForService(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
	f.calls = append(f.calls, "open "+name+" "+p.SID())
	if f.openErr != nil {
		return nil, f.openErr
	}
	return ecSigner{f.key}, nil
}

func (f *fakeKSP) DeleteForService(name string, p windowscng.ServicePolicy, spki []byte) error {
	f.calls = append(f.calls, "delete "+name+" "+p.SID())
	f.deleted = spki
	return f.deleteErr
}

func newTestKeys(t *testing.T) (*CNGKeys, *fakeKSP, lifecycle.Attempt) {
	t.Helper()
	keys, err := NewCNGKeys("KeppinEnterpriseTLS")
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ksp := &fakeKSP{key: k}
	keys.ops = ksp
	a := baseAttempt()
	a.TargetSID = keys.policy.SID()
	return keys, ksp, a
}

func TestCNGKeysCreateAndOpen(t *testing.T) {
	keys, ksp, a := newTestKeys(t)
	h, err := keys.Create(actx, a)
	if err != nil || h == nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := keys.Open(actx, a); err != nil {
		t.Fatal(err)
	}
	want := []string{"create " + a.Container + " " + a.TargetSID, "open " + a.Container + " " + a.TargetSID}
	if fmt.Sprint(ksp.calls) != fmt.Sprint(want) {
		t.Fatalf("calls %v", ksp.calls)
	}

	ksp.createErr = fmt.Errorf("%w: NTE_EXISTS", windowscng.ErrKeyExists)
	if _, err := keys.Create(actx, a); !errors.Is(err, lifecycle.ErrKeyExists) || !errors.Is(err, windowscng.ErrKeyExists) {
		t.Fatalf("existing name: %v", err)
	}
	ksp.createErr = windowscng.ErrPrivilegeRequired
	if _, err := keys.Create(actx, a); !errors.Is(err, windowscng.ErrPrivilegeRequired) || errors.Is(err, lifecycle.ErrKeyExists) {
		t.Fatalf("privilege: %v", err)
	}
}

// The adapter refuses, before any CNG call, an attempt for another service,
// another provider or without a container.
func TestCNGKeysRefusals(t *testing.T) {
	keys, ksp, a := newTestKeys(t)
	for name, mutate := range map[string]func(*lifecycle.Attempt){
		"other target":   func(a *lifecycle.Attempt) { a.TargetSID = "S-1-5-80-1-2-3-4-5" },
		"other provider": func(a *lifecycle.Attempt) { a.Provider = "Microsoft Platform Crypto Provider" },
		"no container":   func(a *lifecycle.Attempt) { a.Container = "" },
	} {
		b := a
		mutate(&b)
		if _, err := keys.Create(actx, b); err == nil {
			t.Errorf("%s: create accepted", name)
		}
		if _, err := keys.Open(actx, b); err == nil {
			t.Errorf("%s: open accepted", name)
		}
	}
	if len(ksp.calls) != 0 {
		t.Fatalf("CNG called for a refused attempt: %v", ksp.calls)
	}
	if _, err := (&CNGKeys{}).Create(actx, a); err == nil {
		t.Fatal("zero adapter accepted")
	}
}

func TestCNGKeysDelete(t *testing.T) {
	keys, ksp, a := newTestKeys(t)
	der, err := x509.MarshalPKIXPublicKey(ksp.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	art := lifecycle.Artifact{Kind: lifecycle.Key, Name: "key", Provider: a.Provider, Container: a.Container,
		SPKI: sha256Hex(der), PublicKey: base64.StdEncoding.EncodeToString(der)}
	if err := keys.Delete(actx, art); err != nil || !bytes.Equal(ksp.deleted, der) || len(ksp.calls) != 1 {
		t.Fatalf("delete: %v calls=%v", err, ksp.calls)
	}

	for name, tc := range map[string]struct {
		cngErr error
		want   error
	}{
		"not found":           {windowscng.ErrKeyNotFound, lifecycle.ErrNotFound},
		"verification failed": {windowscng.ErrDeleteVerificationFailed, lifecycle.ErrNotOwned},
		"policy mismatch":     {fmt.Errorf("%w: %w", windowscng.ErrDeleteVerificationFailed, windowscng.ErrPolicyMismatch), lifecycle.ErrNotOwned},
	} {
		ksp.deleteErr = tc.cngErr
		if err := keys.Delete(actx, art); !errors.Is(err, tc.want) || !errors.Is(err, tc.cngErr) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ksp.deleteErr = errors.New("NTE_INTERNAL_ERROR")
	if err := keys.Delete(actx, art); err == nil || errors.Is(err, lifecycle.ErrNotFound) || errors.Is(err, lifecycle.ErrNotOwned) {
		t.Fatalf("delete failure classified as absence or not owned: %v", err)
	}

	// Without a public key matching the SPKI nothing reaches CNG.
	ksp.calls = nil
	other := sha256Hex([]byte("other"))
	for name, bad := range map[string]lifecycle.Artifact{
		"no public key":      {Kind: lifecycle.Key, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: art.SPKI},
		"SPKI mismatch":      {Kind: lifecycle.Key, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: other, PublicKey: art.PublicKey},
		"not base64":         {Kind: lifecycle.Key, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: art.SPKI, PublicKey: "%%"},
		"not a public key":   {Kind: lifecycle.Key, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: sha256Hex([]byte("x")), PublicKey: base64.StdEncoding.EncodeToString([]byte("x"))},
		"other provider":     {Kind: lifecycle.Key, Name: "key", Provider: "other", Container: a.Container, SPKI: art.SPKI, PublicKey: art.PublicKey},
		"not a key artifact": {Kind: lifecycle.File, Name: "key", Provider: a.Provider, Container: a.Container, SPKI: art.SPKI, PublicKey: art.PublicKey},
	} {
		if err := keys.Delete(actx, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(ksp.calls) != 0 {
		t.Fatalf("CNG called for a refused artifact: %v", ksp.calls)
	}
}
