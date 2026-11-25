package enterprise

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/keppin-oss/cng/windowscng"

	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

// cngKeyOps is the subset of windowscng v0.5 that CNGKeys uses. It is typed on
// ServicePolicy, although windowscng accepts any KeyPolicy, so the adapter can
// only ever pass the configured service policy. Tests substitute an in-memory
// KSP.
type cngKeyOps interface {
	Create(name string, policy windowscng.ServicePolicy) (windowscng.Signer, error)
	Open(name string, policy windowscng.ServicePolicy) (windowscng.Signer, error)
	Delete(name string, policy windowscng.ServicePolicy, expectedSPKI []byte) error
}

type nativeKeyOps struct{}

func (nativeKeyOps) Create(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
	return windowscng.Create(name, p)
}

func (nativeKeyOps) Open(name string, p windowscng.ServicePolicy) (windowscng.Signer, error) {
	return windowscng.Open(name, p)
}

func (nativeKeyOps) Delete(name string, p windowscng.ServicePolicy, spki []byte) error {
	return windowscng.Delete(name, p, spki)
}

// CNGKeys implements lifecycle.KeyStore and the key part of the enrollment
// cleanup with cng v0.5. The policy is
// the ServicePolicy of the configured service; an attempt whose TargetSID is
// not that policy's SID, or whose provider is not the Microsoft Software KSP,
// is refused before any CNG call.
type CNGKeys struct {
	policy windowscng.ServicePolicy
	ops    cngKeyOps
}

// NewCNGKeys returns the key adapter for the Windows service serviceName.
func NewCNGKeys(serviceName string) (*CNGKeys, error) {
	p, err := windowscng.NewServicePolicy(serviceName)
	if err != nil {
		return nil, err
	}
	return &CNGKeys{policy: p, ops: nativeKeyOps{}}, nil
}

var (
	_ lifecycle.KeyStore = (*CNGKeys)(nil)
	_ lifecycle.Deleter  = (*CNGKeys)(nil)
)

func (k *CNGKeys) check(provider, container, targetSID string) error {
	if k == nil || k.ops == nil {
		return errors.New("cng key adapter not initialized")
	}
	if provider != expectedCNGProvider {
		return fmt.Errorf("provider %q is not %q", provider, expectedCNGProvider)
	}
	if container == "" {
		return errors.New("key container required")
	}
	if targetSID != "" && targetSID != k.policy.SID() {
		return fmt.Errorf("attempt target %s is not the configured service %s", targetSID, k.policy.SID())
	}
	return nil
}

// Create creates the attempt's key create-only. windowscng.ErrKeyExists maps
// to lifecycle.ErrKeyExists, keeping the cng error in the chain.
func (k *CNGKeys) Create(_ context.Context, a lifecycle.Attempt) (lifecycle.KeyHandle, error) {
	if err := k.check(a.Provider, a.Container, a.TargetSID); err != nil {
		return nil, err
	}
	s, err := k.ops.Create(a.Container, k.policy)
	if errors.Is(err, windowscng.ErrKeyExists) {
		return nil, fmt.Errorf("%w: %w", lifecycle.ErrKeyExists, err)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Open opens the attempt's key with the record's policy. An error is never
// proof of absence.
func (k *CNGKeys) Open(_ context.Context, a lifecycle.Attempt) (lifecycle.KeyHandle, error) {
	if err := k.check(a.Provider, a.Container, a.TargetSID); err != nil {
		return nil, err
	}
	s, err := k.ops.Open(a.Container, k.policy)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Delete deletes a key artifact with windowscng.Delete, which verifies policy
// and SPKI on the handle it deletes. The artifact must carry the DER public
// key whose SHA-256 is its SPKI. A missing key is NOT_FOUND_UNVERIFIED, a key
// that fails verification is SKIPPED_NOT_OWNED: in both cases nothing was
// deleted.
func (k *CNGKeys) Delete(_ context.Context, art lifecycle.Artifact) error {
	if art.Kind != lifecycle.Key {
		return fmt.Errorf("artifact kind %q is not a key", art.Kind)
	}
	if err := k.check(art.Provider, art.Container, ""); err != nil {
		return err
	}
	der, err := base64.StdEncoding.DecodeString(art.PublicKey)
	if err != nil || len(der) == 0 || sha256Hex(der) != art.SPKI {
		return fmt.Errorf("%w: key artifact without a public key matching its SPKI", lifecycle.ErrNotOwned)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return fmt.Errorf("%w: recorded public key unreadable: %v", lifecycle.ErrNotOwned, err)
	}
	err = k.ops.Delete(art.Container, k.policy, bytes.Clone(der))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windowscng.ErrKeyNotFound):
		return fmt.Errorf("%w: %w", lifecycle.ErrNotFound, err)
	case errors.Is(err, windowscng.ErrDeleteVerificationFailed), errors.Is(err, windowscng.ErrPolicyMismatch):
		return fmt.Errorf("%w: %w", lifecycle.ErrNotOwned, err)
	}
	return err
}

// TargetSID returns the per-service SID of the configured policy: the
// TargetSID an attempt must carry for this adapter.
func (k *CNGKeys) TargetSID() string { return k.policy.SID() }
