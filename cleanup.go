package enterprise

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// expectedCNGProvider is the CNG key storage provider requested by the
// enrollment INF and therefore the only provider this module will remove keys
// from.
const expectedCNGProvider = "Microsoft Software Key Storage Provider"

// ErrCleanupFailed wraps any failure to complete cleanup of owned material.
var ErrCleanupFailed = errors.New("enterprise cleanup failed")

// ErrOwnershipMismatch indicates one or more ownership guards did not match the
// persisted enrollment metadata. Cleanup refuses to delete either artifact.
var ErrOwnershipMismatch = errors.New("ownership could not be verified; refusing to delete")

// errCertNotFound and errKeyNotFound are internal signals that an artifact is
// already absent, so cleanup can be treated as idempotent.
var (
	errCertNotFound = errors.New("certificate not found")
	errKeyNotFound  = errors.New("key not found")
)

// CleanupInfo is the enrollment metadata used to later remove the leaf
// certificate and its associated private key without broad discovery.
//
// Treat CleanupInfo as privileged input: Uninstall trusts the values it
// contains. Its provenance and integrity must be protected by the caller.
//
// The certificate-identity fields (Issuer, SerialNumber, LeafSHA256, SPKISHA256)
// are computed from the validated leaf. The key-association fields (Provider,
// ContainerName, ProviderType, KeySpec) are read from the installed
// certificate's CERT_KEY_PROV_INFO_PROP_ID.
type CleanupInfo struct {
	Issuer       string // RFC2253 string of the issuer name
	SerialNumber string // hex of the serial number (big-endian)
	LeafSHA256   string // hex SHA-256 of the leaf certificate DER
	SPKISHA256   string // hex SHA-256 of the SubjectPublicKeyInfo DER

	Provider      string // key storage provider name
	ContainerName string // key container name
	ProviderType  uint32
	KeySpec       uint32
}

// keyProvInfo is the CERT_KEY_PROV_INFO_PROP_ID content read from a stored
// certificate.
type keyProvInfo struct {
	provider      string
	containerName string
	providerType  uint32
	keySpec       uint32
}

// certStore abstracts the LocalMachine\My certificate-store operations needed
// for cleanup and metadata capture. Every operation re-resolves the target by
// exact SHA-256 fingerprint, so no stale handle can outlive a verification.
type certStore interface {
	// FindLeafBySHA256 returns the raw DER of the certificate whose SHA-256
	// fingerprint equals fp, or errCertNotFound.
	FindLeafBySHA256(fp [32]byte) ([]byte, error)
	// KeyProvInfo reads CERT_KEY_PROV_INFO_PROP_ID from the certificate whose
	// SHA-256 equals fp, or errCertNotFound.
	KeyProvInfo(fp [32]byte) (keyProvInfo, error)
	// DeleteLeafBySHA256 deletes the exact certificate whose SHA-256 equals fp,
	// or errCertNotFound.
	DeleteLeafBySHA256(fp [32]byte) error
}

// keyRemover abstracts CNG key removal.
type keyRemover interface {
	// DeleteCNGKey deletes the CNG key identified by provider and container.
	// It returns errKeyNotFound when the key does not already exist.
	DeleteCNGKey(provider, container string) error
}

// Uninstall removes the leaf certificate and private key described by info.
// info must originate from an enrollment result and be treated as trusted,
// integrity-protected administrative data: when the certificate is not found,
// the provider and container name from info are used to attempt key deletion
// without re-verifying ownership. Cleanup is best-effort and not transactional;
// it deletes only the artifacts this module manages and does not roll back every
// side effect of certreq.exe.
func Uninstall(info CleanupInfo) error {
	return runCleanup(winStore{}, winKeyRemover{}, info)
}

// runCleanup is the pure, testable cleanup orchestration. When the certificate
// is present it verifies the persisted identity and key association before
// deleting; when the certificate is absent it attempts to delete the named key
// using the provider/container from info. It fails closed when a present
// artifact disagrees with the persisted metadata.
func runCleanup(store certStore, keys keyRemover, info CleanupInfo) error {
	fp, err := decodeSHA256(info.LeafSHA256)
	if err != nil {
		return fmt.Errorf("%w: invalid persisted leaf fingerprint: %v", ErrCleanupFailed, err)
	}

	der, err := store.FindLeafBySHA256(fp)
	if errors.Is(err, errCertNotFound) {
		return removeOrphanKey(keys, info)
	}
	if err != nil {
		return fmt.Errorf("%w: find leaf certificate: %v", ErrCleanupFailed, err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("%w: parse stored certificate: %v", ErrCleanupFailed, err)
	}
	if !info.matches(cert) {
		return fmt.Errorf("%w: certificate identity does not match persisted metadata", ErrOwnershipMismatch)
	}

	kpi, err := store.KeyProvInfo(fp)
	if errors.Is(err, errCertNotFound) {
		return removeOrphanKey(keys, info)
	}
	if err != nil {
		return fmt.Errorf("%w: read key association: %v", ErrCleanupFailed, err)
	}
	if kpi.provider != info.Provider {
		return fmt.Errorf("%w: key provider %q does not match persisted %q", ErrOwnershipMismatch, kpi.provider, info.Provider)
	}
	if kpi.containerName != info.ContainerName {
		return fmt.Errorf("%w: key container %q does not match persisted %q", ErrOwnershipMismatch, kpi.containerName, info.ContainerName)
	}
	if kpi.providerType != info.ProviderType {
		return fmt.Errorf("%w: provider type %d does not match persisted %d", ErrOwnershipMismatch, kpi.providerType, info.ProviderType)
	}
	if kpi.keySpec != info.KeySpec {
		return fmt.Errorf("%w: key spec %d does not match persisted %d", ErrOwnershipMismatch, kpi.keySpec, info.KeySpec)
	}

	if err := store.DeleteLeafBySHA256(fp); err != nil {
		if errors.Is(err, errCertNotFound) {
			return removeOrphanKey(keys, info)
		}
		return fmt.Errorf("%w: delete leaf certificate: %v", ErrCleanupFailed, err)
	}

	return removeKey(keys, info)
}

// removeKey deletes the exact key described by info, treating an already-absent
// key as idempotent success.
func removeKey(keys keyRemover, info CleanupInfo) error {
	if keys == nil {
		return fmt.Errorf("%w: no key removal implementation available", ErrCleanupFailed)
	}
	if err := keys.DeleteCNGKey(info.Provider, info.ContainerName); err != nil {
		if errors.Is(err, errKeyNotFound) {
			return nil
		}
		return fmt.Errorf("%w: delete key: %v", ErrCleanupFailed, err)
	}
	return nil
}

// removeOrphanKey handles the case where the certificate is already absent.
// The key is deleted using the provider and container name from info when both
// are non-empty; otherwise cleanup fails closed and reports the orphan rather
// than risking an unrelated key. Ownership of an absent certificate's key is
// not independently reconstructed here.
func removeOrphanKey(keys keyRemover, info CleanupInfo) error {
	if info.ContainerName == "" || info.Provider == "" {
		return fmt.Errorf("%w: certificate absent and key ownership cannot be proven from persisted metadata", ErrOwnershipMismatch)
	}
	return removeKey(keys, info)
}

// matches verifies every certificate-identity guard against a stored leaf. The
// LeafSHA256 comparison is the authoritative exact match; the issuer, serial,
// and SPKI checks provide defense in depth against stale or corrupted metadata.
func (ci CleanupInfo) matches(cert *x509.Certificate) bool {
	if ci.Issuer != cert.Issuer.String() {
		return false
	}
	if ci.SerialNumber != serialHex(cert.SerialNumber) {
		return false
	}
	if ci.LeafSHA256 != sha256Hex(cert.Raw) {
		return false
	}
	if ci.SPKISHA256 != sha256Hex(cert.RawSubjectPublicKeyInfo) {
		return false
	}
	return true
}

// cleanupInfoForCert computes the certificate-identity portion of CleanupInfo
// from a parsed leaf certificate.
func cleanupInfoForCert(cert *x509.Certificate) CleanupInfo {
	return CleanupInfo{
		Issuer:       cert.Issuer.String(),
		SerialNumber: serialHex(cert.SerialNumber),
		LeafSHA256:   sha256Hex(cert.Raw),
		SPKISHA256:   sha256Hex(cert.RawSubjectPublicKeyInfo),
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sha256Sum(b []byte) [32]byte {
	return sha256.Sum256(b)
}

func serialHex(s *big.Int) string {
	if s == nil {
		return ""
	}
	b := s.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return hex.EncodeToString(b)
}

func decodeSHA256(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != len(out) {
		return out, fmt.Errorf("SHA-256 fingerprint must be %d bytes, got %d", len(out), len(b))
	}
	copy(out[:], b)
	return out, nil
}
