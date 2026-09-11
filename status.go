package enterprise

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// Status classifies the outcome of an enrollment attempt so a future
// orchestration layer can reason about it without string matching.
type Status int

const (
	// StatusUnknown is the zero value; it indicates no attempt was made.
	StatusUnknown Status = iota
	// StatusNotConfigured means the required CA configuration is missing.
	StatusNotConfigured
	// StatusUnavailable means certreq.exe or the Enterprise CA infrastructure
	// could not be reached.
	StatusUnavailable
	// StatusEnrollmentFailed means enrollment failed. This includes local errors
	// that occur before or around the tool run (for example file or request
	// handling), as well as the CA rejecting the request or certreq.exe failing.
	StatusEnrollmentFailed
	// StatusInvalidCertificate means material was returned but failed
	// independent validation (malformed, wrong identity, wrong EKU/key usage,
	// key mismatch, or untrusted chain).
	StatusInvalidCertificate
	// StatusSuccess means enrollment succeeded and the certificate passed
	// independent validation.
	StatusSuccess
	// StatusEnrollmentIncomplete means a valid certificate was installed but
	// the cleanup metadata required for later safe removal could not be
	// captured. The caller must treat this as an observable orphan state.
	StatusEnrollmentIncomplete
)

func (s Status) String() string {
	switch s {
	case StatusNotConfigured:
		return "not-configured"
	case StatusUnavailable:
		return "unavailable"
	case StatusEnrollmentFailed:
		return "enrollment-failed"
	case StatusInvalidCertificate:
		return "invalid-certificate"
	case StatusSuccess:
		return "success"
	case StatusEnrollmentIncomplete:
		return "enrollment-incomplete"
	default:
		return "unknown"
	}
}

// Sentinel errors allow callers to classify outcomes by matching the sentinels
// with errors.Is; the concrete *Result type can be extracted with errors.As.
var (
	// ErrNotConfigured indicates required Enterprise CA configuration is missing.
	ErrNotConfigured = errors.New("enterprise enrollment is not configured")
	// ErrUnavailable indicates certreq.exe or the Enterprise CA infrastructure
	// could not be reached.
	ErrUnavailable = errors.New("enterprise CA infrastructure or tool is unavailable")
	// ErrEnrollmentFailed indicates enrollment was attempted but failed.
	ErrEnrollmentFailed = errors.New("enterprise enrollment was attempted but failed")
	// ErrInvalidCertificate indicates the returned certificate material is
	// invalid, untrusted, or mismatched.
	ErrInvalidCertificate = errors.New("returned certificate is invalid, untrusted, or mismatched")
	// ErrEnrollmentIncomplete indicates a valid certificate was installed but
	// the cleanup metadata required for later safe removal is missing.
	ErrEnrollmentIncomplete = errors.New("enrollment installed a certificate but cleanup metadata is incomplete")
)

// KeyState classifies what is known about the key container generated for an
// enrollment attempt.
type KeyState int

const (
	// KeyStateNone is the zero/unclassified state, also used on success. It does
	// not imply that no key container was allocated or that no key exists.
	KeyStateNone KeyState = iota
	// KeyStateRemoved means the owned key was created and successfully removed.
	KeyStateRemoved
	// KeyStatePresent means the owned key may remain and can be retried using
	// Result.KeyContainer.
	KeyStatePresent
	// KeyStateUnproven means key ownership could not be proven; the caller must
	// not attempt to delete the key.
	KeyStateUnproven
)

func (s KeyState) String() string {
	switch s {
	case KeyStateRemoved:
		return "removed"
	case KeyStatePresent:
		return "present"
	case KeyStateUnproven:
		return "unproven"
	default:
		return "none"
	}
}

// Result is the structured outcome of an enrollment attempt. Status is the
// canonical classification; Err carries a wrapped sentinel error that errors.Is
// can match, while errors.As extracts the *Result type itself.
type Result struct {
	Status      Status
	Certificate *x509.Certificate
	Err         error

	// Diagnostics (populated where available).
	Tool       string // e.g. "certreq.exe"
	ExitCode   int    // raw process exit code when a tool returned non-zero
	Stderr     string // tool stderr, when non-empty
	Thumbprint string // SHA-1 thumbprint of the validated certificate (hex)

	// Cleanup holds the enrollment metadata used to later remove the leaf
	// certificate and its private key. It is populated on success and, on a
	// failed attempt where retry cleanup is possible, as best-effort metadata.
	Cleanup *CleanupInfo

	// KeyContainer is the key container name generated for this attempt and
	// selected before certreq -new. It is populated whenever a container name
	// was allocated, including failure paths, so the key identity is not lost
	// when the module can determine it.
	KeyContainer string
	// KeyState describes the state of the owned key after the attempt.
	KeyState KeyState
	// KeyCleanupErr, when non-nil, records a key-removal failure so it is not
	// hidden behind the primary enrollment error.
	KeyCleanupErr error
}

// Error implements error, allowing a Result to be returned directly as the
// error of an enrollment attempt.
func (r *Result) Error() string {
	if r.Err == nil {
		return fmt.Sprintf("enterprise enrollment: %s", r.Status)
	}
	return fmt.Sprintf("enterprise enrollment: %s: %v", r.Status, r.Err)
}

// Unwrap exposes the underlying error so errors.Is can match the sentinel.
func (r *Result) Unwrap() error { return r.Err }
