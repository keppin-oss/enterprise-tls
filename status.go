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
	// StatusUnavailable means certreq.exe is missing. Network/RPC failures
	// remain enrollment-failed and do not authorize fallback.
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
	// StatusEnrollmentPending means the CA accepted the request but left it
	// pending (for example manager approval): certreq -submit succeeded without
	// returning a certificate. It is not a failure. The key, the request object
	// in LocalMachine\REQUEST and the attempt files are kept; Result.CA and
	// Result.RequestID identify the request. Do not delete or resubmit: after the
	// PKI decides, the request can be retrieved (certreq -retrieve) and accepted.
	StatusEnrollmentPending
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
	case StatusEnrollmentPending:
		return "enrollment-pending"
	default:
		return "unknown"
	}
}

// Sentinel errors allow callers to classify outcomes by matching the sentinels
// with errors.Is; the concrete *Result type can be extracted with errors.As.
var (
	// ErrNotConfigured indicates required Enterprise CA configuration is missing.
	ErrNotConfigured = errors.New("enterprise enrollment is not configured")
	// ErrUnavailable indicates that the required enrollment tool is missing.
	ErrUnavailable = errors.New("enterprise enrollment tool is unavailable")
	// ErrEnrollmentFailed indicates enrollment was attempted but failed.
	ErrEnrollmentFailed = errors.New("enterprise enrollment was attempted but failed")
	// ErrInvalidCertificate indicates the returned certificate material is
	// invalid, untrusted, or mismatched.
	ErrInvalidCertificate = errors.New("returned certificate is invalid, untrusted, or mismatched")
	// ErrEnrollmentIncomplete indicates a valid certificate was installed but
	// the cleanup metadata required for later safe removal is missing.
	ErrEnrollmentIncomplete = errors.New("enrollment installed a certificate but cleanup metadata is incomplete")
	// ErrEnrollmentPending indicates the request is pending at the CA. It does
	// not match ErrEnrollmentFailed: failure handling (cleanup, retry with a
	// new key, fallback) must not run for a pending request.
	ErrEnrollmentPending = errors.New("enterprise enrollment request is pending at the CA")
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
	// KeyStateRetained means the owned key exists and must be kept: the request
	// is pending at the CA and the key is needed to accept a later issuance.
	// Unlike KeyStatePresent it does not invite a cleanup retry.
	KeyStateRetained
)

func (s KeyState) String() string {
	switch s {
	case KeyStateRemoved:
		return "removed"
	case KeyStatePresent:
		return "present"
	case KeyStateUnproven:
		return "unproven"
	case KeyStateRetained:
		return "retained"
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
	// ArtifactDirectory is retained on uncertain process quiescence and on a
	// pending request. It contains the attempt files, not authorization to
	// replay or delete.
	ArtifactDirectory string
	// CA is the CA configuration the request was submitted to, and RequestID
	// the CA request ID read from certreq -submit output (0 when unknown).
	// Both are set on every result that follows a submit which printed an ID:
	// denied, pending, issued, and later validation/accept failures or success.
	// They stay unset when submit never ran or printed no ID; a pending result
	// always carries CA, with RequestID 0 if the ID could not be read.
	// A RequestID is meaningful only together with CA.
	CA        string
	RequestID int
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
