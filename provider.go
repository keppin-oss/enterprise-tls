package enterprise

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Provider enrolls and validates a machine-scoped localhost certificate from
// an Enterprise CA using certreq.exe. It is a standalone provider and
// contains no fallback/orchestration logic.
//
// Deprecated: Provider bypasses the enrollment journal and its recovery
// rules, and starts certreq.exe child processes. Use lifecycle.Enrollment with
// the native adapters (CNGKeys, NativeRequester, MachineMy, AttemptDeleter,
// EnrollmentValidator). Provider keeps
// working in this release and will be removed in a later breaking release.
type Provider struct {
	cfg    Config
	runner runner
	// validateOpts allows tests to inject trust roots, intermediates, and a
	// clock without mutating the host trust store. ExpectedPublicKey is set
	// per-enrollment.
	validateOpts ValidateOptions
	// store and keys are the machine certificate-store and CNG key-removal
	// seams used for cleanup metadata capture and uninstall.
	store certStore
	keys  keyRemover
	// keyContainer generates the key container name for an attempt (a random,
	// module-namespaced name fixed for the attempt); injected in tests so the
	// generated identity is predictable.
	keyContainer func() (string, error)
}

// New creates a Provider using the real certreq.exe runner and the native
// Windows machine certificate store and CNG key providers.
//
// Deprecated: use lifecycle.Enrollment with the native adapters; see Provider.
func New(cfg Config) *Provider {
	return &Provider{
		cfg:          cfg,
		runner:       execRunner{},
		store:        winStore{},
		keys:         winKeyRemover{},
		keyContainer: newKeyContainer,
	}
}

// Enroll performs the full enterprise enrollment workflow and returns a
// structured Result. On success, Result.Status is StatusSuccess and
// Result.Certificate holds the validated certificate.
//
// The result classification is: not-configured, unavailable,
// enrollment-failed, invalid-certificate, enrollment-incomplete, or success
// (see Status). Result.KeyContainer and Result.KeyState describe the state of
// the key container generated for this attempt across the failure and success
// paths.
//
// Deprecated: Enroll runs certreq.exe outside the enrollment journal: a crash
// or a lost result is not recovered by the native state machine, and the
// barriers of lifecycle.Enrollment (CA_UNKNOWN, never-adopt, binding
// check) do not apply. Use lifecycle.Enrollment with the native adapters.
func (p *Provider) Enroll(ctx context.Context) (result *Result, resultErr error) {
	if !p.cfg.configured() {
		res := &Result{Status: StatusNotConfigured, Err: fmt.Errorf("%w: CA identifier is empty", ErrNotConfigured)}
		return res, res
	}

	// Allocate the key container name before any certreq call, so the key is
	// identifiable even if enrollment later fails.
	container, err := p.newKeyContainerName()
	if err != nil {
		res := &Result{Status: StatusEnrollmentFailed, Err: fmt.Errorf("%w: generate key container: %v", ErrEnrollmentFailed, err)}
		return res, res
	}

	dir, err := os.MkdirTemp("", "keppin-ent-*")
	if err != nil {
		res := &Result{Status: StatusEnrollmentFailed, KeyContainer: container, Err: fmt.Errorf("%w: create temp dir: %v", ErrEnrollmentFailed, err)}
		return res, res
	}
	// submitID is the RequestId printed by certreq -submit. Every result returned
	// after a submit that printed one carries CA + RequestID, whatever happens
	// later (issued, validation or accept failure, success). A submit that never
	// ran, or printed no ID, leaves both unset (except pending, see below).
	var submitID int
	defer func() {
		if result != nil && submitID > 0 {
			result.CA, result.RequestID = p.cfg.CA, submitID
		}
		if errors.Is(resultErr, ErrProcessQuiescence) || errors.Is(resultErr, ErrEnrollmentPending) {
			if result != nil {
				result.ArtifactDirectory = dir
			}
			return
		}
		_ = os.RemoveAll(dir)
	}()

	infPath := filepath.Join(dir, "request.inf")
	reqPath := filepath.Join(dir, "request.req")
	certPath := filepath.Join(dir, "issued.cer")
	chainPath := filepath.Join(dir, "chain.p7b")

	if err := os.WriteFile(infPath, []byte(BuildRequestINF(p.cfg, container)), 0o600); err != nil {
		res := &Result{Status: StatusEnrollmentFailed, KeyContainer: container, Err: fmt.Errorf("%w: write request INF: %v", ErrEnrollmentFailed, err)}
		return res, res
	}

	// 1. Generate the machine-scoped key and PKCS#10 request. If -new fails we
	// cannot prove whether the key was actually created (it may have collided
	// with a pre-existing container), so fail closed and never delete it.
	// A guard block means certreq was never started in this call, so no key
	// was created for this attempt.
	if _, res := p.certreq(ctx, phaseNew, "-new", "-machine", "-q", infPath, reqPath); res != nil {
		res.KeyContainer = container
		res.KeyState = KeyStateUnproven
		if errors.Is(res.Err, ErrOperationBlocked) {
			res.KeyState = KeyStateNone
		}
		return res, res
	}

	// From here the key container is owned by this attempt and must be removed
	// on any subsequent failure before a certificate is installed.
	reqData, err := os.ReadFile(reqPath)
	if err != nil {
		return p.failOwned(container, StatusEnrollmentFailed, ErrEnrollmentFailed, "read request file: %v", err)
	}
	expectedKey, err := parseRequestPublicKey(reqData)
	if err != nil {
		return p.failOwned(container, StatusEnrollmentFailed, ErrEnrollmentFailed, "parse generated request: %v", err)
	}

	// 2. Submit the request to the Enterprise CA and capture leaf + chain.
	// -submit takes no -machine option (certreq.exe rejects it as an
	// unexpected argument). Submit authenticates with the credentials of the
	// process running certreq (the computer account when running as SYSTEM);
	// the machine scope of the key comes from -new -machine, not from submit.
	submitOut, res := p.certreq(ctx, phaseSubmit, "-submit", "-q", "-config", p.cfg.CA, reqPath, certPath, chainPath)
	submitID = parseRequestID(submitOut)
	if res != nil {
		return p.finishOwnedFailure(res, container)
	}
	// A successful submit without a certificate file is a pending request
	// (observed: exit 0 and no output file; the exit code alone does not
	// separate pending from issued). Keep the key, the REQUEST object and the
	// attempt files: the PKI may still issue it.
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		res := &Result{
			Status:       StatusEnrollmentPending,
			Tool:         "certreq.exe",
			KeyContainer: container,
			KeyState:     KeyStateRetained,
			// The request reached the CA, so CA is set even when no
			// RequestId could be read (RequestID stays 0).
			CA:  p.cfg.CA,
			Err: fmt.Errorf("%w: CA %q, RequestId %d", ErrEnrollmentPending, p.cfg.CA, submitID),
		}
		return res, res
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return p.failOwned(container, StatusEnrollmentFailed, ErrEnrollmentFailed, "read issued certificate: %v", err)
	}
	if len(certData) == 0 {
		return p.failOwned(container, StatusEnrollmentFailed, ErrEnrollmentFailed, "issued certificate is empty")
	}

	// 3. Independently validate the returned material before reporting success.
	opts := p.validateOpts
	opts.ExpectedPublicKey = expectedKey

	// The chain (if returned) supplies intermediates. Errors produced by the
	// supported extractor are treated conservatively (fail closed): a chain
	// that is present but rejected by the extractor, or that yields no usable
	// certificates, is invalid-certificate. The extractor is a minimal
	// certificate extractor, not a complete CMS validator, so this is not a
	// claim about every conceivable malformed or ambiguous chain material.
	if chainData, err := os.ReadFile(chainPath); err == nil && len(chainData) > 0 {
		chainCerts, perr := parsePKCS7Certificates(chainData)
		if perr != nil {
			return p.failOwned(container, StatusInvalidCertificate, ErrInvalidCertificate, "parse returned chain: %v", perr)
		}
		if len(chainCerts) == 0 {
			return p.failOwned(container, StatusInvalidCertificate, ErrInvalidCertificate, "returned chain contains no usable certificates")
		}
		inter := opts.Intermediates
		if inter == nil {
			inter = x509.NewCertPool()
		}
		for _, c := range chainCerts {
			inter.AddCert(c)
		}
		opts.Intermediates = inter
	}

	cert, err := ValidateCertificate(certData, opts)
	if err != nil {
		res := &Result{Status: StatusInvalidCertificate, Err: err}
		return p.finishOwnedFailure(res, container)
	}

	// 4. Accept/install the certificate into the machine store, binding the
	// machine-scoped key. This is a host mutation required for normal
	// provisioning; it is never exercised by ordinary unit tests.
	if _, res := p.certreq(ctx, phaseAccept, "-accept", "-machine", "-q", certPath); res != nil {
		return p.finishOwnedFailure(res, container)
	}

	// 5. Capture and verify cleanup metadata. The accepted certificate must be
	// bound to the preselected container; any mismatch is an ownership/integrity
	// failure and fails closed. On failure the certificate is installed but
	// best-effort cleanup metadata is returned so the caller can retry removal.
	cleanup, err := p.captureCleanupInfo(cert, container)
	if err != nil {
		retryCleanup := cleanupInfoForCert(cert)
		retryCleanup.Provider = expectedCNGProvider
		retryCleanup.ContainerName = container
		res := &Result{
			Status:       StatusEnrollmentIncomplete,
			Certificate:  cert,
			Thumbprint:   sha1Thumbprint(cert.Raw),
			KeyContainer: container,
			KeyState:     KeyStatePresent,
			Cleanup:      &retryCleanup,
			Err:          err,
		}
		return res, res
	}

	return &Result{
		Status:       StatusSuccess,
		Certificate:  cert,
		Thumbprint:   sha1Thumbprint(cert.Raw),
		KeyContainer: container,
		Cleanup:      &cleanup,
	}, nil
}

// captureCleanupInfo computes the exact cleanup metadata for a just-installed
// leaf: certificate identity from the parsed leaf plus the key association read
// from the installed certificate's CERT_KEY_PROV_INFO_PROP_ID. The read
// provider/container must match the expected CNG provider and the preselected
// container, otherwise an ownership/integrity error is returned.
func (p *Provider) captureCleanupInfo(cert *x509.Certificate, expectedContainer string) (CleanupInfo, error) {
	info := cleanupInfoForCert(cert)
	if p.store == nil {
		return CleanupInfo{}, fmt.Errorf("%w: no certificate store implementation available", ErrEnrollmentIncomplete)
	}
	kpi, err := p.store.KeyProvInfo(sha256Sum(cert.Raw))
	if err != nil {
		return CleanupInfo{}, fmt.Errorf("%w: read installed key association: %w", ErrEnrollmentIncomplete, err)
	}
	if kpi.provider != expectedCNGProvider {
		return CleanupInfo{}, fmt.Errorf("%w: installed key provider %q does not match expected %q", ErrEnrollmentIncomplete, kpi.provider, expectedCNGProvider)
	}
	if kpi.containerName != expectedContainer {
		return CleanupInfo{}, fmt.Errorf("%w: installed key container %q does not match expected %q", ErrEnrollmentIncomplete, kpi.containerName, expectedContainer)
	}
	info.Provider = kpi.provider
	info.ContainerName = kpi.containerName
	info.ProviderType = kpi.providerType
	info.KeySpec = kpi.keySpec
	return info, nil
}

// newKeyContainerName returns the key container name for this attempt, using
// the injected generator when present.
func (p *Provider) newKeyContainerName() (string, error) {
	if p.keyContainer == nil {
		return "", errors.New("key container generator is not configured")
	}
	return p.keyContainer()
}

// cleanupOwnedKey removes the exact owned key container. It reports removed
// only when the delete call succeeded. errKeyNotFound is returned as an error,
// not as removal: the key was not found or not accessible, nothing was deleted,
// and its absence is not proven.
func (p *Provider) cleanupOwnedKey(container string) (bool, error) {
	if p.keys == nil {
		return false, errors.New("no key removal implementation available")
	}
	if err := p.keys.DeleteCNGKey(expectedCNGProvider, container); err != nil {
		return false, err
	}
	return true, nil
}

// finishOwnedFailure marks a failure that occurred after the owned key was
// created: it removes the exact key immediately where safe, and records the key
// state (including any cleanup failure) on the result.
func (p *Provider) finishOwnedFailure(res *Result, container string) (*Result, error) {
	res.KeyContainer = container
	// Uncertain quiescence forbids cleanup: report the key as unproven, never
	// as present-and-retryable, so callers do not attempt the deletion this
	// error withholds.
	if errors.Is(res.Err, ErrProcessQuiescence) {
		res.KeyState = KeyStateUnproven
		res.KeyCleanupErr = res.Err
		return res, res
	}
	removed, keyErr := p.cleanupOwnedKey(container)
	switch {
	case keyErr != nil:
		res.KeyState = KeyStatePresent
		res.KeyCleanupErr = keyErr
	case removed:
		res.KeyState = KeyStateRemoved
	default:
		res.KeyState = KeyStatePresent
	}
	return res, res
}

// failOwned builds a failure Result after the owned key was created and cleans
// up the exact key.
func (p *Provider) failOwned(container string, status Status, sentinel error, format string, a ...any) (*Result, error) {
	res := &Result{Status: status, Err: fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, a...))}
	return p.finishOwnedFailure(res, container)
}

// certreq runs certreq.exe for the given phase with the given arguments and
// returns a non-nil Result only when the tool failed (non-zero exit or spawn
// error). The phase is passed explicitly so failure classification is
// phase-aware and never inferred from stderr text.
// The tool's stdout is returned in both cases (it carries the RequestId).
func (p *Provider) certreq(ctx context.Context, phase certreqPhase, args ...string) (string, *Result) {
	stdout, stderr, code, err := p.runner.Run(ctx, "certreq.exe", args...)
	if err == nil && code == 0 {
		return stdout, nil
	}
	status := classifyToolError(phase, code, err)
	var sentinel error
	switch status {
	case StatusUnavailable:
		sentinel = ErrUnavailable
	default:
		sentinel = ErrEnrollmentFailed
	}
	res := &Result{Status: status, Tool: "certreq.exe", ExitCode: code, Stderr: stderr}
	res.Err = fmt.Errorf("%w: certreq.exe %s failed (exit=%d): %s",
		errors.Join(sentinel, err), strings.Join(args, " "), code, strings.TrimSpace(stderr))
	return stdout, res
}

// requestIDPattern matches the RequestId line certreq prints for -submit and
// -retrieve. The label is not localized (observed on it-IT); the disposition
// text that follows is, so it is never parsed.
// Only horizontal whitespace is allowed, so the ID must be on the label's own
// line (CRLF tolerated), and quotes must be paired or absent. Malformed output
// yields 0: a missing ID is safer than pointing the PKI at the wrong request.
var requestIDPattern = regexp.MustCompile(`(?m)^[ \t]*RequestId:[ \t]*(?:"(\d+)"|(\d+))[ \t]*\r?$`)

// parseRequestID returns the first RequestId in certreq output, or 0.
func parseRequestID(stdout string) int {
	m := requestIDPattern.FindStringSubmatch(stdout)
	if m == nil {
		return 0
	}
	digits := m[1]
	if digits == "" {
		digits = m[2]
	}
	id, err := strconv.Atoi(digits)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}
