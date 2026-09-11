package enterprise

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
)

// runner abstracts process execution so policy/validation logic can be tested
// without certreq.exe or a live Enterprise CA.
type runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, exitCode int, err error)
}

// execRunner is the real runner backed by os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err == nil {
		return out.String(), errb.String(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), errb.String(), ee.ExitCode(), err
	}
	return out.String(), errb.String(), -1, err
}

// certreqPhase identifies which stage of the certreq.exe workflow a failure
// originated from. Classification is phase-aware so that "unavailable" is
// reserved for fallback-safe conditions.
type certreqPhase int

const (
	phaseNew    certreqPhase = iota // certreq -new
	phaseSubmit                     // certreq -submit
	phaseAccept                     // certreq -accept
)

// classifyToolError maps a failed tool invocation to a Status using a
// conservative, fail-closed policy that is aware of the certreq.exe phase.
//
// "unavailable" is reserved for the cases where the provider cannot operate or
// the Enterprise CA is genuinely unreachable, so that a higher-level
// orchestration layer can distinguish a reachable-but-failing CA from an
// unreachable one:
//
//   - certreq.exe itself is missing (exec.ErrNotFound), in any phase, is
//     "unavailable" because the provider cannot operate at all;
//   - CA reachability HRESULTs map to "unavailable" only in the -submit phase,
//     where they actually mean the Enterprise CA cannot be reached.
//
// Every other non-zero outcome — request rejection, template/policy denial,
// authentication/authorization failure, malformed request, a failed -new
// after the tool launched, a failed -accept, or any ambiguous/unrecognized
// failure — is classified as enrollment-failed. Unknown failures never become
// "unavailable".
func classifyToolError(phase certreqPhase, exitCode int, err error) Status {
	if err != nil && errors.Is(err, exec.ErrNotFound) {
		return StatusUnavailable
	}
	if phase == phaseSubmit && hresultUnavailable(exitCode) {
		return StatusUnavailable
	}
	return StatusEnrollmentFailed
}

// hresultUnavailable reports whether an HRESULT exit code indicates the CA
// infrastructure was unreachable rather than a rejected request. This is an
// allow-list: only genuinely "can't reach the CA" codes are listed, so that
// any denial/policy/auth/ambiguous failure falls through to
// StatusEnrollmentFailed (fail closed).
func hresultUnavailable(exitCode int) bool {
	switch uint32(exitCode) {
	case 0x800706BA, // RPC_S_SERVER_UNAVAILABLE — CA RPC server not responding
		0x800706D9, // RPC_S_NO_ENDPOINTS — CA not registered/reachable
		0x80072EE7: // ERROR_WINHTTP_NAME_NOT_RESOLVED — CA hostname unresolvable
		return true
	}
	return false
}
