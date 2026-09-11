package enterprise

import (
	"errors"
	"os/exec"
	"testing"
)

const rpcUnavailable = int(uint32(0x800706BA)) // RPC_S_SERVER_UNAVAILABLE

// TestClassifyToolError_MissingTool verifies that a missing certreq.exe is
// "unavailable" in every phase (the provider cannot operate at all).
func TestClassifyToolError_MissingTool(t *testing.T) {
	for _, phase := range []certreqPhase{phaseNew, phaseSubmit, phaseAccept} {
		if got := classifyToolError(phase, -1, exec.ErrNotFound); got != StatusUnavailable {
			t.Errorf("phase %d + ErrNotFound: expected unavailable, got %s", phase, got)
		}
	}
}

// TestClassifyToolError_SubmitUnavailable verifies that a CA-reachability
// HRESULT maps to "unavailable" only in the -submit phase.
func TestClassifyToolError_SubmitUnavailable(t *testing.T) {
	unavailable := []int{
		int(uint32(0x800706BA)), // RPC_S_SERVER_UNAVAILABLE
		int(uint32(0x800706D9)), // RPC_S_NO_ENDPOINTS
		int(uint32(0x80072EE7)), // ERROR_WINHTTP_NAME_NOT_RESOLVED
	}
	for _, code := range unavailable {
		if got := classifyToolError(phaseSubmit, code, nil); got != StatusUnavailable {
			t.Errorf("submit + %#x: expected unavailable, got %s", uint32(code), got)
		}
	}
}

// TestClassifyToolError_ReachabilityOnlyOnSubmit proves the phase-aware rule:
// the same CA-reachability HRESULT is enrollment-failed in -new and -accept.
func TestClassifyToolError_ReachabilityOnlyOnSubmit(t *testing.T) {
	for _, phase := range []certreqPhase{phaseNew, phaseAccept} {
		if got := classifyToolError(phase, rpcUnavailable, nil); got != StatusEnrollmentFailed {
			t.Errorf("phase %d + %#x: expected enrollment-failed, got %s", phase, uint32(rpcUnavailable), got)
		}
	}
}

// TestClassifyToolError_UnknownFailEveryPhase verifies that unknown/ambiguous
// failures are enrollment-failed in every phase (fail closed).
func TestClassifyToolError_UnknownFailEveryPhase(t *testing.T) {
	codes := []int{
		int(uint32(0x80070002)), // ERROR_FILE_NOT_FOUND (ambiguous)
		int(uint32(0x800706BF)), // RPC_S_CALL_FAILED (ambiguous)
		int(uint32(0x80092004)), // CRYPT_E_NOT_FOUND
		int(uint32(0x80094801)), // template/policy denial
		int(uint32(0x80004005)), // E_FAIL
		2,
		int(uint32(0xDEADBEEF)),
	}
	for _, phase := range []certreqPhase{phaseNew, phaseSubmit, phaseAccept} {
		for _, code := range codes {
			if got := classifyToolError(phase, code, nil); got != StatusEnrollmentFailed {
				t.Errorf("phase %d + code %#x: expected enrollment-failed, got %s", phase, uint32(code), got)
			}
		}
	}
}

func TestStatusString(t *testing.T) {
	cases := map[Status]string{
		StatusUnknown:              "unknown",
		StatusNotConfigured:        "not-configured",
		StatusUnavailable:          "unavailable",
		StatusEnrollmentFailed:     "enrollment-failed",
		StatusInvalidCertificate:   "invalid-certificate",
		StatusSuccess:              "success",
		StatusEnrollmentIncomplete: "enrollment-incomplete",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestSentinelErrorsDistinct(t *testing.T) {
	errs := []error{ErrNotConfigured, ErrUnavailable, ErrEnrollmentFailed, ErrInvalidCertificate, ErrEnrollmentIncomplete, ErrCleanupFailed, ErrOwnershipMismatch}
	for i, a := range errs {
		for j, b := range errs {
			if i != j && errors.Is(a, b) {
				t.Fatalf("sentinels %d and %d should be distinct", i, j)
			}
		}
	}
}
