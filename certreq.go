package enterprise

import (
	"context"
	"errors"
	"os/exec"
)

// runner abstracts process execution for offline enrollment tests.
type runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, exitCode int, err error)
}

// execRunner resolves only the system executable, never PATH or the current
// directory. On Windows the entire process tree is contained in a job.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, string, int, error) {
	path, err := resolveTool(name)
	if err != nil {
		return "", "", -1, err
	}
	return runCommandTree(ctx, path, args...)
}

type certreqPhase int

const (
	phaseNew certreqPhase = iota
	phaseSubmit
	phaseAccept
)

// Only a missing executable is unavailable. RPC/DNS failures do not establish
// CA availability or authorize fallback: a wrong enrollment identity can
// produce the same HRESULT as a network failure.
//
// A guard refusal never ran certreq, so a cause such as exec.ErrNotFound from
// a recovery or journal adapter does not establish that certreq is missing.
func classifyToolError(_ certreqPhase, _ int, err error) Status {
	if errors.Is(err, ErrProcessQuiescence) || errors.Is(err, ErrOperationBlocked) {
		return StatusEnrollmentFailed
	}
	if err != nil && errors.Is(err, exec.ErrNotFound) {
		return StatusUnavailable
	}
	return StatusEnrollmentFailed
}
