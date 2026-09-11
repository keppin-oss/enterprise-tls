// Command classification demonstrates caller-side classification of structured
// enrollment statuses and sentinel errors through the public API, without any
// production changes or machine-state mutation.
//
// It never string-matches stderr. Policy decisions use Status and
// errors.Is/errors.As, exactly as a real caller would.
package main

import (
	"errors"
	"fmt"

	enterprise "github.com/keppin-oss/enterprise-tls"
)

// classify shows the supported policy-classification contract. On a structured
// failure, Enroll's value and error are the same *Result; on success the error
// is nil. Both are passed here for clarity. errors.Is works on the error
// because Result implements Unwrap.
func classify(res *enterprise.Result, err error) {
	if err == nil {
		fmt.Println("outcome: success")
		return
	}
	if res == nil {
		fmt.Println("outcome: no structured result")
		return
	}

	fmt.Println("status:", res.Status)
	switch res.Status {
	case enterprise.StatusNotConfigured:
		fmt.Println("decision: fix configuration before retrying")
	case enterprise.StatusUnavailable:
		fmt.Println("decision: infrastructure/tool unavailable (orchestrator may fall back)")
	case enterprise.StatusEnrollmentFailed:
		fmt.Println("decision: enrollment attempted but rejected/failed")
	case enterprise.StatusInvalidCertificate:
		fmt.Println("decision: returned material failed validation")
	case enterprise.StatusEnrollmentIncomplete:
		fmt.Println("decision: certificate installed; cleanup metadata incomplete")
	default:
		fmt.Println("decision: unknown")
	}

	switch {
	case errors.Is(err, enterprise.ErrNotConfigured):
		fmt.Println("sentinel: ErrNotConfigured")
	case errors.Is(err, enterprise.ErrUnavailable):
		fmt.Println("sentinel: ErrUnavailable")
	case errors.Is(err, enterprise.ErrEnrollmentFailed):
		fmt.Println("sentinel: ErrEnrollmentFailed")
	case errors.Is(err, enterprise.ErrInvalidCertificate):
		fmt.Println("sentinel: ErrInvalidCertificate")
	case errors.Is(err, enterprise.ErrEnrollmentIncomplete):
		fmt.Println("sentinel: ErrEnrollmentIncomplete")
	}

	// Key state drives ownership decisions; it must never trigger deletion of
	// a key whose ownership is unproven.
	fmt.Println("key state:", res.KeyState)
}

func main() {
	fmt.Println("synthetic classification walkthrough (no machine state changed)")

	cases := []struct {
		name string
		res  *enterprise.Result
	}{
		{
			name: "not-configured",
			res: &enterprise.Result{
				Status: enterprise.StatusNotConfigured,
				Err:    fmt.Errorf("%w: CA identifier is empty", enterprise.ErrNotConfigured),
			},
		},
		{
			name: "unavailable",
			res: &enterprise.Result{
				Status: enterprise.StatusUnavailable,
				Err:    fmt.Errorf("certreq.exe: %w", enterprise.ErrUnavailable),
			},
		},
		{
			name: "enrollment-failed",
			res: &enterprise.Result{
				Status:   enterprise.StatusEnrollmentFailed,
				KeyState: enterprise.KeyStateRemoved,
				Err:      fmt.Errorf("%w: denied by policy", enterprise.ErrEnrollmentFailed),
			},
		},
		{
			name: "invalid-certificate",
			res: &enterprise.Result{
				Status:   enterprise.StatusInvalidCertificate,
				KeyState: enterprise.KeyStateRemoved,
				Err:      fmt.Errorf("%w: disallowed SAN identity", enterprise.ErrInvalidCertificate),
			},
		},
		{
			name: "enrollment-incomplete",
			res: &enterprise.Result{
				Status:   enterprise.StatusEnrollmentIncomplete,
				KeyState: enterprise.KeyStatePresent,
				Err:      fmt.Errorf("%w: capture cleanup metadata", enterprise.ErrEnrollmentIncomplete),
			},
		},
	}

	for _, c := range cases {
		fmt.Println("---", c.name)
		classify(c.res, c.res)
	}

	fmt.Println("--- success")
	classify(&enterprise.Result{Status: enterprise.StatusSuccess}, nil)
}
