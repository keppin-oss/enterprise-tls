// Command enroll demonstrates the Enterprise CA enrollment flow for a
// machine/computer certificate.
//
// This is a demonstrative example, not a production recovery workflow. When run
// with a valid CA it attempts a real enrollment and mutates machine certificate
// and key state. Do not run it against a production CA with placeholder
// identifiers.
//
// Prerequisites to run it:
//
//   - a domain-joined Windows machine that can reach the Enterprise CA;
//   - an elevated (Administrator) prompt;
//   - an Enterprise CA identifier in certreq.exe "-config" form
//     ("CAHostName\CAName") and, optionally, a template name.
//
// Example (elevated PowerShell):
//
//	$env:CA             = 'ca-host.example.com\Issuing-CA'
//	$env:TEMPLATE       = 'WebServer'
//	$env:ENROLL_TIMEOUT = '5m'
//	$env:CLEANUP_FILE   = 'cleanup.json'
//	go run ./examples/enroll
//
// On success, and when CLEANUP_FILE is set, the example persists CleanupInfo.
// On a failure path it prints diagnostics and does not persist Result.Cleanup;
// retaining recovery metadata is a consumer responsibility, not behavior the
// example implements. StatusEnrollmentIncomplete may mean a certificate was
// already installed. The example never prints or exports private-key material.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	enterprise "github.com/keppin-oss/enterprise-tls"
)

func main() {
	cfg := enterprise.Config{
		CA:       os.Getenv("CA"),
		Template: os.Getenv("TEMPLATE"),
	}

	timeout := 5 * time.Minute
	if s := os.Getenv("ENROLL_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			timeout = d
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := enterprise.New(cfg).Enroll(ctx)
	if err != nil {
		reportFailure(result, err)
		os.Exit(1)
	}

	fmt.Println("enrollment succeeded")
	fmt.Println("status:", result.Status)
	fmt.Println("thumbprint:", result.Thumbprint)
	fmt.Println("key container:", result.KeyContainer)
	fmt.Println("key state:", result.KeyState)

	if result.Cleanup != nil {
		if path := os.Getenv("CLEANUP_FILE"); path != "" {
			if perr := persistCleanup(result.Cleanup, path); perr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not persist cleanup metadata: %v\n", perr)
			}
		}
	}
}

// reportFailure classifies an enrollment failure through structured status and
// sentinel errors. Diagnostics are printed for humans only, never used as the
// policy signal.
func reportFailure(result *enterprise.Result, err error) {
	fmt.Fprintln(os.Stderr, "enrollment did not succeed")
	if result == nil {
		fmt.Fprintln(os.Stderr, "no structured result")
		return
	}

	fmt.Fprintln(os.Stderr, "status:", result.Status)
	fmt.Fprintln(os.Stderr, "key state:", result.KeyState)
	if result.KeyContainer != "" {
		fmt.Fprintln(os.Stderr, "key container:", result.KeyContainer)
	}
	if result.KeyCleanupErr != nil {
		fmt.Fprintln(os.Stderr, "key cleanup error:", result.KeyCleanupErr)
	}

	switch {
	case errors.Is(err, enterprise.ErrNotConfigured):
		fmt.Fprintln(os.Stderr, "classification: not configured")
	case errors.Is(err, enterprise.ErrUnavailable):
		fmt.Fprintln(os.Stderr, "classification: tool or CA unavailable")
	case errors.Is(err, enterprise.ErrEnrollmentFailed):
		fmt.Fprintln(os.Stderr, "classification: enrollment failed")
	case errors.Is(err, enterprise.ErrInvalidCertificate):
		fmt.Fprintln(os.Stderr, "classification: invalid certificate")
	case errors.Is(err, enterprise.ErrEnrollmentIncomplete):
		fmt.Fprintln(os.Stderr, "classification: enrollment incomplete (certificate installed)")
		if result.Cleanup != nil {
			fmt.Fprintln(os.Stderr, "retain retry cleanup metadata for later safe uninstall")
		}
	default:
		fmt.Fprintln(os.Stderr, "classification: unclassified:", err)
	}

	if result.Tool != "" {
		fmt.Fprintf(os.Stderr, "diagnostic tool: %s exit=%d\n", result.Tool, result.ExitCode)
	}
	if result.Stderr != "" {
		fmt.Fprintf(os.Stderr, "diagnostic stderr: %s\n", result.Stderr)
	}
}

func persistCleanup(info *enterprise.CleanupInfo, path string) error {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
