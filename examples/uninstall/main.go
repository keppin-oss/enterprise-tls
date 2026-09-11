// Command uninstall demonstrates the cleanup boundary: it removes the leaf
// certificate and associated machine key described by a CleanupInfo previously
// persisted from an enrollment result.
//
// The JSON metadata is treated as trusted administrative input; its provenance
// and integrity are the caller's responsibility. Deletion targets the SHA-256
// fingerprint and the persisted provider/container, not subject, friendly name,
// prefix, or wildcard. The metadata must originate from an enrollment result
// (for example via examples/enroll writing CLEANUP_FILE).
//
// Prerequisites: elevated (Administrator) Windows prompt.
//
//	$env:CLEANUP_FILE = 'cleanup.json'   # produced by examples/enroll
//	go run ./examples/uninstall -cleanup $env:CLEANUP_FILE
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	enterprise "github.com/keppin-oss/enterprise-tls"
)

func main() {
	path := flag.String("cleanup", "", "path to JSON CleanupInfo persisted from an enrollment result")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "usage: uninstall -cleanup <cleanup.json>")
		os.Exit(2)
	}

	data, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read cleanup metadata: %v\n", err)
		os.Exit(1)
	}

	var info enterprise.CleanupInfo
	if err := json.Unmarshal(data, &info); err != nil {
		fmt.Fprintf(os.Stderr, "parse cleanup metadata: %v\n", err)
		os.Exit(1)
	}

	// Fail closed rather than guessing if the metadata is incomplete. This is a
	// completeness check on metadata whose provenance and integrity are already
	// assumed trusted (see the file comment); it does not itself re-prove
	// ownership.
	if info.LeafSHA256 == "" || info.Provider == "" || info.ContainerName == "" {
		fmt.Fprintln(os.Stderr, "refusing to run with incomplete cleanup metadata (must originate from an enrollment result)")
		os.Exit(1)
	}

	if err := enterprise.Uninstall(info); err != nil {
		switch {
		case errors.Is(err, enterprise.ErrOwnershipMismatch):
			fmt.Fprintln(os.Stderr, "ownership could not be verified; nothing was deleted")
		default:
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Println("uninstall complete")
}
