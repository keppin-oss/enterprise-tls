// Command native-enroll shows how to wire lifecycle.Enrollment to the native
// adapters, which replace the deprecated
// Provider.Enroll.
//
// This is a demonstrative example, not a production broker. When run with a
// valid CA it performs a real enrollment as LocalSystem: it creates a machine
// key, calls the CA through ICertRequest and installs the certificate in
// LocalMachine\My. No child process is started.
//
// Prerequisites to run it:
//
//   - a domain-joined Windows machine that can reach the Enterprise CA;
//   - running as LocalSystem (the CA client refuses any other identity);
//   - a protected journal directory (SYSTEM and Administrators only);
//   - the issuing CA and root certificates (DER) for the validation of the issued certificate.
//
// Example:
//
//	native-enroll -journal C:\ProgramData\Keppin\enroll -ca 'ca-host\Issuing-CA' \
//	    -template ExampleECDSA -template-oid 1.3.6.1.4.1.311.21.8.1.2.3 \
//	    -service KeppinAgent -issuer issuing.cer -root root.cer
package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	enterprise "github.com/keppin-oss/enterprise-tls"
	"github.com/keppin-oss/enterprise-tls/lifecycle"
)

func main() {
	journalDir := flag.String("journal", "", "protected journal directory")
	ca := flag.String("ca", "", `CA configuration "CAHostName\CAName"`)
	template := flag.String("template", "", "certificate template name")
	templateOID := flag.String("template-oid", "", "OID of the template in the v2 template extension")
	service := flag.String("service", "", "Windows service that will use the key")
	issuerFile := flag.String("issuer", "", "issuing CA certificate (DER)")
	rootFile := flag.String("root", "", "root CA certificate (DER)")
	flag.Parse()
	if err := run(*journalDir, *ca, *template, *templateOID, *service, *issuerFile, *rootFile); err != nil {
		fmt.Fprintln(os.Stderr, "native-enroll:", err)
		os.Exit(1)
	}
}

func readCert(path string) (*x509.Certificate, error) {
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func run(journalDir, ca, template, templateOID, service, issuerFile, rootFile string) error {
	if journalDir == "" || ca == "" || template == "" || service == "" {
		return errors.New("-journal, -ca, -template and -service are required")
	}
	issuer, err := readCert(issuerFile)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}
	root, err := readCert(rootFile)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	oid, err := parseOID(templateOID)
	if err != nil {
		return err
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	inter.AddCert(issuer)

	journal, err := lifecycle.OpenJournal(journalDir)
	if err != nil {
		return err
	}
	defer journal.Close()
	store, err := lifecycle.OpenAttemptStore(journalDir)
	if err != nil {
		return err
	}
	defer store.Close()
	keys, err := enterprise.NewCNGKeys(service)
	if err != nil {
		return err
	}
	validator := enterprise.EnrollmentValidator{Roots: roots, Intermediates: inter, Issuer: issuer,
		Templates: map[string]asn1.ObjectIdentifier{template: oid}}
	e := lifecycle.Enrollment{
		Journal:  journal,
		Guard:    lifecycle.ProcessGuard{Journal: journal}, // no Quiescer: a latch waits for an administrator
		Deleter:  enterprise.NewAttemptDeleter(store, keys),
		Requests: enterprise.NewNativeRequester(store, "S-1-5-18"),
		Keys:     keys,
		Stores:   enterprise.NewMachineMy(),
		Validate: validator.Validate,
		Pace:     lifecycle.PacePolicy{MinInterval: time.Minute, RetrieveMax: 3},
	}

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	ctx := context.Background()
	a, err := e.Start(ctx, lifecycle.Params{CA: ca, Template: template, Provider: "Microsoft Software Key Storage Provider",
		Container: "keppin-enterprise-tls-" + hex.EncodeToString(b[:]), TargetSID: keys.TargetSID(), Profile: "service-sid"})
	if err != nil {
		return err
	}
	for {
		_, err := e.Step(ctx)
		switch {
		case errors.Is(err, lifecycle.ErrNoOpenAttempt):
			got, plan, rerr := e.Report(ctx, a.ID)
			if rerr != nil {
				return rerr
			}
			fmt.Printf("attempt %s: %s (%s), RequestId %d, SPKI %s\n", got.ID, got.Outcome, got.Reason, got.RequestID, got.SPKI)
			if plan != nil {
				fmt.Printf("cleanup: terminal=%t complete=%t\n", plan.Terminal, plan.Complete)
			}
			// Only ACCEPTED is a success: installed with a proven binding.
			// It does not say the certificate is in use; the consumer confirms that.
			if got.Outcome != lifecycle.Accepted {
				return fmt.Errorf("attempt %s ended %s", got.ID, got.Outcome)
			}
			return nil
		case errors.Is(err, lifecycle.ErrRetrieveNotDue):
			time.Sleep(time.Minute)
		case errors.Is(err, lifecycle.ErrCleanupIncomplete):
			// Reported by the closed plan; the next Step returns the report.
		case err != nil:
			return err
		}
	}
}
