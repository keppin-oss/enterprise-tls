package enterprise

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// serverAuthOID is the Server Authentication EKU OID (1.3.6.1.5.5.7.3.1).
const serverAuthOID = "1.3.6.1.5.5.7.3.1"

// ValidateOptions controls independent certificate validation and allows the
// caller to inject trust roots, intermediates, a reference clock, and the
// expected public key.
type ValidateOptions struct {
	// Roots and Intermediates default to the platform/system trust available to
	// the calling process and an empty pool respectively when nil. Callers can
	// supply explicit pools when they must control the trust set.
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// ExpectedPublicKey, when set, must match the certificate's public key
	// (the key generated for the enrollment request).
	ExpectedPublicKey any
	// Now is the reference time for validity checks; defaults to time.Now.
	Now time.Time
}

// ValidateCertificate independently validates certificate material returned
// by the CA. A nil error means the certificate is acceptable. It performs, at
// minimum: parse, validity window, localhost SAN policy, Server Authentication
// EKU/key usage, public-key match against the requested key, and chain/trust
// verification against the platform/system trust available to the calling
// process.
func ValidateCertificate(data []byte, opts ValidateOptions) (*x509.Certificate, error) {
	cert, err := parseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: certificate not currently valid (notBefore=%s notAfter=%s)",
			ErrInvalidCertificate, cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))
	}

	if err := validateSANs(cert); err != nil {
		return nil, err
	}

	if err := validateUsage(cert); err != nil {
		return nil, err
	}

	if opts.ExpectedPublicKey != nil {
		if !publicKeysEqual(cert.PublicKey, opts.ExpectedPublicKey) {
			return nil, fmt.Errorf("%w: certificate public key does not match the key generated for enrollment", ErrInvalidCertificate)
		}
	}

	if err := validateChain(cert, opts, now); err != nil {
		return nil, err
	}

	return cert, nil
}

func parseCertificate(data []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert, nil
		}
	}
	if cert, err := x509.ParseCertificate(data); err == nil {
		return cert, nil
	}
	trimmed := stripASCIIWhitespace(data)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(decoded, trimmed)
	if err == nil {
		if cert, err := x509.ParseCertificate(decoded[:n]); err == nil {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("certificate is not valid PEM, DER, or base64 X.509")
}

// validateSANs enforces the localhost identity policy against the SAN fields
// exposed by the X.509 parser: the certificate must carry one DNS SAN
// ("localhost") and two IP SANs (127.0.0.1 and ::1). Additional DNS names, IP
// addresses, URIs, and email addresses are rejected, as are wildcards. Other
// GeneralName forms that the parser does not expose are not inspected here.
func validateSANs(cert *x509.Certificate) error {
	if len(cert.DNSNames) != 1 {
		return fmt.Errorf("%w: certificate must have exactly one DNS SAN (localhost), got %d", ErrInvalidCertificate, len(cert.DNSNames))
	}
	if !strings.EqualFold(cert.DNSNames[0], "localhost") {
		return fmt.Errorf("%w: disallowed SAN identity %q", ErrInvalidCertificate, cert.DNSNames[0])
	}

	if len(cert.IPAddresses) != 2 {
		return fmt.Errorf("%w: certificate must have exactly two IP SANs (127.0.0.1 and ::1), got %d", ErrInvalidCertificate, len(cert.IPAddresses))
	}
	var hasIPv4, hasIPv6 bool
	for _, ip := range cert.IPAddresses {
		switch {
		case ip.Equal(net.IPv4(127, 0, 0, 1)):
			if hasIPv4 {
				return fmt.Errorf("%w: duplicate SAN IP %s", ErrInvalidCertificate, ip)
			}
			hasIPv4 = true
		case ip.Equal(net.IPv6loopback):
			if hasIPv6 {
				return fmt.Errorf("%w: duplicate SAN IP %s", ErrInvalidCertificate, ip)
			}
			hasIPv6 = true
		default:
			return fmt.Errorf("%w: disallowed SAN IP %s", ErrInvalidCertificate, ip)
		}
	}
	if !hasIPv4 || !hasIPv6 {
		return fmt.Errorf("%w: certificate must include exactly the loopback IP SANs 127.0.0.1 and ::1", ErrInvalidCertificate)
	}

	if len(cert.URIs) > 0 || len(cert.EmailAddresses) > 0 {
		return fmt.Errorf("%w: disallowed non-DNS/IP SAN identity", ErrInvalidCertificate)
	}

	return nil
}

// validateUsage requires the Server Authentication EKU and the
// digitalSignature key usage.
func validateUsage(cert *x509.Certificate) error {
	hasServerAuth := false
	for _, ku := range cert.ExtKeyUsage {
		if ku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		for _, oid := range cert.UnknownExtKeyUsage {
			if oid.String() == serverAuthOID {
				hasServerAuth = true
				break
			}
		}
	}
	if !hasServerAuth {
		return fmt.Errorf("%w: missing Server Authentication EKU (%s)", ErrInvalidCertificate, serverAuthOID)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: missing digitalSignature key usage", ErrInvalidCertificate)
	}
	return nil
}

func publicKeysEqual(a, b any) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(da, db)
}

// validateChain verifies the certificate against the platform/system trust
// available to the calling process (x509.SystemCertPool by default, or the
// caller-provided ValidateOptions.Roots).
func validateChain(cert *x509.Certificate, opts ValidateOptions, now time.Time) error {
	roots := opts.Roots
	if roots == nil {
		roots, _ = x509.SystemCertPool()
	}
	intermediates := opts.Intermediates
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime:   now,
	})
	if err != nil {
		return fmt.Errorf("%w: chain/trust verification failed: %v", ErrInvalidCertificate, err)
	}
	return nil
}
