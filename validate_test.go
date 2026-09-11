package enterprise

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestValidateCertificate_Success(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	cert := issueCert(t, leafTemplate(), root, rootKey, &key.PublicKey)

	got, err := ValidateCertificate(cert.Raw, ValidateOptions{
		Roots:             rootsPool(root),
		ExpectedPublicKey: &key.PublicKey,
	})
	if err != nil {
		t.Fatalf("ValidateCertificate: %v", err)
	}
	if got == nil {
		t.Fatal("expected certificate")
	}
}

func TestValidateCertificate_Malformed(t *testing.T) {
	if _, err := ValidateCertificate([]byte("not a certificate"), ValidateOptions{}); err == nil {
		t.Fatal("expected error for malformed input")
	}
}

func TestValidateCertificate_NotYetValid(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.NotBefore = time.Now().Add(time.Hour)
	tmpl.NotAfter = time.Now().Add(2 * time.Hour)
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	if _, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)}); err == nil {
		t.Fatal("expected error for not-yet-valid certificate")
	}
}

func TestValidateCertificate_Expired(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.NotBefore = time.Now().Add(-2 * time.Hour)
	tmpl.NotAfter = time.Now().Add(-time.Hour)
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	if _, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)}); err == nil {
		t.Fatal("expected error for expired certificate")
	}
}

func TestValidateCertificate_WrongSAN(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.DNSNames = []string{"server01.contoso.com"}
	tmpl.IPAddresses = nil
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for non-localhost SAN")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_WildcardSAN(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.DNSNames = []string{"*.localhost"}
	tmpl.IPAddresses = nil
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for wildcard SAN")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_NoSAN(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.DNSNames = nil
	tmpl.IPAddresses = nil
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for missing SAN")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_WrongEKU(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for missing Server Authentication EKU")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_WrongKeyUsage(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.KeyUsage = x509.KeyUsageKeyEncipherment
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for missing digitalSignature key usage")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_KeyMismatch(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	otherKey := mustRSAKey(t)
	cert := issueCert(t, leafTemplate(), root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{
		Roots:             rootsPool(root),
		ExpectedPublicKey: &otherKey.PublicKey,
	})
	if err == nil {
		t.Fatal("expected error for key mismatch")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_Untrusted(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	cert := issueCert(t, leafTemplate(), root, rootKey, &key.PublicKey)

	// Different root: the leaf should not verify.
	otherRoot, _ := rootCA(t)
	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(otherRoot)})
	if err == nil {
		t.Fatal("expected error for untrusted chain")
	}
	assertInvalid(t, err)
}

func TestValidateCertificate_Intermediates(t *testing.T) {
	root, rootKey := rootCA(t)
	interKey := mustRSAKey(t)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	inter := issueCert(t, interTmpl, root, rootKey, &interKey.PublicKey)

	leafKey := mustRSAKey(t)
	leaf := issueCert(t, leafTemplate(), inter, interKey, &leafKey.PublicKey)

	_, err := ValidateCertificate(leaf.Raw, ValidateOptions{
		Roots:         rootsPool(root),
		Intermediates: rootsPool(inter),
	})
	if err != nil {
		t.Fatalf("ValidateCertificate with intermediate: %v", err)
	}
}

func TestValidateCertificate_RejectsNonLocalhostIP(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)
	tmpl := leafTemplate()
	tmpl.DNSNames = nil
	tmpl.IPAddresses = []net.IP{net.IPv4(192, 168, 1, 10)}
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for LAN IP SAN")
	}
	assertInvalid(t, err)
}

func TestValidateSANs(t *testing.T) {
	loopback4 := net.IPv4(127, 0, 0, 1)
	loopback6 := net.IPv6loopback

	tests := []struct {
		name   string
		dns    []string
		ips    []net.IP
		emails []string
		uris   []*url.URL
		want   bool
	}{
		{name: "exact set", dns: []string{"localhost"}, ips: []net.IP{loopback4, loopback6}, want: true},
		{name: "exact set mixed case dns", dns: []string{"LOCALHOST"}, ips: []net.IP{loopback4, loopback6}, want: true},
		{name: "only localhost", dns: []string{"localhost"}, want: false},
		{name: "localhost plus ipv4 only", dns: []string{"localhost"}, ips: []net.IP{loopback4}, want: false},
		{name: "localhost plus ipv6 only", dns: []string{"localhost"}, ips: []net.IP{loopback6}, want: false},
		{name: "only the two ips", ips: []net.IP{loopback4, loopback6}, want: false},
		{name: "extra dns", dns: []string{"localhost", "localhost.localdomain"}, ips: []net.IP{loopback4, loopback6}, want: false},
		{name: "extra ip", dns: []string{"localhost"}, ips: []net.IP{loopback4, loopback6, net.IPv4(127, 0, 0, 2)}, want: false},
		{name: "wildcard dns", dns: []string{"*.localhost"}, ips: []net.IP{loopback4, loopback6}, want: false},
		{name: "duplicate dns", dns: []string{"localhost", "localhost"}, ips: []net.IP{loopback4, loopback6}, want: false},
		{name: "duplicate ipv4", dns: []string{"localhost"}, ips: []net.IP{loopback4, loopback4}, want: false},
		{name: "duplicate ipv6", dns: []string{"localhost"}, ips: []net.IP{loopback6, loopback6}, want: false},
		{name: "wrong dns lan", dns: []string{"server01.contoso.com"}, ips: []net.IP{loopback4, loopback6}, want: false},
		{name: "public ip", dns: []string{"localhost"}, ips: []net.IP{loopback4, net.IPv4(8, 8, 8, 8)}, want: false},
		{name: "unspecified ip", dns: []string{"localhost"}, ips: []net.IP{loopback4, net.IPv4zero}, want: false},
		{name: "link local ip", dns: []string{"localhost"}, ips: []net.IP{loopback4, net.ParseIP("169.254.1.1")}, want: false},
		{name: "no san", want: false},
		{name: "email san", dns: []string{"localhost"}, ips: []net.IP{loopback4, loopback6}, emails: []string{"a@b.c"}, want: false},
		{name: "uri san", dns: []string{"localhost"}, ips: []net.IP{loopback4, loopback6}, uris: []*url.URL{{Host: "example.com"}}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				DNSNames:       tt.dns,
				IPAddresses:    tt.ips,
				EmailAddresses: tt.emails,
				URIs:           tt.uris,
			}
			err := validateSANs(cert)
			if tt.want {
				if err != nil {
					t.Fatalf("validateSANs: unexpected error %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			assertInvalid(t, err)
		})
	}
}

func TestValidateCertificate_DuplicateSANRoundTrip(t *testing.T) {
	root, rootKey := rootCA(t)
	key := mustRSAKey(t)

	tmpl := leafTemplate()
	tmpl.DNSNames = []string{"localhost", "localhost"}
	tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 1)}
	cert := issueCert(t, tmpl, root, rootKey, &key.PublicKey)

	_, err := ValidateCertificate(cert.Raw, ValidateOptions{Roots: rootsPool(root)})
	if err == nil {
		t.Fatal("expected error for duplicate SANs")
	}
	assertInvalid(t, err)
}

func assertInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected ErrInvalidCertificate, got %v", err)
	}
}
