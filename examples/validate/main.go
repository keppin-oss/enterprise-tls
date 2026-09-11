// Command validate demonstrates the strict localhost certificate validation
// policy using synthetic in-memory fixtures (a self-signed root CA and a
// matching localhost leaf certificate).
//
// It does not touch the machine certificate store, CNG, certreq.exe, or any
// trust store, and it does not weaken trust or identity verification. It uses
// the real public validation entry point enterprise.ValidateCertificate with an
// explicit injected trust root, so the strict localhost/key/trust checks are
// exercised as implemented.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	enterprise "github.com/keppin-oss/enterprise-tls"
)

func main() {
	root, rootKey, err := selfSignedRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, "root:", err)
		return
	}
	leaf, leafKey, err := localhostLeaf(root, rootKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "leaf:", err)
		return
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)

	validated, err := enterprise.ValidateCertificate(leaf.Raw, enterprise.ValidateOptions{
		Roots:             roots,
		ExpectedPublicKey: &leafKey.PublicKey,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "unexpected validation failure:", err)
		return
	}

	fmt.Println("validation passed for:", validated.Subject.CommonName)
	fmt.Println("DNS SANs:", validated.DNSNames)
	fmt.Println("IP SANs:", validated.IPAddresses)
}

func selfSignedRoot() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func localhostLeaf(root *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
