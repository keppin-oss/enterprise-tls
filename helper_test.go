package enterprise

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// issueCert signs tmpl using parentKey, with parentCert as the issuer. For a
// self-signed root, pass tmpl itself as parentCert.
func issueCert(t *testing.T, tmpl, parentCert *x509.Certificate, parentKey *rsa.PrivateKey, pub any) *x509.Certificate {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	if tmpl.SubjectKeyId == nil {
		tmpl.SubjectKeyId = []byte{1, 2, 3, 4}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, parentKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func rootCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key := mustRSAKey(t)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return issueCert(t, tmpl, tmpl, key, &key.PublicKey), key
}

func leafTemplate() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:   big.NewInt(2),
		Subject:        pkix.Name{CommonName: "localhost"},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:       []string{"localhost"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		SubjectKeyId:   []byte{1, 2, 3, 4},
		AuthorityKeyId: []byte{5, 6, 7, 8},
	}
}

func rootsPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}
