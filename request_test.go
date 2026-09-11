package enterprise

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildRequestINF(t *testing.T) {
	inf := BuildRequestINF(Config{CA: "ca1\\RootCA", Template: "WebServer"}, "")

	for _, want := range []string{
		"Signature = \"$Windows NT$\"",
		"Subject = \"CN=localhost\"",
		"Exportable = FALSE",
		"MachineKeySet = TRUE",
		"UseExistingKeySet = FALSE",
		"ProviderName = \"Microsoft Software Key Storage Provider\"",
		"RequestType = PKCS10",
		"CertificateTemplate = WebServer",
		"2.5.29.17 = \"{text}\"",
		"dns=localhost",
		"ipaddress=127.0.0.1",
		"ipaddress=::1",
		"2.5.29.37 = \"{text}1.3.6.1.5.5.7.3.1\"",
	} {
		if !strings.Contains(inf, want) {
			t.Errorf("BuildRequestINF missing %q\n%s", want, inf)
		}
	}

	for _, forbidden := range []string{"*.", "dns=*.", "contoso.com", "example.com"} {
		if strings.Contains(inf, forbidden) {
			t.Errorf("BuildRequestINF unexpectedly contains %q\n%s", forbidden, inf)
		}
	}
}

func TestBuildRequestINF_KeyContainer(t *testing.T) {
	inf := BuildRequestINF(Config{CA: "ca1\\RootCA"}, "keppin-enterprise-tls-test")
	if !strings.Contains(inf, "KeyContainer = \"keppin-enterprise-tls-test\"") {
		t.Errorf("BuildRequestINF missing exact KeyContainer:\n%s", inf)
	}
}

func TestBuildRequestINF_NoKeyContainer(t *testing.T) {
	inf := BuildRequestINF(Config{CA: "ca1\\RootCA"}, "")
	if strings.Contains(inf, "KeyContainer") {
		t.Errorf("KeyContainer should be omitted when empty:\n%s", inf)
	}
}

func TestBuildRequestINF_NoTemplate(t *testing.T) {
	inf := BuildRequestINF(Config{CA: "ca1\\RootCA"}, "")
	if strings.Contains(inf, "CertificateTemplate") {
		t.Errorf("CertificateTemplate should be omitted when unset:\n%s", inf)
	}
}

func TestBuildRequestINF_NoHardcodedCA(t *testing.T) {
	inf := BuildRequestINF(Config{CA: "ca1\\RootCA"}, "")
	if strings.Contains(inf, "ca1\\RootCA") {
		t.Errorf("CA identifier must not be embedded in the INF (it is a -config flag):\n%s", inf)
	}
}

func TestNewKeyContainer_Namespaced(t *testing.T) {
	c, err := newKeyContainer()
	if err != nil {
		t.Fatalf("newKeyContainer: %v", err)
	}
	if !strings.HasPrefix(c, keyContainerPrefix) {
		t.Fatalf("container %q must have Enterprise-TLS prefix %q", c, keyContainerPrefix)
	}
	if len(c) <= len(keyContainerPrefix) {
		t.Fatalf("container %q has no unique suffix", c)
	}
}

func TestNewKeyContainer_Unique(t *testing.T) {
	a, err := newKeyContainer()
	if err != nil {
		t.Fatalf("newKeyContainer: %v", err)
	}
	b, err := newKeyContainer()
	if err != nil {
		t.Fatalf("newKeyContainer: %v", err)
	}
	if a == b {
		t.Fatalf("expected distinct containers, got %q twice", a)
	}
}

func TestParseRequestPublicKey_PEM(t *testing.T) {
	key := mustRSAKey(t)
	csrDER := mustCSR(t, key)
	pem := "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
		base64.StdEncoding.EncodeToString(csrDER) + "\n" +
		"-----END NEW CERTIFICATE REQUEST-----\n"

	got, err := parseRequestPublicKey([]byte(pem))
	if err != nil {
		t.Fatalf("parseRequestPublicKey: %v", err)
	}
	if !publicKeysEqual(got, &key.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}

func TestParseRequestPublicKey_Base64(t *testing.T) {
	key := mustRSAKey(t)
	csrDER := mustCSR(t, key)
	b64 := base64.StdEncoding.EncodeToString(csrDER)

	got, err := parseRequestPublicKey([]byte(b64))
	if err != nil {
		t.Fatalf("parseRequestPublicKey: %v", err)
	}
	if !publicKeysEqual(got, &key.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}

func TestParseRequestPublicKey_DER(t *testing.T) {
	key := mustRSAKey(t)
	csrDER := mustCSR(t, key)

	got, err := parseRequestPublicKey(csrDER)
	if err != nil {
		t.Fatalf("parseRequestPublicKey: %v", err)
	}
	if !publicKeysEqual(got, &key.PublicKey) {
		t.Fatalf("public key mismatch")
	}
}

func TestParseRequestPublicKey_Garbage(t *testing.T) {
	if _, err := parseRequestPublicKey([]byte("not a request")); err == nil {
		t.Fatalf("expected error for garbage input")
	}
}

func mustCSR(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"},
	}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return csr
}
