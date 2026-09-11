package enterprise

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func validLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	root, rootKey := rootCA(t)
	leafKey := mustRSAKey(t)
	return issueCert(t, leafTemplate(), root, rootKey, &leafKey.PublicKey)
}

func TestParsePKCS7_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":      {},
		"garbage":    []byte("this is not DER and not base64 pkcs7"),
		"random-bin": {0xDE, 0xAD, 0xBE, 0xEF},
	}
	for name, in := range cases {
		if _, err := parsePKCS7Certificates(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParsePKCS7_Truncated(t *testing.T) {
	leaf := validLeaf(t)
	full := buildPKCS7(t, leaf)
	for _, cut := range []int{1, 5, len(full) / 2, len(full) - 1} {
		if _, err := parsePKCS7Certificates(full[:cut]); err == nil {
			t.Errorf("truncated at %d bytes: expected error, got nil", cut)
		}
	}
}

func TestParsePKCS7_WrongContentType(t *testing.T) {
	leaf := validLeaf(t)
	sd := buildSignedDataDER(t, leaf)
	blob := buildContentInfo(t, oidDataDER, sd) // "data" content type, not SignedData

	if _, err := parsePKCS7Certificates(blob); err == nil {
		t.Fatal("expected error for non-SignedData content type")
	}
}

func TestParsePKCS7_NoCertificates(t *testing.T) {
	blob := buildPKCS7(t) // valid SignedData, empty certificate set
	certs, err := parsePKCS7Certificates(blob)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("expected zero certificates, got %d", len(certs))
	}
}

func TestParsePKCS7_Base64Input(t *testing.T) {
	leaf := validLeaf(t)
	b64 := base64.StdEncoding.EncodeToString(buildPKCS7(t, leaf))

	got, err := parsePKCS7Certificates([]byte(b64))
	if err != nil {
		t.Fatalf("parsePKCS7Certificates(base64): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(got))
	}
	if !publicKeysEqual(got[0].PublicKey, leaf.PublicKey) {
		t.Fatal("public key mismatch")
	}
}
