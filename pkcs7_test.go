package enterprise

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

// certreq.exe -submit writes the chain as PEM with CRLF line endings and the
// label "CERTIFICATE", although the payload is PKCS#7 SignedData.
func TestParsePKCS7_CertreqPEMInput(t *testing.T) {
	leaf := validLeaf(t)
	for _, label := range []string{"CERTIFICATE", "PKCS7"} {
		armored := pem.EncodeToMemory(&pem.Block{Type: label, Bytes: buildPKCS7(t, leaf)})
		crlf := bytes.ReplaceAll(armored, []byte("\n"), []byte("\r\n"))

		got, err := parsePKCS7Certificates(crlf)
		if err != nil {
			t.Fatalf("%s: parsePKCS7Certificates(PEM): %v", label, err)
		}
		if len(got) != 1 || !publicKeysEqual(got[0].PublicKey, leaf.PublicKey) {
			t.Fatalf("%s: expected the leaf certificate, got %d certificates", label, len(got))
		}
	}
}

// A PEM block that is not PKCS#7 (for example a bare certificate) is rejected,
// not silently treated as an empty chain.
func TestParsePKCS7_PEMNotPKCS7(t *testing.T) {
	leaf := validLeaf(t)
	armored := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if _, err := parsePKCS7Certificates(armored); err == nil {
		t.Fatal("expected error for a PEM certificate that is not PKCS#7")
	}
}

// The chain file policy: exactly one encoding, with only whitespace around it.
func TestParsePKCS7_PEMPolicy(t *testing.T) {
	leaf := validLeaf(t)
	good := buildPKCS7(t, leaf)
	armor := func(label string, headers map[string]string, der []byte) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: label, Headers: headers, Bytes: der})
	}
	valid := armor("CERTIFICATE", nil, good)
	bareCert := armor("CERTIFICATE", nil, leaf.Raw)
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	// A block whose base64 body is broken, so pem.Decode cannot decode it.
	malformed := []byte("-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n")

	accepted := map[string][]byte{
		"surrounding whitespace": join([]byte("\r\n \t"), valid, []byte("\r\n\r\n")),
		"label PKCS7":            armor("PKCS7", nil, good),
		"DER then CRLF":          join(good, []byte("\r\n")),
		"whitespace then DER":    join([]byte(" \t\r\n"), good, []byte(" ")),
		"base64 with whitespace": join([]byte("\r\n "), []byte(base64.StdEncoding.EncodeToString(good)), []byte("\r\n")),
	}
	for name, in := range accepted {
		got, err := parsePKCS7Certificates(in)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
			continue
		}
		if len(got) != 1 {
			t.Errorf("%s: expected 1 certificate, got %d", name, len(got))
		}
	}

	trailing := append(append([]byte{}, good...), 0x05, 0x00)
	rejected := map[string][]byte{
		"arbitrary label":          armor("X509 CRL", nil, good),
		"PEM header":               armor("PKCS7", map[string]string{"Proc-Type": "4,ENCRYPTED"}, good),
		"text before block":        join([]byte("chain follows\n"), valid),
		"text after block":         join(valid, []byte("trailing text\n")),
		"two valid blocks":         join(valid, valid),
		"valid then bare cert":     join(valid, bareCert),
		"bare cert then valid":     join(bareCert, valid),
		"malformed then valid":     join(malformed, valid),
		"wrong OID in PEM":         armor("PKCS7", nil, buildContentInfo(t, oidDataDER, buildSignedDataDER(t, leaf))),
		"trailing bytes in PEM":    armor("PKCS7", nil, trailing),
		"trailing bytes in DER":    trailing,
		"DER then whitespace+junk": join(good, []byte("\r\nx")),
		"DER then VT":              join(good, []byte("\v")),
		"FF then DER":              join([]byte("\f"), good),
		"trailing bytes in base64": []byte(base64.StdEncoding.EncodeToString(trailing)),
		"unterminated block":       []byte("-----BEGIN PKCS7-----\n" + base64.StdEncoding.EncodeToString(good) + "\n"),
		"base64 of a bare cert":    []byte(base64.StdEncoding.EncodeToString(leaf.Raw)),
	}
	for name, in := range rejected {
		if _, err := parsePKCS7Certificates(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// Trailing whitespace after raw DER is recognised from the encoded length:
// content bytes equal to whitespace (here a final LF inside the ContentInfo)
// are kept.
func TestDecodePKCS7DER_KeepsWhitespaceValuedContent(t *testing.T) {
	der := buildContentInfo(t, oidDataDER, []byte{0x04, 0x02, 0x20, 0x0A}) // OCTET STRING " \n"
	got, err := decodePKCS7DER(append(append([]byte{}, der...), '\r', '\n', ' '))
	if err != nil {
		t.Fatalf("decodePKCS7DER: %v", err)
	}
	if !bytes.Equal(got, der) {
		t.Fatalf("DER changed: got % x, want % x", got, der)
	}
}

// A well-formed but empty SignedData stays an empty result in PEM form too;
// Enroll rejects it separately.
func TestParsePKCS7_PEMNoCertificates(t *testing.T) {
	in := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: buildPKCS7(t)})
	certs, err := parsePKCS7Certificates(in)
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
