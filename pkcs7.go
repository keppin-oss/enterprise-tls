package enterprise

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// oidSignedData is the PKCS#7/CMS SignedData content type OID.
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// pkcs7ContentInfo mirrors the CMS ContentInfo structure.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

// pkcs7SignedData mirrors the minimal CMS SignedData structure needed to
// extract certificates from a chain response. signerInfos is intentionally
// omitted; encoding/asn1 returns trailing elements as rest.
type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	ContentInfo      struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}
	Certificates asn1.RawValue `asn1:"tag:0,optional"`
}

// parsePKCS7Certificates extracts every certificate embedded in a PKCS#7
// SignedData structure (the certreq.exe "certchainfileout" format). The input
// may be raw DER, base64-encoded DER, or a single PEM block (see
// decodePKCS7DER for the exact policy).
func parsePKCS7Certificates(data []byte) ([]*x509.Certificate, error) {
	der, err := decodePKCS7DER(data)
	if err != nil {
		return nil, err
	}

	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("decode PKCS#7 ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("not a PKCS#7 SignedData (content type %s)", ci.ContentType)
	}

	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("decode PKCS#7 SignedData: %w", err)
	}

	if len(sd.Certificates.Bytes) == 0 {
		return nil, nil
	}
	rawCerts, err := decodeCertElements(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decode PKCS#7 certificate set: %w", err)
	}

	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, rc := range rawCerts {
		c, err := x509.ParseCertificate(rc.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#7 certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// decodeCertElements parses a (possibly SET-wrapped) run of DER certificates
// into raw elements. Some producers encode an explicit SET wrapper; others
// use the IMPLICIT [0] form that omits it. A progress guard prevents any
// possibility of a non-terminating loop on malformed input.
func decodeCertElements(b []byte) ([]asn1.RawValue, error) {
	rest := b
	if len(rest) > 0 && rest[0] == 0x31 {
		var set asn1.RawValue
		if _, err := asn1.Unmarshal(rest, &set); err == nil {
			rest = set.Bytes
		}
	}
	var out []asn1.RawValue
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		next, err := asn1.Unmarshal(rest, &rv)
		if err != nil {
			return nil, err
		}
		if len(next) >= len(rest) {
			return nil, fmt.Errorf("PKCS#7 certificate set made no progress")
		}
		out = append(out, rv)
		rest = next
	}
	return out, nil
}

// pkcs7PEMLabels are the PEM labels accepted for a chain file. certreq.exe
// labels its PKCS#7 output "CERTIFICATE"; "PKCS7" is the RFC 7468 label.
var pkcs7PEMLabels = map[string]bool{"CERTIFICATE": true, "PKCS7": true}

// chainWhitespace is the whitespace tolerated around a chain file encoding:
// space, tab, CR and LF (not VT or FF).
const chainWhitespace = " \t\r\n"

// decodePKCS7DER returns the DER ContentInfo of a chain file. Exactly one of
// these encodings is accepted, with nothing around it but chainWhitespace:
//
//   - raw DER;
//   - a single PEM block labelled "CERTIFICATE" or "PKCS7", without headers;
//   - bare base64 of the DER.
//
// In every form the DER must be a single ContentInfo. Around raw DER, trailing
// whitespace is recognised only after the end given by the encoded length, so
// content bytes that happen to equal a whitespace byte are never trimmed.
// Anything else (text before or after the PEM block, several blocks, other
// labels, PEM headers, trailing bytes) is rejected rather than interpreted.
// The SignedData content type is enforced by the caller.
func decodePKCS7DER(data []byte) ([]byte, error) {
	data = bytes.TrimLeft(data, chainWhitespace)
	if len(data) > 0 && data[0] == 0x30 {
		rest, err := asn1.Unmarshal(data, &pkcs7ContentInfo{})
		if err != nil {
			return nil, fmt.Errorf("decode PKCS#7 ContentInfo: %w", err)
		}
		if len(bytes.TrimLeft(rest, chainWhitespace)) != 0 {
			return nil, fmt.Errorf("unexpected bytes after the PKCS#7 ContentInfo")
		}
		return data[:len(data)-len(rest)], nil
	}
	trimmed := bytes.TrimRight(data, chainWhitespace)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return decodePKCS7PEM(trimmed)
	}
	clean := stripASCIIWhitespace(trimmed)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
	n, err := base64.StdEncoding.Decode(decoded, clean)
	if err != nil || n == 0 {
		return nil, fmt.Errorf("PKCS#7 data is not DER, PEM or base64")
	}
	return singleContentInfo(decoded[:n])
}

// decodePKCS7PEM decodes data that starts with a PEM boundary and must contain
// exactly one block. Counting the boundaries matters: on a malformed block
// pem.Decode silently moves on to the next one.
func decodePKCS7PEM(data []byte) ([]byte, error) {
	if bytes.Count(data, []byte("-----BEGIN ")) != 1 || bytes.Count(data, []byte("-----END ")) != 1 {
		return nil, fmt.Errorf("PKCS#7 PEM data must contain exactly one PEM block")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("malformed PEM block in PKCS#7 data")
	}
	if len(bytes.Trim(rest, chainWhitespace)) != 0 {
		return nil, fmt.Errorf("unexpected data after the PKCS#7 PEM block")
	}
	if !pkcs7PEMLabels[block.Type] {
		return nil, fmt.Errorf("unsupported PEM label %q for PKCS#7 data", block.Type)
	}
	if len(block.Headers) != 0 {
		return nil, fmt.Errorf("PEM headers are not supported for PKCS#7 data")
	}
	der, err := singleContentInfo(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("PEM block %q: %w", block.Type, err)
	}
	return der, nil
}

// singleContentInfo checks that der is exactly one ContentInfo.
func singleContentInfo(der []byte) ([]byte, error) {
	rest, err := asn1.Unmarshal(der, &pkcs7ContentInfo{})
	if err != nil {
		return nil, fmt.Errorf("decode PKCS#7 ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d unexpected bytes after the PKCS#7 ContentInfo", len(rest))
	}
	return der, nil
}
