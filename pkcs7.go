package enterprise

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
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
// may be raw DER or base64-encoded DER.
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

func decodePKCS7DER(data []byte) ([]byte, error) {
	if _, err := asn1.Unmarshal(data, &pkcs7ContentInfo{}); err == nil {
		return data, nil
	}
	trimmed := stripASCIIWhitespace(data)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(decoded, trimmed)
	if err != nil {
		return nil, fmt.Errorf("PKCS#7 data is not DER or base64")
	}
	return decoded[:n], nil
}
