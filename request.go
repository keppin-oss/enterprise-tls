package enterprise

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// keyContainerPrefix namespaces this module's CNG key containers so they cannot
// collide with key names owned by other components.
const keyContainerPrefix = "keppin-enterprise-tls-"

// newKeyContainer returns a unique, Enterprise-TLS-namespaced CNG key container
// name. It must be generated before certreq -new so the key identity is known
// even if enrollment later fails.
func newKeyContainer() (string, error) {
	u, err := newUUID()
	if err != nil {
		return "", err
	}
	return keyContainerPrefix + u, nil
}

// newUUID returns a random RFC 4122 version 4 UUID string.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// BuildRequestINF renders the certreq.exe request (INF) content for a
// machine-scoped, localhost-only server-authentication certificate.
//
// keyContainer, when non-empty, is the CNG key container name that certreq -new
// must generate the key into. It is fixed for the enrollment attempt (a
// randomly generated, module-namespaced name) so the key identity is known
// before key creation.
//
// The INF requires a machine-scoped private key in the Microsoft Software Key
// Storage Provider (MachineKeySet = TRUE) that is not exportable
// (Exportable = FALSE). The module does not subsequently verify either the
// resulting key export policy or the actual machine-scope ownership of the
// key, and it never writes private-key material as PEM or PFX.
func BuildRequestINF(cfg Config, keyContainer string) string {
	var b strings.Builder
	b.WriteString("[Version]\n")
	b.WriteString("Signature = \"$Windows NT$\"\n")
	b.WriteString("\n")
	b.WriteString("[NewRequest]\n")
	b.WriteString("Subject = \"CN=localhost\"\n")
	b.WriteString("Exportable = FALSE\n")
	b.WriteString("MachineKeySet = TRUE\n")
	b.WriteString("SMIME = FALSE\n")
	b.WriteString("PrivateKeyArchive = FALSE\n")
	b.WriteString("UseExistingKeySet = FALSE\n")
	if keyContainer != "" {
		b.WriteString("KeyContainer = \"" + keyContainer + "\"\n")
	}
	b.WriteString("ProviderName = \"Microsoft Software Key Storage Provider\"\n")
	b.WriteString("ProviderType = 0\n")
	b.WriteString("KeyLength = 2048\n")
	b.WriteString("KeyUsage = 0xA0\n") // digitalSignature | keyEncipherment
	b.WriteString("HashAlgorithm = sha256\n")
	b.WriteString("RequestType = PKCS10\n")
	if cfg.Template != "" {
		b.WriteString("CertificateTemplate = " + cfg.Template + "\n")
	}
	b.WriteString("\n")
	b.WriteString("[Extensions]\n")
	b.WriteString("2.5.29.17 = \"{text}\"\n")
	b.WriteString("_continue_ = \"dns=localhost&\"\n")
	b.WriteString("_continue_ = \"ipaddress=127.0.0.1&\"\n")
	b.WriteString("_continue_ = \"ipaddress=::1\"\n")
	b.WriteString("2.5.29.37 = \"{text}1.3.6.1.5.5.7.3.1\"\n")
	return b.String()
}

// parseRequestPublicKey extracts the public key from a certreq.exe "-new"
// request file. certreq writes PKCS#10, which may be PEM-wrapped, raw DER, or
// base64-encoded. It returns an error if the request cannot be parsed.
func parseRequestPublicKey(data []byte) (any, error) {
	der, err := decodeRequestDER(data)
	if err != nil {
		return nil, err
	}
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("request signature check: %w", err)
	}
	return req.PublicKey, nil
}

func decodeRequestDER(data []byte) ([]byte, error) {
	// PEM-wrapped request ("CERTIFICATE REQUEST" / "NEW CERTIFICATE REQUEST").
	if block, _ := pem.Decode(data); block != nil && strings.Contains(block.Type, "CERTIFICATE REQUEST") {
		return block.Bytes, nil
	}
	// Raw DER.
	if _, err := x509.ParseCertificateRequest(data); err == nil {
		return data, nil
	}
	// Base64 (strip whitespace/newlines).
	trimmed := stripASCIIWhitespace(data)
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(trimmed)))
	n, err := base64.StdEncoding.Decode(decoded, trimmed)
	if err != nil {
		return nil, fmt.Errorf("request is not PEM, DER, or base64 PKCS#10")
	}
	return decoded[:n], nil
}
