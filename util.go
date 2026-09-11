package enterprise

import (
	"crypto/sha1"
	"encoding/hex"
)

// stripASCIIWhitespace removes spaces, tabs, CR and LF from a byte slice.
func stripASCIIWhitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			out = append(out, c)
		}
	}
	return out
}

// sha1Thumbprint returns the lowercase hex SHA-1 thumbprint of a DER-encoded
// certificate, matching the "Thumbprint" shown by Windows cert tools.
func sha1Thumbprint(der []byte) string {
	h := sha1.Sum(der)
	return hex.EncodeToString(h[:])
}
