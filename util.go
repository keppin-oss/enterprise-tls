package enterprise

import (
	"crypto/sha256"
	"encoding/hex"
)

// expectedCNGProvider is the only CNG key storage provider this module creates,
// binds and deletes keys in.
const expectedCNGProvider = "Microsoft Software Key Storage Provider"

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

// sha256Hex returns the lowercase hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
