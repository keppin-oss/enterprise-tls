package enterprise

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"math/big"
)

// parseECCPublicBlob decodes a BCRYPT_ECCKEY_BLOB with the
// BCRYPT_ECDSA_PUBLIC_P256_MAGIC header: dwMagic, cbKey, then X and Y of
// cbKey bytes each. Anything else, or a point not on P-256, is an error.
func parseECCPublicBlob(blob []byte) (*ecdsa.PublicKey, error) {
	const magicP256 = 0x31534345
	if len(blob) != 8+64 || binary.LittleEndian.Uint32(blob) != magicP256 || binary.LittleEndian.Uint32(blob[4:]) != 32 {
		return nil, errors.New("not an ECDSA P-256 public key blob")
	}
	point := append([]byte{4}, blob[8:]...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, errors.New("public key blob is not a P-256 point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(),
		X: new(big.Int).SetBytes(blob[8:40]), Y: new(big.Int).SetBytes(blob[40:72])}, nil
}
