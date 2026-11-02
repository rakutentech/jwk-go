// Package akp implements the "AKP" (Algorithm Key Pair) JWK key type used to
// represent post-quantum signature keys such as ML-DSA (FIPS 204).
//
// The key material is held as the raw FIPS 204 byte encodings, mirroring how
// the okp package represents Ed25519 and X25519 keys. No signing or
// verification is performed here; this package only validates and carries the
// encoded key, following draft-ietf-jose-pqc.
package akp

import (
	"errors"
	"fmt"
)

// JWA algorithm names for ML-DSA (FIPS 204), as used in the JWK "alg" field.
const (
	MLDSA44 = "ML-DSA-44"
	MLDSA65 = "ML-DSA-65"
	MLDSA87 = "ML-DSA-87"
)

// FIPS 204 encoded public key sizes in bytes, keyed by algorithm name.
var publicKeySizes = map[string]int{
	MLDSA44: 1312,
	MLDSA65: 1952,
	MLDSA87: 2592,
}

// FIPS 204 expanded private key sizes in bytes, keyed by algorithm name.
var privateKeySizes = map[string]int{
	MLDSA44: 2560,
	MLDSA65: 4032,
	MLDSA87: 4896,
}

// seedSize is the length of the ML-DSA key generation seed (xi) in bytes.
// The JOSE post-quantum drafts allow the private key to be carried either as
// this seed or as the expanded private key above.
const seedSize = 32

// Key is an ML-DSA algorithm key pair held as the raw FIPS 204 encodings.
type Key struct {
	algorithm  string
	publicKey  []byte
	privateKey []byte
}

// Algorithm returns the JWA algorithm name of the key.
func (k Key) Algorithm() string { return k.algorithm }

// PublicKey returns the raw encoded public key.
func (k Key) PublicKey() []byte { return k.publicKey }

// PrivateKey returns the raw encoded private key, or nil for a public-only key.
func (k Key) PrivateKey() []byte { return k.privateKey }

// NewKey builds an ML-DSA key pair after validating the encoded sizes.
// privKey may be nil for a public-only key.
func NewKey(algorithm string, pubKey []byte, privKey []byte) (Key, error) {
	pubSize, ok := publicKeySizes[algorithm]
	if !ok {
		return Key{}, fmt.Errorf("unknown ML-DSA algorithm: %s", algorithm)
	}
	if len(pubKey) == 0 {
		return Key{}, errors.New("missing public key for ML-DSA key")
	}
	if len(pubKey) != pubSize {
		return Key{}, fmt.Errorf("ML-DSA %s public key must be %d bytes, got %d",
			algorithm, pubSize, len(pubKey))
	}
	if privKey != nil {
		privSize := privateKeySizes[algorithm]
		if len(privKey) != privSize && len(privKey) != seedSize {
			return Key{}, fmt.Errorf("ML-DSA %s private key must be %d bytes (expanded) or %d bytes (seed), got %d",
				algorithm, privSize, seedSize, len(privKey))
		}
	}
	return Key{algorithm: algorithm, publicKey: pubKey, privateKey: privKey}, nil
}

// ExtractPublic returns a public-only copy of the key.
func (k Key) ExtractPublic() Key {
	return Key{algorithm: k.algorithm, publicKey: k.publicKey, privateKey: nil}
}
