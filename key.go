package kiwi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

// The key implementation is a modified version of github.com/WireGuard/wgctrl-go
//
// It is used here as WireGuard is considered secure and should be followed for
// good security examples.

// KeyLen is the expected key length for kiwi.
const KeyLen = 32

// A Key is a public, private, or pre-shared secret key.  The Key constructor
// functions in this package can be used to create Keys suitable for each of
// these applications.
type Key [KeyLen]byte

// GenerateKey generates a Key suitable for use as a pre-shared secret key from
// a cryptographically safe source.
//
// The output Key should not be used as a private key; use GeneratePrivateKey
// instead.
func GenerateKey() (Key, error) {
	b := make([]byte, KeyLen)
	if _, err := rand.Read(b); err != nil {
		return Key{}, fmt.Errorf("kiwi: failed to read random bytes: %v", err)
	}

	return NewKey(b)
}

// GeneratePrivateKey generates a Key suitable for use as a private key from a
// cryptographically safe source.
func GeneratePrivateKey() (Key, error) {
	key, err := GenerateKey()
	if err != nil {
		return Key{}, err
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	return key, nil
}

// NewKey creates a Key from an existing byte slice.  The byte slice must be
// exactly 32 bytes in length.
func NewKey(b []byte) (Key, error) {
	if len(b) != KeyLen {
		return Key{}, fmt.Errorf("kiwi: incorrect key size: %d", len(b))
	}

	var k Key
	copy(k[:], b)

	return k, nil
}

// ParseKey parses a Key from a base64-encoded string, as produced by the
// Key.String method.
func ParseKey(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("kiwi: failed to parse base64-encoded key: %v", err)
	}

	return NewKey(b)
}

// PublicKey computes a public key from the private key k.
//
// PublicKey should only be called when k is a private key.
func (k Key) PublicKey() Key {
	var (
		pub  [KeyLen]byte
		priv = [KeyLen]byte(k)
	)

	// ScalarBaseMult uses the correct base value per https://cr.yp.to/ecdh.html,
	// so no need to specify it.
	curve25519.ScalarBaseMult(&pub, &priv)

	return pub
}

func (k Key) SharedKey(publicKey Key) (Key, error) {
	sharedKey, err := curve25519.X25519(k[:], publicKey[:])
	if err != nil {
		return Key{}, err
	}
	return NewKey(sharedKey)
}

// String returns the base64-encoded string representation of a Key.
//
// ParseKey can be used to produce a new Key from this string.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

type KeyHash [32]byte

func (k Key) Hash() KeyHash {
	return sha256.Sum256(k[:])
}
