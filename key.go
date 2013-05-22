package fernet

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
	"time"
)

var errKeyLen = errors.New("fernet: key decodes to wrong size")

type Key []byte

// Decodes a base64-encoded key from s and returns it.
func DecodeKey(s string) (Key, error) {
	b, err := encoding.DecodeString(s)
	return Key(b), err
}

// MustDecodeKey is like DecodeKey, but panics if an error occurs.
// It simplifies safe initialization of global variables holding keys.
func MustDecodeKey(s string) Key {
	k, err := DecodeKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

// Generates a pseudorandom key using package crypto/rand.
func GenKey() (*Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

func (k Key) cryptBytes() []byte {
	return k[len(k)/2:][:16]
}

func (k Key) signBytes() []byte {
	return k[:len(k)/2]
}

// Returns the base64 encoding of k.
func (k Key) Encode() string {
	b := make([]byte, encoding.EncodedLen(len(k)))
	encoding.Encode(b, k[:])
	return string(b)
}

// Encrypts and signs msg with key k and returns the resulting fernet token.
func (k Key) EncryptAndSign(msg []byte) (tok []byte, err error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return gen(msg, iv, time.Now(), k)
}

// Verifies that tok is a valid fernet token that was signed at most ttl time
// ago, and returns the decrypted plaintext message contained in it.
//
// Returns nil if tok is invalid.
func (k Key) VerifyAndDecrypt(tok []byte, ttl time.Duration) (msg []byte) {
	if !bytes.Contains(tok, pipe) {
		return jsonVerify(tok, ttl, time.Now(), k)
	}
	return verify(tok, ttl, time.Now(), k)
}
