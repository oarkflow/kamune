package enigma

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	nonceSize     = chacha20poly1305.NonceSizeX
	uint64Size    = int(unsafe.Sizeof(uint64(0)))
	BaseNonceSize = nonceSize - uint64Size
	SaltSize      = 32
)

var (
	ErrInvalidNonceLength = errors.New("bad nonce length")

	hasher = sha512.New
)

type Enigma struct {
	aead      cipher.AEAD
	baseNonce []byte
}

func NewEnigma(secret, salt, baseNonce []byte) (*Enigma, error) {
	if len(baseNonce) != BaseNonceSize {
		return nil, ErrInvalidNonceLength
	}
	salt = hasher().Sum(salt)
	r := hkdf.New(hasher, secret, salt, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("xchacha20poly1305: %w", err)
	}

	return &Enigma{aead: aead, baseNonce: baseNonce}, nil
}

func (e *Enigma) Encrypt(plaintext []byte, counter uint64) []byte {
	return e.aead.Seal(nil, e.nonce(counter), plaintext, nil)
}

func (e *Enigma) Decrypt(ciphertext []byte, counter uint64) ([]byte, error) {
	return e.aead.Open(nil, e.nonce(counter), ciphertext, nil)
}

func (e *Enigma) nonce(counter uint64) []byte {
	nonce := make([]byte, nonceSize)
	copy(nonce[:BaseNonceSize], e.baseNonce)
	binary.LittleEndian.PutUint64(nonce[BaseNonceSize:], counter)
	return nonce
}
