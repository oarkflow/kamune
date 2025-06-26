package enigma

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ArgonTime    = 2
	ArgonMemory  = 64 * 1024
	ArgonThreads = 4
	ArgonKeyLen  = 32
)

var (
	ErrInvalidCiphertext = errors.New("ciphertext is not valid")
)

type Enigma struct {
	aead      cipher.AEAD
	nonceSize int
}

func NewEnigma(secret, salt []byte) (*Enigma, error) {
	key := argon2.IDKey(
		secret, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen,
	)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &Enigma{aead: aead, nonceSize: aead.NonceSize()}, nil
}

func (e *Enigma) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make(
		[]byte, e.nonceSize, e.nonceSize+len(plaintext)+e.aead.Overhead(),
	)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := e.aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

func (e *Enigma) Decrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) < e.nonceSize {
		return nil, ErrInvalidCiphertext
	}
	nonce, ciphertext := encrypted[:e.nonceSize], encrypted[e.nonceSize:]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	return plaintext, nil
}
