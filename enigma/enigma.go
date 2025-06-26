package enigma

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrInvalidCiphertext = errors.New("ciphertext is not valid")

	hasher = sha512.New
)

type Enigma struct {
	aead      cipher.AEAD
	nonceSize int
}

func NewEnigma(secret, salt []byte) (*Enigma, error) {
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
