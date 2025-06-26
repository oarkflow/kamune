package exchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
)

var (
	ErrInvalidInput = errors.New("invalid key type")
)

type ECDH struct {
	publicKey  *ecdh.PublicKey
	privateKey *ecdh.PrivateKey
}

func (e *ECDH) PublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (e *ECDH) Exchange(remote []byte) ([]byte, error) {
	parsed, err := x509.ParsePKIXPublicKey(remote)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	pub, ok := parsed.(*ecdh.PublicKey)
	if !ok {
		return nil, ErrInvalidInput
	}
	secret, err := e.privateKey.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("perform ECDH exchange: %w", err)
	}

	return secret, nil
}

func NewECDH() (*ECDH, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh: generating key: %w", err)
	}

	return &ECDH{privateKey: key, publicKey: key.PublicKey()}, nil
}
