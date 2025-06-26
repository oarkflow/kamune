package exchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"fmt"
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

func (e *ECDH) Exchange(remote *ecdh.PublicKey) ([]byte, error) {
	return e.privateKey.ECDH(remote)
}

func NewECDH() (*ECDH, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdh: generating key: %w", err)
	}

	return &ECDH{privateKey: key, publicKey: key.PublicKey()}, nil
}
