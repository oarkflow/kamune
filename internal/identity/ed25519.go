package identity

import (
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

func VerifyEd25519(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

type Ed25519 struct {
	PublicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (e *Ed25519) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (e *Ed25519) MarshalPublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(e.PublicKey)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (e *Ed25519) Save(path string) error {
	data, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return fmt.Errorf("marshalling key: %w", err)
	}
	err = saveKey(data, privateKeyType, path)
	if err != nil {
		return fmt.Errorf("saving private key: %w", err)
	}

	return nil
}

func (e *Ed25519) Load(path string) error {
	data, err := readKeyData(path)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return ErrInvalidKey
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		panic("type assertion: public key is not of type ed25519.Key")
	}
	*e = Ed25519{privateKey: private, PublicKey: public}

	return nil
}

func NewEd25519() (*Ed25519, error) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Ed25519{privateKey: private, PublicKey: public}, nil
}
