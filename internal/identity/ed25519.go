package identity

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ed25519"

	"github.com/hossein1376/kamune/sign"
)

func VerifyEd25519(remote crypto.PublicKey, msg, sig []byte) (crypto.PublicKey, error) {
	switch r := remote.(type) {
	case ed25519.PublicKey:
		if ok := ed25519.Verify(r, msg, sig); !ok {
			return nil, ErrInvalidSignature
		}
		return remote, nil

	case []byte:
		key, err := x509.ParsePKIXPublicKey(r)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, ErrInvalidKey
		}
		if ok := ed25519.Verify(pub, msg, sig); !ok {
			return nil, ErrInvalidSignature
		}
		return pub, nil

	default:
		return nil, ErrInvalidKey
	}
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

func (e *Ed25519) Verifier() sign.Verifier {
	return VerifyEd25519
}

func NewEd25519() (*Ed25519, error) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &Ed25519{privateKey: private, PublicKey: public}, nil
}

func LoadEd25519(path string) (sign.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissingFile
		}
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrMissingPEM
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		panic("type assertion: public key is not of type ed25519.Key")
	}

	return &Ed25519{privateKey: private, PublicKey: public}, nil
}
