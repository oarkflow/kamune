package identity

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/hossein1376/kamune/sign"
)

type MLDSA struct {
	PublicKey  *mldsa65.PublicKey
	privateKey *mldsa65.PrivateKey
}

func VerifyMLDSA(remote crypto.PublicKey, msg, sig []byte) (crypto.PublicKey, error) {
	switch r := remote.(type) {
	case *mldsa65.PublicKey:
		if ok := mldsa65.Verify(r, msg, nil, sig); !ok {
			return nil, ErrInvalidSignature
		}
		return remote, nil

	case []byte:
		key, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(r)
		if err != nil {
			return nil, fmt.Errorf("unmarshal public key: %w", err)
		}
		pub, ok := key.(*mldsa65.PublicKey)
		if !ok {
			return nil, ErrInvalidKey
		}
		if ok := mldsa65.Verify(pub, msg, nil, sig); !ok {
			return pub, ErrInvalidSignature
		}
		return pub, nil

	default:
		return nil, ErrInvalidKey
	}
}

func (m *MLDSA) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	err := mldsa65.SignTo(m.privateKey, msg, nil, true, sig)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (m *MLDSA) MarshalPublicKey() []byte {
	b, _ := m.PublicKey.MarshalBinary()
	return b
}

func NewMLDSA() (*MLDSA, error) {
	public, private, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &MLDSA{PublicKey: public, privateKey: private}, nil
}

func (m *MLDSA) Verifier() sign.Verifier {
	return VerifyMLDSA
}
