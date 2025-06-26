package identity

import (
	"crypto/rand"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type MLDSA struct {
	PublicKey  *mldsa65.PublicKey
	privateKey *mldsa65.PrivateKey
}

func VerifyMLDSA(publicKey *mldsa65.PublicKey, msg, sig []byte) bool {
	return mldsa65.Verify(publicKey, msg, nil, sig)
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
