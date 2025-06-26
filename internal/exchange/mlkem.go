package exchange

import (
	"crypto/mlkem"
)

type MLKEM struct {
	publicKey  *mlkem.EncapsulationKey768
	privateKey *mlkem.DecapsulationKey768
}

func (m *MLKEM) PublicKey() []byte {
	return m.publicKey.Bytes()
}

func (m *MLKEM) Decapsulate(ct []byte) ([]byte, error) {
	return m.privateKey.Decapsulate(ct)
}

func MLKEMEncapsulate(remote []byte) (ss, ct []byte, err error) {
	public, err := mlkem.NewEncapsulationKey768(remote)
	if err != nil {
		return nil, nil, err
	}
	secret, cipher := public.Encapsulate()

	return secret, cipher, nil
}

func NewMLKEM() (*MLKEM, error) {
	private, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}

	return &MLKEM{privateKey: private, publicKey: private.EncapsulationKey()}, nil
}
