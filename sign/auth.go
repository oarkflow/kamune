package sign

import (
	"crypto"
)

type Identity interface {
	MarshalPublicKey() []byte
	Sign(msg []byte) ([]byte, error)
	Verifier() Verifier
}

type Verifier func(
	remote crypto.PublicKey, msg []byte, sig []byte,
) (crypto.PublicKey, error)
