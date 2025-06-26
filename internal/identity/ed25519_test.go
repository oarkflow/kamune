package identity_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hossein1376/kamune/internal/identity"
	"github.com/hossein1376/kamune/sign"
)

var _ sign.Identity = &identity.Ed25519{}

func TestEd25519_SignVerify(t *testing.T) {
	a := require.New(t)
	msg := []byte("Make the world a better place")

	e, err := identity.NewEd25519()
	a.NoError(err)
	a.NotNil(e)
	pub := e.PublicKey
	a.NotNil(pub)
	sig, err := e.Sign(msg)
	a.NoError(err)
	a.NotNil(sig)

	t.Run("valid signature", func(t *testing.T) {
		_, err := identity.VerifyEd25519(pub, msg, sig)
		a.NoError(err)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xFF

		_, err := identity.VerifyEd25519(pub, msg, sig)
		a.Error(err)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		_, err := identity.VerifyEd25519(pub, msg, sig)
		a.Error(err)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := identity.NewEd25519()
		a.NoError(err)
		_, err = identity.VerifyEd25519(another.PublicKey, msg, sig)
		a.Error(err)
	})
}
