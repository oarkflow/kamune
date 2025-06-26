package identity_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hossein1376/kamune/internal/identity"
)

func TestMLDSA(t *testing.T) {
	a := require.New(t)
	msg := []byte("Make the world a better place")

	m, err := identity.NewMLDSA()
	a.NoError(err)
	a.NotNil(m)
	pub := m.PublicKey
	a.NotNil(pub)
	sig, err := m.Sign(msg)
	a.NoError(err)
	a.NotNil(sig)

	t.Run("valid signature", func(t *testing.T) {
		verified := identity.VerifyMLDSA(pub, msg, sig)
		a.True(verified)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xDD

		verified := identity.VerifyMLDSA(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		verified := identity.VerifyMLDSA(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := identity.NewMLDSA()
		a.NoError(err)
		verified := identity.VerifyMLDSA(another.PublicKey, msg, sig)
		a.False(verified)
	})
}
