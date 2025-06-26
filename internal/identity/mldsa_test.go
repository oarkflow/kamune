package identity_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hossein1376/kamune/internal/identity"
	"github.com/hossein1376/kamune/sign"
)

var _ sign.Identity = &identity.MLDSA{}

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
		_, err := identity.VerifyMLDSA(pub, msg, sig)
		a.NoError(err)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xDD

		_, err := identity.VerifyMLDSA(pub, msg, sig)
		a.Error(err)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		_, err := identity.VerifyMLDSA(pub, msg, sig)
		a.Error(err)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := identity.NewMLDSA()
		a.NoError(err)
		_, err = identity.VerifyMLDSA(another.PublicKey, msg, sig)
		a.Error(err)
	})
}
