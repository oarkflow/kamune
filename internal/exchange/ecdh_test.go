package exchange

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDH(t *testing.T) {
	a := require.New(t)

	p1, err := NewECDH()
	a.NoError(err)
	a.NotNil(p1)
	pub1 := p1.PublicKey()

	p2, err := NewECDH()
	a.NoError(err)
	a.NotNil(p2)
	pub2 := p2.PublicKey()

	secretP1, err := p1.Exchange(pub2)
	a.NoError(err)
	a.NotNil(secretP1)

	secretP2, err := p2.Exchange(pub1)
	a.NoError(err)
	a.NotNil(secretP2)

	a.Equal(secretP1, secretP2)
}
