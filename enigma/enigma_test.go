package enigma

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChaCha20Poly1305(t *testing.T) {
	a := require.New(t)
	msg := []byte("May tomorrow be a better day")
	secret := []byte("let this be our secret")
	salt := []byte("super salty")

	eng, err := NewEnigma(secret, salt)
	a.NoError(err)
	a.NotNil(eng)

	encrypted, err := eng.Encrypt(msg)
	a.NoError(err)
	a.NotNil(encrypted)

	decrypted, err := eng.Decrypt(encrypted)
	a.NoError(err)
	a.NotNil(decrypted)
	a.Equal(msg, decrypted)
}
