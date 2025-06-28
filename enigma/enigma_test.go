package enigma

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChaCha20Poly1305(t *testing.T) {
	a := require.New(t)
	msg := []byte("May tomorrow be a better day")
	secret := []byte("let this be our secret")
	salt := []byte("super salty")
	baseNonce := make([]byte, BaseNonceSize)
	rand.Read(baseNonce)

	eng, err := NewEnigma(secret, salt, baseNonce)
	a.NoError(err)
	a.NotNil(eng)

	encrypted := eng.Encrypt(msg, 1)
	a.NotNil(encrypted)
	a.NotEqual(msg, encrypted)

	decrypted, err := eng.Decrypt(encrypted, 1)
	a.NoError(err)
	a.NotNil(decrypted)
	a.Equal(msg, decrypted)
}
