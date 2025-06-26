package stp

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/exchange"
	"github.com/hossein1376/kamune/sign"
)

type Handshake struct {
	Identity  []byte `json:"id"`
	PublicKey []byte `json:"key"`
	Salt      []byte `json:"salt,omitempty"`
}

func RequestHandshake(id sign.Identity, c net.Conn) (*Transport, error) {
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM: %v", err)
	}
	if _, err := c.Write(ml.MarshalPublicKey()); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}

	ct, err := read(c)
	if err != nil {
		return nil, fmt.Errorf("read ct: %w", err)
	}
	secret, err := ml.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("decapsulate: %w", err)
	}
	aead, err := enigma.NewEnigma(secret, ct)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}

	if err := encryptAndSendMyID(id, c, aead); err != nil {
		return nil, fmt.Errorf("encrypt and send myID: %w", err)
	}

	remote, err := readAndVerifyTheirID(id, c, aead)
	if err != nil {
		return nil, fmt.Errorf("read and verify theirID: %w", err)
	}

	return newTransport(id, remote.(ed25519.PublicKey), aead), nil
}

func AcceptHandshake(id sign.Identity, c net.Conn) (*Transport, error) {
	encKey, err := read(c)
	if err != nil {
		return nil, fmt.Errorf("read encKey: %w", err)
	}
	secret, ct, err := exchange.EncapsulateMLKEM(encKey)
	if err != nil {
		return nil, fmt.Errorf("encapsulateMLKEM: %w", err)
	}
	aead, err := enigma.NewEnigma(secret, ct)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	if _, err := c.Write(ct); err != nil {
		return nil, fmt.Errorf("write ct: %w", err)
	}

	remote, err := readAndVerifyTheirID(id, c, aead)
	if err != nil {
		return nil, fmt.Errorf("read and verify theirID: %w", err)
	}

	if err := encryptAndSendMyID(id, c, aead); err != nil {
		return nil, fmt.Errorf("encrypt and send myID: %w", err)
	}

	return newTransport(id, remote.(ed25519.PublicKey), aead), nil
}

func encryptAndSendMyID(
	id sign.Identity, c net.Conn, aead *enigma.Enigma,
) error {
	myID, err := seal(id, id.MarshalPublicKey())
	if err != nil {
		return fmt.Errorf("seal myID: %w", err)
	}
	encryptedMyID, err := aead.Encrypt(myID)
	if err != nil {
		return fmt.Errorf("encrypt myID: %w", err)
	}
	if _, err := c.Write(encryptedMyID); err != nil {
		return fmt.Errorf("write myID: %w", err)
	}

	return nil
}

func readAndVerifyTheirID(
	id sign.Identity, c net.Conn, aead *enigma.Enigma,
) (crypto.PublicKey, error) {
	payload, err := read(c)
	if err != nil {
		return nil, fmt.Errorf("read theirID payload: %w", err)
	}
	decryptedTheirID, err := aead.Decrypt(payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt theirID: %w", err)
	}
	var st SignedTransport
	if err := json.Unmarshal(decryptedTheirID, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling transport: %w", err)
	}
	var theirPubKey []byte
	if err := json.Unmarshal(st.Message, &theirPubKey); err != nil {
		return nil, fmt.Errorf("unmarshal their public key: %w", err)
	}
	remote, err := id.Verifier()(
		theirPubKey, st.Message, st.Signature,
	)
	if err != nil {
		return nil, fmt.Errorf("verify theirID: %w", err)
	}

	return remote, nil
}
