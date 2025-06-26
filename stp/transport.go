package stp

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/identity"
)

const maxTransportSize = 10 * 1024

type Transport struct {
	identity *identity.Ed25519
	remote   ed25519.PublicKey
	aead     *enigma.Enigma
}

func (t Transport) Receive(c net.Conn, dst any) error {
	payload, err := readMessage(c)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	decrypted, err := t.aead.Decrypt(payload)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	return open(t.remote, decrypted, dst)
}

func open(remote ed25519.PublicKey, payload []byte, dst any) error {
	var st SignedTransport
	if err := json.Unmarshal(payload, &st); err != nil {
		return fmt.Errorf("unmarshalling Transport: %w", err)
	}
	msg := st.Message
	msg = append(msg, []byte(" ")...)
	if !identity.VerifyEd25519(remote, msg, st.Signature) {
		return identity.ErrInvalidSignature
	}
	if err := json.Unmarshal(msg, dst); err != nil {
		return fmt.Errorf("unmarshalling msg: %w", err)
	}
	return nil
}

func (t Transport) Send(c net.Conn, message any) error {
	payload, err := seal(t.identity, message)
	if err != nil {
		return err
	}
	encrypted, err := t.aead.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	if len(encrypted) > maxTransportSize {
		return errors.New("data exceeds max size")
	}
	if _, err := c.Write(encrypted); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

func readMessage(c net.Conn) ([]byte, error) {
	buf := make([]byte, maxTransportSize)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

func seal(id *identity.Ed25519, message any) ([]byte, error) {
	msg, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshalling msg: %w", err)
	}
	sig, err := id.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	st := SignedTransport{Message: msg, Signature: sig}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("marshalling Transport: %w", err)
	}

	return payload, nil
}

func newTransport(
	id *identity.Ed25519, remote ed25519.PublicKey, aead *enigma.Enigma,
) *Transport {
	return &Transport{
		identity: id,
		remote:   remote,
		aead:     aead,
	}
}
