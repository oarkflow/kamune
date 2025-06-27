package stp

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/identity"
	"github.com/hossein1376/kamune/sign"
)

const (
	maxTransportSize = 10 * 1024
	clockSkewSeconds = 10
)

var (
	ErrInvalidTimestamp = errors.New("timestamp is out of range")
)

type Transport struct {
	code     string
	identity sign.Identity
	remote   crypto.PublicKey
	aead     *enigma.Enigma
	conn     net.Conn
}

func (t *Transport) Receive(dst any) error {
	payload, err := read(t.conn)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	decrypted, err := t.aead.Decrypt(payload)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	return open(t.remote, decrypted, dst)
}

func (t *Transport) Send(message any) error {
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
	if _, err := t.conn.Write(encrypted); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

func (t *Transport) Code() string {
	return t.code
}

func seal(id sign.Identity, message any) ([]byte, error) {
	msg, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshalling msg: %w", err)
	}
	sig, err := id.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	st := SignedTransport{Message: msg, Signature: sig, Timestamp: Now()}
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("marshalling Transport: %w", err)
	}

	return payload, nil
}

func open(remote crypto.PublicKey, payload []byte, dst any) error {
	var st SignedTransport
	if err := json.Unmarshal(payload, &st); err != nil {
		return fmt.Errorf("unmarshalling Transport: %w", err)
	}
	if !st.Timestamp.IsInPlusMinusSeconds(clockSkewSeconds) {
		return ErrInvalidTimestamp
	}
	msg := st.Message
	if _, err := identity.VerifyEd25519(remote, msg, st.Signature); err != nil {
		return identity.ErrInvalidSignature
	}
	if err := json.Unmarshal(msg, dst); err != nil {
		return fmt.Errorf("unmarshalling msg: %w", err)
	}

	return nil
}

func read(c net.Conn) ([]byte, error) {
	buf := make([]byte, maxTransportSize)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func newTransport(
	id sign.Identity,
	remote ed25519.PublicKey,
	aead *enigma.Enigma,
	c net.Conn,
	code string,
) *Transport {
	return &Transport{
		code:     code,
		identity: id,
		remote:   remote,
		aead:     aead,
		conn:     c,
	}
}
