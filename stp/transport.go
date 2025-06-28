package stp

import (
	"errors"
	"fmt"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/attest"
	"github.com/hossein1376/kamune/internal/box/pb"
)

const (
	maxTransportSize = 10 * 1024
)

type Transport struct {
	conn     Conn
	attest   *attest.Attest
	remote   *attest.PublicKey
	encoder  *enigma.Enigma
	decoder  *enigma.Enigma
	sent     atomic.Uint64
	received atomic.Uint64
}

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

func (t *Transport) Receive(dst Transferable) error {
	payload, err := read(t.conn)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	decrypted, err := t.decoder.Decrypt(payload, t.received.Add(1))
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}

	return deserialize(decrypted, dst, t.remote)
}

func (t *Transport) Send(message Transferable) error {
	payload, err := serialize(message, t.attest)
	if err != nil {
		return err
	}
	encrypted := t.encoder.Encrypt(payload, t.sent.Add(1))
	if _, err := t.conn.Write(encrypted); err != nil {
		return fmt.Errorf("writing: %w", err)
	}

	return nil
}

func (t *Transport) Close() error {
	return t.conn.Close()
}

func serialize(
	message Transferable, at *attest.Attest,
) ([]byte, error) {
	msg, err := proto.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("marshalling message: %w", err)
	}
	sig, err := at.Sign(msg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	st := &pb.SignedTransport{Data: msg, Signature: sig}
	payload, err := proto.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("marshalling transport: %w", err)
	}

	return payload, nil
}

func deserialize(
	payload []byte, dst Transferable, remote *attest.PublicKey,
) error {
	var st pb.SignedTransport
	if err := proto.Unmarshal(payload, &st); err != nil {
		return fmt.Errorf("unmarshal transport: %w", err)
	}
	msg := st.GetData()
	if !attest.Verify(remote, msg, st.Signature) {
		return ErrInvalidSignature
	}
	if err := proto.Unmarshal(msg, dst); err != nil {
		return fmt.Errorf("unmarshal transport: %w", err)
	}

	return nil
}

func read(c Conn) ([]byte, error) {
	buf := make([]byte, maxTransportSize)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func newTransport(
	at *attest.Attest,
	remote *attest.PublicKey,
	encoder, decoder *enigma.Enigma,
	c Conn,
) *Transport {
	return &Transport{
		attest:  at,
		remote:  remote,
		encoder: encoder,
		decoder: decoder,
		conn:    c,
	}
}
