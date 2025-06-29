package stp

import (
	"bytes"
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/internal/exchange"
)

var motto = [][]byte{
	[]byte("For those who kept on fighting, against all odds."),
	[]byte("Nothing is really gone, just forgotten."),
	[]byte("A beautiful illusion, or an ugly reality? Make your choice."),
	[]byte("Will you still do it, even if it wouldn't matter in the end?"),
}

func requestHandshake(pt *plainTransport) (*Transport, error) {
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM: %w", err)
	}
	nonce := randomBytes(enigma.BaseNonceSize)
	req := &pb.Handshake{
		Key:     ml.PublicKey.Bytes(),
		Nonce:   nonce,
		Padding: padding(),
	}
	reqBytes, _, err := pt.serialize(req, pt.sent.Load())
	if err != nil {
		return nil, fmt.Errorf("serializing handshake req: %w", err)
	}
	if _, err = pt.conn.Write(reqBytes); err != nil {
		return nil, fmt.Errorf("writing handshake req: %w", err)
	}
	pt.sent.Add(1)

	respBytes, err := read(pt.conn)
	if err != nil {
		return nil, fmt.Errorf("reading handshake resp: %w", err)
	}
	var resp pb.Handshake
	if _, err = pt.deserialize(respBytes, &resp, pt.received.Load()); err != nil {
		return nil, fmt.Errorf("deserializing handshake resp: %w", err)
	}
	pt.received.Add(1)
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		return nil, fmt.Errorf("decapsulating secret: %w", err)
	}

	encoder, err := enigma.NewEnigma(secret, nonce, enigma.C2S)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(secret, resp.GetNonce(), enigma.S2C)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, resp.GetSessionID(), encoder, decoder)
	if err := sendVerification(t); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}
	if err := receiveVerification(t); err != nil {
		return nil, fmt.Errorf("receiving verification: %w", err)
	}

	return t, nil
}

func acceptHandshake(pt *plainTransport) (*Transport, error) {
	reqBytes, err := read(pt.conn)
	if err != nil {
		return nil, fmt.Errorf("reading handshake req: %w", err)

	}
	var req pb.Handshake
	if _, err = pt.deserialize(reqBytes, &req, pt.received.Load()); err != nil {
		return nil, fmt.Errorf("deserializing handshake req: %w", err)
	}
	pt.received.Add(1)
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		return nil, fmt.Errorf("encapsulating: %w", err)
	}

	sessionID := rand.Text()
	nonce := randomBytes(enigma.BaseNonceSize)
	resp := &pb.Handshake{
		Key:       ct,
		Nonce:     nonce,
		SessionID: &sessionID,
		Padding:   padding(),
	}
	respBytes, _, err := pt.serialize(resp, pt.sent.Load())
	if err != nil {
		return nil, fmt.Errorf("serializing handshake resp: %w", err)
	}
	if _, err = pt.conn.Write(respBytes); err != nil {
		return nil, fmt.Errorf("writing handshake resp: %w", err)
	}
	pt.sent.Add(1)

	encoder, err := enigma.NewEnigma(secret, nonce, enigma.S2C)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	decoder, err := enigma.NewEnigma(secret, req.GetNonce(), enigma.C2S)
	if err != nil {
		return nil, fmt.Errorf("creating decrypter: %w", err)
	}

	t := newTransport(pt, sessionID, encoder, decoder)
	if err := receiveVerification(t); err != nil {
		return nil, fmt.Errorf("receiving verification: %w", err)
	}
	if err := sendVerification(t); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}

	return t, nil
}

func sendVerification(t *Transport) error {
	m := motto[mathrand.IntN(len(motto))]
	if _, err := t.Send(Bytes(m)); err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if !bytes.Equal(r.Value, m) {
		return ErrVerificationFailed
	}

	return nil
}

func receiveVerification(t *Transport) error {
	r := Bytes(nil)
	if _, err := t.Receive(r); err != nil {
		return fmt.Errorf("receiving: %w", err)
	}
	if _, err := t.Send(Bytes(r.Value)); err != nil {
		return fmt.Errorf("sending: %w", err)
	}

	return nil
}

func randomBytes(l int) []byte {
	rnd := make([]byte, l)
	if _, err := rand.Read(rnd); err != nil {
		panic(fmt.Errorf("generating random bytes: %w", err))
	}
	return rnd
}

func padding() []byte {
	r := mathrand.IntN(maxPaddingSize)
	fmt.Println(r)
	return randomBytes(r)
}
