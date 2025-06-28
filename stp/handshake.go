package stp

import (
	"crypto/rand"
	"fmt"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/attest"
	"github.com/hossein1376/kamune/internal/box/pb"
	"github.com/hossein1376/kamune/internal/exchange"
)

func RequestHandshake(
	conn Conn, at *attest.Attest, remote *attest.PublicKey,
) (encoder, decoder *enigma.Enigma, err error) {
	ml, err := exchange.NewMLKEM()
	if err != nil {
		err = fmt.Errorf("creating MLKEM: %w", err)
		return
	}
	salt := randomBytes(enigma.SaltSize)
	nonce := randomBytes(enigma.BaseNonceSize)
	req := &pb.Handshake{Key: ml.PublicKey.Bytes(), Salt: salt, Nonce: nonce}
	reqBytes, err := serialize(req, at)
	if err != nil {
		err = fmt.Errorf("serializing handshake req: %w", err)
		return
	}
	if _, err = conn.Write(reqBytes); err != nil {
		err = fmt.Errorf("writing handshake req: %w", err)
		return
	}

	respBytes, err := read(conn)
	if err != nil {
		err = fmt.Errorf("reading handshake resp: %w", err)
		return
	}
	var resp pb.Handshake
	if err = deserialize(respBytes, &resp, remote); err != nil {
		err = fmt.Errorf("deserializing handshake resp: %w", err)
		return
	}
	secret, err := ml.Decapsulate(resp.GetKey())
	if err != nil {
		err = fmt.Errorf("decapsulating secret: %w", err)
		return
	}

	encoder, err = enigma.NewEnigma(secret, salt, nonce)
	if err != nil {
		err = fmt.Errorf("creating encrypter: %w", err)
		return
	}
	decoder, err = enigma.NewEnigma(secret, resp.GetSalt(), resp.GetNonce())
	if err != nil {
		err = fmt.Errorf("creating decrypter: %w", err)
		return
	}

	return encoder, decoder, nil
}

func AcceptHandshake(
	conn Conn, at *attest.Attest, remote *attest.PublicKey,
) (encoder, decoder *enigma.Enigma, err error) {
	reqBytes, err := read(conn)
	if err != nil {
		err = fmt.Errorf("reading handshake req: %w", err)
		return
	}
	var req pb.Handshake
	if err = deserialize(reqBytes, &req, remote); err != nil {
		err = fmt.Errorf("deserializing handshake req: %w", err)
		return
	}
	secret, ct, err := exchange.EncapsulateMLKEM(req.GetKey())
	if err != nil {
		err = fmt.Errorf("encapsulating: %w", err)
		return
	}

	salt := randomBytes(enigma.SaltSize)
	nonce := randomBytes(enigma.BaseNonceSize)
	resp := &pb.Handshake{Key: ct, Salt: salt, Nonce: nonce}
	respBytes, err := serialize(resp, at)
	if err != nil {
		err = fmt.Errorf("serializing handshake resp: %w", err)
		return
	}
	if _, err = conn.Write(respBytes); err != nil {
		err = fmt.Errorf("writing handshake resp: %w", err)
		return
	}

	encoder, err = enigma.NewEnigma(secret, salt, nonce)
	if err != nil {
		err = fmt.Errorf("creating encrypter: %w", err)
		return
	}
	decoder, err = enigma.NewEnigma(secret, req.GetSalt(), req.GetNonce())
	if err != nil {
		err = fmt.Errorf("creating decrypter: %w", err)
		return
	}

	return
}

func randomBytes(l int) []byte {
	rnd := make([]byte, l)
	if _, err := rand.Read(rnd); err != nil {
		panic(fmt.Errorf("generating random bytes: %w", err))
	}
	return rnd
}
