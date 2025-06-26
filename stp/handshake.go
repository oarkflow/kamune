package stp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"

	"github.com/hossein1376/kamune/enigma"
	"github.com/hossein1376/kamune/internal/exchange"
	"github.com/hossein1376/kamune/internal/identity"
)

type Handshake struct {
	Identity  []byte `json:"id"`
	PublicKey []byte `json:"key"`
	Salt      []byte `json:"salt,omitempty"`
}

func RequestHandshake(i *identity.Ed25519, c net.Conn) (*Transport, error) {
	ec, err := exchange.NewECDH()
	if err != nil {
		return nil, fmt.Errorf("new ecdh: %w", err)
	}
	h := Handshake{
		Identity:  i.MarshalPublicKey(),
		PublicKey: ec.PublicKey(),
	}
	payload, err := seal(i, h)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if _, err := c.Write(payload); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	resp, err := readMessage(c)
	if err != nil {
		return nil, fmt.Errorf("read handshake: %w", err)
	}
	var st SignedTransport
	if err := json.Unmarshal(resp, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling Transport: %w", err)
	}
	var handshakeResp Handshake
	if err := json.Unmarshal(st.Message, &handshakeResp); err != nil {
		return nil, fmt.Errorf("unmarshalling msg: %w", err)
	}
	id, err := x509.ParsePKIXPublicKey(handshakeResp.Identity)
	if err != nil {
		return nil, fmt.Errorf("parse identity pubKey: %w", err)
	}
	identifier, ok := id.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("identity does not implement ed25519.PublicKey")
	}

	pub, err := x509.ParsePKIXPublicKey(handshakeResp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public pubKey: %w", err)
	}
	publicKey, ok := pub.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public pubKey does not implement *ecdh.PublicKey")
	}

	secret, err := ec.Exchange(publicKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh exchange: %w", err)
	}
	eng, err := enigma.NewEnigma(secret, handshakeResp.Salt)
	if err != nil {
		return nil, fmt.Errorf("new enigma: %w", err)
	}

	return newTransport(i, identifier, eng), nil
}

func AcceptHandshake(i *identity.Ed25519, c net.Conn) (*Transport, error) {
	payload, err := readMessage(c)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	var st SignedTransport
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, fmt.Errorf("unmarshalling Transport: %w", err)
	}
	var h Handshake
	if err := json.Unmarshal(st.Message, &h); err != nil {
		return nil, fmt.Errorf("unmarshal handshake: %w", err)
	}

	id, err := x509.ParsePKIXPublicKey(h.Identity)
	if err != nil {
		return nil, fmt.Errorf("parse identity pubKey: %w", err)
	}
	identifier, ok := id.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("identity does not implement ed25519.PublicKey")
	}

	pub, err := x509.ParsePKIXPublicKey(h.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse public pubKey: %w", err)
	}
	publicKey, ok := pub.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public pubKey does not implement *ecdh.PublicKey")
	}

	if !identity.VerifyEd25519(identifier, st.Message, st.Signature) {
		return nil, identity.ErrInvalidSignature
	}

	ec, err := exchange.NewECDH()
	if err != nil {
		return nil, fmt.Errorf("new ecdh key: %w", err)
	}
	secret, err := ec.Exchange(publicKey)
	if err != nil {
		return nil, fmt.Errorf("get ecdh secret: %w", err)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	eng, err := enigma.NewEnigma(secret, salt)
	if err != nil {
		return nil, fmt.Errorf("new enigma: %w", err)
	}

	resp := Handshake{
		Identity:  i.MarshalPublicKey(),
		PublicKey: ec.PublicKey(),
		Salt:      salt,
	}
	payload, err = seal(i, resp)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	if _, err := c.Write(payload); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	return newTransport(i, identifier, eng), nil
}
