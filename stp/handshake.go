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
	Key       []byte `json:"key"`
	TimeStamp Time   `json:"time"`
}

func RequestHandshake(id sign.Identity, conn net.Conn) (*Transport, error) {
	ml, err := exchange.NewMLKEM()
	if err != nil {
		return nil, fmt.Errorf("creating MLKEM: %w", err)
	}
	h := Handshake{Key: ml.MarshalPublicKey(), TimeStamp: Now()}
	handshakeReq, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshaling handshake request: %w", err)
	}
	if _, err := conn.Write(handshakeReq); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}

	response, err := read(conn)
	if err != nil {
		return nil, fmt.Errorf("read ct: %w", err)
	}
	var handshakeResp Handshake
	if err := json.Unmarshal(response, &handshakeResp); err != nil {
		return nil, fmt.Errorf("unmarshaling handshake response: %w", err)
	}
	if !handshakeResp.TimeStamp.IsInPlusMinusSeconds(clockSkewSeconds) {
		return nil, fmt.Errorf("handshake response: %w", ErrInvalidTimestamp)
	}
	ct := handshakeResp.Key
	secret, err := ml.Decapsulate(ct)
	if err != nil {
		return nil, fmt.Errorf("decapsulate: %w", err)
	}
	aead, err := enigma.NewEnigma(secret, ct)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}

	if err := encryptAndSendMyID(id, conn, aead); err != nil {
		return nil, fmt.Errorf("encrypt and send myID: %w", err)
	}

	remote, err := readAndVerifyTheirID(id, conn, aead)
	if err != nil {
		return nil, fmt.Errorf("read and verify theirID: %w", err)
	}
	code := fmt.Sprintf("%.32X", ct)

	return newTransport(id, remote.(ed25519.PublicKey), aead, conn, code), nil
}

func AcceptHandshake(id sign.Identity, conn net.Conn) (*Transport, error) {
	request, err := read(conn)
	if err != nil {
		return nil, fmt.Errorf("read encKey: %w", err)
	}
	var handshakeReq Handshake
	if err := json.Unmarshal(request, &handshakeReq); err != nil {
		return nil, fmt.Errorf("unmarshaling handshake request: %w", err)
	}
	if !handshakeReq.TimeStamp.IsInPlusMinusSeconds(clockSkewSeconds) {
		return nil, fmt.Errorf("handshake request: %w", ErrInvalidTimestamp)
	}
	secret, ct, err := exchange.EncapsulateMLKEM(handshakeReq.Key)
	if err != nil {
		return nil, fmt.Errorf("encapsulateMLKEM: %w", err)
	}
	aead, err := enigma.NewEnigma(secret, ct)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}
	h := Handshake{Key: ct, TimeStamp: Now()}
	handshakeResp, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshaling handshake response: %w", err)
	}
	if _, err := conn.Write(handshakeResp); err != nil {
		return nil, fmt.Errorf("write ct: %w", err)
	}

	remote, err := readAndVerifyTheirID(id, conn, aead)
	if err != nil {
		return nil, fmt.Errorf("read and verify theirID: %w", err)
	}

	if err := encryptAndSendMyID(id, conn, aead); err != nil {
		return nil, fmt.Errorf("encrypt and send myID: %w", err)
	}
	code := fmt.Sprintf("%.32X", ct)

	return newTransport(id, remote.(ed25519.PublicKey), aead, conn, code), nil
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
	if !st.Timestamp.IsInPlusMinusSeconds(clockSkewSeconds) {
		return nil, ErrInvalidTimestamp
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
