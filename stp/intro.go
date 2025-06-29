package stp

import (
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/hossein1376/kamune/internal/attest"
	"github.com/hossein1376/kamune/internal/box/pb"
)

type RemoteVerifier func(key *attest.PublicKey) (err error)

func defaultRemoteVerifier(remote *attest.PublicKey) error {
	key := base64.StdEncoding.EncodeToString(remote.Marshal())
	fmt.Printf("Peer's public key: %s\n", key)
	fmt.Printf("Do you verify it (y/N)? ")
	var answer string
	fmt.Scanln(&answer)
	if answer == "y" || answer == "yes" {
		return nil
	}
	return ErrVerificationFailed
}

func sendIntroduction(conn Conn, at *attest.Attest) error {
	intro := &pb.Introduce{Public: at.MarshalPublicKey()}
	introBytes, err := proto.Marshal(intro)
	if err != nil {
		return fmt.Errorf("marshal host intoduce message: %w", err)
	}
	if _, err := conn.Write(introBytes); err != nil {
		return fmt.Errorf("writing intro: %w", err)
	}

	return nil
}

func receiveIntroduction(conn Conn) (*attest.PublicKey, error) {
	payload, err := read(conn)
	var introduce pb.Introduce
	err = proto.Unmarshal(payload, &introduce)
	if err != nil {
		return nil, fmt.Errorf("deserializing intoduce message: %w", err)
	}
	remote, err := attest.ParsePublicKey(introduce.GetPublic())
	if err != nil {
		return nil, fmt.Errorf("parsing advertised key: %w", err)
	}

	return remote, nil
}
