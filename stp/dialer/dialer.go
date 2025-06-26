package main

import (
	"fmt"
	"net"

	"github.com/hossein1376/kamune/internal/identity"
	"github.com/hossein1376/kamune/stp"
)

func main() {
	id, err := identity.NewEd25519()
	if err != nil {
		panic(err)
	}
	if err := dial(id); err != nil {
		panic(err)
	}
}

func dial(id *identity.Ed25519) error {
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	t, err := stp.RequestHandshake(id, conn)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	stp.Chat(t, conn)

	return nil
}
