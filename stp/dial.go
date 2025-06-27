package stp

import (
	"fmt"
	"net"
)

func Dial(network, addr string) (*Transport, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	id, err := loadCert()

	t, err := RequestHandshake(id, conn)
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return t, nil
}
