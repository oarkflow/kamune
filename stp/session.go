package stp

import (
	"crypto/rand"
	"fmt"
	"net"
)

type Session struct {
	ID        string
	Transport *Transport
}

func NewSession(t *Transport) *Session {
	return &Session{
		ID:        rand.Text(),
		Transport: t,
	}
}

func (s *Session) Talk(c net.Conn) error {
	fmt.Print("> ")
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	err = s.Transport.Send(c, []byte(input))
	if err != nil {
		return fmt.Errorf("sending input: %w", err)
	}

	return nil
}

func (s *Session) Hear(c net.Conn) error {
	var output []byte
	if err := s.Transport.Receive(c, &output); err != nil {
		return err
	}
	fmt.Printf("\nPeer: %s\n> ", output)

	return nil
}
