package stp

import (
	"fmt"
	"log"
	"net"

	"github.com/hossein1376/kamune/internal/identity"
)

func ListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer l.Close()

	id, err := identity.NewEd25519()
	if err != nil {
		return fmt.Errorf("create new identity: %w", err)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go func() {
			defer conn.Close()
			t, err := AcceptHandshake(id, conn)
			if err != nil {
				log.Fatalf("accept handshake: %v", err)
			}
			Chat(t, conn)
		}()
	}
}

func Chat(t *Transport, c net.Conn) {
	s := NewSession(t)
	end := make(chan struct{})
	go func() {
		for {
			if err := s.Hear(c); err != nil {
				log.Printf("hear: %v", err)
				end <- struct{}{}
				return
			}
		}
	}()
	go func() {
		for {
			if err := s.Talk(c); err != nil {
				log.Printf("talk: %v", err)
				end <- struct{}{}
				return
			}
		}
	}()

	<-end
}
