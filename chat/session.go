package chat

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/hossein1376/kamune/stp"
)

type Session struct {
	transport *stp.Transport
	stop      chan struct{}
}

func NewSession(t *stp.Transport) (*Session, func()) {
	s := &Session{transport: t}
	return s, func() {
		s.stop <- struct{}{}
		s.stop <- struct{}{}
	}
}

func (s *Session) talk(r io.Reader, w io.Writer) error {
	fmt.Fprintf(w, "> ")
	var input string
	_, err := fmt.Fscanln(r, &input)
	if err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return nil
		default:
			return fmt.Errorf("reading input: %w", err)
		}
	}
	err = s.transport.Send([]byte(input))
	if err != nil {
		return fmt.Errorf("sending input: %w", err)
	}
	fmt.Fprint(w, "\033[2K\r")
	return nil
}

func (s *Session) hear(w io.Writer) error {
	var output []byte
	if err := s.transport.Receive(&output); err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return nil
		default:
			return fmt.Errorf("receive input: %w", err)
		}
	}
	fmt.Fprint(w, "\033[2K\r")
	fmt.Fprintf(w, "Peer: %s\n> ", output)

	return nil
}

func (s *Session) Chat() {
	errs := s.chat(os.Stdin, os.Stdout)
	for err := range errs {
		slog.Error("chat", slog.Any("error", err))
	}
}

func (s *Session) chat(src io.Reader, dst io.Writer) <-chan error {
	fmt.Fprintf(dst, "Session ID is %s. Happy chatting!\n", s.transport.Code())
	errs := make(chan error)
	go func() {
		for {
			select {
			case <-s.stop:
				return
			default:
				if err := s.hear(dst); err != nil {
					errs <- fmt.Errorf("hear: %w", err)
				}
			}
		}
	}()
	go func() {
		for {
			select {
			case <-s.stop:
				return
			default:
				if err := s.talk(src, dst); err != nil {
					errs <- fmt.Errorf("talk: %w", err)
				}
			}
		}
	}()

	return errs
}
