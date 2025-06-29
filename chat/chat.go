package chat

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/hossein1376/kamune/stp"
)

type Chat struct {
	transport *stp.Transport
	stop      chan struct{}
}

func NewSession(t *stp.Transport) (*Chat, func()) {
	s := &Chat{transport: t, stop: make(chan struct{}, 2)}
	return s, func() {
		s.stop <- struct{}{}
		s.stop <- struct{}{}
	}
}

func (s *Chat) talk(r io.Reader, w io.Writer) error {
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
	_, err = s.transport.Send(stp.Bytes([]byte(input)))
	if err != nil {
		return fmt.Errorf("sending input: %w", err)
	}
	fmt.Fprint(w, "\033[2K\r")
	return nil
}

func (s *Chat) hear(w io.Writer) error {
	b := stp.Bytes(nil)
	metadata, err := s.transport.Receive(b)
	if err != nil {
		switch {
		case errors.Is(err, io.EOF):
			return nil
		default:
			return fmt.Errorf("receive input: %w", err)
		}
	}
	fmt.Fprint(w, "\033[2K\r")
	fmt.Fprintf(
		w,
		"[%s] Peer: %s\n> ",
		metadata.Timestamp().Local().Format(time.DateTime),
		b.Value,
	)

	return nil
}

func (s *Chat) Start() {
	errs := s.chat(os.Stdin, os.Stdout)
	for err := range errs {
		slog.Error("chat", slog.Any("error", err))
	}
}

func (s *Chat) chat(src io.Reader, dst io.Writer) <-chan error {
	fmt.Fprintf(dst, "Session ID is %s. Happy chatting!\n", s.transport.SessionID())
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
