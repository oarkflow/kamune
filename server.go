package kamune

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/hossein1376/kamune/internal/attest"
)

type HandlerFunc func(t *Transport) error

type Server struct {
	Addr           string
	HandlerFunc    HandlerFunc
	RemoteVerifier RemoteVerifier
	attest         *attest.Attest
}

func ListenAndServe(addr string, h HandlerFunc) error {
	s, err := NewServer(addr, h)
	if err != nil {
		return fmt.Errorf("creating new server: %w", err)
	}
	return s.ListenAndServe()
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.Addr, err)
	}
	return s.Serve(l)
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.log(slog.LevelError, "accept conn", slog.Any("err", err))
			continue
		}
		go func() {
			if err := s.serve(conn); err != nil {
				s.log(slog.LevelWarn, "serve conn", slog.Any("err", err))
				return
			}
		}()
	}
}

func (s *Server) serve(c net.Conn) error {
	conn := Conn{Conn: c}
	defer func() {
		if err := recover(); err != nil {
			s.log(slog.LevelError, "serve panic", slog.Any("err", err))
		}
		if !conn.isClosed {
			if err := conn.Close(); err != nil {
				s.log(slog.LevelError, "close conn", slog.Any("err", err))
			}
		}
	}()

	remote, err := receiveIntroduction(conn)
	if err != nil {
		return fmt.Errorf("receive introduction: %w", err)
	}
	if err := s.RemoteVerifier(remote); err != nil {
		return fmt.Errorf("verify remote: %w", err)
	}
	if err := sendIntroduction(conn, s.attest); err != nil {
		return fmt.Errorf("send introduction: %w", err)
	}

	pt := &plainTransport{conn: conn, remote: remote, attest: s.attest}
	t, err := acceptHandshake(pt)
	if err != nil {
		return fmt.Errorf("accept handshake: %w", err)
	}
	err = s.HandlerFunc(t)
	if err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	return nil
}

func (s *Server) log(lvl slog.Level, msg string, args ...any) {
	slog.Log(nil, lvl, msg, args...)
}

func NewServer(addr string, handler HandlerFunc) (*Server, error) {
	at, err := attest.LoadFromDisk(privKeyPath)
	if err != nil {
		return nil, err
	}
	return &Server{
		attest:         at,
		Addr:           addr,
		HandlerFunc:    handler,
		RemoteVerifier: defaultRemoteVerifier,
	}, nil
}
