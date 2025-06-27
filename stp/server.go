package stp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/hossein1376/kamune/internal/identity"
	"github.com/hossein1376/kamune/sign"
)

var (
	defaultIdentityDir  = filepath.Join(os.Getenv("HOME"), ".config", "kamune")
	defaultIdentityPath = filepath.Join(defaultIdentityDir, "id.key")
)

type HandlerFunc func(t *Transport) error

type Server struct {
	Addr        string
	ID          sign.Identity
	HandlerFunc HandlerFunc
}

func ListenAndServe(addr string, h HandlerFunc) error {
	s, err := NewServer(addr, h)
	if err != nil {
		return err
	}
	return s.ListenAndServe()
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
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
				s.log(slog.LevelError, "serve conn", slog.Any("err", err))
				return
			}
		}()
	}
}

func (s *Server) serve(conn net.Conn) error {
	defer func() {
		if err := recover(); err != nil {
			s.log(slog.LevelError, "serve panic", slog.Any("err", err))
		}
		conn.Close()
	}()

	t, err := AcceptHandshake(s.ID, conn)
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

func NewServer(addr string, h HandlerFunc) (*Server, error) {
	id, err := loadCert()
	if err != nil {
		return nil, err
	}
	return &Server{ID: id, Addr: addr, HandlerFunc: h}, nil
}

func loadCert() (sign.Identity, error) {
	id, err := identity.LoadEd25519(defaultIdentityPath)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrMissingFile):
			id, err = newCert()
			if err != nil {
				return nil, fmt.Errorf("newCert: %w", err)
			}
		default:
			return nil, fmt.Errorf("loading ed25519 cert: %w", err)
		}
	}

	return id, nil
}

func newCert() (sign.Identity, error) {
	if err := os.MkdirAll(defaultIdentityDir, 0760); err != nil {
		return nil, fmt.Errorf("MkdirAll: %w", err)
	}
	id, err := identity.NewEd25519()
	if err != nil {
		return nil, fmt.Errorf("NewEd25519: %w", err)
	}
	if err := id.Save(defaultIdentityPath); err != nil {
		return nil, fmt.Errorf("saving cert: %w", err)
	}

	return id, nil
}
