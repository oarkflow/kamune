package kamune

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/hossein1376/kamune/internal/attest"
)

type dialer struct {
	conn         Conn
	verifyRemote RemoteVerifier
}

func newDialer(conn net.Conn, verifier RemoteVerifier) *dialer {
	return &dialer{conn: Conn{Conn: conn}, verifyRemote: verifier}
}

func Dial(addr string) (*Transport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	d := newDialer(conn, defaultRemoteVerifier)

	return d.dial()
}

func (d *dialer) dial() (*Transport, error) {
	defer func() {
		if err := recover(); err != nil {
			d.log(slog.LevelError, "dial panic", slog.Any("err", err))
		}
	}()
	at, err := attest.LoadFromDisk(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	if err = sendIntroduction(d.conn, at); err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}
	remote, err := receiveIntroduction(d.conn)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}
	if err = d.verifyRemote(remote); err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}

	pt := &plainTransport{conn: d.conn, attest: at, remote: remote}
	t, err := requestHandshake(pt)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	return t, nil
}

func (dialer) log(lvl slog.Level, msg string, args ...any) {
	slog.Log(nil, lvl, msg, args...)
}
