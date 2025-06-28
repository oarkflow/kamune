package stp

import (
	"fmt"
	"log/slog"
	"net"
)

type dialer struct {
	conn         Conn
	introHandler IntroductionHandler
}

func newDialer(conn net.Conn, intro IntroductionHandler) *dialer {
	return &dialer{conn: Conn{Conn: conn}, introHandler: intro}
}

func Dial(addr string) (*Transport, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return newDialer(conn, defaultIntroductionHandler).dial()
}

func (d *dialer) dial() (_ *Transport, err error) {
	defer func() {
		if err := recover(); err != nil {
			d.log(slog.LevelError, "dial panic", slog.Any("err", err))
		}
	}()
	at, err := loadCert()
	if err != nil {
		err = fmt.Errorf("loading certificate: %w", err)
		return
	}

	if err = sendIntroduction(d.conn, at); err != nil {
		err = fmt.Errorf("send introduction: %w", err)
		return
	}
	remote, err := receiveIntroduction(d.conn)
	if err != nil {
		err = fmt.Errorf("receive introduction: %w", err)
		return
	}
	if err = d.introHandler(remote); err != nil {
		err = fmt.Errorf("intro handler: %w", err)
		return
	}
	encoder, decoder, err := RequestHandshake(d.conn, at, remote)
	if err != nil {
		err = fmt.Errorf("request handshake: %w", err)
		return
	}
	t := newTransport(at, remote, encoder, decoder, d.conn)

	return t, nil
}

func (dialer) log(lvl slog.Level, msg string, args ...any) {
	slog.Log(nil, lvl, msg, args...)
}
