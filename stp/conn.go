package stp

import (
	"errors"
	"net"
)

var (
	ErrAlreadyClosed = errors.New("conn has already been closed")
)

type Conn struct {
	net.Conn
	isClosed bool
}

func (c *Conn) Close() error {
	if c.isClosed {
		return ErrAlreadyClosed
	}
	err := c.Conn.Close()
	if err != nil {
		return err
	}
	c.isClosed = true

	return nil
}
