package main

import (
	"fmt"

	"github.com/hossein1376/kamune/chat"
	"github.com/hossein1376/kamune/stp"
)

func main() {
	err := RunServer(":9999")
	if err != nil {
		panic(err)
	}
}

func RunServer(addr string) error {
	srv, err := stp.NewServer(addr, handler)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}

	return srv.ListenAndServe()
}

func handler(t *stp.Transport) error {
	c, stop := chat.NewSession(t)
	defer stop()
	c.Start()

	return nil
}
