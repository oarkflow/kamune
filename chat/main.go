package main

// A simple program demonstrating the text area component from the Bubbles
// component library.

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hossein1376/kamune/stp"
)

var (
	errCh = make(chan error)
	stop  = make(chan struct{}, 2)
)

type Program struct {
	*tea.Program
	transport *stp.Transport
}

func NewProgram(p *tea.Program) *Program {
	return &Program{Program: p}
}

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		return
	}

	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)
	switch addr := args[1]; args[0] {
	case "dial":
		go func() {
			client(addr)
		}()
	case "serve":
		go func() {
			server(addr)
		}()
	default:
		panic(fmt.Errorf("invalid command: %s", args[0]))
	}

	select {
	case err := <-errCh:
		fmt.Println("error:", err)
	case <-exitCh:
		fmt.Println("program exited")
	}
}

func serveHandler(t *stp.Transport) error {
	p := NewProgram(tea.NewProgram(initialModel(t), tea.WithAltScreen()))
	go func() {
		if _, err := p.Run(); err != nil {
			panic(err)
		}
	}()

	for {
		select {
		case <-stop:
			return nil
		default:
			b := stp.Bytes(nil)
			metadata, err := t.Receive(b)
			if err != nil {
				errCh <- fmt.Errorf("receiving: %w", err)
				continue
			}
			p.Send(NewPeerMessage(metadata.Timestamp(), b.Value))
		}
	}
}

func server(addr string) {
	srv, err := stp.NewServer(addr, serveHandler)
	if err != nil {
		errCh <- fmt.Errorf("starting server: %w", err)
		return
	}
	errCh <- srv.ListenAndServe()
}

func client(addr string) {
	var t *stp.Transport
	for {
		var opErr *net.OpError
		var err error
		t, err = stp.Dial(addr)
		if err == nil {
			break
		}
		if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("dial err: %v", err)
		time.Sleep(5 * time.Second)
	}
	defer t.Close()

	p := NewProgram(tea.NewProgram(initialModel(t), tea.WithAltScreen()))
	go func() {
		if _, err := p.Run(); err != nil {
			errCh <- err
		}
	}()

	for {
		select {
		case <-stop:
			return
		default:
			b := stp.Bytes(nil)
			metadata, err := t.Receive(b)
			if err != nil {
				errCh <- fmt.Errorf("receiving: %w", err)
				return
			}
			p.Send(NewPeerMessage(metadata.Timestamp(), b.Value))
		}
	}
}

type PeerMessage struct {
	prefix string
	text   string
}

func NewPeerMessage(timestamp time.Time, text []byte) PeerMessage {
	return PeerMessage{
		prefix: fmt.Sprintf("[%s] Peer: ", timestamp.Format(time.DateTime)),
		text:   string(text),
	}
}
