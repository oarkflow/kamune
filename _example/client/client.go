package main

import (
	"log"
	"time"

	"github.com/hossein1376/kamune/chat"
	"github.com/hossein1376/kamune/stp"
)

func main() {
	var t *stp.Transport
	var err error
	for {
		t, err = stp.Dial("127.0.0.1:9999")
		if err == nil {
			break
		}
		log.Printf("dial err: %v", err)
		time.Sleep(5 * time.Second)
	}
	defer t.Close()

	c, stop := chat.NewSession(t)
	defer stop()
	c.Chat()

	return
}
