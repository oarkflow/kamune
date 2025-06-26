package main

import (
	"github.com/hossein1376/kamune/stp"
)

func main() {
	err := stp.ListenAndServe(":9999")
	if err != nil {
		panic(err)
	}
}
