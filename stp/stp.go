// Package stp stands for: signed transfer protocol, or secure telecommunication
// passthrough; or (to anyone involved in internet censorship) suck this, punks.
package stp

import (
	"google.golang.org/protobuf/proto"

	"github.com/hossein1376/kamune/internal/box/pb"
)

type SignedTransport = pb.SignedTransport

type Transferable interface {
	proto.Message
}
