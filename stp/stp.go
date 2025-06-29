// Package stp stands for: signed transfer protocol, or secure telecommunication
// passthrough; or (to anyone involved in internet censorship) suck this, punks.
package stp

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/hossein1376/kamune/internal/box/pb"
)

type Transferable interface {
	proto.Message
}

func Bytes(b []byte) *wrapperspb.BytesValue {
	return &wrapperspb.BytesValue{Value: b}
}

type Metadata struct {
	pb *pb.Metadata
}

func (m Metadata) Timestamp() time.Time {
	return m.pb.Timestamp.AsTime()
}

func (m Metadata) SequenceNum() uint64 {
	return m.pb.GetSequence()
}
