package kamune

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/hossein1376/kamune/internal/box/pb"
)

type Transferable interface {
	proto.Message
}

type String struct {
	Data *pb.String
}

func NewString(s string) String {
	return String{Data: &pb.String{Str: s}}
}

func (s String) ProtoReflect() protoreflect.Message {
	return s.Data.ProtoReflect()
}

type Bytes struct {
	Data *pb.Bytes
}

func NewBytes(b []byte) Bytes {
	if b == nil {
		b = []byte{}
	}
	return Bytes{Data: &pb.Bytes{Bytes: b}}
}

func (b *Bytes) ProtoReflect() protoreflect.Message {
	return b.Data.ProtoReflect()
}
