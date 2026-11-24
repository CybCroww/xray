package encoding

import (
	"fmt"

	"github.com/xtls/xray-core/common/buf"
	grpcencoding "google.golang.org/grpc/encoding"
	grpcproto "google.golang.org/grpc/encoding/proto"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/encoding/protowire"
)

type mobileMultiHunk struct {
	payload buf.MultiBuffer
}

// mobileMultiHunkCodec decodes repeated bytes directly into the byte stream's
// buffers. Small fields share a buffer and large fields can be released as
// individual buffers are consumed. Sending and other messages still use proto.
type mobileMultiHunkCodec struct{ grpcencoding.CodecV2 }

var compactMultiHunkCodec = mobileMultiHunkCodec{grpcencoding.GetCodecV2(grpcproto.Name)}

func (c mobileMultiHunkCodec) Unmarshal(data mem.BufferSlice, message any) (err error) {
	hunk, ok := message.(*mobileMultiHunk)
	if !ok {
		return c.CodecV2.Unmarshal(data, message)
	}
	wire := data.MaterializeToBuffer(mem.DefaultBufferPool())
	defer wire.Free()
	defer func() {
		if err != nil {
			buf.ReleaseMulti(hunk.payload)
			hunk.payload = nil
		}
	}()
	for remaining := wire.ReadOnlyData(); len(remaining) > 0; {
		number, typ, n := protowire.ConsumeTag(remaining)
		if n < 0 {
			return protowire.ParseError(n)
		}
		if !number.IsValid() {
			return fmt.Errorf("invalid protobuf field number: %d", number)
		}
		remaining = remaining[n:]
		if number == 1 && typ == protowire.BytesType { // MultiHunk.data
			var payload []byte
			payload, n = protowire.ConsumeBytes(remaining)
			if n < 0 {
				return protowire.ParseError(n)
			}
			hunk.payload = buf.MergeBytes(hunk.payload, payload)
		} else {
			n = protowire.ConsumeFieldValue(number, typ, remaining)
			if n < 0 {
				return protowire.ParseError(n)
			}
		}
		remaining = remaining[n:]
	}
	return nil
}
