package encoding

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestMobileMultiHunkIgnoresUnknownFieldsAndRejectsTruncation(t *testing.T) {
	wire := protowire.AppendTag(nil, 1, protowire.BytesType)
	wire = protowire.AppendString(wire, "first")
	wire = protowire.AppendTag(wire, 2, protowire.VarintType)
	wire = protowire.AppendVarint(wire, 123)
	wire = protowire.AppendTag(wire, 1, protowire.BytesType)
	wire = protowire.AppendString(wire, "second")
	decode := func(wire []byte, hunk *mobileMultiHunk) error {
		mid := len(wire) / 2
		return compactMultiHunkCodec.Unmarshal(mem.BufferSlice{mem.SliceBuffer(wire[:mid]), mem.SliceBuffer(wire[mid:])}, hunk)
	}
	var valid mobileMultiHunk
	if err := decode(wire, &valid); err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(valid.payload)
	if len(valid.payload) != 1 || string(valid.payload[0].Bytes()) != "firstsecond" {
		t.Fatal("unexpected byte stream after decoding")
	}
	var truncated mobileMultiHunk
	if err := decode(wire[:len(wire)-1], &truncated); err == nil || len(truncated.payload) != 0 {
		t.Fatalf("truncated message retained payload or was accepted: %v", err)
	}
}
