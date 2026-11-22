package encoding

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type mockHunkConn struct {
	frames [][]byte
}

func (*mockHunkConn) Context() context.Context { return context.Background() }
func (*mockHunkConn) Send(*Hunk) error         { return nil }
func (*mockHunkConn) SendMsg(any) error        { return nil }
func (*mockHunkConn) RecvMsg(any) error        { return io.ErrUnexpectedEOF }

func (c *mockHunkConn) Recv() (*Hunk, error) {
	if len(c.frames) == 0 {
		return nil, io.EOF
	}
	frame := c.frames[0]
	c.frames = c.frames[1:]
	return &Hunk{Data: frame}, nil
}

func TestHunkReadMultiBufferAfterPartialRead(t *testing.T) {
	for _, frameSize := range []int{buf.Size, 2*buf.Size + 17} {
		for _, prefixSize := range []int{0, 1, 257, buf.Size + 32} {
			if prefixSize >= frameSize {
				continue
			}
			t.Run(strconv.Itoa(frameSize)+"/prefix_"+strconv.Itoa(prefixSize), func(t *testing.T) {
				frame := make([]byte, frameSize)
				for i := range frame {
					frame[i] = byte(i % 251)
				}
				reader := NewHunkReadWriter(&mockHunkConn{frames: [][]byte{frame, []byte("next")}}, nil)
				prefix := make([]byte, prefixSize)
				if prefixSize > 0 {
					n, err := reader.Read(prefix)
					if err != nil || n != prefixSize || !bytes.Equal(prefix, frame[:prefixSize]) {
						t.Fatalf("Read prefix: n=%d, err=%v", n, err)
					}
				}
				var got []byte
				for len(got) < frameSize-prefixSize {
					mb, err := reader.ReadMultiBuffer()
					if err != nil {
						t.Fatal(err)
					}
					if len(mb) == 0 {
						t.Fatal("empty buffer before end of frame")
					}
					for _, b := range mb {
						if b.Len() == 0 || b.Len() > buf.Size {
							t.Fatalf("invalid standard buffer length: %d", b.Len())
						}
						got = append(got, b.Bytes()...)
					}
					buf.ReleaseMulti(mb)
				}
				if !bytes.Equal(got, frame[prefixSize:]) {
					t.Fatal("repeated, omitted or crossed frame bytes")
				}
				next, err := reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				defer buf.ReleaseMulti(next)
				if len(next) != 1 || string(next[0].Bytes()) != "next" {
					t.Fatal("did not advance to next frame")
				}
			})
		}
	}
}
