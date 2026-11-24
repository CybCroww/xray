package buf_test

import (
	"crypto/tls"
	"io"
	"testing"
	"testing/synctest"
	"time"

	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

type blockingReader chan MultiBuffer

func (r blockingReader) ReadMultiBuffer() (MultiBuffer, error) {
	return <-r, nil
}

func TestTimeoutWrapperLeavesPendingReadAvailable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := make(blockingReader, 1)
		reader := &TimeoutWrapperReader{Reader: source}
		if got, err := reader.ReadMultiBufferTimeout(time.Second); !got.IsEmpty() || err != nil {
			t.Fatalf("timeout returned %v, %v", got, err)
		}
		source <- MultiBuffer{FromBytes([]byte("pending"))}
		got, err := reader.ReadMultiBuffer()
		defer ReleaseMulti(got)
		if err != nil || got.String() != "pending" {
			t.Fatalf("pending read returned %q, %v", got.String(), err)
		}
	})
}

func TestWriterCreation(t *testing.T) {
	tcpServer := tcp.Server{}
	dest, err := tcpServer.Start()
	if err != nil {
		t.Fatal("failed to start tcp server: ", err)
	}
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	if err != nil {
		t.Fatal("failed to dial a TCP connection: ", err)
	}
	defer conn.Close()

	{
		writer := NewWriter(conn)
		if _, ok := writer.(*BufferToBytesWriter); !ok {
			t.Fatal("writer is not a BufferToBytesWriter")
		}

		writer2 := NewWriter(writer.(io.Writer))
		if writer2 != writer {
			t.Fatal("writer is not reused")
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	{
		writer := NewWriter(tlsConn)
		if _, ok := writer.(*SequentialWriter); !ok {
			t.Fatal("writer is not a SequentialWriter")
		}
	}
}
