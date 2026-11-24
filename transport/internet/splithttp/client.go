package splithttp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, buf.MultiBuffer) error
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          atomic.Bool
	httpVersion     string
	packetHTTP1     *http.Client
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	type dialResult struct {
		remote, local net.Addr
		err           error
	}
	ready := make(chan dialResult, 1)
	var announce sync.Once
	emit := func(r dialResult) { announce.Do(func() { ready <- r }) }
	requestCtx, cancel := context.WithCancel(ctx)
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Conn != nil {
				emit(dialResult{remote: connInfo.Conn.RemoteAddr(), local: connInfo.Conn.LocalAddr()})
			}
		},
	})

	method := "GET" // stream-down
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, err := http.NewRequestWithContext(requestCtx, method, url, body)
	if err != nil {
		cancel()
		errors.LogInfoInner(ctx, err, "failed to create HTTP request for "+url)
		return nil, nil, nil, err
	}
	c.transportConfig.FillStreamRequest(req, sessionId, "")

	wrc := &WaitReadCloser{wait: done.New(), cancel: cancel}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly && requestCtx.Err() == nil {
				c.closed.Store(true)
				errors.LogInfoInner(ctx, err, "failed to "+method+" "+url)
			}
			emit(dialResult{err: err})
			common.Close(body)
			wrc.Close()
			return
		}
		emit(dialResult{}) // Some RoundTrippers do not emit GotConn.
		if resp.StatusCode != 200 && !uploadOnly {
			errors.LogInfo(ctx, "unexpected status ", resp.StatusCode)
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			if uploadOnly {
				io.Copy(io.Discard, resp.Body)
			}
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			common.Close(body)
			wrc.Close()
			return
		}
		wrc.Set(resp.Body)
	}()

	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	select {
	case r := <-ready:
		if r.err != nil {
			wrc.Close()
			return nil, nil, nil, r.err
		}
		return wrc, r.remote, r.local, nil
	case <-ctx.Done():
		wrc.Close()
		return nil, nil, nil, ctx.Err()
	case <-timer.C:
		wrc.Close()
		return nil, nil, nil, context.DeadlineExceeded
	}
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		buf.ReleaseMulti(payload)
		return err
	}

	if c.httpVersion != "1.1" || c.packetHTTP1 != nil {
		c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload)
		client := c.client
		if c.packetHTTP1 != nil {
			client = c.packetHTTP1
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				c.closed.Store(true)
			}
			common.Close(req.Body)
			return err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	} else {
		replayBody := c.prepareHTTP1PacketRequest(req, sessionId, seqStr, payload)
		if replayBody {
			defer buf.ReleaseMulti(payload)
		}

		var uploadConn any
		var h1UploadConn *H1Conn

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(ctx)
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)
			}
			if deadline, ok := ctx.Deadline(); ok {
				h1UploadConn.SetDeadline(deadline)
			}
			if !newConnection {
				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					stop := context.AfterFunc(ctx, func() { h1UploadConn.Close() })
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						stop()
						if ctx.Err() == nil {
							c.closed.Store(true)
						}
						h1UploadConn.Close()
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					_, err = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					stop()
					if err != nil {
						h1UploadConn.Close()
						return err
					}
					h1UploadConn.UnreadedResponsesCount--
					if resp.StatusCode != 200 {
						h1UploadConn.Close()
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}

			if replayBody {
				req.Body = &replayMultiBufferBody{payload: payload}
			}
			stop := context.AfterFunc(ctx, func() { h1UploadConn.Close() })
			err := req.Write(h1UploadConn)
			if !stop() || ctx.Err() != nil {
				h1UploadConn.Close()
				return ctx.Err()
			}
			req.Body = nil
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				h1UploadConn.UnreadedResponsesCount++
				h1UploadConn.SetDeadline(time.Time{})
				break
			} else if newConnection {
				h1UploadConn.Close()
				return err
			} else {
				h1UploadConn.Close()
			}
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}

func (c *DefaultDialerClient) prepareHTTP1PacketRequest(req *http.Request, sessionId string, seqStr string, payload buf.MultiBuffer) bool {
	dataPlacement := c.transportConfig.GetNormalizedUplinkDataPlacement()
	if dataPlacement != PlacementBody && dataPlacement != PlacementAuto {
		c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload)
		return false
	}

	req.Header = c.transportConfig.GetRequestHeader()
	req.ContentLength = int64(payload.Len())
	c.transportConfig.applyPacketRequestControls(req, sessionId, seqStr)
	return true
}

type replayMultiBufferBody struct {
	payload buf.MultiBuffer
	index   int
	offset  int32
}

func (b *replayMultiBufferBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for b.index < len(b.payload) {
		buffer := b.payload[b.index]
		if buffer == nil {
			b.index++
			b.offset = 0
			continue
		}
		data := buffer.BytesFrom(b.offset)
		if len(data) == 0 {
			b.index++
			b.offset = 0
			continue
		}
		n := copy(p, data)
		b.offset += int32(n)
		return n, nil
	}
	return 0, io.EOF
}

func (b *replayMultiBufferBody) Close() error {
	return nil
}

// HTTP/1.1 and HTTP/2 will close itself, we only handle HTTP/3 here
func (c *DefaultDialerClient) Close() error {
	transport := c.client.Transport
	c.client.CloseIdleConnections()
	if c.packetHTTP1 != nil {
		c.packetHTTP1.CloseIdleConnections()
	}
	if h3Transport, ok := transport.(*http3.Transport); ok {
		h3Transport.Close()
	}
	return nil
}

type WaitReadCloser struct {
	wait   *done.Instance
	cancel context.CancelFunc
	reader atomic.Pointer[io.ReadCloser]
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.reader.Store(&rc)
	if w.wait.Done() {
		if p := w.reader.Swap(nil); p != nil {
			(*p).Close()
		}
	}
	w.wait.Close()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	rc := w.reader.Load()
	if rc == nil {
		<-w.wait.Wait()
		if rc = w.reader.Load(); rc == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return (*rc).Read(b)
}

func (w *WaitReadCloser) Close() error {
	if w.cancel != nil {
		w.cancel()
	}
	w.wait.Close()
	if p := w.reader.Swap(nil); p != nil {
		return (*p).Close()
	}
	return nil
}
