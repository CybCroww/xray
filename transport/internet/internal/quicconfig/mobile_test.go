package quicconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/qlog"
	"github.com/apernet/quic-go/qlogwriter"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
)

type parameterTrace chan qlog.ParametersSet

func (t parameterTrace) AddProducer() qlogwriter.Recorder { return t }
func (parameterTrace) SupportsSchemas(string) bool        { return true }
func (parameterTrace) Close() error                       { return nil }

func (t parameterTrace) RecordEvent(event qlogwriter.Event) {
	if parameters, ok := event.(qlog.ParametersSet); ok && parameters.Initiator == qlog.InitiatorLocal && !parameters.Restore {
		t <- parameters
	}
}

func TestMobileQUICAdvertisesLimitedWindowsAndTransfersLargerStream(t *testing.T) {
	generated, _ := cert.MustGenerate(nil)
	key, err := x509.ParsePKCS8PrivateKey(generated.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{generated.Certificate}, PrivateKey: key}},
		NextProtos:   []string{"cvpn-flow-test"},
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	parameters := make(parameterTrace, 8)
	cfg := &quic.Config{
		ChromeParrot:                   true,
		InitialStreamReceiveWindow:     6 << 20,
		MaxStreamReceiveWindow:         12 << 20,
		InitialConnectionReceiveWindow: 15 << 20,
		MaxConnectionReceiveWindow:     20 << 20,
	}
	LimitMobileReceiveWindow(cfg)
	if cfg.MaxStreamReceiveWindow != 512<<10 || cfg.MaxConnectionReceiveWindow != 2<<20 {
		t.Fatalf("unexpected window ceilings: stream %d, connection %d", cfg.MaxStreamReceiveWindow, cfg.MaxConnectionReceiveWindow)
	}
	cfg.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
		return parameters
	}
	clientTLS := &tls.Config{InsecureSkipVerify: true, NextProtos: serverTLS.NextProtos}
	client, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseWithError(0, "")
	select {
	case p := <-parameters:
		if p.InitialMaxData != 2<<20 || p.InitialMaxStreamDataBidiRemote != 512<<10 {
			t.Fatalf("wrong advertised initial windows: %d connection, %d stream", p.InitialMaxData, p.InitialMaxStreamDataBidiRemote)
		}
	case <-ctx.Done():
		t.Fatal("no recorded QUIC transport parameters")
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := server.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	stream.SetWriteDeadline(deadline)
	payload := bytes.Repeat([]byte("x"), 3<<20)
	written := make(chan error, 1)
	go func() {
		_, err := stream.Write(payload)
		if err == nil {
			err = stream.Close()
		}
		written <- err
	}()
	recv, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recv.SetReadDeadline(deadline)
	n, err := io.Copy(io.Discard, recv)
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("read %d of %d bytes: %v", n, len(payload), err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}
