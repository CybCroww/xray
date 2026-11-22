//go:build xhysteria_interop && xhysteria_native && cgo && (linux || android)

package interop_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
)

func TestNativeServerWithDefaultQuicParams(t *testing.T) {
	for _, masked := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "salamander"}[masked], func(t *testing.T) {
			t.Setenv("XRAY_HYSTERIA_NATIVE", "0")
			server, caPath, _ := xrayServerWithConfig(t, masked, func(c *core.Config) {
				nativeServerConfig(t, c, false)
				raw, err := c.Inbound[0].ReceiverSettings.GetInstance()
				if err != nil {
					t.Fatal(err)
				}
				receiver := raw.(*proxyman.ReceiverConfig)
				receiver.StreamSettings.QuicParams = nil
				c.Inbound[0].ReceiverSettings = serial.ToTypedMessage(receiver)
			})
			ca, err := os.ReadFile(caPath)
			if err != nil {
				t.Fatal(err)
			}
			config := embeddedClientConfig(t, server, ca, masked, auth)
			raw, err := config.Outbound[0].SenderSettings.GetInstance()
			if err != nil {
				t.Fatal(err)
			}
			sender := raw.(*proxyman.SenderConfig)
			sender.StreamSettings.QuicParams.DisableChromeParrot = false
			config.Outbound[0].SenderSettings = serial.ToTypedMessage(sender)
			client, err := core.New(config)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Start(); err != nil {
				t.Fatal(err)
			}
			tcp, udp := echoTargets(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, target := range []string{"tcp:" + tcp, "udp:" + udp} {
				destination, err := xnet.ParseDestination(target)
				if err != nil {
					t.Fatal(err)
				}
				conn, err := core.Dial(ctx, client, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(8 * time.Second))
				payload := bytes.Repeat([]byte{0x7b}, 4096)
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(payload, got) {
					t.Fatalf("default ChromeParrot client failed: %v", err)
				}
			}
		})
	}
}
