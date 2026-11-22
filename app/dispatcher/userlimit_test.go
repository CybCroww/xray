package dispatcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apppolicy "github.com/xtls/xray-core/app/policy"
	appstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/userlimit"
	"github.com/xtls/xray-core/transport"
)

func TestUserLimitBothDispatchPathsKeepStatsAndTimeoutReader(t *testing.T) {
	file := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(file, []byte(`{"version":1,"users":{"458":{"uplinkBytesPerSecond":125000,"downlinkBytesPerSecond":125000}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := userlimit.Default
	userlimit.Default = userlimit.New(file)
	t.Cleanup(func() { userlimit.Default = old })
	for _, path := range []string{"pipe", "direct"} {
		t.Run(path, func(t *testing.T) {
			policy, _ := apppolicy.New(context.Background(), &apppolicy.Config{Level: map[uint32]*apppolicy.Policy{0: {Stats: &apppolicy.Policy_Stats{UserUplink: true, UserDownlink: true}}}})
			stats, _ := appstats.NewManager(context.Background(), &appstats.Config{})
			in := &session.Inbound{User: &protocol.MemoryUser{Email: "458"}, CanSpliceCopy: 2}
			ctx, cancel := context.WithCancel(session.ContextWithInbound(context.Background(), in))
			defer cancel()
			var input, output *transport.Link
			if path == "pipe" {
				d := &DefaultDispatcher{policy: policy, stats: stats}
				input, output = d.getLink(ctx)
				if err := input.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("up"))); err != nil {
					t.Fatal(err)
				}
				mb, err := output.Reader.ReadMultiBuffer()
				if err != nil {
					t.Fatal(err)
				}
				buf.ReleaseMulti(mb)
			} else {
				output = WrapLink(ctx, policy, stats, &transport.Link{Reader: buf.NewReader(strings.NewReader("up")), Writer: buf.Discard})
				if _, ok := output.Reader.(buf.TimeoutReader); !ok {
					t.Fatal("sniffing timeout reader lost")
				}
				mb, _ := output.Reader.ReadMultiBuffer()
				buf.ReleaseMulti(mb)
			}
			if in.CanSpliceCopy != 3 {
				t.Fatal("splice can bypass dynamic user limit")
			}
			if err := output.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("down"))); err != nil {
				t.Fatal(err)
			}
			if stats.GetCounter("user>>>458>>>traffic>>>uplink").Value() != 2 || stats.GetCounter("user>>>458>>>traffic>>>downlink").Value() != 4 {
				t.Fatal("authenticated user traffic counters changed")
			}
			cancel()
			if err := output.Writer.WriteMultiBuffer(buf.MergeBytes(nil, []byte("cancelled"))); err != context.Canceled {
				t.Fatalf("cancelled writer: %v", err)
			}
		})
	}
}
