//go:build !windows

package internet

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestUnixListenerConcurrentClose(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: filepath.Join(dir, "socket")})
	if err != nil {
		t.Fatal(err)
	}
	locker := &FileLocker{path: filepath.Join(dir, "lock")}
	if err := locker.Acquire(); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	wrapper := &UnixListenerWrapper{UnixListener: listener, locker: locker}
	t.Cleanup(func() { wrapper.Close() })
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() { <-start; wrapper.Close() })
	}
	close(start)
	workers.Wait()
	if wrapper.locker != nil {
		t.Fatal("listener retained the file lock")
	}
	if _, err := os.Stat(locker.path); !os.IsNotExist(err) {
		t.Fatalf("lock file was not removed: %v", err)
	}
	if err := locker.Acquire(); err != nil {
		t.Fatal(err)
	}
	locker.Release()
}
