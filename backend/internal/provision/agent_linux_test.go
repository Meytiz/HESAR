//go:build linux

package provision

import (
	"bytes"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentRejectsUntypedOperations(t *testing.T) {
	a := &agent{entries: map[string]*coreEntry{}}
	for _, test := range []struct{ path, body string }{
		{"/v1/ensure", `{"command":"sh","arguments":["-c","id"]}`},
		{"/v1/ensure", `{"tunnel":{"id":"../foreign","binary":"/bin/sh"}}`},
		{"/v1/release", `{"id":"../foreign"}`},
		{"/v1/status", `{} {}`},
		{"/v1/run", `{}`},
	} {
		w := httptest.NewRecorder()
		a.handle(w, httptest.NewRequest("POST", test.path, bytes.NewBufferString(test.body)))
		if w.Code < 400 {
			t.Fatalf("accepted untyped operation %s", test.path)
		}
	}
}

func TestUnixSocketChecksPeerUID(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		if !allowed && os.Geteuid() == 0 {
			continue
		} // Root is explicitly trusted.
		path := filepath.Join(t.TempDir(), "agent.sock")
		base, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		uid := uint32(os.Geteuid())
		if !allowed {
			uid = ^uint32(0)
		}
		listener := authorizedListener{Listener: base, uid: uid}
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			c, err := listener.Accept()
			if err == nil {
				defer c.Close()
				_, _ = c.Write([]byte("allowed"))
			}
		}()
		client, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		data, err := io.ReadAll(client)
		client.Close()
		listener.Close()
		<-finished
		if allowed && (err != nil || string(data) != "allowed") {
			t.Fatal("authorized peer rejected")
		}
		if !allowed && len(data) != 0 {
			t.Fatal("unauthorized peer accepted")
		}
	}
}

func TestSystemdSocketReadinessNotification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	if err := notifyReady(); err != nil {
		t.Fatal(err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 256)
	n, _, err := listener.ReadFromUnix(data)
	if err != nil || !bytes.Contains(data[:n], []byte("READY=1")) {
		t.Fatal("readiness notification missing")
	}
}
