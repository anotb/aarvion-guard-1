package govern

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"
)

// peerUID must read the connecting process's uid off a real unix socket. Both
// ends are this test process, so the reported uid is our own.
func TestPeerUIDReadsOwnUID(t *testing.T) {
	sock := shortSocketPath(t)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	dialed, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialed.Close()

	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()

	uid, err := peerUID(server)
	if err != nil {
		t.Fatalf("peerUID: %v", err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("peerUID: got %d want %d", uid, os.Getuid())
	}
}

// peerUID must reject a non-unix connection rather than panic.
func TestPeerUIDRejectsNonUnix(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialed.Close()

	server := <-accepted
	defer server.Close()

	if _, err := peerUID(server); err == nil {
		t.Fatal("expected error for non-unix conn")
	}
}

// A configured peer uid that doesn't match the connecting process is rejected
// with 403 before token or body are even considered.
func TestWrongPeerUIDForbidden(t *testing.T) {
	// Build a server whose accepted peer uid (ours) will not equal PeerUID, so
	// the kernel-reported uid mismatches and the connection is refused.
	sock := shortSocketPath(t)
	cfg := Config{SocketPath: sock, Token: testToken, PeerUID: uint32(os.Getuid()) + 1}
	srv := New(cfg, opaStub(t, true), testRecorder(t))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	waitForSocket(t, sock, errCh)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}

	resp := post(t, client, sock, testToken, sampleRequest("n-uid", "POST", "api.example.com"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong peer uid: got %d want 403", resp.StatusCode)
	}
}
