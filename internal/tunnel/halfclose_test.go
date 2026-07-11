package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// tcpDialer forwards SSHDial straight to a TCP dial so the forward path uses
// real TCP conns (net.Pipe lacks CloseWrite and would mask half-close bugs).
type tcpDialer struct{}

func (tcpDialer) SSHDial(ctx context.Context, _, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (tcpDialer) SSHListen(context.Context, string, string, int) (net.Listener, error) {
	return nil, fmt.Errorf("not implemented")
}

// TestLocalForward_HalfCloseAllowsResponseAfterClientEOF: a client that
// half-closes its write side (request/EOF pattern) must still receive the
// server's response. A forwarder that full-Closes on EOF kills the reverse
// direction and drops the response.
func TestLocalForward_HalfCloseAllowsResponseAfterClientEOF(t *testing.T) {
	// Target server: read until EOF, pause, then reply.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	go func() {
		c, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c) // unblocks at client EOF
		time.Sleep(50 * time.Millisecond)
		_, _ = c.Write(append([]byte("echo:"), data...))
	}()

	_, portStr, _ := net.SplitHostPort(targetLn.Addr().String())
	targetPort, _ := strconv.Atoi(portStr)

	m := NewManager(tcpDialer{})
	id, err := m.CreateLocal("srv", "127.0.0.1", 0, "127.0.0.1", targetPort)
	if err != nil {
		t.Fatalf("CreateLocal: %v", err)
	}
	defer func() { _ = m.Close(id) }()

	var localAddr string
	for _, info := range m.List() {
		if info.ID == id {
			localAddr = info.LocalAddr
		}
	}

	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response after half-close: %v", err)
	}
	if string(resp) != "echo:hello" {
		t.Fatalf("response = %q, want %q (dropped by forwarder full-close?)", resp, "echo:hello")
	}
}
