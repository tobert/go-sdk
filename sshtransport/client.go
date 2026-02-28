package sshtransport

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
)

// SSHClientTransport implements mcp.Transport for connecting to an MCP server
// over SSH. It establishes an SSH connection and requests the MCP subsystem.
type SSHClientTransport struct {
	// Addr is the host:port to connect to. Required.
	Addr string

	// Subsystem is the SSH subsystem name. Default "mcp".
	Subsystem string

	// Config is the SSH client configuration, including auth methods and
	// host key verification. Required.
	Config *ssh.ClientConfig
}

// Connect implements mcp.Transport. It dials the SSH server, authenticates,
// opens a session, requests the subsystem, and returns the resulting
// IOTransport connection.
func (t *SSHClientTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	subsystem := t.Subsystem
	if subsystem == "" {
		subsystem = "mcp"
	}

	// Dial with context support.
	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", t.Addr, err)
	}

	// SSH handshake.
	sshConn, chans, reqs, err := ssh.NewClientConn(tcpConn, t.Addr, t.Config)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("SSH handshake with %s: %w", t.Addr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("opening SSH session: %w", err)
	}

	// Get stdin/stdout pipes.
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("getting stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("getting stdout pipe: %w", err)
	}

	// Request subsystem.
	if err := session.RequestSubsystem(subsystem); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("requesting subsystem %q: %w", subsystem, err)
	}

	// Wrap as IOTransport.
	ioTransport := &mcp.IOTransport{
		Reader: io.NopCloser(stdout),
		Writer: &sessionWriter{w: stdin, session: session, client: client},
	}

	return ioTransport.Connect(ctx)
}

// sessionWriter wraps the SSH session stdin pipe and closes the session
// and client when closed.
type sessionWriter struct {
	w       io.WriteCloser
	session *ssh.Session
	client  *ssh.Client
}

func (sw *sessionWriter) Write(p []byte) (int, error) {
	return sw.w.Write(p)
}

func (sw *sessionWriter) Close() error {
	sw.w.Close()
	sw.session.Close()
	return sw.client.Close()
}
