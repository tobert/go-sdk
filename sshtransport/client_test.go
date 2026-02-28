package sshtransport

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
)

func TestSSHClientTransport_Connect(t *testing.T) {
	env := newTestEnv(t, nil)
	defer env.Close()

	ctx := context.Background()

	transport := &SSHClientTransport{
		Addr:      env.Addr,
		Subsystem: "mcp",
		Config:    env.ClientConfig,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "client-test"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the connection works by calling a tool.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "hello from SSH" {
		t.Errorf("got %q, want %q", text, "hello from SSH")
	}

	cs.Close()
}

func TestSSHClientTransport_DefaultSubsystem(t *testing.T) {
	env := newTestEnv(t, nil)
	defer env.Close()

	ctx := context.Background()

	// Don't set Subsystem — should default to "mcp".
	transport := &SSHClientTransport{
		Addr:   env.Addr,
		Config: env.ClientConfig,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "client-test"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Should work with default subsystem.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) == 0 {
		t.Error("expected at least one tool")
	}
}

func TestSSHClientTransport_BadAddr(t *testing.T) {
	transport := &SSHClientTransport{
		Addr: "127.0.0.1:1", // Almost certainly not listening.
		Config: &ssh.ClientConfig{
			User:            "mcp",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         1 * time.Second,
		},
	}

	ctx := context.Background()
	_, err := transport.Connect(ctx)
	if err == nil {
		t.Fatal("expected error connecting to bad address")
	}
}
