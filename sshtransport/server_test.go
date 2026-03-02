// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package sshtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
)

// testEnv sets up a complete SSH MCP server with one authorized key,
// returning the client SSH config and server address.
type testEnv struct {
	Server       *mcp.Server
	Handler      *SSHHandler
	Addr         string
	ClientConfig *ssh.ClientConfig
	Cancel       context.CancelFunc
}

func newTestEnv(t *testing.T, perm *Permission) *testEnv {
	t.Helper()

	// Generate host key.
	hostKey, err := GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}

	// Generate client key.
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(clientPub)
	if err != nil {
		t.Fatal(err)
	}

	// Set up authorized keys.
	fp := ssh.FingerprintSHA256(sshPub)
	if perm == nil {
		perm = &Permission{
			Identity:          "test-user",
			RestrictTools:     []string{"*"},
			RestrictResources: []string{"*"},
			RestrictPrompts:   []string{"*"},
		}
	}
	ak := NewAuthorizedKeys(map[string]*Permission{fp: perm})

	// Create MCP server with tools.
	server := mcp.NewServer(&mcp.Implementation{Name: "ssh-test", Version: "0.1.0"}, nil)
	server.AddTool(&mcp.Tool{
		Name:        "echo",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "hello from SSH"}},
		}, nil
	})
	server.AddTool(&mcp.Tool{
		Name:        "whoami",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Return identity from TransportAuth if present.
		if req.Extra != nil {
			if mp, ok := req.Extra.TransportAuth.(*MergedPermission); ok {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("identity:%s", mp.Identity())}},
				}, nil
			}
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "identity:unknown"}},
		}, nil
	})

	// Listen on random port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	handler := NewSSHHandler(func() *mcp.Server { return server }, &SSHHandlerOptions{
		HostKey:        hostKey,
		AuthorizedKeys: ak,
		Subsystems:     []string{"mcp"},
	})

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		handler.Serve(ctx, ln)
	}()

	// Client config.
	clientConfig := &ssh.ClientConfig{
		User:            "mcp",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(clientSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	return &testEnv{
		Server:       server,
		Handler:      handler,
		Addr:         ln.Addr().String(),
		ClientConfig: clientConfig,
		Cancel:       cancel,
	}
}

func (te *testEnv) Close() {
	te.Cancel()
	te.Handler.Close()
}

func TestSSHServer_BasicConnection(t *testing.T) {
	env := newTestEnv(t, nil)
	defer env.Close()

	ctx := context.Background()

	// Connect as MCP client via SSH.
	transport := &SSHClientTransport{
		Addr:      env.Addr,
		Subsystem: "mcp",
		Config:    env.ClientConfig,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// List tools.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(tools.Tools))
	}

	// Call a tool.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "hello from SSH" {
		t.Errorf("expected 'hello from SSH', got %q", text)
	}
}

func TestSSHServer_TransportAuth(t *testing.T) {
	perm := &Permission{
		Identity:          "alice",
		RestrictTools:     []string{"echo", "whoami"},
		RestrictResources: []string{"*"},
		RestrictPrompts:   []string{"*"},
	}
	env := newTestEnv(t, perm)
	defer env.Close()

	ctx := context.Background()

	transport := &SSHClientTransport{
		Addr:      env.Addr,
		Subsystem: "mcp",
		Config:    env.ClientConfig,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil)
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	// Call whoami — handler reads TransportAuth to return identity.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "identity:alice" {
		t.Errorf("expected 'identity:alice', got %q", text)
	}
}

func TestSSHServer_RejectedSubsystem(t *testing.T) {
	env := newTestEnv(t, nil)
	defer env.Close()

	// Connect with wrong subsystem.
	sshConn, err := ssh.Dial("tcp", env.Addr, env.ClientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer sshConn.Close()

	session, err := sshConn.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	// Request a non-MCP subsystem — should fail.
	err = session.RequestSubsystem("sftp")
	if err == nil {
		t.Error("expected error requesting non-MCP subsystem")
	}
}

func TestSSHServer_UnauthorizedKey(t *testing.T) {
	env := newTestEnv(t, nil)
	defer env.Close()

	// Generate a different key that is NOT authorized.
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unknownSigner, err := ssh.NewSignerFromKey(unknownPriv)
	if err != nil {
		t.Fatal(err)
	}

	config := &ssh.ClientConfig{
		User:            "mcp",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(unknownSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err = ssh.Dial("tcp", env.Addr, config)
	if err == nil {
		t.Fatal("expected connection to fail with unauthorized key")
	}
}
