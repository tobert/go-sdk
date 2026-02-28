package sshtransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
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
		perm = &Permission{Identity: "test-user"}
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
		Name:        "secret",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "secret data"}},
		}, nil
	})

	// Install authorization middleware.
	server.AddReceivingMiddleware(AuthorizationMiddleware())

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

func TestSSHServer_Authorization(t *testing.T) {
	perm := &Permission{
		Identity:      "restricted-user",
		RestrictTools: []string{"echo"},
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

	// List should be filtered.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 {
		t.Errorf("expected 1 tool (echo only), got %d", len(tools.Tools))
		for _, tool := range tools.Tools {
			t.Logf("  tool: %s", tool.Name)
		}
	}

	// Allowed tool works.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "hello from SSH" {
		t.Errorf("expected 'hello from SSH', got %q", text)
	}

	// Forbidden tool rejected.
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "secret"})
	if err == nil {
		t.Fatal("expected error calling forbidden tool")
	}
	var jErr *jsonrpc.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("expected jsonrpc.Error, got %T: %v", err, err)
	}
	if jErr.Code != jsonrpc.CodeMethodNotFound {
		t.Errorf("expected code %d, got %d", jsonrpc.CodeMethodNotFound, jErr.Code)
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
