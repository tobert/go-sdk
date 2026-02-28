package sshtransport

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var emptySchema = map[string]any{"type": "object"}

func setupServer(t *testing.T, perm *Permission) (*mcp.ClientSession, func()) {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0.1.0"}, nil)

	// Add tools.
	server.AddTool(&mcp.Tool{Name: "query_spans", InputSchema: emptySchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "spans"}}}, nil
	})
	server.AddTool(&mcp.Tool{Name: "delete_all", InputSchema: emptySchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}}}, nil
	})
	server.AddTool(&mcp.Tool{Name: "list_traces", InputSchema: emptySchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "traces"}}}, nil
	})

	// Add resources.
	server.AddResource(&mcp.Resource{Name: "public", URI: "file:///data/public/readme.txt"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "file:///data/public/readme.txt", Text: "public data"}}}, nil
	})
	server.AddResource(&mcp.Resource{Name: "private", URI: "file:///data/private/secret.txt"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: "file:///data/private/secret.txt", Text: "secret data"}}}, nil
	})

	// Add prompts.
	server.AddPrompt(&mcp.Prompt{Name: "summarize_docs"}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "summarize"}}}}, nil
	})
	server.AddPrompt(&mcp.Prompt{Name: "generate_code"}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: "generate"}}}}, nil
	})

	// Install middleware.
	server.AddReceivingMiddleware(AuthorizationMiddleware())

	// Also inject permissions into context via a second middleware that runs first.
	if perm != nil {
		server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				ctx = ContextWithPermissions(ctx, perm)
				return next(ctx, method, req)
			}
		})
	}

	ctx := context.Background()
	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	ss, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client"}, nil)
	cs, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := func() {
		cs.Close()
		ss.Wait()
	}
	return cs, cleanup
}

func TestMiddleware_NoPermissions(t *testing.T) {
	cs, cleanup := setupServer(t, nil)
	defer cleanup()

	ctx := context.Background()

	// Without permissions, everything should work.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(tools.Tools))
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "delete_all"})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "deleted" {
		t.Errorf("expected 'deleted', got %q", text)
	}
}

func TestMiddleware_RestrictTools(t *testing.T) {
	perm := &Permission{
		Identity:      "intern",
		RestrictTools: []string{"query_*", "list_*"},
	}
	cs, cleanup := setupServer(t, perm)
	defer cleanup()

	ctx := context.Background()

	// List should be filtered.
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 2 {
		t.Errorf("expected 2 tools (query_spans, list_traces), got %d", len(tools.Tools))
		for _, tool := range tools.Tools {
			t.Logf("  tool: %s", tool.Name)
		}
	}

	// Calling allowed tool should work.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "query_spans"})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	if text != "spans" {
		t.Errorf("expected 'spans', got %q", text)
	}

	// Calling forbidden tool should fail with -32601.
	_, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "delete_all"})
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

func TestMiddleware_RestrictResources(t *testing.T) {
	perm := &Permission{
		Identity:          "partner",
		RestrictResources: []string{"file:///data/public/**"},
	}
	cs, cleanup := setupServer(t, perm)
	defer cleanup()

	ctx := context.Background()

	// List should be filtered.
	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(resources.Resources))
	}
	if len(resources.Resources) > 0 && !strings.Contains(resources.Resources[0].URI, "public") {
		t.Errorf("expected public resource, got %s", resources.Resources[0].URI)
	}

	// Reading allowed resource should work.
	res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "file:///data/public/readme.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) == 0 || res.Contents[0].Text != "public data" {
		t.Error("unexpected result reading public resource")
	}

	// Reading forbidden resource should fail.
	_, err = cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "file:///data/private/secret.txt"})
	if err == nil {
		t.Fatal("expected error reading forbidden resource")
	}
	var jErr *jsonrpc.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("expected jsonrpc.Error, got %T: %v", err, err)
	}
	if jErr.Code != jsonrpc.CodeMethodNotFound {
		t.Errorf("expected code %d, got %d", jsonrpc.CodeMethodNotFound, jErr.Code)
	}
}

func TestMiddleware_RestrictPrompts(t *testing.T) {
	perm := &Permission{
		Identity:        "reader",
		RestrictPrompts: []string{"summarize_*"},
	}
	cs, cleanup := setupServer(t, perm)
	defer cleanup()

	ctx := context.Background()

	// List should be filtered.
	prompts, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts.Prompts) != 1 {
		t.Errorf("expected 1 prompt, got %d", len(prompts.Prompts))
	}

	// Getting allowed prompt should work.
	res, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "summarize_docs"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Messages) == 0 {
		t.Error("expected prompt messages")
	}

	// Getting forbidden prompt should fail.
	_, err = cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "generate_code"})
	if err == nil {
		t.Fatal("expected error getting forbidden prompt")
	}
	var jErr *jsonrpc.Error
	if !errors.As(err, &jErr) {
		t.Fatalf("expected jsonrpc.Error, got %T: %v", err, err)
	}
	if jErr.Code != jsonrpc.CodeMethodNotFound {
		t.Errorf("expected code %d, got %d", jsonrpc.CodeMethodNotFound, jErr.Code)
	}
}

func TestMiddleware_UnrestrictedDimensions(t *testing.T) {
	// Restrict only tools; resources and prompts should be unrestricted.
	perm := &Permission{
		Identity:      "partial",
		RestrictTools: []string{"query_*"},
	}
	cs, cleanup := setupServer(t, perm)
	defer cleanup()

	ctx := context.Background()

	// Resources should be unfiltered.
	resources, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resources.Resources) != 2 {
		t.Errorf("expected 2 resources (unrestricted), got %d", len(resources.Resources))
	}

	// Prompts should be unfiltered.
	prompts, err := cs.ListPrompts(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(prompts.Prompts) != 2 {
		t.Errorf("expected 2 prompts (unrestricted), got %d", len(prompts.Prompts))
	}
}
