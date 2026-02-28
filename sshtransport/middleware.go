package sshtransport

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// AuthorizationMiddleware returns middleware that enforces SSH permission
// restrictions on MCP methods.
//
// Install it on the server before connecting SSH sessions:
//
//	server.AddReceivingMiddleware(sshtransport.AuthorizationMiddleware())
//
// Behavior:
//   - If the context has no Permission (non-SSH transport), passes through.
//   - tools/call: checks AllowTool(name), rejects with -32601.
//   - resources/read: checks AllowResource(uri), rejects with -32601.
//   - prompts/get: checks AllowPrompt(name), rejects with -32601.
//   - tools/list, resources/list, prompts/list: delegates then filters result.
func AuthorizationMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			perm := PermissionsFromContext(ctx)
			if perm == nil {
				return next(ctx, method, req)
			}

			switch method {
			case "tools/call":
				return handleToolCall(ctx, method, req, perm, next)
			case "resources/read":
				return handleResourceRead(ctx, method, req, perm, next)
			case "prompts/get":
				return handlePromptGet(ctx, method, req, perm, next)
			case "tools/list":
				return handleToolList(ctx, method, req, perm, next)
			case "resources/list":
				return handleResourceList(ctx, method, req, perm, next)
			case "prompts/list":
				return handlePromptList(ctx, method, req, perm, next)
			default:
				return next(ctx, method, req)
			}
		}
	}
}

func handleToolCall(ctx context.Context, method string, req mcp.Request, perm *Permission, next mcp.MethodHandler) (mcp.Result, error) {
	params, ok := req.GetParams().(*mcp.CallToolParamsRaw)
	if !ok || params == nil {
		return next(ctx, method, req)
	}
	if !perm.AllowTool(params.Name) {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeMethodNotFound,
			Message: fmt.Sprintf("tool %q not authorized for this key", params.Name),
		}
	}
	return next(ctx, method, req)
}

func handleResourceRead(ctx context.Context, method string, req mcp.Request, perm *Permission, next mcp.MethodHandler) (mcp.Result, error) {
	params, ok := req.GetParams().(*mcp.ReadResourceParams)
	if !ok || params == nil {
		return next(ctx, method, req)
	}
	if !perm.AllowResource(params.URI) {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeMethodNotFound,
			Message: fmt.Sprintf("resource %q not authorized for this key", params.URI),
		}
	}
	return next(ctx, method, req)
}

func handlePromptGet(ctx context.Context, method string, req mcp.Request, perm *Permission, next mcp.MethodHandler) (mcp.Result, error) {
	params, ok := req.GetParams().(*mcp.GetPromptParams)
	if !ok || params == nil {
		return next(ctx, method, req)
	}
	if !perm.AllowPrompt(params.Name) {
		return nil, &jsonrpc.Error{
			Code:    jsonrpc.CodeMethodNotFound,
			Message: fmt.Sprintf("prompt %q not authorized for this key", params.Name),
		}
	}
	return next(ctx, method, req)
}

func handleToolList(ctx context.Context, method string, req mcp.Request, perm *Permission, next mcp.MethodHandler) (mcp.Result, error) {
	if perm.RestrictTools == nil {
		return next(ctx, method, req)
	}
	result, err := next(ctx, method, req)
	if err != nil {
		return nil, err
	}
	tr, ok := result.(*mcp.ListToolsResult)
	if !ok || tr == nil {
		return result, nil
	}
	filtered := make([]*mcp.Tool, 0, len(tr.Tools))
	for _, t := range tr.Tools {
		if perm.AllowTool(t.Name) {
			filtered = append(filtered, t)
		}
	}
	tr.Tools = filtered
	return tr, nil
}

func handleResourceList(ctx context.Context, method string, req mcp.Request, perm *Permission, next mcp.MethodHandler) (mcp.Result, error) {
	if perm.RestrictResources == nil {
		return next(ctx, method, req)
	}
	result, err := next(ctx, method, req)
	if err != nil {
		return nil, err
	}
	rr, ok := result.(*mcp.ListResourcesResult)
	if !ok || rr == nil {
		return result, nil
	}
	filtered := make([]*mcp.Resource, 0, len(rr.Resources))
	for _, r := range rr.Resources {
		if perm.AllowResource(r.URI) {
			filtered = append(filtered, r)
		}
	}
	rr.Resources = filtered
	return rr, nil
}

func handlePromptList(ctx context.Context, method string, req mcp.Request, perm *Permission, next mcp.MethodHandler) (mcp.Result, error) {
	if perm.RestrictPrompts == nil {
		return next(ctx, method, req)
	}
	result, err := next(ctx, method, req)
	if err != nil {
		return nil, err
	}
	pr, ok := result.(*mcp.ListPromptsResult)
	if !ok || pr == nil {
		return result, nil
	}
	filtered := make([]*mcp.Prompt, 0, len(pr.Prompts))
	for _, p := range pr.Prompts {
		if perm.AllowPrompt(p.Name) {
			filtered = append(filtered, p)
		}
	}
	pr.Prompts = filtered
	return pr, nil
}
