// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package sshtransport

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// authTransport wraps an mcp.Transport to inject SSH MergedPermission into
// RequestExtra.TransportAuth on every incoming request.
type authTransport struct {
	inner mcp.Transport
	perm  *MergedPermission
}

func (t *authTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &authConnection{inner: conn, perm: t.perm}, nil
}

// authConnection wraps an mcp.Connection to inject MergedPermission into
// incoming JSON-RPC requests.
type authConnection struct {
	inner mcp.Connection
	perm  *MergedPermission
}

func (c *authConnection) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.inner.Read(ctx)
	if err != nil {
		return nil, err
	}
	if req, ok := msg.(*jsonrpc.Request); ok {
		extra, ok := req.Extra.(*mcp.RequestExtra)
		if !ok {
			extra = &mcp.RequestExtra{}
			req.Extra = extra
		}
		extra.TransportAuth = c.perm
	}
	return msg, nil
}

func (c *authConnection) Write(ctx context.Context, msg jsonrpc.Message) error {
	return c.inner.Write(ctx, msg)
}

func (c *authConnection) Close() error {
	return c.inner.Close()
}

func (c *authConnection) SessionID() string {
	return c.inner.SessionID()
}
