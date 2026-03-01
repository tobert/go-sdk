// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package sshtransport

import "context"

type permissionsKey struct{}

// ContextWithPermissions returns a context carrying the given Permission.
// The permission can be retrieved later with PermissionsFromContext.
func ContextWithPermissions(ctx context.Context, p *Permission) context.Context {
	return context.WithValue(ctx, permissionsKey{}, p)
}

// PermissionsFromContext extracts the Permission from the context, or nil
// if the context has no permissions (e.g., non-SSH transport).
func PermissionsFromContext(ctx context.Context) *Permission {
	p, _ := ctx.Value(permissionsKey{}).(*Permission)
	return p
}
