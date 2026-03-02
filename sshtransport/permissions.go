// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package sshtransport

import "context"

type permissionsKey struct{}

// ContextWithPermissions returns a context carrying the given MergedPermission.
// The permission can be retrieved later with PermissionsFromContext.
func ContextWithPermissions(ctx context.Context, p *MergedPermission) context.Context {
	return context.WithValue(ctx, permissionsKey{}, p)
}

// PermissionsFromContext extracts the MergedPermission from the context, or nil
// if the context has no permissions (e.g., non-SSH transport).
func PermissionsFromContext(ctx context.Context) *MergedPermission {
	p, _ := ctx.Value(permissionsKey{}).(*MergedPermission)
	return p
}
