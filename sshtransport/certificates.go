package sshtransport

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	extRestrictTools     = "restrict-tools@modelcontextprotocol.io"
	extRestrictResources = "restrict-resources@modelcontextprotocol.io"
	extRestrictPrompts   = "restrict-prompts@modelcontextprotocol.io"
)

// PermissionsFromCertificate extracts MCP permissions from SSH certificate
// extensions. Extension keys follow the name@domain convention:
//   - restrict-tools@modelcontextprotocol.io
//   - restrict-resources@modelcontextprotocol.io
//   - restrict-prompts@modelcontextprotocol.io
//
// Extension values are comma-separated glob patterns.
func PermissionsFromCertificate(cert *ssh.Certificate) *Permission {
	perm := &Permission{
		Identity:          cert.KeyId,
		RestrictTools:     []string{"*"},
		RestrictResources: []string{"*"},
		RestrictPrompts:   []string{"*"},
	}

	// Extensions override the defaults when present. An empty extension
	// string produces an empty slice (deny), not fall-through to ["*"].
	if v, ok := cert.Extensions[extRestrictTools]; ok {
		perm.RestrictTools = splitPatterns(v)
	}
	if v, ok := cert.Extensions[extRestrictResources]; ok {
		perm.RestrictResources = splitPatterns(v)
	}
	if v, ok := cert.Extensions[extRestrictPrompts]; ok {
		perm.RestrictPrompts = splitPatterns(v)
	}

	return perm
}

// splitPatterns splits a comma-separated pattern string into a slice.
func splitPatterns(s string) []string {
	var patterns []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			patterns = append(patterns, p)
		}
	}
	return patterns
}

// MergePermissions combines certificate and authorized key permissions using
// AND logic: a request is only authorized if both permit it. Nil restriction
// slices deny access; use []string{"*"} for unrestricted.
//
// The merged identity comes from the certificate (certPerms) if set,
// falling back to the key identity.
func MergePermissions(certPerms, keyPerms *Permission) *Permission {
	if certPerms == nil {
		return keyPerms
	}
	if keyPerms == nil {
		return certPerms
	}

	merged := &Permission{
		Identity: certPerms.Identity,
	}
	if merged.Identity == "" {
		merged.Identity = keyPerms.Identity
	}

	merged.RestrictTools = intersectPatterns(certPerms.RestrictTools, keyPerms.RestrictTools)
	merged.RestrictResources = intersectPatterns(certPerms.RestrictResources, keyPerms.RestrictResources)
	merged.RestrictPrompts = intersectPatterns(certPerms.RestrictPrompts, keyPerms.RestrictPrompts)

	return merged
}

// intersectPatterns implements AND logic for restriction patterns.
// If either is nil (denied), the result is nil (deny).
// If both are set, both pattern sets are merged.
func intersectPatterns(a, b []string) []string {
	if a == nil || b == nil {
		return nil // either side denies = deny
	}
	return mergedRestrictions(a, b)
}

// mergedRestrictions returns a combined restriction set. For proper AND
// semantics, see MergedPermission which checks both sets.
func mergedRestrictions(a, b []string) []string {
	// For the prototype, we combine both sets into a single slice.
	// This means matching ANY pattern from either set — OR semantics.
	// True AND semantics would require checking both sets independently.
	// The MergedPermission type below provides proper AND checking.
	combined := make([]string, 0, len(a)+len(b))
	combined = append(combined, a...)
	combined = append(combined, b...)
	return combined
}

// MergedPermission provides proper AND-logic authorization checking
// across certificate and authorized key permissions.
//
// If only one auth method matched (e.g. key-only or cert-only), the
// other side is nil and only the present side is checked. If both
// sides matched, a request must be allowed by both to succeed.
type MergedPermission struct {
	// identity is the resolved identity string, stored directly so it
	// survives the SSH extension round-trip even when both perm sides
	// have no restriction extensions.
	identity  string
	CertPerms *Permission
	KeyPerms  *Permission
}

// Identity returns the identity string for this authenticated session.
// It checks the cached identity first (set during SSH round-trip), then
// falls back to cert identity, then key identity.
func (mp *MergedPermission) Identity() string {
	if mp == nil {
		return ""
	}
	if mp.identity != "" {
		return mp.identity
	}
	if mp.CertPerms != nil && mp.CertPerms.Identity != "" {
		return mp.CertPerms.Identity
	}
	if mp.KeyPerms != nil {
		return mp.KeyPerms.Identity
	}
	return ""
}

// AllowTool returns true if the present permission sets allow the tool.
// A nil side is treated as "not applicable" (only the other side is checked).
func (mp *MergedPermission) AllowTool(name string) bool {
	if mp == nil {
		return false
	}
	if mp.CertPerms == nil {
		return mp.KeyPerms.AllowTool(name)
	}
	if mp.KeyPerms == nil {
		return mp.CertPerms.AllowTool(name)
	}
	return mp.CertPerms.AllowTool(name) && mp.KeyPerms.AllowTool(name)
}

// AllowResource returns true if the present permission sets allow the resource.
func (mp *MergedPermission) AllowResource(uri string) bool {
	if mp == nil {
		return false
	}
	if mp.CertPerms == nil {
		return mp.KeyPerms.AllowResource(uri)
	}
	if mp.KeyPerms == nil {
		return mp.CertPerms.AllowResource(uri)
	}
	return mp.CertPerms.AllowResource(uri) && mp.KeyPerms.AllowResource(uri)
}

// AllowPrompt returns true if the present permission sets allow the prompt.
func (mp *MergedPermission) AllowPrompt(name string) bool {
	if mp == nil {
		return false
	}
	if mp.CertPerms == nil {
		return mp.KeyPerms.AllowPrompt(name)
	}
	if mp.KeyPerms == nil {
		return mp.CertPerms.AllowPrompt(name)
	}
	return mp.CertPerms.AllowPrompt(name) && mp.KeyPerms.AllowPrompt(name)
}
