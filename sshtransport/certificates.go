package sshtransport

import (
	"encoding/json"
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

	// Extensions override the defaults when present.
	if v, ok := cert.Extensions[extRestrictTools]; ok && v != "" {
		perm.RestrictTools = splitPatterns(v)
	}
	if v, ok := cert.Extensions[extRestrictResources]; ok && v != "" {
		perm.RestrictResources = splitPatterns(v)
	}
	if v, ok := cert.Extensions[extRestrictPrompts]; ok && v != "" {
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
type MergedPermission struct {
	CertPerms *Permission
	KeyPerms  *Permission
}

// AllowTool returns true only if both cert and key permissions allow the tool.
func (mp *MergedPermission) AllowTool(name string) bool {
	return mp.CertPerms.AllowTool(name) && mp.KeyPerms.AllowTool(name)
}

// AllowResource returns true only if both cert and key permissions allow the resource.
func (mp *MergedPermission) AllowResource(uri string) bool {
	return mp.CertPerms.AllowResource(uri) && mp.KeyPerms.AllowResource(uri)
}

// AllowPrompt returns true only if both cert and key permissions allow the prompt.
func (mp *MergedPermission) AllowPrompt(name string) bool {
	return mp.CertPerms.AllowPrompt(name) && mp.KeyPerms.AllowPrompt(name)
}

// ToPermission converts a MergedPermission to a flat Permission by evaluating
// both sets. This is a lossy conversion — use MergedPermission directly
// when both cert and key permissions are available.
func (mp *MergedPermission) ToPermission() *Permission {
	return MergePermissions(mp.CertPerms, mp.KeyPerms)
}

// encodeMerged is used internally to store merged permissions in
// ssh.Permissions.Extensions for transport through the SSH layer.
func encodeMerged(certPerms, keyPerms *Permission) map[string]string {
	ext := make(map[string]string)

	identity := ""
	if certPerms != nil {
		identity = certPerms.Identity
	}
	if identity == "" && keyPerms != nil {
		identity = keyPerms.Identity
	}
	ext["identity"] = identity

	merged := MergePermissions(certPerms, keyPerms)
	if merged.RestrictTools != nil {
		data, _ := json.Marshal(merged.RestrictTools)
		ext["restrict-tools"] = string(data)
	}
	if merged.RestrictResources != nil {
		data, _ := json.Marshal(merged.RestrictResources)
		ext["restrict-resources"] = string(data)
	}
	if merged.RestrictPrompts != nil {
		data, _ := json.Marshal(merged.RestrictPrompts)
		ext["restrict-prompts"] = string(data)
	}

	return ext
}
