package sshtransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPermissionsFromCertificate(t *testing.T) {
	// Generate a CA key.
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	_ = caPub

	// Generate a user key.
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSSHPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatal(err)
	}

	// Create a certificate with MCP extensions.
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             userSSHPub,
		KeyId:           "amy@example.com",
		ValidPrincipals: []string{"mcp-user"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"restrict-tools@modelcontextprotocol.io":     "query_*,list_*",
				"restrict-resources@modelcontextprotocol.io": "file:///data/analytics/**",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	perm := PermissionsFromCertificate(cert)

	if perm.Identity != "amy@example.com" {
		t.Errorf("identity = %q, want %q", perm.Identity, "amy@example.com")
	}

	// Tool restrictions.
	if !perm.AllowTool("query_spans") {
		t.Error("should allow query_spans")
	}
	if !perm.AllowTool("list_traces") {
		t.Error("should allow list_traces")
	}
	if perm.AllowTool("delete_all") {
		t.Error("should NOT allow delete_all")
	}

	// Resource restrictions.
	if !perm.AllowResource("file:///data/analytics/report.csv") {
		t.Error("should allow analytics resource")
	}
	if perm.AllowResource("file:///data/private/secret.txt") {
		t.Error("should NOT allow private resource")
	}

	// Prompts should be unrestricted (no extension set).
	if !perm.AllowPrompt("anything") {
		t.Error("prompts should be unrestricted")
	}
}

func TestPermissionsFromCertificate_NoExtensions(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := ssh.NewPublicKey(userPriv.Public())
	if err != nil {
		t.Fatal(err)
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             userPub,
		KeyId:           "service-account",
		ValidPrincipals: []string{"mcp-admin"},
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	perm := PermissionsFromCertificate(cert)

	if perm.Identity != "service-account" {
		t.Errorf("identity = %q, want %q", perm.Identity, "service-account")
	}
	// No extensions → defaults to ["*"] (allow all), not nil.
	if len(perm.RestrictTools) != 1 || perm.RestrictTools[0] != "*" {
		t.Errorf("RestrictTools = %v, want [\"*\"]", perm.RestrictTools)
	}
	if !perm.AllowTool("anything") {
		t.Error("should allow all tools (default [\"*\"])")
	}
	if !perm.AllowResource("anything") {
		t.Error("should allow all resources (default [\"*\"])")
	}
	if !perm.AllowPrompt("anything") {
		t.Error("should allow all prompts (default [\"*\"])")
	}
}

func TestMergePermissions(t *testing.T) {
	cert := &Permission{
		Identity:      "alice",
		RestrictTools: []string{"query_*", "list_*"},
	}
	key := &Permission{
		Identity:      "alice-workstation",
		RestrictTools: []string{"query_*"},
	}

	merged := MergePermissions(cert, key)

	if merged.Identity != "alice" {
		t.Errorf("identity = %q, want %q (cert takes precedence)", merged.Identity, "alice")
	}

	// The merged permission should include patterns from both.
	if merged.RestrictTools == nil {
		t.Fatal("RestrictTools should not be nil")
	}
}

func TestMergePermissions_NilCases(t *testing.T) {
	perm := &Permission{Identity: "test", RestrictTools: []string{"foo"}}

	// Nil cert → key wins.
	result := MergePermissions(nil, perm)
	if result.Identity != "test" {
		t.Errorf("nil cert: identity = %q, want %q", result.Identity, "test")
	}

	// Nil key → cert wins.
	result = MergePermissions(perm, nil)
	if result.Identity != "test" {
		t.Errorf("nil key: identity = %q, want %q", result.Identity, "test")
	}

	// Both non-nil but one has nil slice → intersect returns nil (deny).
	withNil := &Permission{Identity: "a", RestrictTools: nil}
	withStar := &Permission{Identity: "b", RestrictTools: []string{"*"}}
	merged := MergePermissions(withNil, withStar)
	if merged.RestrictTools != nil {
		t.Errorf("nil intersect [\"*\"] should be nil (deny), got %v", merged.RestrictTools)
	}
	if merged.AllowTool("anything") {
		t.Error("merged with nil side should deny tools")
	}
}

func TestPermissionsFromCertificate_EmptyExtension(t *testing.T) {
	_, userPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userPub, err := ssh.NewPublicKey(userPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}

	// Empty extension string should deny (empty pattern list), not allow.
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             userPub,
		KeyId:           "restricted",
		ValidPrincipals: []string{"mcp-user"},
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"restrict-tools@modelcontextprotocol.io": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}

	perm := PermissionsFromCertificate(cert)
	if perm.AllowTool("anything") {
		t.Error("empty restrict-tools extension should deny all tools")
	}
	// Resources and prompts unset → default ["*"] (allow all).
	if !perm.AllowResource("anything") {
		t.Error("unset resources should allow all")
	}
}

func TestMergedPermission_AND_Logic(t *testing.T) {
	certPerms := &Permission{
		RestrictTools: []string{"query_*", "list_*"},
	}
	keyPerms := &Permission{
		RestrictTools: []string{"query_spans"},
	}

	mp := &MergedPermission{CertPerms: certPerms, KeyPerms: keyPerms}

	// query_spans matches both cert (query_*) and key (query_spans).
	if !mp.AllowTool("query_spans") {
		t.Error("should allow query_spans (matches both)")
	}

	// list_traces matches cert (list_*) but NOT key (query_spans).
	if mp.AllowTool("list_traces") {
		t.Error("should NOT allow list_traces (key doesn't allow it)")
	}

	// delete_all matches neither.
	if mp.AllowTool("delete_all") {
		t.Error("should NOT allow delete_all")
	}
}

func TestMergedPermission_NilSides(t *testing.T) {
	keyOnly := &MergedPermission{
		KeyPerms: &Permission{
			Identity:      "bob",
			RestrictTools: []string{"query_*"},
		},
	}
	// Nil cert side → only key perms checked.
	if !keyOnly.AllowTool("query_spans") {
		t.Error("key-only: should allow query_spans")
	}
	if keyOnly.AllowTool("delete_all") {
		t.Error("key-only: should NOT allow delete_all")
	}

	certOnly := &MergedPermission{
		CertPerms: &Permission{
			Identity:      "alice",
			RestrictTools: []string{"*"},
		},
	}
	// Nil key side → only cert perms checked.
	if !certOnly.AllowTool("anything") {
		t.Error("cert-only: should allow anything")
	}

	// Both nil → deny.
	empty := &MergedPermission{}
	if empty.AllowTool("anything") {
		t.Error("both nil: should deny")
	}

	// Nil MergedPermission → deny.
	var nilMP *MergedPermission
	if nilMP.AllowTool("anything") {
		t.Error("nil MergedPermission: should deny")
	}
}

func TestMergedPermission_Identity(t *testing.T) {
	// Cert identity preferred.
	mp := &MergedPermission{
		CertPerms: &Permission{Identity: "cert-alice"},
		KeyPerms:  &Permission{Identity: "key-bob"},
	}
	if mp.Identity() != "cert-alice" {
		t.Errorf("Identity() = %q, want %q", mp.Identity(), "cert-alice")
	}

	// Falls back to key identity.
	mp2 := &MergedPermission{
		KeyPerms: &Permission{Identity: "key-bob"},
	}
	if mp2.Identity() != "key-bob" {
		t.Errorf("Identity() = %q, want %q", mp2.Identity(), "key-bob")
	}

	// Nil → empty.
	var nilMP *MergedPermission
	if nilMP.Identity() != "" {
		t.Errorf("nil Identity() = %q, want empty", nilMP.Identity())
	}
}
