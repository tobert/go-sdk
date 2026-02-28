package sshtransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// genTestKey generates a test Ed25519 key pair and returns the ssh.PublicKey
// and the authorized_keys line format "ssh-ed25519 <base64>".
func genTestKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(sshPub.Marshal())
	return sshPub, fmt.Sprintf("ssh-ed25519 %s", b64)
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseAuthorizedKeysFile_BareKeys(t *testing.T) {
	key1, line1 := genTestKey(t)
	key2, line2 := genTestKey(t)

	content := fmt.Sprintf("# comment line\n%s amy@workstation\n\n%s ci-bot@jenkins\n", line1, line2)
	path := writeFile(t, content)

	ak, err := ParseAuthorizedKeysFile(path)
	if err != nil {
		t.Fatal(err)
	}

	fp1 := ssh.FingerprintSHA256(key1)
	perm1, ok := ak.Lookup(fp1)
	if !ok {
		t.Fatalf("key1 not found by fingerprint %s", fp1)
	}
	if perm1.Identity != "amy@workstation" {
		t.Errorf("key1 identity = %q, want %q", perm1.Identity, "amy@workstation")
	}
	// No restrictions.
	if perm1.RestrictTools != nil {
		t.Errorf("key1 RestrictTools = %v, want nil", perm1.RestrictTools)
	}
	if !perm1.AllowTool("anything") {
		t.Error("unrestricted key should allow any tool")
	}

	fp2 := ssh.FingerprintSHA256(key2)
	perm2, ok := ak.Lookup(fp2)
	if !ok {
		t.Fatalf("key2 not found by fingerprint %s", fp2)
	}
	if perm2.Identity != "ci-bot@jenkins" {
		t.Errorf("key2 identity = %q, want %q", perm2.Identity, "ci-bot@jenkins")
	}
}

func TestParseAuthorizedKeysFile_WithOptions(t *testing.T) {
	_, line := genTestKey(t)

	content := fmt.Sprintf(`restrict-tools="query_*,list_*" %s intern@laptop`, line)
	path := writeFile(t, content)

	ak, err := ParseAuthorizedKeysFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// There should be exactly one key.
	count := 0
	ak.mu.RLock()
	for _, perm := range ak.keys {
		count++
		if perm.Identity != "intern@laptop" {
			t.Errorf("identity = %q, want %q", perm.Identity, "intern@laptop")
		}
		if !perm.AllowTool("query_spans") {
			t.Error("should allow query_spans")
		}
		if !perm.AllowTool("list_traces") {
			t.Error("should allow list_traces")
		}
		if perm.AllowTool("delete_all") {
			t.Error("should NOT allow delete_all")
		}
	}
	ak.mu.RUnlock()
	if count != 1 {
		t.Errorf("expected 1 key, got %d", count)
	}
}

func TestParseAuthorizedKeysFile_MultipleOptions(t *testing.T) {
	_, line := genTestKey(t)

	content := fmt.Sprintf(`identity="alice",restrict-tools="query_*",restrict-resources="file:///data/public/**" %s`, line)
	path := writeFile(t, content)

	ak, err := ParseAuthorizedKeysFile(path)
	if err != nil {
		t.Fatal(err)
	}

	ak.mu.RLock()
	defer ak.mu.RUnlock()
	for _, perm := range ak.keys {
		if perm.Identity != "alice" {
			t.Errorf("identity = %q, want %q", perm.Identity, "alice")
		}
		if !perm.AllowTool("query_spans") {
			t.Error("should allow query_spans")
		}
		if perm.AllowTool("write_data") {
			t.Error("should NOT allow write_data")
		}
		if !perm.AllowResource("file:///data/public/readme.txt") {
			t.Error("should allow public resource")
		}
		if perm.AllowResource("file:///data/private/secret.txt") {
			t.Error("should NOT allow private resource")
		}
	}
}

func TestParseAuthorizedKeysFile_RestrictPrompts(t *testing.T) {
	_, line := genTestKey(t)

	content := fmt.Sprintf(`restrict-prompts="summarize_*" %s bob@laptop`, line)
	path := writeFile(t, content)

	ak, err := ParseAuthorizedKeysFile(path)
	if err != nil {
		t.Fatal(err)
	}

	ak.mu.RLock()
	defer ak.mu.RUnlock()
	for _, perm := range ak.keys {
		if !perm.AllowPrompt("summarize_docs") {
			t.Error("should allow summarize_docs")
		}
		if perm.AllowPrompt("generate_code") {
			t.Error("should NOT allow generate_code")
		}
	}
}

func TestAuthorizedKeys_Reload(t *testing.T) {
	key1, line1 := genTestKey(t)
	key2, line2 := genTestKey(t)

	path := writeFile(t, fmt.Sprintf("%s user1\n", line1))

	ak, err := ParseAuthorizedKeysFile(path)
	if err != nil {
		t.Fatal(err)
	}

	fp1 := ssh.FingerprintSHA256(key1)
	if _, ok := ak.Lookup(fp1); !ok {
		t.Fatal("key1 should be present initially")
	}

	// Replace file contents.
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%s user2\n", line2)), 0600); err != nil {
		t.Fatal(err)
	}

	if err := ak.Reload(); err != nil {
		t.Fatal(err)
	}

	if _, ok := ak.Lookup(fp1); ok {
		t.Error("key1 should be gone after reload")
	}
	fp2 := ssh.FingerprintSHA256(key2)
	if _, ok := ak.Lookup(fp2); !ok {
		t.Error("key2 should be present after reload")
	}
}

func TestParseAuthorizedKeysFile_BadFile(t *testing.T) {
	path := writeFile(t, "this is not a valid key line\n")
	_, err := ParseAuthorizedKeysFile(path)
	if err == nil {
		t.Error("expected error for invalid file")
	}
}

func TestParseAuthorizedKeysFile_NotFound(t *testing.T) {
	_, err := ParseAuthorizedKeysFile("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestPermission_NilReceiver(t *testing.T) {
	var p *Permission
	if !p.AllowTool("anything") {
		t.Error("nil Permission should allow all tools")
	}
	if !p.AllowResource("anything") {
		t.Error("nil Permission should allow all resources")
	}
	if !p.AllowPrompt("anything") {
		t.Error("nil Permission should allow all prompts")
	}
}
