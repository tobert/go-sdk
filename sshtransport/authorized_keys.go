package sshtransport

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Permission describes the identity and access restrictions for an
// authenticated SSH client. Nil restriction slices deny all access;
// use []string{"*"} to allow all.
type Permission struct {
	Identity          string
	RestrictTools     []string
	RestrictResources []string
	RestrictPrompts   []string
}

// AllowTool reports whether this permission allows calling the named tool.
// A nil Permission or nil RestrictTools denies access.
func (p *Permission) AllowTool(name string) bool {
	if p == nil {
		return false
	}
	return MatchAnyGlob(p.RestrictTools, name)
}

// AllowResource reports whether this permission allows reading the given resource URI.
// A nil Permission or nil RestrictResources denies access.
func (p *Permission) AllowResource(uri string) bool {
	if p == nil {
		return false
	}
	return MatchAnyGlob(p.RestrictResources, uri)
}

// AllowPrompt reports whether this permission allows using the named prompt.
// A nil Permission or nil RestrictPrompts denies access.
func (p *Permission) AllowPrompt(name string) bool {
	if p == nil {
		return false
	}
	return MatchAnyGlob(p.RestrictPrompts, name)
}

// AuthorizedKeys holds a mapping from SSH public key fingerprints to permissions.
// It is safe for concurrent use.
type AuthorizedKeys struct {
	mu   sync.RWMutex
	path string
	keys map[string]*Permission // SHA256 fingerprint → permission
}

// ParseAuthorizedKeysFile reads and parses an MCP authorized keys file.
//
// The format is similar to OpenSSH's authorized_keys but with MCP-specific
// options:
//
//	[options] key-type base64-key comment
//
// Supported options (comma-separated key="value" pairs):
//   - identity="name"
//   - restrict-tools="pattern"
//   - restrict-resources="pattern"
//   - restrict-prompts="pattern"
//
// Multiple restrict options of the same type are unioned.
func ParseAuthorizedKeysFile(path string) (*AuthorizedKeys, error) {
	ak := &AuthorizedKeys{
		path: path,
		keys: make(map[string]*Permission),
	}
	if err := ak.Reload(); err != nil {
		return nil, err
	}
	return ak, nil
}

// NewAuthorizedKeys creates an AuthorizedKeys from a pre-built map.
// Useful for testing or programmatic configuration.
func NewAuthorizedKeys(keys map[string]*Permission) *AuthorizedKeys {
	return &AuthorizedKeys{keys: keys}
}

// Lookup returns the permission for the given SSH public key fingerprint.
// The fingerprint should be in SHA256:base64 format (as returned by ssh.FingerprintSHA256).
func (ak *AuthorizedKeys) Lookup(fingerprint string) (*Permission, bool) {
	ak.mu.RLock()
	defer ak.mu.RUnlock()
	p, ok := ak.keys[fingerprint]
	return p, ok
}

// Reload re-reads the authorized keys file. This can be called on SIGHUP
// to pick up key changes without restart.
func (ak *AuthorizedKeys) Reload() error {
	if ak.path == "" {
		return nil
	}

	f, err := os.Open(ak.path)
	if err != nil {
		return fmt.Errorf("opening authorized keys: %w", err)
	}
	defer f.Close()

	keys := make(map[string]*Permission)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		perm, pubKey, err := parseAuthorizedKeyLine(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}

		fp := ssh.FingerprintSHA256(pubKey)
		if existing, ok := keys[fp]; ok {
			// Merge: union the restriction patterns.
			mergeInto(existing, perm)
		} else {
			keys[fp] = perm
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading authorized keys: %w", err)
	}

	ak.mu.Lock()
	ak.keys = keys
	ak.mu.Unlock()
	return nil
}

// parseAuthorizedKeyLine parses a single authorized keys line.
func parseAuthorizedKeyLine(line string) (*Permission, ssh.PublicKey, error) {
	// Try parsing as a bare key first (no options).
	// Bare keys default to ["*"] (allow all).
	if pubKey, comment, err := tryParseKey(line); err == nil {
		perm := &Permission{
			RestrictTools:     []string{"*"},
			RestrictResources: []string{"*"},
			RestrictPrompts:   []string{"*"},
		}
		if comment != "" {
			perm.Identity = comment
		}
		return perm, pubKey, nil
	}

	// Parse options prefix. Options start with nil slices;
	// only fields explicitly set in options will be non-nil.
	perm := &Permission{}
	rest, err := parseOptions(line, perm)
	if err != nil {
		return nil, nil, err
	}

	pubKey, comment, err := tryParseKey(rest)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing key: %w", err)
	}
	// Comment becomes identity if not set by options.
	if perm.Identity == "" && comment != "" {
		perm.Identity = comment
	}
	// Fields not explicitly restricted by options default to ["*"] (allow all).
	if perm.RestrictTools == nil {
		perm.RestrictTools = []string{"*"}
	}
	if perm.RestrictResources == nil {
		perm.RestrictResources = []string{"*"}
	}
	if perm.RestrictPrompts == nil {
		perm.RestrictPrompts = []string{"*"}
	}
	return perm, pubKey, nil
}

// tryParseKey attempts to parse "key-type base64-key [comment]".
func tryParseKey(s string) (ssh.PublicKey, string, error) {
	s = strings.TrimSpace(s)
	fields := strings.SplitN(s, " ", 3)
	if len(fields) < 2 {
		return nil, "", fmt.Errorf("expected key-type and key data")
	}

	keyType := fields[0]
	keyData := fields[1]
	comment := ""
	if len(fields) == 3 {
		comment = strings.TrimSpace(fields[2])
	}

	// Validate it looks like a key type.
	if !isKeyType(keyType) {
		return nil, "", fmt.Errorf("unrecognized key type %q", keyType)
	}

	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return nil, "", fmt.Errorf("decoding key data: %w", err)
	}

	pubKey, err := ssh.ParsePublicKey(decoded)
	if err != nil {
		return nil, "", fmt.Errorf("parsing public key: %w", err)
	}

	return pubKey, comment, nil
}

// isKeyType checks if the string looks like an SSH key type.
func isKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") ||
		strings.HasPrefix(s, "ecdsa-") ||
		strings.HasPrefix(s, "sk-")
}

// parseOptions parses comma-separated options from the beginning of the line.
// Returns the remaining string (key-type base64 comment).
func parseOptions(line string, perm *Permission) (string, error) {
	i := 0
	for i < len(line) {
		// Skip whitespace between options.
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i >= len(line) {
			break
		}

		// Check if we've reached the key type (no more options).
		rest := line[i:]
		if isKeyType(strings.SplitN(rest, " ", 2)[0]) {
			return rest, nil
		}

		// Parse option name.
		eqIdx := strings.IndexByte(rest, '=')
		if eqIdx < 0 {
			return "", fmt.Errorf("expected '=' in option at position %d", i)
		}
		optName := strings.TrimRight(rest[:eqIdx], " ")

		// Parse quoted value.
		afterEq := rest[eqIdx+1:]
		if len(afterEq) == 0 || afterEq[0] != '"' {
			return "", fmt.Errorf("expected '\"' after '=' for option %q", optName)
		}

		val, consumed, err := parseQuotedValue(afterEq)
		if err != nil {
			return "", fmt.Errorf("option %q: %w", optName, err)
		}

		switch optName {
		case "identity":
			perm.Identity = val
		case "restrict-tools":
			perm.RestrictTools = appendPatterns(perm.RestrictTools, val)
		case "restrict-resources":
			perm.RestrictResources = appendPatterns(perm.RestrictResources, val)
		case "restrict-prompts":
			perm.RestrictPrompts = appendPatterns(perm.RestrictPrompts, val)
		default:
			return "", fmt.Errorf("unknown option %q", optName)
		}

		i += eqIdx + 1 + consumed
		// Skip comma separator.
		rest2 := line[i:]
		rest2 = strings.TrimLeft(rest2, " ")
		if len(rest2) > 0 && rest2[0] == ',' {
			i = len(line) - len(rest2) + 1
		} else {
			i = len(line) - len(rest2)
		}
	}
	return "", fmt.Errorf("no key found in line")
}

// parseQuotedValue parses a "value" and returns the unquoted content
// and the number of bytes consumed (including quotes).
func parseQuotedValue(s string) (string, int, error) {
	if len(s) == 0 || s[0] != '"' {
		return "", 0, fmt.Errorf("expected opening quote")
	}
	var b strings.Builder
	i := 1
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i += 2
			continue
		}
		if s[i] == '"' {
			return b.String(), i + 1, nil
		}
		b.WriteByte(s[i])
		i++
	}
	return "", 0, fmt.Errorf("unterminated quoted string")
}

// appendPatterns splits a comma-separated pattern string and appends to existing.
func appendPatterns(existing []string, val string) []string {
	for _, p := range strings.Split(val, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			existing = append(existing, p)
		}
	}
	return existing
}

// mergeInto unions restriction patterns from src into dst.
func mergeInto(dst, src *Permission) {
	if src.Identity != "" {
		dst.Identity = src.Identity
	}
	if src.RestrictTools != nil {
		dst.RestrictTools = append(dst.RestrictTools, src.RestrictTools...)
	}
	if src.RestrictResources != nil {
		dst.RestrictResources = append(dst.RestrictResources, src.RestrictResources...)
	}
	if src.RestrictPrompts != nil {
		dst.RestrictPrompts = append(dst.RestrictPrompts, src.RestrictPrompts...)
	}
}
