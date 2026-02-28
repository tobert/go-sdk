// Package sshtransport implements an SSH transport for MCP servers and clients.
//
// The SSH transport embeds an SSH server within the MCP server process,
// handling key-based authentication and authorization directly. This is the
// same model used by Git hosting services like GitHub and Gitea.
//
// See SEP-0000 (SSH Transport) for the full specification.
package sshtransport

import "strings"

// MatchGlob reports whether value matches the glob pattern.
//
// Patterns use fnmatch semantics with globstar:
//   - * matches any sequence of characters except /
//   - ** matches any sequence of characters including /
//   - ? matches any single character except /
//   - [abc] matches any character in the set
//   - [!abc] or [^abc] matches any character not in the set
//   - backslash escapes the next character
func MatchGlob(pattern, value string) bool {
	return matchGlob(pattern, value)
}

// MatchAnyGlob reports whether value matches any of the given patterns.
func MatchAnyGlob(patterns []string, value string) bool {
	for _, p := range patterns {
		if matchGlob(p, value) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, value string) bool {
	// Fast path for universal wildcard.
	if pattern == "**" || pattern == "*" && !strings.Contains(value, "/") {
		return true
	}
	return doMatch(pattern, value)
}

// doMatch implements recursive glob matching.
func doMatch(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Check for globstar (**).
			if len(pattern) >= 2 && pattern[1] == '*' {
				// Consume the **.
				rest := pattern[2:]
				// ** at end matches everything.
				if len(rest) == 0 {
					return true
				}
				// If followed by /, consume it: **/ matches zero or more path segments.
				if len(rest) > 0 && rest[0] == '/' {
					rest = rest[1:]
				}
				// Try matching rest against every suffix of value.
				if doMatch(rest, value) {
					return true
				}
				for i := range value {
					if doMatch(rest, value[i+1:]) {
						return true
					}
				}
				return false
			}
			// Single * — match any sequence except /.
			rest := pattern[1:]
			// Try matching rest starting at every position within the current segment.
			if doMatch(rest, value) {
				return true
			}
			for i := 0; i < len(value); i++ {
				if value[i] == '/' {
					break
				}
				if doMatch(rest, value[i+1:]) {
					return true
				}
			}
			return false

		case '?':
			if len(value) == 0 || value[0] == '/' {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]

		case '[':
			if len(value) == 0 {
				return false
			}
			// Parse character class.
			matched, newPattern, ok := matchCharClass(pattern, value[0])
			if !ok {
				return false
			}
			if !matched {
				return false
			}
			pattern = newPattern
			value = value[1:]

		case '\\':
			// Escape: next character is literal.
			if len(pattern) < 2 {
				return false
			}
			if len(value) == 0 || value[0] != pattern[1] {
				return false
			}
			pattern = pattern[2:]
			value = value[1:]

		default:
			if len(value) == 0 || value[0] != pattern[0] {
				return false
			}
			pattern = pattern[1:]
			value = value[1:]
		}
	}
	return len(value) == 0
}

// matchCharClass processes a [...] character class pattern.
// Returns whether the character matched, the remaining pattern after ], and success.
func matchCharClass(pattern string, ch byte) (matched bool, rest string, ok bool) {
	// pattern starts with '['.
	i := 1
	if i >= len(pattern) {
		return false, "", false
	}

	negate := false
	if pattern[i] == '!' || pattern[i] == '^' {
		negate = true
		i++
	}

	matched = false
	first := true
	for i < len(pattern) {
		if pattern[i] == ']' && !first {
			if negate {
				matched = !matched
			}
			return matched, pattern[i+1:], true
		}
		first = false

		// Range: a-z.
		lo := pattern[i]
		i++
		if i+1 < len(pattern) && pattern[i] == '-' && pattern[i+1] != ']' {
			hi := pattern[i+1]
			i += 2
			if ch >= lo && ch <= hi {
				matched = true
			}
		} else {
			if ch == lo {
				matched = true
			}
		}
	}
	// No closing ] found.
	return false, "", false
}
