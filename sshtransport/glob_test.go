package sshtransport

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Exact match.
		{"hello", "hello", true},
		{"hello", "world", false},
		{"", "", true},
		{"", "a", false},

		// Single star — matches within segment.
		{"*", "hello", true},
		{"*", "", true},
		{"*", "a/b", false},
		{"*.txt", "file.txt", true},
		{"*.txt", "file.go", false},
		{"test_*", "test_foo", true},
		{"test_*", "test_", true},
		{"test_*", "foo", false},
		{"query_*", "query_spans", true},
		{"query_*", "delete_all", false},
		{"list_*", "list_traces", true},

		// Question mark — single character.
		{"?", "a", true},
		{"?", "", false},
		{"?", "ab", false},
		{"fo?", "foo", true},
		{"fo?", "fo", false},

		// Character class.
		{"[abc]", "a", true},
		{"[abc]", "d", false},
		{"[a-z]", "m", true},
		{"[a-z]", "M", false},
		{"[!abc]", "d", true},
		{"[!abc]", "a", false},
		{"[^abc]", "d", true},

		// Globstar — matches across segments.
		{"**", "anything", true},
		{"**", "a/b/c", true},
		{"**", "", true},
		{"**/foo", "foo", true},
		{"**/foo", "bar/foo", true},
		{"**/foo", "bar/baz/foo", true},
		{"**/foo", "bar/baz/foobar", false},
		{"foo/**", "foo/bar", true},
		{"foo/**", "foo/bar/baz", true},
		{"foo/**", "foo/", true},
		{"foo/**", "foo", false},
		{"a/**/z", "a/z", true},
		{"a/**/z", "a/b/z", true},
		{"a/**/z", "a/b/c/z", true},

		// Resource URI patterns.
		{"file:///data/public/**", "file:///data/public/readme.txt", true},
		{"file:///data/public/**", "file:///data/public/sub/file.txt", true},
		{"file:///data/public/**", "file:///data/private/secret.txt", false},

		// Multiple patterns in tool names.
		{"query_*", "query_spans", true},
		{"list_*", "list_traces", true},

		// Escape.
		{"hello\\*world", "hello*world", true},
		{"hello\\*world", "helloXworld", false},

		// Edge cases.
		{"*/*", "a/b", true},
		{"*/*", "abc", false},
	}

	for _, tt := range tests {
		got := MatchGlob(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

func TestMatchAnyGlob(t *testing.T) {
	patterns := []string{"query_*", "list_*"}

	tests := []struct {
		value string
		want  bool
	}{
		{"query_spans", true},
		{"list_traces", true},
		{"delete_all", false},
		{"query_", true},
	}

	for _, tt := range tests {
		got := MatchAnyGlob(patterns, tt.value)
		if got != tt.want {
			t.Errorf("MatchAnyGlob(%v, %q) = %v, want %v", patterns, tt.value, got, tt.want)
		}
	}

	// Empty patterns should match nothing.
	if MatchAnyGlob(nil, "anything") {
		t.Error("MatchAnyGlob(nil, ...) should return false")
	}
}
