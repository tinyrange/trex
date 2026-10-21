package shell

import "strings"

// GNU-style target identity ignores leading ./; keep recipe operands otherwise
// intact rather than rewriting paths containing internal .. components.
func makeTargetName(name string) string {
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	return name
}
