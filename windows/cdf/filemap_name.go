package cdf

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/windows/internal/csihash"
)

// FileMapName derives the native FileMaps leaf name from canonical absolute
// image paths (slash separators), not host paths. The Windows subtree is
// represented by $$; paths elsewhere are relative to the image drive root.
// Only printable ASCII is supported. No filesystem or ownership lookup occurs.
func FileMapName(imagePath, windowsRoot string) (string, error) {
	if e := validateFileMapImagePath(imagePath); e != nil {
		return "", e
	}
	if e := validateFileMapImagePath(windowsRoot); e != nil {
		return "", e
	}
	if windowsRoot == "/" {
		return "", fmt.Errorf("Windows root cannot be the image drive root")
	}
	relative := imagePath[1:]
	if strings.EqualFold(imagePath, windowsRoot) {
		relative = "$$"
	} else if len(imagePath) > len(windowsRoot) && imagePath[len(windowsRoot)] == '/' && strings.EqualFold(imagePath[:len(windowsRoot)], windowsRoot) {
		relative = "$$" + imagePath[len(windowsRoot):]
	}
	relative = strings.ReplaceAll(relative, "/", `\`)
	filtered := make([]byte, 0, 100)
	changed := false
	previousUnderscore := false
	for i := 0; i < len(relative); i++ {
		c := relative[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		keep := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '$'
		if !keep {
			changed = true
			c = '_'
			if previousUnderscore {
				continue
			}
		}
		previousUnderscore = c == '_'
		if len(filtered) == 100 {
			changed = true
			continue
		}
		filtered = append(filtered, c)
	}
	name := string(filtered)
	if changed || relative == "" {
		hash, e := csihash.UpperText(relative)
		if e != nil {
			return "", e
		}
		name += fmt.Sprintf("_%016x", hash)
	}
	return name + ".cdf-ms", nil
}

func validateFileMapImagePath(p string) error {
	if len(p) == 0 || len(p) > 32767 || p[0] != '/' {
		return fmt.Errorf("FileMap name requires a bounded absolute image path")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 32 || p[i] > 126 || p[i] == 92 || p[i] == ':' {
			return fmt.Errorf("FileMap name requires printable ASCII image paths without drive prefixes")
		}
	}
	if p != "/" {
		for _, part := range strings.Split(p[1:], "/") {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("FileMap name requires canonical image paths")
			}
		}
	}
	return nil
}
