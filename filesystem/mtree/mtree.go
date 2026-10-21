// Package mtree reads BSD mtree metadata manifests through portable file views.
package mtree

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/tinyrange/trex/storage"
)

type Entry struct {
	Path       string
	Attributes map[string]string
}

// Read interprets /set, /unset, directory descent and parent navigation. It
// preserves metadata keywords, including Apple extensions, as decoded strings.
// It never follows links or accesses the namespace described by the manifest.
func Read(source storage.Reader, maximum int) ([]Entry, error) {
	if source == nil || source.Size() < 0 || source.Size() > 16<<20 || maximum < 1 || maximum > 1000000 {
		return nil, fmt.Errorf("mtree: invalid source or entry bound")
	}
	data := make([]byte, source.Size())
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, source.Size()), data); err != nil {
		return nil, err
	}
	var entries []Entry
	defaults := map[string]string{}
	seen := map[string]bool{}
	stack := []string{"/"}
	attributes, pathBytes := 0, 0
	var logical []byte
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 200000 {
		return nil, fmt.Errorf("mtree: excessive lines")
	}
	for lineNo, physical := range lines {
		if lineNo == len(lines)-1 && len(physical) == 0 && len(logical) != 0 {
			return nil, fmt.Errorf("mtree: unfinished line continuation")
		}
		physical = bytes.TrimSuffix(physical, []byte{'\r'})
		slashes := 0
		for i := len(physical) - 1; i >= 0 && physical[i] == '\\'; i-- {
			slashes++
		}
		continuation := slashes%2 != 0
		if continuation {
			physical = physical[:len(physical)-1]
		}
		if len(physical) > 1<<20-len(logical) {
			return nil, fmt.Errorf("mtree: excessive logical line")
		}
		logical = append(logical, physical...)
		if continuation {
			logical = append(logical, ' ')
			continue
		}
		tokens, err := tokenize(logical)
		logical = nil
		if err != nil {
			return nil, fmt.Errorf("mtree: line %d: %w", lineNo+1, err)
		}
		if len(tokens) == 0 {
			continue
		}
		if tokens[0] == "/unset" {
			for _, key := range tokens[1:] {
				if key == "all" {
					clear(defaults)
				} else {
					delete(defaults, key)
				}
			}
			continue
		}
		values := map[string]string{}
		for _, token := range tokens[1:] {
			key, value, _ := strings.Cut(token, "=")
			if key == "" {
				return nil, fmt.Errorf("mtree: empty metadata key")
			}
			if _, ok := values[key]; ok {
				return nil, fmt.Errorf("mtree: duplicate metadata key %s", key)
			}
			values[key] = value
		}
		if tokens[0] == "/set" {
			for k, v := range values {
				defaults[k] = v
			}
			continue
		}
		name := tokens[0]
		if name == ".." {
			if len(tokens) != 1 || len(stack) == 1 {
				return nil, fmt.Errorf("mtree: invalid parent navigation")
			}
			stack = stack[:len(stack)-1]
			continue
		}
		if len(entries) == maximum {
			return nil, fmt.Errorf("mtree: excessive entries")
		}
		if strings.HasPrefix(name, "/") || strings.IndexByte(name, 0) >= 0 {
			return nil, fmt.Errorf("mtree: invalid entry path")
		}
		full := strings.HasPrefix(name, "./")
		base := stack[len(stack)-1]
		if full {
			base = "/"
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return nil, fmt.Errorf("mtree: embedded parent traversal")
			}
		}
		p := path.Join(base, name)
		if p == "/" && name != "." && name != "./" {
			return nil, fmt.Errorf("mtree: invalid root path")
		}
		if seen[p] {
			return nil, fmt.Errorf("mtree: duplicate path %s", p)
		}
		seen[p] = true
		attributes += len(defaults) + len(values)
		pathBytes += len(p)
		if attributes > 1000000 || pathBytes > 64<<20 {
			return nil, fmt.Errorf("mtree: expanded metadata exceeds limit")
		}
		attrs := make(map[string]string, len(defaults)+len(values))
		for k, v := range defaults {
			attrs[k] = v
		}
		for k, v := range values {
			attrs[k] = v
		}
		entries = append(entries, Entry{p, attrs})
		if attrs["type"] == "dir" && !full {
			stack = append(stack, p)
		}
	}
	if len(logical) != 0 {
		return nil, fmt.Errorf("mtree: unfinished line continuation")
	}
	return entries, nil
}

func tokenize(line []byte) ([]string, error) {
	var out []string
	var token []byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == ' ' || c == '\t' {
			if len(token) > 0 {
				out = append(out, string(token))
				token = nil
			}
			continue
		}
		if c == '#' && len(token) == 0 {
			break
		}
		if c != '\\' {
			if c == 0 {
				return nil, fmt.Errorf("NUL in manifest")
			}
			token = append(token, c)
			continue
		}
		i++
		if i == len(line) {
			return nil, fmt.Errorf("unfinished escape")
		}
		c = line[i]
		if c >= '0' && c <= '7' {
			if i+2 >= len(line) || line[i+1] < '0' || line[i+1] > '7' || line[i+2] < '0' || line[i+2] > '7' {
				return nil, fmt.Errorf("invalid octal escape")
			}
			n := int(c-'0')*64 + int(line[i+1]-'0')*8 + int(line[i+2]-'0')
			if n == 0 || n > 255 {
				return nil, fmt.Errorf("invalid escaped byte")
			}
			token = append(token, byte(n))
			i += 2
			continue
		}
		switch c {
		case '\\', '#', ' ', '\t':
			token = append(token, c)
		case 's':
			token = append(token, ' ')
		case 't':
			token = append(token, '\t')
		case 'n':
			token = append(token, '\n')
		case 'r':
			token = append(token, '\r')
		case 'b':
			token = append(token, '\b')
		case 'f':
			token = append(token, '\f')
		case 'v':
			token = append(token, '\v')
		default:
			return nil, fmt.Errorf("unsupported escape \\%c", c)
		}
	}
	if len(token) > 0 {
		out = append(out, string(token))
	}
	return out, nil
}
