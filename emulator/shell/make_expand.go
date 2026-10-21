package shell

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

func (m *virtualMake) expand(text string, auto map[string]string, depth int) (string, error) {
	if depth >= m.s.cfg.MaxDepth {
		return "", fmt.Errorf("make: variable expansion nesting budget exceeded")
	}
	if err := m.s.tick(); err != nil {
		return "", err
	}
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] != '$' {
			out.WriteByte(text[i])
		} else {
			i++
			if i == len(text) {
				break
			}
			key := string(text[i])
			value := ""
			if text[i] == '$' {
				value = "$"
			} else {
				if text[i] == '(' || text[i] == '{' {
					close := byte(')')
					if text[i] == '{' {
						close = '}'
					}
					start := i + 1
					n := 1
					for i++; i < len(text); i++ {
						if text[i] == text[start-1] {
							n++
						}
						if text[i] == close {
							n--
							if n == 0 {
								break
							}
						}
					}
					if i == len(text) {
						return "", fmt.Errorf("make: unterminated variable reference in %q", text)
					}
					key = text[start:i]
				}
				var err error
				value, err = m.reference(key, auto, depth+1)
				if err != nil {
					return "", err
				}
			}
			out.WriteString(value)
		}
		if out.Len() > m.s.cfg.MaxSubstitutionBytes {
			return "", fmt.Errorf("make: expansion budget exceeded")
		}
	}
	return out.String(), nil
}
func (m *virtualMake) reference(key string, auto map[string]string, depth int) (string, error) {
	fn, arg, hasArg := strings.Cut(key, " ")
	if hasArg {
		return m.function(fn, strings.TrimLeft(arg, " \t"), auto, depth)
	}
	key, err := m.expand(key, auto, depth)
	if err != nil {
		return "", err
	}
	name, sub, subst := strings.Cut(key, ":")
	if len(name) == 2 && (name[1] == 'D' || name[1] == 'F') {
		if original, ok := auto[name[:1]]; ok {
			words := strings.Fields(original)
			for i, w := range words {
				if name[1] == 'D' {
					words[i] = path.Dir(w)
				} else {
					words[i] = path.Base(w)
				}
			}
			return strings.Join(words, " "), nil
		}
	}
	value, ok := auto[name]
	if !ok {
		v := m.vars[name]
		value = v.text
		if !v.simple {
			value, err = m.expand(value, auto, depth)
			if err != nil {
				return "", err
			}
		}
	}
	if subst {
		from, to, ok := strings.Cut(sub, "=")
		if !ok {
			return "", fmt.Errorf("make: malformed substitution")
		}
		words := strings.Fields(value)
		for i, w := range words {
			if strings.Contains(from, "%") {
				if stem, ok := makeMatch(from, w); ok {
					words[i] = strings.ReplaceAll(to, "%", stem)
				}
			} else if strings.HasSuffix(w, from) {
				words[i] = strings.TrimSuffix(w, from) + to
			}
		}
		value = strings.Join(words, " ")
	}
	return value, nil
}
func makeArguments(text string) []string {
	var result []string
	start, depth := 0, 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(', '{':
			depth++
		case ')', '}':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, text[start:i])
				start = i + 1
			}
		}
	}
	return append(result, text[start:])
}
func (m *virtualMake) function(fn, arg string, auto map[string]string, depth int) (string, error) {
	args := makeArguments(arg)
	// if/or/and evaluate only selected branches, including their side effects.
	if fn == "if" {
		if len(args) < 2 || len(args) > 3 {
			return "", fmt.Errorf("make: if requires 2 or 3 arguments")
		}
		cond, e := m.expand(strings.TrimSpace(args[0]), auto, depth)
		if e != nil {
			return "", e
		}
		if cond != "" {
			return m.expand(args[1], auto, depth)
		}
		if len(args) == 3 {
			return m.expand(args[2], auto, depth)
		}
		return "", nil
	}
	if fn == "or" || fn == "and" {
		v := ""
		for _, a := range args {
			var e error
			v, e = m.expand(a, auto, depth)
			if e != nil {
				return "", e
			}
			if (fn == "or" && v != "") || (fn == "and" && v == "") {
				break
			}
		}
		return v, nil
	}
	for i, a := range args {
		v, e := m.expand(a, auto, depth)
		if e != nil {
			return "", e
		}
		args[i] = v
	}
	need := func(n int) error {
		if len(args) != n {
			return fmt.Errorf("make: %s requires %d arguments", fn, n)
		}
		return nil
	}
	switch fn {
	case "subst":
		if e := need(3); e != nil {
			return "", e
		}
		return strings.ReplaceAll(args[2], args[0], args[1]), nil
	case "patsubst":
		if e := need(3); e != nil {
			return "", e
		}
		words := strings.Fields(args[2])
		for i, w := range words {
			if stem, ok := makeMatch(args[0], w); ok {
				words[i] = strings.ReplaceAll(args[1], "%", stem)
			}
		}
		return strings.Join(words, " "), nil
	case "filter", "filter-out":
		if e := need(2); e != nil {
			return "", e
		}
		var words []string
		for _, w := range strings.Fields(args[1]) {
			match := false
			for _, p := range strings.Fields(args[0]) {
				if _, ok := makeMatch(p, w); ok {
					match = true
				}
			}
			if match == (fn == "filter") {
				words = append(words, w)
			}
		}
		return strings.Join(words, " "), nil
	case "addprefix", "addsuffix":
		if e := need(2); e != nil {
			return "", e
		}
		words := strings.Fields(args[1])
		for i, w := range words {
			if fn == "addprefix" {
				words[i] = args[0] + w
			} else {
				words[i] = w + args[0]
			}
		}
		return strings.Join(words, " "), nil
	case "findstring":
		if e := need(2); e != nil {
			return "", e
		}
		if strings.Contains(args[1], args[0]) {
			return args[0], nil
		}
		return "", nil
	case "word":
		if e := need(2); e != nil {
			return "", e
		}
		n, e := strconv.Atoi(args[0])
		if e != nil || n < 1 {
			return "", fmt.Errorf("make: invalid word index")
		}
		words := strings.Fields(args[1])
		if n > len(words) {
			return "", nil
		}
		return words[n-1], nil
	}
	if e := need(1); e != nil {
		return "", e
	}
	value := args[0]
	words := strings.Fields(value)
	switch fn {
	case "strip":
		return strings.Join(words, " "), nil
	case "sort":
		sort.Strings(words)
		unique := words[:0]
		for _, w := range words {
			if len(unique) == 0 || unique[len(unique)-1] != w {
				unique = append(unique, w)
			}
		}
		return strings.Join(unique, " "), nil
	case "words":
		return strconv.Itoa(len(words)), nil
	case "firstword":
		if len(words) > 0 {
			return words[0], nil
		}
		return "", nil
	case "lastword":
		if len(words) > 0 {
			return words[len(words)-1], nil
		}
		return "", nil
	case "dir", "notdir", "basename", "suffix":
		for i, w := range words {
			switch fn {
			case "dir":
				j := strings.LastIndexByte(w, '/')
				if j < 0 {
					words[i] = "./"
				} else {
					words[i] = w[:j+1]
				}
			case "notdir":
				words[i] = path.Base(w)
			case "basename":
				words[i] = strings.TrimSuffix(w, path.Ext(w))
			case "suffix":
				words[i] = path.Ext(w)
			}
		}
		return strings.Join(words, " "), nil
	case "shell":
		c, e := m.s.child()
		if e != nil {
			return "", e
		}
		defer func() { closeDescriptors(c.fds) }()
		var out bytes.Buffer
		end := captureEnd{done: make(chan struct{})}
		c.setDescriptor(1, descriptor{owner: &fileOwner{closer: end}, writer: &makeCapture{buffer: &out, maximum: m.s.cfg.MaxSubstitutionBytes}})
		if e = c.shellBuiltin([]string{"-c", value}, false); e != nil {
			return "", e
		}
		closeDescriptors(c.fds)
		c.fds = nil
		select {
		case <-end.done:
		case <-m.s.ctx.Done():
			return "", m.s.ctx.Err()
		}
		if out.Len() > m.s.cfg.MaxSubstitutionBytes {
			return "", fmt.Errorf("make: shell output budget exceeded")
		}
		return strings.ReplaceAll(strings.TrimRight(out.String(), "\r\n"), "\n", " "), nil
	case "wildcard":
		var found []string
		for _, w := range words {
			dir, base := path.Split(w)
			entries, e := m.s.cfg.FS.ReadDir(m.s.resolve(dir))
			if errorsIsNotExist(e) {
				continue
			}
			if e != nil {
				return "", e
			}
			for _, entry := range entries {
				match, e := path.Match(base, entry.Name())
				if e != nil {
					return "", e
				}
				if match {
					found = append(found, dir+entry.Name())
				}
			}
		}
		sort.Strings(found)
		return strings.Join(found, " "), nil
	case "value":
		return m.vars[value].text, nil
	case "origin":
		v, ok := m.vars[value]
		if !ok {
			return "undefined", nil
		}
		if v.command {
			return "command line", nil
		}
		return "file", nil
	case "error":
		return "", fmt.Errorf("make: %s", value)
	case "warning", "info":
		fd := 1
		if fn == "warning" {
			fd = 2
		}
		_, e := fmt.Fprintln(m.s.output(fd), value)
		return "", e
	}
	return "", unsupported("make function " + fn)
}
