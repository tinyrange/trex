package shell

// The virtual make driver evaluates makefiles and runs recipes through the
// same bounded shell and filesystem as its caller. It never invokes host make.
import (
	"fmt"
	"io"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
)

type makeVariable struct {
	text                      string
	simple, command, exported bool
}
type makeRule struct{ targets, deps, order, recipes []string }
type virtualMake struct {
	s              *shell
	vars           map[string]makeVariable
	rules          map[string]*makeRule
	patterns       []*makeRule
	phony          map[string]bool
	visiting, done map[string]bool
	changed        map[string]bool
	first          string
	quiet, dry     bool
}

func (s *shell) makeCommand(args []string) error {
	c, err := s.child()
	if err != nil {
		return err
	}
	defer closeDescriptors(c.fds)
	c.status = 0
	m := &virtualMake{s: c, vars: map[string]makeVariable{}, rules: map[string]*makeRule{}, phony: map[string]bool{}, visiting: map[string]bool{}, done: map[string]bool{}, changed: map[string]bool{}}
	for k, v := range s.vars {
		if v.Exported {
			m.vars[k] = makeVariable{text: v.String(), exported: true}
		}
	}
	for k, v := range map[string]string{"MAKE": "make", "SHELL": "/bin/sh", "CC": "cc", "AR": "ar", "ARFLAGS": "rv"} {
		if _, ok := m.vars[k]; !ok {
			m.vars[k] = makeVariable{text: v}
		}
	}
	var files, goals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--version":
			_, err = fmt.Fprintln(s.output(1), "make (trex virtual Unix utilities)")
			return err
		case "-f", "--file", "-C", "--directory":
			i++
			if i == len(args) {
				return s.diagnostic(fmt.Errorf("make: missing argument for %s", a))
			}
			if a == "-C" || a == "--directory" {
				c.dir = c.resolve(args[i])
				st, e := c.cfg.FS.Stat(c.dir)
				if e != nil {
					return s.diagnostic(e)
				}
				if !st.IsDir() {
					return s.diagnostic(fmt.Errorf("make: not a directory: %s", c.dir))
				}
			} else {
				files = append(files, args[i])
			}
		case "-s", "--silent", "--quiet":
			m.quiet = true
		case "-n", "--just-print", "--dry-run":
			m.dry = true
		case "-r", "-R", "--no-builtin-rules", "--no-builtin-variables", "--no-print-directory":
			// No implicit built-in rules; explicit suffix/pattern rules are evaluated.
		default:
			if strings.HasPrefix(a, "-") {
				return unsupported("make option " + a)
			}
			if k, v, ok := strings.Cut(a, "="); ok {
				m.vars[k] = makeVariable{text: v, command: true, exported: true}
			} else {
				goals = append(goals, a)
			}
		}
	}
	if len(files) == 0 {
		for _, f := range []string{"GNUmakefile", "makefile", "Makefile"} {
			if _, e := c.cfg.FS.Stat(c.resolve(f)); e == nil {
				files = []string{f}
				break
			}
		}
	}
	if len(files) == 0 {
		return s.diagnostic(fmt.Errorf("make: no makefile found"))
	}
	for _, f := range files {
		if err = m.read(f, false, 0); err != nil {
			return err
		}
	}
	if len(goals) == 0 {
		if m.first == "" {
			return s.diagnostic(fmt.Errorf("make: no targets"))
		}
		goals = []string{m.first}
	}
	for _, g := range goals {
		if err = m.build(g, 0); err != nil {
			return err
		}
		if c.status != 0 {
			s.status = c.status
			return nil
		}
	}
	s.status = 0
	return nil
}

func (m *virtualMake) read(name string, optional bool, depth int) error {
	if depth >= m.s.cfg.MaxDepth {
		return fmt.Errorf("make: include nesting budget exceeded")
	}
	var data []byte
	var err error
	if name == "-" {
		data, err = io.ReadAll(io.LimitReader(m.s.input(), int64(m.s.cfg.MaxSubstitutionBytes)+1))
	} else {
		data, err = m.s.readFile(name)
	}
	if err != nil {
		if optional && errorsIsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) > m.s.cfg.MaxSubstitutionBytes {
		return fmt.Errorf("make: source budget exceeded")
	}
	lines := strings.Split(string(data), "\n")
	var current []*makeRule
	type condition struct{ parent, value, alternative bool }
	var conditions []condition
	active := func() bool {
		if len(conditions) == 0 {
			return true
		}
		v := conditions[len(conditions)-1]
		return v.parent && v.value
	}
	for i := 0; i < len(lines); i++ {
		if err = m.s.tick(); err != nil {
			return err
		}
		line := lines[i]
		recipe := strings.HasPrefix(line, "\t")
		for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
			i++
			if recipe {
				line += "\n" + strings.TrimPrefix(lines[i], "\t")
			} else {
				line = strings.TrimSuffix(line, "\\") + " " + strings.TrimSpace(lines[i])
			}
		}
		if recipe {
			if !active() {
				continue
			}
			if len(current) == 0 {
				return fmt.Errorf("make: %s:%d: recipe without target", name, i+1)
			}
			for _, r := range current {
				r.recipes = append(r.recipes, line[1:])
			}
			continue
		}
		line = strings.TrimSpace(makeComment(line))
		if line == "" {
			continue
		}
		word, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		switch word {
		case "ifdef", "ifndef", "ifeq", "ifneq":
			parent := active()
			value := false
			if parent {
				if word == "ifdef" || word == "ifndef" {
					k, e := m.expand(rest, nil, 0)
					if e != nil {
						return e
					}
					value = m.vars[k].text != ""
				} else {
					var a, b string
					if strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
						parts := makeArguments(rest[1 : len(rest)-1])
						if len(parts) != 2 {
							return fmt.Errorf("make: malformed conditional %s", line)
						}
						a, b = parts[0], parts[1]
						a = strings.TrimSpace(a)
						b = strings.TrimSpace(b)
					} else {
						return unsupported("make conditional " + line)
					}
					a, err = m.expand(a, nil, 0)
					if err != nil {
						return err
					}
					b, err = m.expand(b, nil, 0)
					if err != nil {
						return err
					}
					value = a == b
				}
				if word == "ifndef" || word == "ifneq" {
					value = !value
				}
			}
			conditions = append(conditions, condition{parent: parent, value: value})
			continue
		case "else":
			if len(conditions) == 0 || conditions[len(conditions)-1].alternative || rest != "" {
				return unsupported("make conditional " + line)
			}
			v := &conditions[len(conditions)-1]
			v.value = !v.value
			v.alternative = true
			continue
		case "endif":
			if len(conditions) == 0 {
				return fmt.Errorf("make: unexpected endif")
			}
			conditions = conditions[:len(conditions)-1]
			continue
		}
		if word == "define" {
			var body []string
			nesting := 1
			for i++; i < len(lines); i++ {
				trim := strings.TrimSpace(lines[i])
				if strings.HasPrefix(trim, "define ") {
					nesting++
				}
				if trim == "endef" {
					nesting--
					if nesting == 0 {
						break
					}
				}
				body = append(body, lines[i])
			}
			if nesting != 0 {
				return fmt.Errorf("make: unclosed define")
			}
			if active() {
				k := strings.TrimSpace(rest)
				if strings.ContainsAny(k, " 	=") {
					return unsupported("make define flavor " + k)
				}
				old := m.vars[k]
				if !old.command {
					m.vars[k] = makeVariable{text: strings.Join(body, "\n"), exported: old.exported}
				}
			}
			current = nil
			continue
		}
		if !active() {
			continue
		}
		current = nil
		if word == "include" || word == "-include" || word == "sinclude" {
			names, e := m.expand(rest, nil, 0)
			if e != nil {
				return e
			}
			for _, f := range strings.Fields(names) {
				if e = m.read(f, word != "include", depth+1); e != nil {
					return e
				}
			}
			continue
		}
		exported := false
		if word == "export" {
			exported = true
			line = rest
		}
		if k, op, v, ok := makeAssignment(line); ok {
			old, defined := m.vars[k]
			if old.command {
				continue
			}
			if op == "?=" && defined {
				continue
			}
			simple := op == ":=" || op == "+=" && old.simple
			if simple {
				v, err = m.expand(v, nil, 0)
				if err != nil {
					return err
				}
			}
			if op == "+=" {
				if old.text != "" {
					v = old.text + " " + v
				}
				simple = old.simple
			}
			m.vars[k] = makeVariable{text: v, simple: simple, exported: exported || old.exported}
			continue
		}
		if exported {
			for _, k := range strings.Fields(line) {
				v := m.vars[k]
				v.exported = true
				m.vars[k] = v
			}
			continue
		}
		// Inline recipes, like tab recipes, are expanded at execution time.
		ruleText, inline, hasInline := strings.Cut(line, ";")
		line, err = m.expand(ruleText, nil, 0)
		if err != nil {
			return err
		}
		left, right, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("make: %s:%d: unsupported statement %q", name, i+1, line)
		}
		if strings.HasPrefix(right, ":") {
			return unsupported("make double-colon rule " + line)
		}
		deps := right
		staticPattern := ""
		if pattern, rest, ok := strings.Cut(deps, ":"); ok {
			staticPattern = strings.TrimSpace(pattern)
			deps = rest
			if !strings.Contains(staticPattern, "%") {
				return unsupported("make target-specific assignment " + line)
			}
		}
		deps, order, _ := strings.Cut(deps, "|")
		targets := strings.Fields(left)
		if len(targets) == 0 {
			continue
		}
		if len(targets) == 1 && targets[0] == ".PHONY" {
			for _, d := range strings.Fields(deps) {
				m.phony[makeTargetName(d)] = true
			}
			continue
		}
		if len(targets) == 1 && targets[0] == ".SUFFIXES" {
			continue
		}
		for _, target := range targets {
			target = makeTargetName(target)
			if strings.HasPrefix(target, ".") && strings.Count(target, ".") == 2 && !strings.Contains(target, "/") {
				parts := strings.Split(target[1:], ".")
				target = "%." + parts[1]
				deps = "%." + parts[0]
			}
			r := m.rules[target]
			if r == nil {
				r = &makeRule{targets: []string{target}}
				m.rules[target] = r
				if strings.Contains(target, "%") {
					m.patterns = append(m.patterns, r)
				}
			}
			targetDeps, targetOrder := deps, order
			if staticPattern != "" {
				stem, ok := makeMatch(staticPattern, target)
				if !ok {
					return fmt.Errorf("make: target %s does not match %s", target, staticPattern)
				}
				targetDeps = strings.ReplaceAll(targetDeps, "%", stem)
				targetOrder = strings.ReplaceAll(targetOrder, "%", stem)
			}
			r.deps = append(r.deps, strings.Fields(targetDeps)...)
			r.order = append(r.order, strings.Fields(targetOrder)...)
			if hasInline {
				r.recipes = append(r.recipes, strings.TrimSpace(inline))
			}
			current = append(current, r)
			if m.first == "" && !strings.HasPrefix(target, ".") && !strings.Contains(target, "%") {
				m.first = target
			}
		}
	}
	if len(conditions) != 0 {
		return fmt.Errorf("make: unclosed conditional")
	}
	return nil
}
func makeComment(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '#' {
			return s[:i]
		}
	}
	return s
}
func makeAssignment(s string) (string, string, string, bool) {
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return "", "", "", false
	}
	left := strings.TrimSpace(s[:i])
	op := "="
	if strings.HasSuffix(left, ":") || strings.HasSuffix(left, "+") || strings.HasSuffix(left, "?") {
		op = left[len(left)-1:] + "="
		left = strings.TrimSpace(left[:len(left)-1])
	}
	if left == "" || strings.ContainsAny(left, " \t:") {
		return "", "", "", false
	}
	return left, op, strings.TrimLeft(s[i+1:], " \t"), true
}

func makeMatch(pattern, word string) (string, bool) {
	a, b, ok := strings.Cut(pattern, "%")
	if !ok {
		return "", pattern == word
	}
	if !strings.HasPrefix(word, a) || !strings.HasSuffix(word, b) || len(word) < len(a)+len(b) {
		return "", false
	}
	return word[len(a) : len(word)-len(b)], true
}
func (m *virtualMake) stat(name string) (time.Time, bool, error) {
	st, e := m.s.cfg.FS.Stat(m.s.resolve(name))
	if errorsIsNotExist(e) {
		return time.Time{}, false, nil
	}
	if e != nil {
		return time.Time{}, false, e
	}
	return st.ModTime(), true, nil
}
func (m *virtualMake) build(target string, depth int) error {
	target = makeTargetName(target)
	if depth >= m.s.cfg.MaxDepth {
		return fmt.Errorf("make: dependency nesting budget exceeded")
	}
	if err := m.s.tick(); err != nil {
		return err
	}
	if m.done[target] {
		return nil
	}
	if m.visiting[target] {
		return fmt.Errorf("make: dependency cycle at %s", target)
	}
	m.visiting[target] = true
	defer delete(m.visiting, target)
	stamp, exists, err := m.stat(target)
	if err != nil {
		return err
	}
	r := m.rules[target]
	stem := ""
	if r == nil || len(r.recipes) == 0 {
		for _, p := range m.patterns {
			v, ok := makeMatch(p.targets[0], target)
			if !ok {
				continue
			}
			possible := true
			for _, d := range p.deps {
				d = strings.ReplaceAll(d, "%", v)
				_, found, e := m.stat(d)
				if e != nil {
					return e
				}
				if !found && m.rules[makeTargetName(d)] == nil {
					possible = false
					break
				}
			}
			if possible {
				q := *p
				q.deps = append([]string(nil), p.deps...)
				q.order = append([]string(nil), p.order...)
				for i := range q.deps {
					q.deps[i] = strings.ReplaceAll(q.deps[i], "%", v)
				}
				for i := range q.order {
					q.order[i] = strings.ReplaceAll(q.order[i], "%", v)
				}
				if r != nil {
					q.deps = append(q.deps, r.deps...)
					q.order = append(q.order, r.order...)
				}
				r = &q
				stem = v
				break
			}
		}
	}
	if r == nil {
		if exists || m.phony[target] {
			m.done[target] = true
			m.changed[target] = m.phony[target]
			return nil
		}
		m.s.status = 2
		_, err = fmt.Fprintf(m.s.output(2), "make: no rule to make target %q\n", target)
		return err
	}
	dirty := !exists || m.phony[target]
	var newer []string
	for _, d := range append(append([]string(nil), r.deps...), r.order...) {
		if err = m.build(d, depth+1); err != nil || m.s.status != 0 {
			return err
		}
		normal := false
		for _, n := range r.deps {
			if n == d {
				normal = true
				break
			}
		}
		if !normal {
			continue
		}
		t, _, e := m.stat(d)
		if e != nil {
			return e
		}
		if !exists || m.changed[makeTargetName(d)] || t.After(stamp) {
			dirty = true
			newer = append(newer, d)
		}
	}
	if dirty {
		unique := []string{}
		seen := map[string]bool{}
		for _, d := range r.deps {
			if !seen[d] {
				unique = append(unique, d)
				seen[d] = true
			}
		}
		auto := map[string]string{"@": target, "*": stem, "^": strings.Join(unique, " "), "+": strings.Join(r.deps, " "), "?": strings.Join(newer, " "), "|": strings.Join(r.order, " ")}
		if len(r.deps) > 0 {
			auto["<"] = r.deps[0]
		}
		for _, recipe := range r.recipes {
			text, e := m.expand(recipe, auto, 0)
			if e != nil {
				return e
			}
			quiet, ignore, force := m.quiet, false, false
			for len(text) > 0 {
				switch text[0] {
				case '@':
					quiet = true
				case '-':
					ignore = true
				case '+':
					force = true
				default:
					goto prefixesDone
				}
				text = text[1:]
			}
		prefixesDone:
			if strings.TrimSpace(text) == "" {
				continue
			}
			if !quiet || m.dry {
				if _, e = fmt.Fprintln(m.s.output(1), text); e != nil {
					return e
				}
			}
			if m.dry && !force && !strings.Contains(recipe, "$(MAKE)") && !strings.Contains(recipe, "${MAKE}") {
				continue
			}
			for k, v := range m.vars {
				if v.exported {
					value := v.text
					var e error
					if !v.simple {
						value, e = m.expand(value, nil, 0)
					}
					if e != nil {
						return e
					}
					m.s.vars[k] = expand.Variable{Set: true, Exported: true, Kind: expand.String, Str: value}
				}
			}
			if e = m.s.shellBuiltin([]string{"-c", text}, false); e != nil {
				return e
			}
			if m.s.status != 0 {
				if !ignore {
					m.s.status = 2
					return nil
				}
				m.s.status = 0
			}
		}
	}
	m.done[target] = true
	_, remains, err := m.stat(target)
	if err != nil {
		return err
	}
	// A recipe may deliberately leave an existing target unchanged (Automake
	// stamp rules do this). Only phony/missing outputs force dependents;
	// existing outputs are compared using their actual post-recipe timestamps.
	m.changed[target] = dirty && (m.phony[target] || !remains)
	return nil
}
