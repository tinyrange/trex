package shell

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type sedAddress struct {
	line int
	last bool
	re   *regexp.Regexp
}

func (a sedAddress) matches(line int, last bool, text string) bool {
	if a.last {
		return last
	}
	if a.re != nil {
		return a.re.MatchString(text)
	}
	return a.line == 0 || a.line == line
}

type sedCommand struct {
	first, last            sedAddress
	ranged, active, negate bool
	op                     byte
	re                     *regexp.Regexp
	replacement            string
	global, print          bool
	occurrence             int
	transliteration        *[256]byte
	label                  string
	target                 int
}
type sedParser struct {
	text     string
	i        int
	extended bool
	previous *regexp.Regexp
}

func (p *sedParser) space() {
	for p.i < len(p.text) && (p.text[p.i] == ' ' || p.text[p.i] == '\t') {
		p.i++
	}
}
func (p *sedParser) delimited(delimiter byte) (string, error) {
	var b strings.Builder
	for p.i < len(p.text) {
		c := p.text[p.i]
		p.i++
		if c == delimiter {
			return b.String(), nil
		}
		if c == '\\' && p.i < len(p.text) {
			next := p.text[p.i]
			p.i++
			if next == delimiter {
				if strings.ContainsRune(`.\+*?()|[]{}^$`, rune(delimiter)) {
					b.WriteByte('\\')
				}
				b.WriteByte(next)
			} else {
				b.WriteByte(c)
				b.WriteByte(next)
			}
			continue
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("sed: unterminated expression")
}
func (p *sedParser) compile(text string) (*regexp.Regexp, error) {
	if text == "" {
		if p.previous == nil {
			return nil, fmt.Errorf("sed: no previous regular expression")
		}
		return p.previous, nil
	}
	var re *regexp.Regexp
	var err error
	if p.extended {
		re, err = regexp.Compile(text)
		if err == nil {
			re.Longest()
		}
	} else {
		re, err = basicRegexp(text)
	}
	if err == nil {
		p.previous = re
	}
	return re, err
}
func (p *sedParser) address() (sedAddress, bool, error) {
	p.space()
	a := sedAddress{}
	if p.i == len(p.text) {
		return a, false, nil
	}
	c := p.text[p.i]
	if c == '$' {
		p.i++
		a.last = true
		return a, true, nil
	}
	if c >= '0' && c <= '9' {
		start := p.i
		for p.i < len(p.text) && p.text[p.i] >= '0' && p.text[p.i] <= '9' {
			p.i++
		}
		n, err := strconv.Atoi(p.text[start:p.i])
		if err != nil || n == 0 {
			return a, false, unsupported("sed zero/overflow address")
		}
		a.line = n
		return a, true, nil
	}
	if c == '/' {
		p.i++
		text, err := p.delimited('/')
		if err != nil {
			return a, false, err
		}
		a.re, err = p.compile(text)
		return a, true, err
	}
	return a, false, nil
}
func (p *sedParser) parse() ([]sedCommand, error) {
	var result []sedCommand
	for p.i < len(p.text) {
		if strings.ContainsRune(" \t\n;", rune(p.text[p.i])) {
			p.i++
			continue
		}
		if p.text[p.i] == '#' {
			for p.i < len(p.text) && p.text[p.i] != '\n' {
				p.i++
			}
			continue
		}
		c := sedCommand{}
		var err error
		var present bool
		c.first, present, err = p.address()
		if err != nil {
			return nil, err
		}
		p.space()
		if present && p.i < len(p.text) && p.text[p.i] == ',' {
			p.i++
			c.last, present, err = p.address()
			if err != nil {
				return nil, err
			}
			if !present {
				return nil, fmt.Errorf("sed: missing range end")
			}
			c.ranged = true
		}
		p.space()
		if p.i < len(p.text) && p.text[p.i] == '!' {
			c.negate = true
			p.i++
			p.space()
		}
		if p.i == len(p.text) {
			return nil, fmt.Errorf("sed: missing command")
		}
		c.op = p.text[p.i]
		p.i++
		switch c.op {
		case 'r':
			p.space()
			begin := p.i
			for p.i < len(p.text) && p.text[p.i] != '\n' {
				p.i++
			}
			c.replacement = strings.TrimSpace(p.text[begin:p.i])
			if c.replacement == "" {
				return nil, fmt.Errorf("sed: missing read filename")
			}
		case ':', 'b', 't', 'T':
			p.space()
			begin := p.i
			for p.i < len(p.text) && p.text[p.i] != ';' && p.text[p.i] != 10 {
				p.i++
			}
			c.label = strings.TrimSpace(p.text[begin:p.i])
			if c.op == ':' && c.label == "" {
				return nil, fmt.Errorf("sed: empty label")
			}
		case 'y':
			if p.i == len(p.text) {
				return nil, fmt.Errorf("sed: missing transliteration delimiter")
			}
			delimiter := p.text[p.i]
			p.i++
			if delimiter == '\\' || delimiter == '\n' {
				return nil, fmt.Errorf("sed: invalid transliteration delimiter")
			}
			source, err := p.transliterationString(delimiter)
			if err != nil {
				return nil, err
			}
			dest, err := p.transliterationString(delimiter)
			if err != nil {
				return nil, err
			}
			if len(source) != len(dest) {
				return nil, fmt.Errorf("sed: unequal transliteration lengths")
			}
			c.transliteration = new([256]byte)
			for i := range c.transliteration {
				c.transliteration[i] = byte(i)
			}
			for i := range source {
				c.transliteration[source[i]] = dest[i]
			}
		case 's':
			if p.i == len(p.text) {
				return nil, fmt.Errorf("sed: missing delimiter")
			}
			delimiter := p.text[p.i]
			p.i++
			expression, err := p.delimited(delimiter)
			if err != nil {
				return nil, err
			}
			c.re, err = p.compile(expression)
			if err != nil {
				return nil, err
			}
			c.replacement, err = p.delimited(delimiter)
			if err != nil {
				return nil, err
			}
			for p.i < len(p.text) && !strings.ContainsRune(" \t\n;}", rune(p.text[p.i])) {
				flag := p.text[p.i]
				p.i++
				switch {
				case flag == 'g':
					c.global = true
				case flag == 'p':
					c.print = true
				case flag >= '1' && flag <= '9':
					start := p.i - 1
					for p.i < len(p.text) && p.text[p.i] >= '0' && p.text[p.i] <= '9' {
						p.i++
					}
					c.occurrence, err = strconv.Atoi(p.text[start:p.i])
					if err != nil {
						return nil, err
					}
				default:
					return nil, unsupported("sed substitution flag " + string(flag))
				}
			}
			for i := 0; i+1 < len(c.replacement); i++ {
				if c.replacement[i] == '\\' {
					i++
					n := int(c.replacement[i] - '0')
					if n >= 1 && n <= 9 && n > c.re.NumSubexp() {
						return nil, fmt.Errorf("sed: invalid replacement backreference")
					}
				}
			}
		case 'a', 'i':
			p.space()
			if p.i >= len(p.text) || p.text[p.i] != '\\' {
				return nil, unsupported("sed text without backslash")
			}
			p.i++
			if p.i >= len(p.text) || p.text[p.i] != '\n' {
				return nil, fmt.Errorf("sed: expected newline before text")
			}
			p.i++
			var text strings.Builder
			for p.i < len(p.text) {
				c := p.text[p.i]
				if c == '\n' {
					break
				}
				p.i++
				if c == '\\' && p.i < len(p.text) {
					c = p.text[p.i]
					p.i++
				}
				text.WriteByte(c)
			}
			c.replacement = text.String() + "\n"
		case 'p', 'd', 'q', '=', 'h', 'H', 'g', 'G', 'x', 'n', 'N', '{', '}':
		default:
			return nil, unsupported("sed command " + string(c.op))
		}
		p.space()
		if c.op != '{' && c.op != '}' && p.i < len(p.text) && p.text[p.i] != ';' && p.text[p.i] != '\n' && p.text[p.i] != '}' {
			return nil, unsupported("sed command suffix " + p.text[p.i:])
		}
		result = append(result, c)
	}
	var blocks []int
	for i := range result {
		switch result[i].op {
		case '{':
			blocks = append(blocks, i)
		case '}':
			if len(blocks) == 0 {
				return nil, fmt.Errorf("sed: unmatched closing brace")
			}
			begin := blocks[len(blocks)-1]
			blocks = blocks[:len(blocks)-1]
			result[begin].target = i
		}
	}
	if len(blocks) > 0 {
		return nil, fmt.Errorf("sed: unclosed block")
	}
	labels := make(map[string]int)
	for i, c := range result {
		if c.op == ':' {
			if _, ok := labels[c.label]; ok {
				return nil, fmt.Errorf("sed: duplicate label %s", c.label)
			}
			labels[c.label] = i
		}
	}
	for i := range result {
		c := &result[i]
		if c.op == 'b' || c.op == 't' || c.op == 'T' {
			c.target = len(result)
			if c.label != "" {
				n, ok := labels[c.label]
				if !ok {
					return nil, fmt.Errorf("sed: undefined label %s", c.label)
				}
				c.target = n
			}
		}
	}
	return result, nil
}
func (c *sedCommand) selected(number int, last bool, text string) bool {
	match := false
	if !c.ranged {
		match = c.first.matches(number, last, text)
	} else {
		started := false
		if !c.active && c.first.matches(number, last, text) {
			c.active = true
			started = true
		}
		match = c.active
		if c.active && (!started || c.last.re == nil) && c.last.matches(number, last, text) {
			c.active = false
		}
	}
	if c.negate {
		return !match
	}
	return match
}
func sedReplacement(replacement, text string, indices []int) string {
	var b strings.Builder
	group := func(n int) {
		if 2*n+1 < len(indices) && indices[2*n] >= 0 {
			b.WriteString(text[indices[2*n]:indices[2*n+1]])
		}
	}
	for i := 0; i < len(replacement); i++ {
		c := replacement[i]
		if c == '&' {
			group(0)
			continue
		}
		if c == '\\' && i+1 < len(replacement) {
			i++
			c = replacement[i]
			if c >= '1' && c <= '9' {
				group(int(c - '0'))
				continue
			}
			if c == 'n' {
				c = '\n'
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}
func (c *sedCommand) substitute(text string) (string, bool) {
	matches := c.re.FindAllStringSubmatchIndex(text, -1)
	var b strings.Builder
	end := 0
	changed := false
	for n, indices := range matches {
		if c.occurrence > 0 && n+1 < c.occurrence {
			continue
		}
		if changed && !c.global {
			break
		}
		b.WriteString(text[end:indices[0]])
		b.WriteString(sedReplacement(c.replacement, text, indices))
		end = indices[1]
		changed = true
	}
	if !changed {
		return text, false
	}
	b.WriteString(text[end:])
	return b.String(), true
}
func (s *shell) sed(args []string) error {
	quiet, extended := false, false
	var programs []string
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		switch arg {
		case "-n":
			quiet = true
		case "-E", "-r":
			extended = true
		case "-e", "-f":
			if len(args) == 0 {
				return fmt.Errorf("sed: %s requires argument", arg)
			}
			text := args[0]
			args = args[1:]
			if arg == "-f" {
				data, err := s.readFile(text)
				if err != nil {
					return s.diagnostic(err)
				}
				text = string(data)
			}
			programs = append(programs, text)
		default:
			return unsupported("sed option " + arg)
		}
	}
	if len(programs) == 0 {
		if len(args) == 0 {
			return fmt.Errorf("sed: missing program")
		}
		programs = append(programs, args[0])
		args = args[1:]
	}
	parser := sedParser{text: strings.Join(programs, "\n"), extended: extended}
	commands, err := parser.parse()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		args = []string{"-"}
	}
	// Read file operands as one stream; stdin remains a stream so `sed 1q` can
	// terminate an infinite producer without consuming its remaining output.
	readers := []io.Reader{}
	for _, name := range args {
		if name == "-" {
			readers = append(readers, s.input())
			continue
		}
		f, err := s.cfg.FS.Open(s.resolve(name), Read)
		if err != nil {
			return s.diagnostic(err)
		}
		defer f.Close()
		readers = append(readers, f)
	}
	input := bufio.NewReader(io.MultiReader(readers...))
	number := 0
	needsLast := false
	for _, c := range commands {
		needsLast = needsLast || c.first.last || c.last.last
	}
	readPattern := func() (string, bool, bool, error) {
		var data []byte
		for {
			fragment, e := input.ReadSlice(10)
			if len(fragment) > s.cfg.MaxSubstitutionBytes-len(data) {
				return "", false, false, fmt.Errorf("sed: pattern space budget exceeded")
			}
			data = append(data, fragment...)
			if e == bufio.ErrBufferFull {
				continue
			}
			if e != nil && e != io.EOF {
				return "", false, false, e
			}
			break
		}
		terminated := len(data) > 0 && data[len(data)-1] == 10
		text := string(data)
		if terminated {
			text = text[:len(text)-1]
		}
		return text, terminated, len(data) > 0, nil
	}
	isLast := func(terminated bool) (bool, error) {
		if !terminated {
			return true, nil
		}
		if !needsLast {
			return false, nil
		}
		_, e := input.Peek(1)
		if e != nil && e != io.EOF {
			return false, e
		}
		return e == io.EOF, nil
	}
	hold := ""
	for {
		if err := s.tick(); err != nil {
			return err
		}
		text, terminated, ok, e := readPattern()
		if e != nil {
			return e
		}
		if !ok {
			return nil
		}
		number++
		last, e := isLast(terminated)
		if e != nil {
			return e
		}
		print := func(text string) error {
			if terminated {
				text += "\n"
			}
			_, e := io.WriteString(s.output(1), text)
			return e
		}
		deleted, quit := false, false
		var appended strings.Builder
		substituted := false
		for i := 0; i < len(commands); i++ {
			if err := s.tick(); err != nil {
				return err
			}
			c := &commands[i]
			if !c.selected(number, last, text) {
				if c.op == '{' {
					i = c.target
				}
				continue
			}
			switch c.op {
			case '{', '}':
			case 'h':
				hold = text
			case 'H':
				hold += "\n" + text
			case 'g':
				text = hold
			case 'G':
				text += "\n" + hold
			case 'x':
				text, hold = hold, text
			case 'n', 'N':
				if c.op == 'n' && !quiet {
					if err = print(text); err != nil {
						return err
					}
				}
				if _, err = io.WriteString(s.output(1), appended.String()); err != nil {
					return err
				}
				appended.Reset()
				next, term, ok, e := readPattern()
				if e != nil {
					return e
				}
				if !ok {
					if c.op == 'N' && !quiet {
						return print(text)
					}
					return nil
				}
				number++
				terminated = term
				last, e = isLast(terminated)
				if e != nil {
					return e
				}
				substituted = false
				if c.op == 'n' {
					text = next
				} else {
					text += "\n" + next
				}
			case ':':
			case 'b':
				i = c.target - 1
			case 't', 'T':
				branch := substituted
				if c.op == 'T' {
					branch = !branch
				}
				substituted = false
				if branch {
					i = c.target - 1
				}
			case 'y':
				data := []byte(text)
				for i, b := range data {
					data[i] = c.transliteration[b]
				}
				text = string(data)
			case 's':
				var changed bool
				text, changed = c.substitute(text)
				substituted = substituted || changed
				if len(text) > s.cfg.MaxSubstitutionBytes {
					return fmt.Errorf("sed: pattern space budget exceeded")
				}
				if changed && c.print {
					if err = print(text); err != nil {
						return err
					}
				}
			case 'r':
				data, e := s.readFile(c.replacement)
				if e != nil {
					if errorsIsNotExist(e) {
						continue
					}
					return e
				}
				if len(data) > s.cfg.MaxSubstitutionBytes-appended.Len() {
					return fmt.Errorf("sed: append budget exceeded")
				}
				appended.Write(data)
			case 'a':
				appended.WriteString(c.replacement)
			case 'i':
				if _, err = io.WriteString(s.output(1), c.replacement); err != nil {
					return err
				}
			case 'p':
				if err = print(text); err != nil {
					return err
				}
			case 'd':
				deleted = true
			case 'q':
				quit = true
			case '=':
				if _, err = fmt.Fprintln(s.output(1), number); err != nil {
					return err
				}
			}
			if len(text) > s.cfg.MaxSubstitutionBytes || len(hold) > s.cfg.MaxSubstitutionBytes {
				return fmt.Errorf("sed: pattern/hold space budget exceeded")
			}
			if deleted || quit {
				break
			}
		}
		if !quiet && !deleted {
			if err = print(text); err != nil {
				return err
			}
		}
		if _, err = io.WriteString(s.output(1), appended.String()); err != nil {
			return err
		}
		if quit || last {
			return nil
		}
	}
}

// Transliteration is byte-oriented, matching this environment's C locale.
func (p *sedParser) transliterationString(delimiter byte) ([]byte, error) {
	var result []byte
	for p.i < len(p.text) {
		ch := p.text[p.i]
		p.i++
		if ch == delimiter {
			return result, nil
		}
		if ch == '\\' {
			if p.i == len(p.text) {
				break
			}
			ch = p.text[p.i]
			p.i++
			switch ch {
			case 'n':
				ch = '\n'
			case '\\', delimiter:
			default:
				return nil, unsupported("sed transliteration escape")
			}
		}
		result = append(result, ch)
	}
	return nil, fmt.Errorf("sed: unterminated transliteration")
}
