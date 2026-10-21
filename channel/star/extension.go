package star

import (
	"bufio"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	channelpkg "github.com/tinyrange/trex/channel"
	"go.starlark.net/starlark"
)

// Extension is a synchronous v1 protocol session over a portable byte channel.
// The caller must give it exclusive use of the transport.
type Extension struct {
	transport *Value
	reader    *bufio.Reader
	timeout   time.Duration
	limit     int
	functions map[string]*extensionFunction
	manifest  string
	mu        sync.Mutex
	closed    bool
}
type extensionFunction struct {
	name, result, doc string
	args, types       []string
}

var extensionName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
var extensionInteger = regexp.MustCompile(`^-?[0-9]+$`)
var extensionFloat = regexp.MustCompile(`^-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
var extensionCount = regexp.MustCompile(`^[0-9]+$`)

const extensionReserved = " and as assert async await break class continue def del elif else except finally for from global if import in is lambda load nonlocal not or pass raise return try while with yield True False None "

func validExtensionName(s string) bool {
	return extensionName.MatchString(s) && !strings.Contains(extensionReserved, " "+s+" ")
}
func extensionType(t string) bool {
	return strings.Contains(" any none bool int float str array map ", " "+t+" ") && t != "" && !strings.ContainsAny(t, " \t")
}
func matchesExtensionType(v starlark.Value, t string) bool {
	switch t {
	case "any":
		return true
	case "none":
		return v == starlark.None
	case "str":
		_, ok := v.(starlark.String)
		return ok
	case "array":
		switch v.(type) {
		case *starlark.List, starlark.Tuple:
			return true
		}
		return false
	case "map":
		_, ok := v.(*starlark.Dict)
		return ok
	default:
		return v.Type() == t
	}
}
func extensionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var c *Value
	timeout := starlarkNumber(5)
	if err := starlark.UnpackArgs("channel.extension", args, kwargs, "channel", &c, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > 300 {
		return nil, fmt.Errorf("extension: timeout must be in (0,300] seconds")
	}
	e := &Extension{transport: c, reader: bufio.NewReaderSize(c, 65538), timeout: time.Duration(float64(timeout) * float64(time.Second)), functions: make(map[string]*extensionFunction)}
	if err := e.discover(); err != nil {
		e.close()
		return nil, fmt.Errorf("extension discovery: %w", err)
	}
	return e, nil
}
func (e *Extension) close()          { e.closed = true; _ = e.transport.Close() }
func (e *Extension) deadline() error { return e.transport.SetDeadline(time.Now().Add(e.timeout)) }
func (e *Extension) line() (string, error) {
	b, err := e.reader.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(b)-1 > 65536 {
		return "", fmt.Errorf("extension line exceeds 64 KiB")
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("invalid UTF-8")
	}
	for _, c := range s {
		if (c < 32 && c != '\t') || c == 127 {
			return "", fmt.Errorf("unescaped control")
		}
	}
	return s, nil
}
func (e *Extension) discover() error {
	if err := e.deadline(); err != nil {
		return err
	}
	defer e.transport.SetDeadline(time.Time{})
	if err := channelpkg.WriteAll(e.transport, []byte("?\n")); err != nil {
		return err
	}
	line, err := e.line()
	if err != nil {
		return err
	}
	parts := strings.Split(line, "\t")
	if len(parts) != 3 || parts[0] != "API" || parts[1] != "1" || !extensionCount.MatchString(parts[2]) {
		return fmt.Errorf("expected synchronous API v1 header")
	}
	limit, err := strconv.Atoi(parts[2])
	if err != nil || limit < 32 || limit > 1048576 {
		return fmt.Errorf("invalid device receive limit")
	}
	e.limit = limit
	var manifest strings.Builder
	manifest.WriteString(line + "\n")
	var current *extensionFunction
	about := false
	for manifest.Len() < 1<<20 {
		line, err = e.line()
		if err != nil {
			return err
		}
		manifest.WriteString(line + "\n")
		if manifest.Len() > 1<<20 {
			return fmt.Errorf("manifest exceeds 1 MiB")
		}
		p := strings.Split(line, "\t")
		switch p[0] {
		case "ABOUT":
			if len(p) != 2 || about || current != nil || len(e.functions) > 0 {
				return fmt.Errorf("invalid ABOUT")
			}
			if _, err = decodeExtensionString(p[1]); err != nil {
				return err
			}
			about = true
		case "FN":
			if len(p) != 4 || current != nil || len(e.functions) >= 256 || !validExtensionName(p[1]) || p[1] == "close" || !extensionType(p[2]) || e.functions[p[1]] != nil {
				return fmt.Errorf("invalid FN")
			}
			doc, err := decodeExtensionString(p[3])
			if err != nil {
				return err
			}
			current = &extensionFunction{name: p[1], result: p[2], doc: doc}
		case "ARG":
			if len(p) != 4 || current == nil || len(current.args) >= 64 || !validExtensionName(p[1]) || !extensionType(p[2]) {
				return fmt.Errorf("invalid ARG")
			}
			for _, n := range current.args {
				if n == p[1] {
					return fmt.Errorf("duplicate ARG")
				}
			}
			if _, err = decodeExtensionString(p[3]); err != nil {
				return err
			}
			current.args = append(current.args, p[1])
			current.types = append(current.types, p[2])
		case "END":
			if len(p) != 1 || current == nil {
				return fmt.Errorf("invalid END")
			}
			e.functions[current.name] = current
			current = nil
		case "DONE":
			if len(p) != 1 || current != nil {
				return fmt.Errorf("invalid DONE")
			}
			e.manifest = manifest.String()
			return nil
		default:
			return fmt.Errorf("invalid manifest line")
		}
	}
	return fmt.Errorf("manifest exceeds 1 MiB")
}
func decodeExtensionString(s string) (string, error) {
	if len(s) == 0 || s[0] != 's' {
		return "", fmt.Errorf("expected string token")
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			i++
			if i == len(s) {
				return "", fmt.Errorf("incomplete escape")
			}
			switch s[i] {
			case '\\':
				c = '\\'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			default:
				return "", fmt.Errorf("unknown escape")
			}
		} else if c < 32 || c == 127 {
			return "", fmt.Errorf("unescaped control")
		}
		b.WriteByte(c)
	}
	if !utf8.ValidString(b.String()) {
		return "", fmt.Errorf("invalid UTF-8")
	}
	return b.String(), nil
}
func encodeExtensionValue(v starlark.Value, depth int) (string, error) {
	if depth > 32 {
		return "", fmt.Errorf("value nesting exceeds 32")
	}
	switch v := v.(type) {
	case starlark.NoneType:
		return "n", nil
	case starlark.Bool:
		if v {
			return "b1", nil
		}
		return "b0", nil
	case starlark.Int:
		return "i" + v.String(), nil
	case starlark.Float:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return "", fmt.Errorf("nonfinite float")
		}
		return "f" + strconv.FormatFloat(float64(v), 'g', -1, 64), nil
	case starlark.String:
		s := string(v)
		if !utf8.ValidString(s) {
			return "", fmt.Errorf("invalid UTF-8")
		}
		for _, c := range s {
			if (c < 32 && c != '\t' && c != '\r' && c != '\n') || c == 127 {
				return "", fmt.Errorf("unsupported control")
			}
		}
		return "s" + strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r").Replace(s), nil
	case *starlark.Dict:
		if v.Len() > 65536 {
			return "", fmt.Errorf("map too large")
		}
		parts := []string{"m" + strconv.Itoa(v.Len())}
		for _, item := range v.Items() {
			if _, ok := item[0].(starlark.String); !ok {
				return "", fmt.Errorf("map key must be string")
			}
			for _, x := range item {
				p, err := encodeExtensionValue(x, depth+1)
				if err != nil {
					return "", err
				}
				parts = append(parts, p)
			}
		}
		return joinExtension(parts)
	case *starlark.List:
		return encodeExtensionArray(v, depth)
	case starlark.Tuple:
		return encodeExtensionArray(v, depth)
	default:
		return "", fmt.Errorf("unsupported extension value %s", v.Type())
	}
}
func joinExtension(parts []string) (string, error) {
	s := strings.Join(parts, "\t")
	if len(s) > 1<<20 {
		return "", fmt.Errorf("encoded value exceeds 1 MiB")
	}
	return s, nil
}
func encodeExtensionArray(v starlark.Indexable, depth int) (string, error) {
	if v.Len() > 65536 {
		return "", fmt.Errorf("array too large")
	}
	parts := []string{"a" + strconv.Itoa(v.Len())}
	for i := 0; i < v.Len(); i++ {
		s, err := encodeExtensionValue(v.Index(i), depth+1)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	return joinExtension(parts)
}
func decodeExtensionValue(p *[]string, depth int) (starlark.Value, error) {
	if depth > 32 || len(*p) == 0 {
		return nil, fmt.Errorf("incomplete or deeply nested value")
	}
	s := (*p)[0]
	*p = (*p)[1:]
	if s == "" {
		return nil, fmt.Errorf("empty value token")
	}
	switch s[0] {
	case 'n':
		if s == "n" {
			return starlark.None, nil
		}
	case 'b':
		if s == "b0" {
			return starlark.False, nil
		}
		if s == "b1" {
			return starlark.True, nil
		}
	case 's':
		v, err := decodeExtensionString(s)
		return starlark.String(v), err
	case 'i':
		if extensionInteger.MatchString(s[1:]) {
			if n, ok := new(big.Int).SetString(s[1:], 10); ok {
				return starlark.MakeBigInt(n), nil
			}
		}
	case 'f':
		if extensionFloat.MatchString(s[1:]) {
			n, err := strconv.ParseFloat(s[1:], 64)
			if err == nil && !math.IsInf(n, 0) && !math.IsNaN(n) {
				return starlark.Float(n), nil
			}
		}
	case 'a', 'm':
		if !extensionCount.MatchString(s[1:]) {
			break
		}
		n, err := strconv.Atoi(s[1:])
		if err != nil || n > len(*p) {
			break
		}
		if s[0] == 'a' {
			items := make([]starlark.Value, 0, n)
			for i := 0; i < n; i++ {
				v, err := decodeExtensionValue(p, depth+1)
				if err != nil {
					return nil, err
				}
				items = append(items, v)
			}
			return starlark.NewList(items), nil
		}
		d := starlark.NewDict(n)
		for i := 0; i < n; i++ {
			k, err := decodeExtensionValue(p, depth+1)
			if err != nil {
				return nil, err
			}
			if _, ok := k.(starlark.String); !ok {
				return nil, fmt.Errorf("non-string map key")
			}
			if _, found, _ := d.Get(k); found {
				return nil, fmt.Errorf("duplicate map key")
			}
			v, err := decodeExtensionValue(p, depth+1)
			if err != nil {
				return nil, err
			}
			if err = d.SetKey(k, v); err != nil {
				return nil, err
			}
		}
		return d, nil
	}
	return nil, fmt.Errorf("invalid value token")
}
func (e *Extension) String() string        { return "<extension v1>" }
func (e *Extension) Type() string          { return "extension" }
func (e *Extension) Freeze()               {}
func (e *Extension) Truth() starlark.Bool  { return starlark.True }
func (e *Extension) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable extension") }
func (e *Extension) AttrNames() []string {
	names := []string{"close"}
	for n := range e.functions {
		names = append(names, n)
	}
	return names
}
func (e *Extension) Attr(name string) (starlark.Value, error) {
	if name == "close" {
		return starlark.NewBuiltin("extension.close", func(_ *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("close", a, k); err != nil {
				return nil, err
			}
			e.mu.Lock()
			defer e.mu.Unlock()
			e.close()
			return starlark.None, nil
		}), nil
	}
	f := e.functions[name]
	if f == nil {
		return nil, nil
	}
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
		return e.call(f, a, k)
	}), nil
}
func (e *Extension) call(f *extensionFunction, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
	values := make([]starlark.Value, len(f.args))
	unpack := make([]any, 0, 2*len(values))
	for i, n := range f.args {
		unpack = append(unpack, n, &values[i])
	}
	if err := starlark.UnpackArgs(f.name, a, k, unpack...); err != nil {
		return nil, err
	}
	parts := []string{"CALL", f.name}
	for i, v := range values {
		if !matchesExtensionType(v, f.types[i]) {
			return nil, fmt.Errorf("%s: %s requires %s", f.name, f.args[i], f.types[i])
		}
		s, err := encodeExtensionValue(v, 0)
		if err != nil {
			return nil, err
		}
		parts = append(parts, s)
	}
	line := strings.Join(parts, "\t")
	if len(line) > e.limit {
		return nil, fmt.Errorf("call exceeds device receive limit %d", e.limit)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, fmt.Errorf("extension is closed; never replay uncertain calls")
	}
	uncertain := func(err error) (starlark.Value, error) {
		e.close()
		return nil, fmt.Errorf("extension closed; outcome uncertain, do not replay: %w", err)
	}
	if err := e.deadline(); err != nil {
		return uncertain(err)
	}
	defer e.transport.SetDeadline(time.Time{})
	if err := channelpkg.WriteAll(e.transport, []byte(line+"\n")); err != nil {
		return uncertain(err)
	}
	reply, err := e.line()
	if err != nil {
		return uncertain(err)
	}
	p := strings.Split(reply, "\t")
	if p[0] == "ERR" && len(p) == 3 {
		code, err := decodeExtensionString(p[1])
		if err != nil {
			return uncertain(err)
		}
		message, err := decodeExtensionString(p[2])
		if err != nil {
			return uncertain(err)
		}
		return nil, fmt.Errorf("device %s: %s", code, message)
	}
	if p[0] != "OK" {
		return uncertain(fmt.Errorf("expected OK or ERR"))
	}
	p = p[1:]
	v, err := decodeExtensionValue(&p, 0)
	if err != nil {
		return uncertain(err)
	}
	if len(p) != 0 || !matchesExtensionType(v, f.result) {
		return uncertain(fmt.Errorf("invalid reply shape or result type"))
	}
	return v, nil
}

func (e *Extension) Documentation() string {
	return "Synchronous extension v1. Discovered wire manifest:\n" + e.manifest + "\nCall discovered methods; close() closes the transport. Never retry uncertain calls.\n"
}
