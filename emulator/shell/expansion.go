package shell

import (
	"fmt"
	"io"
	"strconv"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Adapt arithmetic through expand's lazy substitution callback. This preserves
// parameter-default laziness and quoting without mutating shared parsed trees.
// Arithmetic runs in the current shell and does not affect substitution status.
func (s *shell) expansionWords(words []*syntax.Word) (*expand.Config, []*syntax.Word) {
	cfg := s.expansion()
	lazy := &lazyExpansionEnv{shell: s, values: map[string]func() (string, error){}}
	cfg.Env = lazy
	arithmetic := make(map[*syntax.CmdSubst]syntax.ArithmExpr)
	var word func(*syntax.Word) *syntax.Word
	var parts func([]syntax.WordPart) []syntax.WordPart
	parts = func(input []syntax.WordPart) []syntax.WordPart {
		output := make([]syntax.WordPart, len(input))
		for i, part := range input {
			output[i] = part
			switch p := part.(type) {
			case *syntax.ArithmExp:
				placeholder := &syntax.CmdSubst{Left: p.Left, Right: p.Right}
				arithmetic[placeholder] = p.X
				output[i] = placeholder
			case *syntax.DblQuoted:
				copy := *p
				copy.Parts = parts(p.Parts)
				output[i] = &copy
			case *syntax.ParamExp:
				copy := *p
				if p.Exp != nil {
					e := *p.Exp
					switch e.Op {
					case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AlternateUnset, syntax.AlternateUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull, syntax.ErrorUnset, syntax.ErrorUnsetOrNull:
						original := p
						key := "\x00shell.lazy." + strconv.Itoa(len(lazy.values))
						lazy.values[key] = func() (string, error) {
							value := s.Get(original.Param.Value)
							if original.Param.Value == "LINENO" {
								value = expand.Variable{Set: true, Kind: expand.String, Str: strconv.FormatUint(uint64(original.Pos().Line()), 10)}
							}
							set := value.IsSet()
							switch original.Exp.Op {
							case syntax.DefaultUnsetOrNull, syntax.AlternateUnsetOrNull, syntax.AssignUnsetOrNull, syntax.ErrorUnsetOrNull:
								set = set && value.String() != ""
							}
							alternate := original.Exp.Op == syntax.AlternateUnset || original.Exp.Op == syntax.AlternateUnsetOrNull
							if set != alternate {
								return "", nil
							}
							return s.literal(original.Exp.Word)
						}
						e.Word = &syntax.Word{Parts: []syntax.WordPart{&syntax.ParamExp{Param: &syntax.Lit{Value: key}}}}
					default:
						e.Word = word(e.Word)
					}
					copy.Exp = &e
				}
				output[i] = &copy
			}
		}
		return output
	}
	word = func(w *syntax.Word) *syntax.Word {
		if w == nil {
			return nil
		}
		return &syntax.Word{Parts: parts(w.Parts)}
	}
	result := make([]*syntax.Word, len(words))
	for i, w := range words {
		result[i] = word(w)
	}
	command := cfg.CmdSubst
	cfg.CmdSubst = func(out io.Writer, node *syntax.CmdSubst) error {
		if expr, ok := arithmetic[node]; ok {
			value, err := s.arithmetic(expr)
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(out, value)
			return err
		}
		return command(out, node)
	}
	return cfg, result
}
func (s *shell) fields(words ...*syntax.Word) ([]string, error) {
	cfg, w := s.expansionWords(words)
	value, err := expand.Fields(cfg, w...)
	if err == nil {
		err = cfg.Env.(*lazyExpansionEnv).err
	}
	return value, err
}
func (s *shell) literal(word *syntax.Word) (string, error) {
	cfg, w := s.expansionWords([]*syntax.Word{word})
	value, err := expand.Literal(cfg, w[0])
	if err == nil {
		err = cfg.Env.(*lazyExpansionEnv).err
	}
	return value, err
}
func (s *shell) pattern(word *syntax.Word) (string, error) {
	cfg, w := s.expansionWords([]*syntax.Word{word})
	value, err := expand.Pattern(cfg, w[0])
	if err == nil {
		err = cfg.Env.(*lazyExpansionEnv).err
	}
	return value, err
}
func (s *shell) document(word *syntax.Word) (string, error) {
	cfg, w := s.expansionWords([]*syntax.Word{word})
	value, err := expand.Document(cfg, w[0])
	if err == nil {
		err = cfg.Env.(*lazyExpansionEnv).err
	}
	return value, err
}

// expand eagerly reads the default/alternate word. A private parameter defers
// that read until the enclosing variable is known, preserving literal newlines
// (unlike a command substitution). Names contain NUL and cannot name user vars.
type lazyExpansionEnv struct {
	*shell
	values map[string]func() (string, error)
	err    error
}

func (e *lazyExpansionEnv) Get(name string) expand.Variable {
	if fn, ok := e.values[name]; ok {
		var value string
		if e.err == nil {
			value, e.err = fn()
		}
		return expand.Variable{Set: true, Kind: expand.String, Str: value}
	}
	return e.shell.Get(name)
}
