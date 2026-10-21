package shell

import (
	"fmt"
	"mvdan.cc/sh/v3/syntax"
	"strconv"
	"strings"
)

// Arithmetic expansion first expands shell words, then parses the resulting
// expression. Parsing each word as a decimal integer silently turns "$*" such
// as "10 + 1" into zero and loses operator precedence across expansions.
func (s *shell) arithmetic(expr syntax.ArithmExpr) (int64, error) {
	if s.depth >= s.cfg.MaxDepth {
		return 0, fmt.Errorf("shell: arithmetic nesting budget exceeded")
	}
	s.depth++
	defer func() { s.depth-- }()
	var text strings.Builder
	if err := s.arithmeticText(&text, expr); err != nil {
		return 0, err
	}
	if text.Len() > s.cfg.MaxSubstitutionBytes {
		return 0, fmt.Errorf("shell: arithmetic input budget exceeded")
	}
	return s.arithmeticString(text.String(), 0)
}
func (s *shell) arithmeticText(out *strings.Builder, expr syntax.ArithmExpr) error {
	switch e := expr.(type) {
	case *syntax.Word:
		v, err := s.literal(e)
		if err != nil {
			return err
		}
		out.WriteString(v)
	case *syntax.ParenArithm:
		out.WriteByte('(')
		if err := s.arithmeticText(out, e.X); err != nil {
			return err
		}
		out.WriteByte(')')
	case *syntax.UnaryArithm:
		if !e.Post {
			out.WriteString(e.Op.String())
			out.WriteByte(' ')
		}
		if err := s.arithmeticText(out, e.X); err != nil {
			return err
		}
		if e.Post {
			out.WriteString(e.Op.String())
		}
	case *syntax.BinaryArithm:
		if err := s.arithmeticText(out, e.X); err != nil {
			return err
		}
		out.WriteByte(' ')
		out.WriteString(e.Op.String())
		out.WriteByte(' ')
		return s.arithmeticText(out, e.Y)
	default:
		return unsupported(fmt.Sprintf("arithmetic %T", expr))
	}
	return nil
}
func (s *shell) arithmeticString(text string, depth int) (int64, error) {
	if depth >= s.cfg.MaxDepth {
		return 0, fmt.Errorf("shell: arithmetic variable recursion budget exceeded")
	}
	if strings.TrimSpace(text) == "" {
		return 0, nil
	}
	expr, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Arithmetic(strings.NewReader(text))
	if err != nil {
		return 0, err
	}
	return s.arithmeticValue(expr, depth+1)
}
func (s *shell) arithmeticValue(expr syntax.ArithmExpr, depth int) (int64, error) {
	if err := s.tick(); err != nil {
		return 0, err
	}
	truth := func(b bool) int64 {
		if b {
			return 1
		}
		return 0
	}
	switch e := expr.(type) {
	case *syntax.Word:
		name := e.Lit()
		if validName(name) {
			v := s.Get(name)
			if !v.IsSet() && s.nounset {
				return 0, fmt.Errorf("shell: %s is unset", name)
			}
			return s.arithmeticString(v.String(), depth)
		}
		if name == "" {
			return 0, fmt.Errorf("shell: invalid arithmetic operand")
		}
		value, err := strconv.ParseInt(name, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("shell: invalid arithmetic integer %q", name)
		}
		return value, nil
	case *syntax.ParenArithm:
		return s.arithmeticValue(e.X, depth)
	case *syntax.UnaryArithm:
		if e.Op == syntax.Inc || e.Op == syntax.Dec {
			w, ok := e.X.(*syntax.Word)
			if !ok || !validName(w.Lit()) {
				return 0, fmt.Errorf("shell: invalid arithmetic assignment")
			}
			old, err := s.arithmeticValue(e.X, depth)
			if err != nil {
				return 0, err
			}
			value := old + 1
			if e.Op == syntax.Dec {
				value = old - 1
			}
			if err := s.set(w.Lit(), strconv.FormatInt(value, 10)); err != nil {
				return 0, err
			}
			if e.Post {
				return old, nil
			}
			return value, nil
		}
		v, err := s.arithmeticValue(e.X, depth)
		if err != nil {
			return 0, err
		}
		switch e.Op {
		case syntax.Plus:
			return v, nil
		case syntax.Minus:
			return -v, nil
		case syntax.Not:
			return truth(v == 0), nil
		case syntax.BitNegation:
			return ^v, nil
		}
	case *syntax.BinaryArithm:
		if e.Op == syntax.TernQuest {
			cond, err := s.arithmeticValue(e.X, depth)
			if err != nil {
				return 0, err
			}
			branches := e.Y.(*syntax.BinaryArithm)
			if cond != 0 {
				return s.arithmeticValue(branches.X, depth)
			}
			return s.arithmeticValue(branches.Y, depth)
		}
		assignments := map[syntax.BinAritOperator]syntax.BinAritOperator{syntax.Assgn: syntax.Assgn, syntax.AddAssgn: syntax.Add, syntax.SubAssgn: syntax.Sub, syntax.MulAssgn: syntax.Mul, syntax.QuoAssgn: syntax.Quo, syntax.RemAssgn: syntax.Rem, syntax.AndAssgn: syntax.And, syntax.OrAssgn: syntax.Or, syntax.XorAssgn: syntax.Xor, syntax.ShlAssgn: syntax.Shl, syntax.ShrAssgn: syntax.Shr}
		op, assign := assignments[e.Op]
		if !assign {
			op = e.Op
		}
		var left int64
		var err error
		if op != syntax.Assgn {
			left, err = s.arithmeticValue(e.X, depth)
			if err != nil {
				return 0, err
			}
		}
		if op == syntax.AndArit && left == 0 {
			return 0, nil
		}
		if op == syntax.OrArit && left != 0 {
			return 1, nil
		}
		right, err := s.arithmeticValue(e.Y, depth)
		if err != nil {
			return 0, err
		}
		var value int64
		switch op {
		case syntax.Assgn, syntax.Comma:
			value = right
		case syntax.Add:
			value = left + right
		case syntax.Sub:
			value = left - right
		case syntax.Mul:
			value = left * right
		case syntax.Quo, syntax.Rem:
			if right == 0 {
				return 0, fmt.Errorf("shell: arithmetic division by zero")
			}
			if op == syntax.Quo {
				value = left / right
			} else {
				value = left % right
			}
		case syntax.And:
			value = left & right
		case syntax.Or:
			value = left | right
		case syntax.Xor:
			value = left ^ right
		case syntax.Shl, syntax.Shr:
			if right < 0 || right >= 64 {
				return 0, fmt.Errorf("shell: invalid arithmetic shift")
			}
			if op == syntax.Shl {
				value = left << uint(right)
			} else {
				value = left >> uint(right)
			}
		case syntax.Eql:
			value = truth(left == right)
		case syntax.Neq:
			value = truth(left != right)
		case syntax.Gtr:
			value = truth(left > right)
		case syntax.Geq:
			value = truth(left >= right)
		case syntax.Lss:
			value = truth(left < right)
		case syntax.Leq:
			value = truth(left <= right)
		case syntax.AndArit:
			value = truth(left != 0 && right != 0)
		case syntax.OrArit:
			value = truth(left != 0 || right != 0)
		default:
			return 0, unsupported("arithmetic operator " + op.String())
		}
		if assign {
			w, ok := e.X.(*syntax.Word)
			if !ok || !validName(w.Lit()) {
				return 0, fmt.Errorf("shell: invalid arithmetic assignment")
			}
			if err := s.set(w.Lit(), strconv.FormatInt(value, 10)); err != nil {
				return 0, err
			}
		}
		return value, nil
	}
	return 0, unsupported(fmt.Sprintf("arithmetic %T", expr))
}
