package windows

import (
	"bytes"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

// MOF is the declarative schema language consumed by WMI and CIM
// repositories.  Parsing is deliberately independent of repository policy:
// callers decide which sources belong in each namespace and in which order.

type mofPosition struct {
	Line   int
	Column int
}

type mofTokenKind uint8

const (
	mofTokenEOF mofTokenKind = iota
	mofTokenIdentifier
	mofTokenAlias
	mofTokenString
	mofTokenInteger
	mofTokenReal
	mofTokenPunctuation
)

type mofToken struct {
	Kind     mofTokenKind
	Text     string
	Position mofPosition
}

type mofLexer struct {
	source []byte
	offset int
	line   int
	column int
}

func newMOFLexer(source string) *mofLexer {
	return &mofLexer{source: []byte(source), line: 1, column: 1}
}

func (l *mofLexer) position() mofPosition { return mofPosition{Line: l.line, Column: l.column} }

func (l *mofLexer) peek() rune {
	if l.offset >= len(l.source) {
		return 0
	}
	r, _ := utf8.DecodeRune(l.source[l.offset:])
	return r
}

func (l *mofLexer) advance() rune {
	if l.offset >= len(l.source) {
		return 0
	}
	r, size := utf8.DecodeRune(l.source[l.offset:])
	l.offset += size
	if r == '\n' {
		l.line++
		l.column = 1
	} else {
		l.column++
	}
	return r
}

func (l *mofLexer) skipSpaceAndComments() error {
	for {
		for unicode.IsSpace(l.peek()) {
			l.advance()
		}
		if l.peek() != '/' || l.offset+1 >= len(l.source) {
			return nil
		}
		next := l.source[l.offset+1]
		switch next {
		case '/':
			for l.peek() != 0 && l.peek() != '\n' {
				l.advance()
			}
		case '*':
			start := l.position()
			l.advance()
			l.advance()
			for {
				if l.peek() == 0 {
					return fmt.Errorf("%d:%d: unterminated block comment", start.Line, start.Column)
				}
				if l.peek() == '*' && l.offset+1 < len(l.source) && l.source[l.offset+1] == '/' {
					l.advance()
					l.advance()
					break
				}
				l.advance()
			}
		default:
			return nil
		}
	}
}

func isMOFIdentifierStart(r rune) bool { return r == '_' || unicode.IsLetter(r) }
func isMOFIdentifierPart(r rune) bool  { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

func (l *mofLexer) next() (mofToken, error) {
	if err := l.skipSpaceAndComments(); err != nil {
		return mofToken{}, err
	}
	position := l.position()
	r := l.peek()
	if r == 0 {
		return mofToken{Kind: mofTokenEOF, Position: position}, nil
	}
	if isMOFIdentifierStart(r) {
		start := l.offset
		for isMOFIdentifierPart(l.peek()) {
			l.advance()
		}
		return mofToken{Kind: mofTokenIdentifier, Text: string(l.source[start:l.offset]), Position: position}, nil
	}
	if r == '$' {
		l.advance()
		start := l.offset
		if !isMOFIdentifierStart(l.peek()) {
			return mofToken{}, fmt.Errorf("%d:%d: expected alias name after $", position.Line, position.Column)
		}
		for isMOFIdentifierPart(l.peek()) {
			l.advance()
		}
		return mofToken{Kind: mofTokenAlias, Text: string(l.source[start:l.offset]), Position: position}, nil
	}
	if r == '"' || r == '\'' {
		quote := l.advance()
		var value strings.Builder
		for {
			r = l.advance()
			if r == 0 || r == '\n' || r == '\r' {
				return mofToken{}, fmt.Errorf("%d:%d: unterminated string literal", position.Line, position.Column)
			}
			if r == quote {
				break
			}
			if r != '\\' {
				value.WriteRune(r)
				continue
			}
			escapePosition := l.position()
			r = l.advance()
			switch r {
			case 'b':
				value.WriteByte('\b')
			case 't':
				value.WriteByte('\t')
			case 'n':
				value.WriteByte('\n')
			case 'f':
				value.WriteByte('\f')
			case 'r':
				value.WriteByte('\r')
			case '\\', '"', '\'':
				value.WriteRune(r)
			case 'x', 'X':
				digits := make([]byte, 0, 4)
				for len(digits) < 4 {
					n := l.peek()
					if !((n >= '0' && n <= '9') || (n >= 'a' && n <= 'f') || (n >= 'A' && n <= 'F')) {
						break
					}
					digits = append(digits, byte(l.advance()))
				}
				if len(digits) == 0 {
					return mofToken{}, fmt.Errorf("%d:%d: hexadecimal escape has no digits", escapePosition.Line, escapePosition.Column)
				}
				decoded, _ := strconv.ParseUint(string(digits), 16, 16)
				value.WriteRune(rune(decoded))
			case 0:
				return mofToken{}, fmt.Errorf("%d:%d: unterminated escape", escapePosition.Line, escapePosition.Column)
			default:
				// MOF sources in the NT media also use a backslash to quote
				// punctuation. Preserve the quoted character.
				value.WriteRune(r)
			}
		}
		return mofToken{Kind: mofTokenString, Text: value.String(), Position: position}, nil
	}
	if unicode.IsDigit(r) || (r == '.' && l.offset+1 < len(l.source) && l.source[l.offset+1] >= '0' && l.source[l.offset+1] <= '9') {
		start := l.offset
		kind := mofTokenInteger
		if r == '0' && l.offset+1 < len(l.source) && (l.source[l.offset+1] == 'x' || l.source[l.offset+1] == 'X') {
			l.advance()
			l.advance()
			for {
				n := l.peek()
				if !unicode.IsDigit(n) && !(n >= 'a' && n <= 'f') && !(n >= 'A' && n <= 'F') {
					break
				}
				l.advance()
			}
		} else {
			for unicode.IsDigit(l.peek()) {
				l.advance()
			}
			if l.peek() == '.' {
				kind = mofTokenReal
				l.advance()
				for unicode.IsDigit(l.peek()) {
					l.advance()
				}
			}
			if l.peek() == 'e' || l.peek() == 'E' {
				kind = mofTokenReal
				l.advance()
				if l.peek() == '+' || l.peek() == '-' {
					l.advance()
				}
				for unicode.IsDigit(l.peek()) {
					l.advance()
				}
			}
		}
		return mofToken{Kind: kind, Text: string(l.source[start:l.offset]), Position: position}, nil
	}
	if strings.ContainsRune("#[]{}():;,=+-", r) {
		l.advance()
		return mofToken{Kind: mofTokenPunctuation, Text: string(r), Position: position}, nil
	}
	return mofToken{}, fmt.Errorf("%d:%d: unexpected character %q", position.Line, position.Column, r)
}

type mofValueKind string

const (
	mofValueNull       mofValueKind = "null"
	mofValueBool       mofValueKind = "bool"
	mofValueInteger    mofValueKind = "integer"
	mofValueReal       mofValueKind = "real"
	mofValueString     mofValueKind = "string"
	mofValueIdentifier mofValueKind = "identifier"
	mofValueAlias      mofValueKind = "alias"
	mofValueArray      mofValueKind = "array"
	mofValueInstance   mofValueKind = "instance"
)

type mofValue struct {
	Kind     mofValueKind
	Text     string
	Bool     bool
	Integer  int64
	Unsigned uint64
	Negative bool
	Real     float64
	Items    []mofValue
	Instance *mofInstance
	Position mofPosition
}

type mofQualifier struct {
	Name            string
	Values          []mofValue
	Flavors         []string
	DeclaredType    *mofType
	DeclaredFlavors []string
	Position        mofPosition
}

type mofType struct {
	Name      string
	Reference string
	Array     bool
	ArraySize int64
}

type mofParameter struct {
	Name       string
	Type       mofType
	Qualifiers []mofQualifier
	Default    *mofValue
	Position   mofPosition
}

type mofFeature struct {
	Kind       string
	Name       string
	Type       mofType
	Qualifiers []mofQualifier
	Value      *mofValue
	Parameters []mofParameter
	Position   mofPosition
}

type mofClass struct {
	Name       string
	Super      string
	Alias      string
	Namespace  string
	Qualifiers []mofQualifier
	Features   []mofFeature
	Position   mofPosition
}

type mofPropertyAssignment struct {
	Name       string
	Value      mofValue
	Qualifiers []mofQualifier
	Position   mofPosition
}

type mofInstance struct {
	Class      string
	Alias      string
	Namespace  string
	Qualifiers []mofQualifier
	Properties []mofPropertyAssignment
	Position   mofPosition
}

type mofQualifierDeclaration struct {
	Name      string
	Namespace string
	Type      mofType
	Default   *mofValue
	Scopes    []string
	Flavors   []string
	Position  mofPosition
}

type mofPragma struct {
	Name      string
	Namespace string
	Values    []mofValue
	Position  mofPosition
}

type mofDocumentItem struct {
	Kind      string
	Namespace string
	Index     int
	Position  mofPosition
}

type mofDocument struct {
	Pragmas    []mofPragma
	Qualifiers []mofQualifierDeclaration
	Classes    []mofClass
	Instances  []mofInstance
	Items      []mofDocumentItem
}

type mofParser struct {
	lexer   *mofLexer
	current mofToken
	ready   bool
}

func (p *mofParser) peek() (mofToken, error) {
	if !p.ready {
		token, err := p.lexer.next()
		if err != nil {
			return mofToken{}, err
		}
		p.current, p.ready = token, true
	}
	return p.current, nil
}

func (p *mofParser) take() (mofToken, error) {
	token, err := p.peek()
	p.ready = false
	return token, err
}

func mofTokenIs(token mofToken, value string) bool { return strings.EqualFold(token.Text, value) }

func (p *mofParser) accept(value string) (bool, error) {
	token, err := p.peek()
	if err != nil || !mofTokenIs(token, value) {
		return false, err
	}
	p.ready = false
	return true, nil
}

func (p *mofParser) expect(value string) (mofToken, error) {
	token, err := p.take()
	if err != nil {
		return mofToken{}, err
	}
	if !mofTokenIs(token, value) {
		return mofToken{}, fmt.Errorf("%d:%d: got %q, expected %q", token.Position.Line, token.Position.Column, token.Text, value)
	}
	return token, nil
}

func (p *mofParser) identifier(description string) (mofToken, error) {
	token, err := p.take()
	if err != nil {
		return mofToken{}, err
	}
	if token.Kind != mofTokenIdentifier {
		return mofToken{}, fmt.Errorf("%d:%d: got %q, expected %s", token.Position.Line, token.Position.Column, token.Text, description)
	}
	return token, nil
}

func (p *mofParser) parseValue() (mofValue, error) {
	token, err := p.take()
	if err != nil {
		return mofValue{}, err
	}
	value := mofValue{Text: token.Text, Position: token.Position}
	if token.Text == "-" || token.Text == "+" {
		next, err := p.take()
		if err != nil {
			return mofValue{}, err
		}
		if next.Kind != mofTokenInteger && next.Kind != mofTokenReal {
			return mofValue{}, fmt.Errorf("%d:%d: sign must precede a number", token.Position.Line, token.Position.Column)
		}
		value.Text = token.Text + next.Text
		value.Position = token.Position
		token = next
	}
	switch token.Kind {
	case mofTokenString:
		value.Kind = mofValueString
		// Adjacent strings are concatenated by the MOF grammar.
		for {
			next, err := p.peek()
			if err != nil || next.Kind != mofTokenString {
				return value, err
			}
			p.ready = false
			value.Text += next.Text
		}
	case mofTokenAlias:
		value.Kind = mofValueAlias
		return value, nil
	case mofTokenInteger:
		value.Kind = mofValueInteger
		negative := strings.HasPrefix(value.Text, "-")
		digits := strings.TrimPrefix(strings.TrimPrefix(value.Text, "+"), "-")
		base := 10
		if strings.HasPrefix(strings.ToLower(digits), "0x") {
			base, digits = 16, digits[2:]
		}
		unsigned, parseErr := strconv.ParseUint(digits, base, 64)
		if parseErr != nil {
			return mofValue{}, fmt.Errorf("%d:%d: invalid integer %q", value.Position.Line, value.Position.Column, value.Text)
		}
		value.Unsigned, value.Negative = unsigned, negative
		if negative {
			if unsigned > 1<<63 {
				return mofValue{}, fmt.Errorf("%d:%d: integer %q is out of range", value.Position.Line, value.Position.Column, value.Text)
			}
			value.Integer = -int64(unsigned)
		} else {
			value.Integer = int64(unsigned)
		}
		return value, nil
	case mofTokenReal:
		value.Kind = mofValueReal
		value.Real, err = strconv.ParseFloat(value.Text, 64)
		if err != nil {
			return mofValue{}, fmt.Errorf("%d:%d: invalid real %q", value.Position.Line, value.Position.Column, value.Text)
		}
		return value, nil
	case mofTokenIdentifier:
		switch strings.ToLower(token.Text) {
		case "null":
			value.Kind = mofValueNull
		case "true":
			value.Kind, value.Bool = mofValueBool, true
		case "false":
			value.Kind, value.Bool = mofValueBool, false
		case "instance":
			instance, err := p.parseInstanceAfterStart(nil, token, false)
			if err != nil {
				return mofValue{}, err
			}
			value.Kind, value.Text, value.Instance = mofValueInstance, "", &instance
		default:
			value.Kind = mofValueIdentifier
		}
		return value, nil
	case mofTokenPunctuation:
		if token.Text != "{" {
			break
		}
		value.Kind = mofValueArray
		value.Text = ""
		closed, err := p.accept("}")
		if err != nil {
			return mofValue{}, err
		}
		if closed {
			return value, nil
		}
		for {
			item, err := p.parseValue()
			if err != nil {
				return mofValue{}, err
			}
			value.Items = append(value.Items, item)
			if closed, err := p.accept("}"); err != nil {
				return mofValue{}, err
			} else if closed {
				return value, nil
			}
			if _, err := p.expect(","); err != nil {
				return mofValue{}, err
			}
		}
	}
	return mofValue{}, fmt.Errorf("%d:%d: got %q, expected value", token.Position.Line, token.Position.Column, token.Text)
}

func (p *mofParser) parseQualifiers() ([]mofQualifier, error) {
	open, err := p.accept("[")
	if err != nil || !open {
		return nil, err
	}
	var qualifiers []mofQualifier
	for {
		name, err := p.identifier("qualifier name")
		if err != nil {
			return nil, err
		}
		qualifier := mofQualifier{Name: name.Text, Position: name.Position}
		closeValues := ""
		if hasValues, err := p.accept("("); err != nil {
			return nil, err
		} else if hasValues {
			closeValues = ")"
		} else if hasValues, err := p.accept("{"); err != nil {
			return nil, err
		} else if hasValues {
			closeValues = "}"
		}
		if closeValues != "" {
			if closed, err := p.accept(closeValues); err != nil {
				return nil, err
			} else if !closed {
				for {
					value, err := p.parseValue()
					if err != nil {
						return nil, err
					}
					qualifier.Values = append(qualifier.Values, value)
					if closed, err := p.accept(closeValues); err != nil {
						return nil, err
					} else if closed {
						break
					}
					if _, err := p.expect(","); err != nil {
						return nil, err
					}
				}
			}
		}
		separatorConsumed := false
		if hasFlavor, err := p.accept(":"); err != nil {
			return nil, err
		} else if hasFlavor {
			for {
				flavor, err := p.identifier("qualifier flavor")
				if err != nil {
					return nil, err
				}
				qualifier.Flavors = append(qualifier.Flavors, flavor.Text)
				next, err := p.peek()
				if err != nil {
					return nil, err
				}
				if isMOFQualifierFlavor(next.Text) {
					continue
				}
				comma, err := p.accept(",")
				if err != nil {
					return nil, err
				}
				if !comma {
					break
				}
				next, err = p.peek()
				if err != nil {
					return nil, err
				}
				// A comma followed by a known flavor remains part of this
				// qualifier; any other identifier starts the next qualifier.
				if !isMOFQualifierFlavor(next.Text) {
					separatorConsumed = true
					break
				}
			}
		}
		qualifiers = append(qualifiers, qualifier)
		if closed, err := p.accept("]"); err != nil {
			return nil, err
		} else if closed {
			return qualifiers, nil
		}
		if !separatorConsumed {
			if _, err := p.expect(","); err != nil {
				return nil, err
			}
		}
	}
}

func isMOFQualifierFlavor(value string) bool {
	switch strings.ToLower(value) {
	case "amended", "enableoverride", "disableoverride", "restricted", "tosubclass", "toinstance", "translatable":
		return true
	default:
		return false
	}
}

func (p *mofParser) parseArray(t *mofType) error {
	open, err := p.accept("[")
	if err != nil || !open {
		return err
	}
	t.Array, t.ArraySize = true, -1
	if closed, err := p.accept("]"); err != nil {
		return err
	} else if closed {
		return nil
	}
	size, err := p.take()
	if err != nil {
		return err
	}
	if size.Kind != mofTokenInteger {
		return fmt.Errorf("%d:%d: got %q, expected array size", size.Position.Line, size.Position.Column, size.Text)
	}
	t.ArraySize, err = strconv.ParseInt(size.Text, 0, 64)
	if err != nil || t.ArraySize < 0 {
		return fmt.Errorf("%d:%d: invalid array size %q", size.Position.Line, size.Position.Column, size.Text)
	}
	_, err = p.expect("]")
	return err
}

func (p *mofParser) parseTypeAndName(description string) (mofType, mofToken, error) {
	first, err := p.identifier("type name")
	if err != nil {
		return mofType{}, mofToken{}, err
	}
	t := mofType{Name: first.Text, ArraySize: -1}
	if reference, err := p.accept("ref"); err != nil {
		return mofType{}, mofToken{}, err
	} else if reference {
		t.Reference, t.Name = first.Text, "reference"
	}
	name, err := p.identifier(description)
	if err != nil {
		return mofType{}, mofToken{}, err
	}
	if err := p.parseArray(&t); err != nil {
		return mofType{}, mofToken{}, err
	}
	return t, name, nil
}

func (p *mofParser) parseFeature() (mofFeature, error) {
	qualifiers, err := p.parseQualifiers()
	if err != nil {
		return mofFeature{}, err
	}
	t, name, err := p.parseTypeAndName("property or method name")
	if err != nil {
		return mofFeature{}, err
	}
	feature := mofFeature{Kind: "property", Name: name.Text, Type: t, Qualifiers: qualifiers, Position: name.Position}
	if method, err := p.accept("("); err != nil {
		return mofFeature{}, err
	} else if method {
		if t.Array {
			return mofFeature{}, fmt.Errorf("%d:%d: method return type cannot declare an array after its name", name.Position.Line, name.Position.Column)
		}
		feature.Kind = "method"
		if closed, err := p.accept(")"); err != nil {
			return mofFeature{}, err
		} else if !closed {
			for {
				parameterQualifiers, err := p.parseQualifiers()
				if err != nil {
					return mofFeature{}, err
				}
				parameterType, parameterName, err := p.parseTypeAndName("parameter name")
				if err != nil {
					return mofFeature{}, err
				}
				parameter := mofParameter{Name: parameterName.Text, Type: parameterType, Qualifiers: parameterQualifiers, Position: parameterName.Position}
				if initialized, err := p.accept("="); err != nil {
					return mofFeature{}, err
				} else if initialized {
					value, err := p.parseValue()
					if err != nil {
						return mofFeature{}, err
					}
					parameter.Default = &value
				}
				feature.Parameters = append(feature.Parameters, parameter)
				if closed, err := p.accept(")"); err != nil {
					return mofFeature{}, err
				} else if closed {
					break
				}
				if _, err := p.expect(","); err != nil {
					return mofFeature{}, err
				}
			}
		}
	} else if initialized, err := p.accept("="); err != nil {
		return mofFeature{}, err
	} else if initialized {
		value, err := p.parseValue()
		if err != nil {
			return mofFeature{}, err
		}
		feature.Value = &value
	}
	_, err = p.expect(";")
	return feature, err
}

func (p *mofParser) parseClass(qualifiers []mofQualifier) (mofClass, error) {
	start, err := p.expect("class")
	if err != nil {
		return mofClass{}, err
	}
	name, err := p.identifier("class name")
	if err != nil {
		return mofClass{}, err
	}
	class := mofClass{Name: name.Text, Qualifiers: qualifiers, Position: start.Position}
	if alias, err := p.accept("as"); err != nil {
		return mofClass{}, err
	} else if alias {
		token, err := p.take()
		if err != nil {
			return mofClass{}, err
		}
		if token.Kind != mofTokenAlias {
			return mofClass{}, fmt.Errorf("%d:%d: expected class alias", token.Position.Line, token.Position.Column)
		}
		class.Alias = token.Text
	}
	if inherited, err := p.accept(":"); err != nil {
		return mofClass{}, err
	} else if inherited {
		super, err := p.identifier("superclass name")
		if err != nil {
			return mofClass{}, err
		}
		class.Super = super.Text
	}
	if _, err := p.expect("{"); err != nil {
		return mofClass{}, err
	}
	for {
		if closed, err := p.accept("}"); err != nil {
			return mofClass{}, err
		} else if closed {
			break
		}
		feature, err := p.parseFeature()
		if err != nil {
			return mofClass{}, err
		}
		class.Features = append(class.Features, feature)
	}
	_, err = p.expect(";")
	return class, err
}

func (p *mofParser) parseInstance(qualifiers []mofQualifier) (mofInstance, error) {
	start, err := p.expect("instance")
	if err != nil {
		return mofInstance{}, err
	}
	return p.parseInstanceAfterStart(qualifiers, start, true)
}

func (p *mofParser) parseInstanceAfterStart(qualifiers []mofQualifier, start mofToken, terminated bool) (mofInstance, error) {
	if _, err := p.expect("of"); err != nil {
		return mofInstance{}, err
	}
	class, err := p.identifier("instance class name")
	if err != nil {
		return mofInstance{}, err
	}
	instance := mofInstance{Class: class.Text, Qualifiers: qualifiers, Position: start.Position}
	if alias, err := p.accept("as"); err != nil {
		return mofInstance{}, err
	} else if alias {
		token, err := p.take()
		if err != nil {
			return mofInstance{}, err
		}
		if token.Kind != mofTokenAlias {
			return mofInstance{}, fmt.Errorf("%d:%d: expected instance alias", token.Position.Line, token.Position.Column)
		}
		instance.Alias = token.Text
	}
	if _, err := p.expect("{"); err != nil {
		return mofInstance{}, err
	}
	for {
		if closed, err := p.accept("}"); err != nil {
			return mofInstance{}, err
		} else if closed {
			break
		}
		qualifiers, err := p.parseQualifiers()
		if err != nil {
			return mofInstance{}, err
		}
		name, err := p.identifier("property name")
		if err != nil {
			return mofInstance{}, err
		}
		if empty, err := p.accept(";"); err != nil {
			return mofInstance{}, err
		} else if empty {
			instance.Properties = append(instance.Properties, mofPropertyAssignment{
				Name:       name.Text,
				Value:      mofValue{Kind: mofValueNull, Position: name.Position},
				Qualifiers: qualifiers,
				Position:   name.Position,
			})
			continue
		}
		if _, err := p.expect("="); err != nil {
			return mofInstance{}, err
		}
		value, err := p.parseValue()
		if err != nil {
			return mofInstance{}, err
		}
		if _, err := p.expect(";"); err != nil {
			return mofInstance{}, err
		}
		instance.Properties = append(instance.Properties, mofPropertyAssignment{
			Name:       name.Text,
			Value:      value,
			Qualifiers: qualifiers,
			Position:   name.Position,
		})
	}
	if terminated {
		_, err = p.expect(";")
	}
	return instance, err
}

func (p *mofParser) parseQualifierDeclaration() (mofQualifierDeclaration, error) {
	start, err := p.expect("qualifier")
	if err != nil {
		return mofQualifierDeclaration{}, err
	}
	name, err := p.identifier("qualifier name")
	if err != nil {
		return mofQualifierDeclaration{}, err
	}
	if _, err := p.expect(":"); err != nil {
		return mofQualifierDeclaration{}, err
	}
	next, err := p.peek()
	if err != nil {
		return mofQualifierDeclaration{}, err
	}
	if isMOFQualifierFlavor(next.Text) {
		declaration := mofQualifierDeclaration{Name: name.Text, Type: mofType{ArraySize: -1}, Position: start.Position}
		for {
			flavor, err := p.identifier("qualifier flavor")
			if err != nil {
				return mofQualifierDeclaration{}, err
			}
			if !isMOFQualifierFlavor(flavor.Text) {
				return mofQualifierDeclaration{}, fmt.Errorf("%d:%d: unknown qualifier flavor %q", flavor.Position.Line, flavor.Position.Column, flavor.Text)
			}
			declaration.Flavors = append(declaration.Flavors, flavor.Text)
			if finished, err := p.accept(";"); err != nil {
				return mofQualifierDeclaration{}, err
			} else if finished {
				return declaration, nil
			}
			_, _ = p.accept(",")
		}
	}
	typeName, err := p.identifier("qualifier type")
	if err != nil {
		return mofQualifierDeclaration{}, err
	}
	declaration := mofQualifierDeclaration{Name: name.Text, Type: mofType{Name: typeName.Text, ArraySize: -1}, Position: start.Position}
	if err := p.parseArray(&declaration.Type); err != nil {
		return mofQualifierDeclaration{}, err
	}
	if initialized, err := p.accept("="); err != nil {
		return mofQualifierDeclaration{}, err
	} else if initialized {
		value, err := p.parseValue()
		if err != nil {
			return mofQualifierDeclaration{}, err
		}
		declaration.Default = &value
	}
	for {
		if finished, err := p.accept(";"); err != nil {
			return mofQualifierDeclaration{}, err
		} else if finished {
			return declaration, nil
		}
		if _, err := p.expect(","); err != nil {
			return mofQualifierDeclaration{}, err
		}
		category, err := p.identifier("Scope or Flavor")
		if err != nil {
			return mofQualifierDeclaration{}, err
		}
		if _, err := p.expect("("); err != nil {
			return mofQualifierDeclaration{}, err
		}
		var values []string
		for {
			value, err := p.identifier("scope or flavor name")
			if err != nil {
				return mofQualifierDeclaration{}, err
			}
			values = append(values, value.Text)
			if closed, err := p.accept(")"); err != nil {
				return mofQualifierDeclaration{}, err
			} else if closed {
				break
			}
			if _, err := p.expect(","); err != nil {
				return mofQualifierDeclaration{}, err
			}
		}
		switch strings.ToLower(category.Text) {
		case "scope":
			declaration.Scopes = append(declaration.Scopes, values...)
		case "flavor":
			declaration.Flavors = append(declaration.Flavors, values...)
		default:
			return mofQualifierDeclaration{}, fmt.Errorf("%d:%d: unknown qualifier declaration category %q", category.Position.Line, category.Position.Column, category.Text)
		}
	}
}

func (p *mofParser) parsePragma() (mofPragma, error) {
	hash, err := p.expect("#")
	if err != nil {
		return mofPragma{}, err
	}
	name, err := p.identifier("compiler directive")
	if err != nil {
		return mofPragma{}, err
	}
	if strings.EqualFold(name.Text, "pragma") {
		name, err = p.identifier("pragma name")
		if err != nil {
			return mofPragma{}, err
		}
	}
	pragma := mofPragma{Name: name.Text, Position: hash.Position}
	if open, err := p.accept("("); err != nil {
		return mofPragma{}, err
	} else if open {
		if closed, err := p.accept(")"); err != nil {
			return mofPragma{}, err
		} else if !closed {
			for {
				value, err := p.parseValue()
				if err != nil {
					return mofPragma{}, err
				}
				pragma.Values = append(pragma.Values, value)
				if closed, err := p.accept(")"); err != nil {
					return mofPragma{}, err
				} else if closed {
					break
				}
				if _, err := p.expect(","); err != nil {
					return mofPragma{}, err
				}
			}
		}
	}
	return pragma, nil
}

func parseMOF(source string) (*mofDocument, error) {
	p := &mofParser{lexer: newMOFLexer(source)}
	document := &mofDocument{}
	currentNamespace := ""
	for {
		token, err := p.peek()
		if err != nil {
			return nil, err
		}
		if token.Kind == mofTokenEOF {
			return document, nil
		}
		if token.Text == "#" {
			pragma, err := p.parsePragma()
			if err != nil {
				return nil, err
			}
			pragma.Namespace = currentNamespace
			document.Pragmas = append(document.Pragmas, pragma)
			document.Items = append(document.Items, mofDocumentItem{Kind: "pragma", Namespace: currentNamespace, Index: len(document.Pragmas) - 1, Position: pragma.Position})
			if strings.EqualFold(pragma.Name, "namespace") {
				if len(pragma.Values) != 1 || pragma.Values[0].Kind != mofValueString {
					return nil, fmt.Errorf("%d:%d: namespace pragma requires one string value", pragma.Position.Line, pragma.Position.Column)
				}
				currentNamespace = pragma.Values[0].Text
			}
			continue
		}
		qualifiers, err := p.parseQualifiers()
		if err != nil {
			return nil, err
		}
		token, err = p.peek()
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(token.Text) {
		case "class":
			class, err := p.parseClass(qualifiers)
			if err != nil {
				return nil, err
			}
			class.Namespace = currentNamespace
			document.Classes = append(document.Classes, class)
			document.Items = append(document.Items, mofDocumentItem{Kind: "class", Namespace: currentNamespace, Index: len(document.Classes) - 1, Position: class.Position})
		case "instance":
			instance, err := p.parseInstance(qualifiers)
			if err != nil {
				return nil, err
			}
			instance.Namespace = currentNamespace
			document.Instances = append(document.Instances, instance)
			document.Items = append(document.Items, mofDocumentItem{Kind: "instance", Namespace: currentNamespace, Index: len(document.Instances) - 1, Position: instance.Position})
		case "qualifier":
			if len(qualifiers) != 0 {
				return nil, fmt.Errorf("%d:%d: qualifier declaration cannot have qualifiers", token.Position.Line, token.Position.Column)
			}
			declaration, err := p.parseQualifierDeclaration()
			if err != nil {
				return nil, err
			}
			declaration.Namespace = currentNamespace
			document.Qualifiers = append(document.Qualifiers, declaration)
			document.Items = append(document.Items, mofDocumentItem{Kind: "qualifier_declaration", Namespace: currentNamespace, Index: len(document.Qualifiers) - 1, Position: declaration.Position})
		default:
			return nil, fmt.Errorf("%d:%d: got %q, expected class, instance, or qualifier declaration", token.Position.Line, token.Position.Column, token.Text)
		}
	}
}

func decodeMOFText(data []byte) string { return decodeINFText(data) }

func mofBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("mof", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("mof: %w", err)
	}
	document, err := parseMOF(decodeMOFText(data))
	if err != nil {
		source := decodeMOFText(data)
		line := mofErrorSourceLine(source, err)
		if line != "" {
			return nil, fmt.Errorf("mof: %w\n    %s", err, strings.TrimSpace(line))
		}
		return nil, fmt.Errorf("mof: %w", err)
	}
	return &mofFile{document: document}, nil
}

func mofErrorSourceLine(source string, parseError error) string {
	var line int
	if _, err := fmt.Sscanf(parseError.Error(), "%d:", &line); err != nil || line < 1 {
		return ""
	}
	lines := strings.Split(source, "\n")
	if line > len(lines) {
		return ""
	}
	return strings.TrimSuffix(lines[line-1], "\r")
}

type mofFile struct{ document *mofDocument }

func (f *mofFile) String() string {
	return fmt.Sprintf("<windows.mof classes=%d instances=%d>", len(f.document.Classes), len(f.document.Instances))
}
func (f *mofFile) Type() string          { return "windows.mof" }
func (f *mofFile) Freeze()               {}
func (f *mofFile) Truth() starlark.Bool  { return starlark.True }
func (f *mofFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", f.Type()) }
func (f *mofFile) AttrNames() []string {
	return []string{"classes", "instances", "items", "pragmas", "qualifier_declarations"}
}
func (f *mofFile) Attr(name string) (starlark.Value, error) {
	switch name {
	case "classes":
		values := make([]starlark.Value, len(f.document.Classes))
		for i := range f.document.Classes {
			values[i] = mofClassValue(f.document.Classes[i])
		}
		return starlark.NewList(values), nil
	case "instances":
		values := make([]starlark.Value, len(f.document.Instances))
		for i := range f.document.Instances {
			values[i] = mofInstanceValue(f.document.Instances[i])
		}
		return starlark.NewList(values), nil
	case "pragmas":
		values := make([]starlark.Value, len(f.document.Pragmas))
		for i, item := range f.document.Pragmas {
			values[i] = mofPragmaValue(item)
		}
		return starlark.NewList(values), nil
	case "qualifier_declarations":
		values := make([]starlark.Value, len(f.document.Qualifiers))
		for i, item := range f.document.Qualifiers {
			defaultValue := starlark.Value(starlark.None)
			if item.Default != nil {
				defaultValue = mofValueValue(*item.Default)
			}
			values[i] = mofQualifierDeclarationValue(item, defaultValue)
		}
		return starlark.NewList(values), nil
	case "items":
		values := make([]starlark.Value, len(f.document.Items))
		for index, item := range f.document.Items {
			var declaration starlark.Value
			switch item.Kind {
			case "pragma":
				declaration = mofPragmaValue(f.document.Pragmas[item.Index])
			case "qualifier_declaration":
				qualifier := f.document.Qualifiers[item.Index]
				defaultValue := starlark.Value(starlark.None)
				if qualifier.Default != nil {
					defaultValue = mofValueValue(*qualifier.Default)
				}
				declaration = mofQualifierDeclarationValue(qualifier, defaultValue)
			case "class":
				declaration = mofClassValue(f.document.Classes[item.Index])
			case "instance":
				declaration = mofInstanceValue(f.document.Instances[item.Index])
			default:
				return nil, fmt.Errorf("mof: invalid document item kind %q", item.Kind)
			}
			values[index] = starfile.NewRecord(starlark.StringDict{
				"kind":      starlark.String(item.Kind),
				"namespace": starlark.String(item.Namespace),
				"value":     declaration,
				"line":      starlark.MakeInt(item.Position.Line),
				"column":    starlark.MakeInt(item.Position.Column),
			})
		}
		return starlark.NewList(values), nil
	}
	return nil, nil
}

func stringsValue(values []string) starlark.Value {
	items := make([]starlark.Value, len(values))
	for i, value := range values {
		items[i] = starlark.String(value)
	}
	return starlark.NewList(items)
}

func mofTypeValue(t mofType) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(t.Name), "reference": starlark.String(t.Reference), "array": starlark.Bool(t.Array), "array_size": starlark.MakeInt64(t.ArraySize)})
}

func mofValuesValue(values []mofValue) starlark.Value {
	items := make([]starlark.Value, len(values))
	for i := range values {
		items[i] = mofValueValue(values[i])
	}
	return starlark.NewList(items)
}

func mofValueValue(value mofValue) starlark.Value {
	var data starlark.Value = starlark.None
	switch value.Kind {
	case mofValueBool:
		data = starlark.Bool(value.Bool)
	case mofValueInteger:
		if value.Negative {
			data = starlark.MakeInt64(value.Integer)
		} else {
			data = starlark.MakeUint64(value.Unsigned)
		}
	case mofValueReal:
		data = starlark.Float(value.Real)
	case mofValueString, mofValueIdentifier, mofValueAlias:
		data = starlark.String(value.Text)
	case mofValueArray:
		data = mofValuesValue(value.Items)
	case mofValueInstance:
		data = mofInstanceValue(*value.Instance)
	}
	return starfile.NewRecord(starlark.StringDict{"kind": starlark.String(value.Kind), "value": data, "line": starlark.MakeInt(value.Position.Line), "column": starlark.MakeInt(value.Position.Column)})
}

func mofQualifierValue(item mofQualifier) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(item.Name), "values": mofValuesValue(item.Values), "flavors": stringsValue(item.Flavors), "line": starlark.MakeInt(item.Position.Line), "column": starlark.MakeInt(item.Position.Column)})
}

func mofQualifiersValue(values []mofQualifier) starlark.Value {
	items := make([]starlark.Value, len(values))
	for i := range values {
		items[i] = mofQualifierValue(values[i])
	}
	return starlark.NewList(items)
}

func mofParameterValue(item mofParameter) starlark.Value {
	defaultValue := starlark.Value(starlark.None)
	if item.Default != nil {
		defaultValue = mofValueValue(*item.Default)
	}
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(item.Name), "type": mofTypeValue(item.Type), "qualifiers": mofQualifiersValue(item.Qualifiers), "default": defaultValue, "line": starlark.MakeInt(item.Position.Line), "column": starlark.MakeInt(item.Position.Column)})
}

func mofFeatureValue(item mofFeature) starlark.Value {
	parameters := make([]starlark.Value, len(item.Parameters))
	for i := range item.Parameters {
		parameters[i] = mofParameterValue(item.Parameters[i])
	}
	value := starlark.Value(starlark.None)
	if item.Value != nil {
		value = mofValueValue(*item.Value)
	}
	return starfile.NewRecord(starlark.StringDict{"kind": starlark.String(item.Kind), "name": starlark.String(item.Name), "type": mofTypeValue(item.Type), "qualifiers": mofQualifiersValue(item.Qualifiers), "value": value, "parameters": starlark.NewList(parameters), "line": starlark.MakeInt(item.Position.Line), "column": starlark.MakeInt(item.Position.Column)})
}

func mofPragmaValue(item mofPragma) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{
		"name":      starlark.String(item.Name),
		"namespace": starlark.String(item.Namespace),
		"values":    mofValuesValue(item.Values),
		"line":      starlark.MakeInt(item.Position.Line),
		"column":    starlark.MakeInt(item.Position.Column),
	})
}

func mofQualifierDeclarationValue(item mofQualifierDeclaration, defaultValue starlark.Value) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{
		"name":      starlark.String(item.Name),
		"namespace": starlark.String(item.Namespace),
		"type":      mofTypeValue(item.Type),
		"default":   defaultValue,
		"scopes":    stringsValue(item.Scopes),
		"flavors":   stringsValue(item.Flavors),
		"line":      starlark.MakeInt(item.Position.Line),
		"column":    starlark.MakeInt(item.Position.Column),
	})
}

func mofClassValue(item mofClass) starlark.Value {
	features := make([]starlark.Value, len(item.Features))
	for i := range item.Features {
		features[i] = mofFeatureValue(item.Features[i])
	}
	return starfile.NewRecord(starlark.StringDict{"name": starlark.String(item.Name), "superclass": starlark.String(item.Super), "alias": starlark.String(item.Alias), "namespace": starlark.String(item.Namespace), "qualifiers": mofQualifiersValue(item.Qualifiers), "features": starlark.NewList(features), "line": starlark.MakeInt(item.Position.Line), "column": starlark.MakeInt(item.Position.Column)})
}

func mofInstanceValue(item mofInstance) starlark.Value {
	properties := make([]starlark.Value, len(item.Properties))
	for i, property := range item.Properties {
		properties[i] = starfile.NewRecord(starlark.StringDict{
			"name":       starlark.String(property.Name),
			"value":      mofValueValue(property.Value),
			"qualifiers": mofQualifiersValue(property.Qualifiers),
			"line":       starlark.MakeInt(property.Position.Line),
			"column":     starlark.MakeInt(property.Position.Column),
		})
	}
	return starfile.NewRecord(starlark.StringDict{"class": starlark.String(item.Class), "alias": starlark.String(item.Alias), "namespace": starlark.String(item.Namespace), "qualifiers": mofQualifiersValue(item.Qualifiers), "properties": starlark.NewList(properties), "line": starlark.MakeInt(item.Position.Line), "column": starlark.MakeInt(item.Position.Column)})
}

var _ = bytes.Compare
