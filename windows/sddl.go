package windows

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

// CompileSDDL builds a revision-1 self-relative security descriptor without
// identity lookup, generic-right mapping, defaults, or inheritance. This is a
// deliberately bounded SDDL subset: fixed well-known/numeric SIDs, simple
// allow/deny/audit/mandatory-label ACEs and local-attribute Contains/Exists callback ACEs.
// Unsupported syntax fails closed. Absent, empty, and NULL ACLs remain distinct.
// CSI's "(inherit)" marker is not SDDL and must be handled by its caller.
func CompileSDDL(text string) ([]byte, error) {
	return compileSDDL(text, "")
}

// CompileSDDLWithAccountDomain additionally resolves LA using an explicitly
// supplied canonical account-domain SID (S-1-5-21-a-b-c). It never queries the
// host or invents a domain for generalized images. Other relative aliases
// remain unsupported. The caller must use the target image's chosen identity.
func CompileSDDLWithAccountDomain(text, accountDomainSID string) ([]byte, error) {
	sid, err := sddlSID(accountDomainSID)
	if err != nil || len(sid) != 24 || !strings.HasPrefix(accountDomainSID, "S-1-5-21-") {
		return nil, fmt.Errorf("SDDL: invalid account-domain SID")
	}
	canonical, err := SIDString(sid)
	if err != nil || canonical != accountDomainSID {
		return nil, fmt.Errorf("SDDL: account-domain SID must be canonical")
	}
	return compileSDDL(text, accountDomainSID)
}

func sddlSIDInAccountDomain(text, accountDomainSID string) ([]byte, error) {
	if text == "LA" {
		if accountDomainSID == "" {
			return nil, fmt.Errorf("LA requires an explicit account-domain SID")
		}
		return sddlSID(accountDomainSID + "-500")
	}
	return sddlSID(text)
}

func compileSDDL(text, accountDomainSID string) ([]byte, error) {
	if len(text) == 0 || len(text) > 1<<20 || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return nil, fmt.Errorf("SDDL: invalid input")
	}
	sections := map[byte]string{}
	for pos := 0; pos < len(text); {
		if pos+2 > len(text) || !strings.ContainsRune("OGDS", rune(text[pos])) || text[pos+1] != ':' {
			return nil, fmt.Errorf("SDDL: expected section at %d", pos)
		}
		kind := text[pos]
		if _, exists := sections[kind]; exists {
			return nil, fmt.Errorf("SDDL: duplicate %c section", kind)
		}
		start := pos + 2
		pos = start
		depth, quoted := 0, false
		for pos < len(text) {
			c := text[pos]
			if c == '"' {
				quoted = !quoted
			}
			if !quoted {
				if c == '(' {
					depth++
					if depth > 3 {
						return nil, fmt.Errorf("SDDL: unsupported nesting")
					}
				}
				if c == ')' {
					depth--
					if depth < 0 {
						return nil, fmt.Errorf("SDDL: unbalanced parentheses")
					}
				}
				if depth == 0 && pos+1 < len(text) && strings.ContainsRune("OGDS", rune(c)) && text[pos+1] == ':' {
					break
				}
			}
			pos++
		}
		if quoted || depth != 0 {
			return nil, fmt.Errorf("SDDL: unterminated expression")
		}
		sections[kind] = text[start:pos]
	}
	control := uint16(0x8000)
	parts := map[byte][]byte{}
	for _, kind := range []byte{'O', 'G', 'D', 'S'} {
		value, present := sections[kind]
		if !present {
			continue
		}
		var err error
		if kind == 'O' || kind == 'G' {
			parts[kind], err = sddlSIDInAccountDomain(value, accountDomainSID)
		} else {
			var flags uint16
			parts[kind], flags, err = sddlACL(value, kind == 'S', accountDomainSID)
			control |= flags
		}
		if err != nil {
			return nil, fmt.Errorf("SDDL %c: %w", kind, err)
		}
	}
	out := make([]byte, 20)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:], control)
	for _, part := range []struct {
		kind   byte
		offset int
	}{{'O', 4}, {'G', 8}, {'D', 16}, {'S', 12}} {
		if data := parts[part.kind]; data != nil {
			binary.LittleEndian.PutUint32(out[part.offset:], uint32(len(out)))
			out = append(out, data...)
		}
	}
	return out, nil
}

func sddlSID(text string) ([]byte, error) {
	aliases := map[string]string{
		"SY": "S-1-5-18", "BA": "S-1-5-32-544", "BU": "S-1-5-32-545",
		"WD": "S-1-1-0", "AC": "S-1-15-2-1", "LU": "S-1-5-32-559",
		"AU": "S-1-5-11", "BO": "S-1-5-32-551", "CO": "S-1-3-0",
		"IU": "S-1-5-4", "LS": "S-1-5-19", "LW": "S-1-16-4096", "ME": "S-1-16-8192",
		"NO": "S-1-5-32-556", "NS": "S-1-5-20", "RC": "S-1-5-12",
		"SU": "S-1-5-6", "UD": "S-1-5-84-0-0-0-0-0",
		"AN": "S-1-5-7", "BG": "S-1-5-32-546", "CG": "S-1-3-1",
		"OW": "S-1-3-4", "SO": "S-1-5-32-549",
		"CY": "S-1-5-32-569", // SDDL_CRYPTO_OPERATORS, DOMAIN_ALIAS_RID_CRYPTO_OPERATORS (0x239).
	}
	if value, ok := aliases[text]; ok {
		text = value
	}
	fields := strings.Split(text, "-")
	if len(fields) < 3 || len(fields) > 18 || fields[0] != "S" || fields[1] != "1" {
		return nil, fmt.Errorf("unsupported SID %q", text)
	}
	number := func(s string, bits int, hex bool) (uint64, error) {
		base := 10
		if hex && strings.HasPrefix(s, "0x") {
			base = 16
			s = s[2:]
		}
		if s == "" || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") {
			return 0, fmt.Errorf("invalid SID number")
		}
		return strconv.ParseUint(s, base, bits)
	}
	authority, err := number(fields[2], 48, true)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8+4*(len(fields)-3))
	out[0], out[1] = 1, byte(len(fields)-3)
	for i := 7; i >= 2; i-- {
		out[i] = byte(authority)
		authority >>= 8
	}
	for i, field := range fields[3:] {
		value, err := number(field, 32, false)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(out[8+i*4:], uint32(value))
	}
	return out, nil
}

func sddlTokens(text string, tokens map[string]uint32) (uint32, error) {
	var value uint32
	for len(text) > 0 {
		if len(text) < 2 {
			return 0, fmt.Errorf("invalid token %q", text)
		}
		flag, ok := tokens[text[:2]]
		if !ok {
			return 0, fmt.Errorf("unsupported token %q", text[:2])
		}
		value |= flag
		text = text[2:]
	}
	return value, nil
}

func sddlACL(text string, sacl bool, accountDomainSID string) ([]byte, uint16, error) {
	control := uint16(4)
	protected, requested, inherited := uint16(0x1000), uint16(0x100), uint16(0x400)
	if sacl {
		control, protected, requested, inherited = 0x10, 0x2000, 0x200, 0x800
	}
	if text == "NO_ACCESS_CONTROL" {
		return nil, control, nil
	}
	for len(text) > 0 && text[0] != '(' {
		switch {
		case strings.HasPrefix(text, "P"):
			control |= protected
			text = text[1:]
		case strings.HasPrefix(text, "AR"):
			control |= requested
			text = text[2:]
		case strings.HasPrefix(text, "AI"):
			control |= inherited
			text = text[2:]
		default:
			return nil, 0, fmt.Errorf("unsupported ACL flags")
		}
	}
	out := make([]byte, 8)
	out[0] = 2
	count := 0
	for len(text) > 0 {
		if text[0] != '(' {
			return nil, 0, fmt.Errorf("expected ACE")
		}
		depth, quoted, end := 0, false, -1
		for i := 0; i < len(text); i++ {
			if text[i] == '"' {
				quoted = !quoted
			}
			if quoted {
				continue
			}
			if text[i] == '(' {
				depth++
			}
			if text[i] == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return nil, 0, fmt.Errorf("unterminated ACE")
		}
		ace, err := sddlACE(text[1:end], sacl, accountDomainSID)
		if err != nil {
			return nil, 0, err
		}
		if len(out)+len(ace) > 65535 {
			return nil, 0, fmt.Errorf("ACL exceeds binary extent")
		}
		out = append(out, ace...)
		count++
		text = text[end+1:]
	}
	binary.LittleEndian.PutUint16(out[2:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[4:], uint16(count))
	return out, control, nil
}

// Native SDDL accepts a sequence of symbolic and base-zero numeric masks.
// Each term is ORed; a numeric term need not occupy the whole rights field.
// Unlike wcstoul's saturation, numeric overflow is deliberately rejected.
func sddlRights(text string) (uint32, error) {
	tokens := map[string]uint32{
		"GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
		"FA": 0x1f01ff, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200a0,
		"RC": 0x20000, "SD": 0x10000, "WD": 0x40000, "WO": 0x80000,
		"CC": 1, "DC": 2, "LC": 4, "SW": 8, "RP": 0x10, "WP": 0x20,
		"NW": 1, "NR": 2, "NX": 4,
		"DT": 0x40, "LO": 0x80, "CR": 0x100,
		"KA": 0xf003f, "KR": 0x20019, "KW": 0x20006, "KX": 0x20019,
	}
	var mask uint32
	for len(text) > 0 {
		if text[0] >= '0' && text[0] <= '9' {
			base, start, digits := 10, 0, "0123456789"
			if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
				base, start, digits = 16, 2, "0123456789abcdefABCDEF"
			} else if text[0] == '0' {
				base, digits = 8, "01234567"
			}
			end := start
			for end < len(text) && strings.IndexByte(digits, text[end]) >= 0 {
				end++
			}
			if end == start {
				return 0, fmt.Errorf("invalid numeric rights")
			}
			value, err := strconv.ParseUint(text[start:end], base, 32)
			if err != nil {
				return 0, err
			}
			mask |= uint32(value)
			text = text[end:]
			continue
		}
		if len(text) < 2 {
			return 0, fmt.Errorf("invalid rights token %q", text)
		}
		value, ok := tokens[text[:2]]
		if !ok {
			return 0, fmt.Errorf("unsupported rights token %q", text[:2])
		}
		mask |= value
		text = text[2:]
	}
	return mask, nil
}

func sddlACE(text string, sacl bool, accountDomainSID string) ([]byte, error) {
	fields := strings.SplitN(text, ";", 7)
	if len(fields) < 6 {
		return nil, fmt.Errorf("incomplete ACE")
	}
	kinds := map[string]byte{"A": 0, "D": 1, "AU": 2, "XA": 9, "ML": 17}
	kind, ok := kinds[fields[0]]
	if !ok {
		return nil, fmt.Errorf("unsupported ACE type %q", fields[0])
	}
	if (kind == 2 || kind == 17) != sacl {
		return nil, fmt.Errorf("ACE type in wrong ACL")
	}
	flags, err := sddlTokens(fields[1], map[string]uint32{"OI": 1, "CI": 2, "NP": 4, "IO": 8, "ID": 16, "SA": 64, "FA": 128})
	if err != nil {
		return nil, err
	}
	mask, err := sddlRights(fields[2])
	if err != nil {
		return nil, err
	}
	if fields[3] != "" || fields[4] != "" {
		return nil, fmt.Errorf("object GUIDs unsupported for this ACE")
	}
	sid, err := sddlSIDInAccountDomain(fields[5], accountDomainSID)
	if err != nil {
		return nil, err
	}
	if kind == 17 && (flags&0xc0 != 0 || mask & ^uint32(7) != 0 || len(sid) != 12 || sid[1] != 1 || (sid[2] != 0 || sid[3] != 0 || sid[4] != 0 || sid[5] != 0 || sid[6] != 0 || sid[7] != 16)) {
		return nil, fmt.Errorf("invalid mandatory label ACE")
	}
	var condition []byte
	if kind == 9 {
		if len(fields) != 7 {
			return nil, fmt.Errorf("conditional ACE requires condition")
		}
		condition, err = sddlCondition(fields[6])
		if err != nil {
			return nil, err
		}
	} else if len(fields) != 6 {
		return nil, fmt.Errorf("unexpected ACE condition")
	}
	if 8+len(sid)+len(condition)+3 > 65535 {
		return nil, fmt.Errorf("ACE exceeds binary extent")
	}
	return appxACE(kind, byte(flags), mask, sid, condition), nil
}

// Only local-attribute Contains-string, Exists, and parenthesized NOT expressions are supported.
// Unrecognized operators are never silently treated as one of those predicates.
func sddlLocalAttribute(attribute string) ([]byte, error) {
	if attribute == "" {
		return nil, fmt.Errorf("empty local attribute")
	}
	for _, c := range attribute {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_:/.-", c)) {
			return nil, fmt.Errorf("unsupported local attribute")
		}
	}
	raw := appxUTF16(attribute)
	out := []byte{0xf8}
	out = binary.LittleEndian.AppendUint32(out, uint32(len(raw)))
	return append(out, raw...), nil
}
func sddlCondition(text string) ([]byte, error) {
	if len(text) < 2 || text[0] != '(' || text[len(text)-1] != ')' {
		return nil, fmt.Errorf("invalid condition")
	}
	text = strings.TrimSpace(text[1 : len(text)-1])
	if strings.HasPrefix(text, "!(") && strings.HasSuffix(text, ")") {
		attribute, err := sddlLocalAttribute(text[2 : len(text)-1])
		if err != nil {
			return nil, err
		}
		return append(append([]byte("artx"), attribute...), 0xa2), nil
	}
	if strings.HasPrefix(text, "exists ") {
		attribute, err := sddlLocalAttribute(strings.TrimSpace(text[len("exists "):]))
		if err != nil {
			return nil, err
		}
		return append(append([]byte("artx"), attribute...), 0x87), nil
	}
	split := strings.Index(text, " Contains ")
	if split <= 0 {
		return nil, fmt.Errorf("unsupported conditional expression")
	}
	attribute, literal := text[:split], strings.TrimSpace(text[split+10:])
	if _, err := sddlLocalAttribute(attribute); err != nil {
		return nil, err
	}
	if len(literal) < 2 || literal[0] != '"' || literal[len(literal)-1] != '"' {
		return nil, fmt.Errorf("expected string literal")
	}
	literal = literal[1 : len(literal)-1]
	if strings.ContainsAny(literal, "\"\\") {
		return nil, fmt.Errorf("unsupported string escape or compound expression")
	}
	out := []byte("artx")
	for _, token := range []struct {
		kind byte
		text string
	}{{0xf8, attribute}, {0x10, literal}} {
		raw := appxUTF16(token.text)
		out = append(out, token.kind)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(raw)))
		out = append(out, raw...)
	}
	return append(out, 0x86), nil
}

func compileSDDLBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var text string
	var domain starlark.Value = starlark.None
	if err := starlark.UnpackArgs("compile_sddl", args, kwargs, "text", &text, "account_domain_sid?", &domain); err != nil {
		return nil, err
	}
	var data []byte
	var err error
	if domain == starlark.None {
		data, err = CompileSDDL(text)
	} else {
		value, ok := starlark.AsString(domain)
		if !ok {
			return nil, fmt.Errorf("compile_sddl: account_domain_sid requires a string or None")
		}
		data, err = CompileSDDLWithAccountDomain(text, value)
	}
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}
