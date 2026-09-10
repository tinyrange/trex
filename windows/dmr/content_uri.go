package dmr

import (
	"fmt"
	"strings"
)

// ContentURIRule is one application content-URI rule. Flag1 represents bit 0
// of the repository rule's Flags. RuntimeAccess is the native enum 0, 1, or 2
// (encoded as no prefix, 'a', or 'w'). Include selects '+' rather than '-'.
// URI text and rule order are preserved without URI normalization or evaluation.
type ContentURIRule struct {
	Flag1         bool
	RuntimeAccess uint8
	Include       bool
	URI           string
}

// EncodeContentURIRules emits consecutive terminated UTF-16 rule records with
// no additional final NUL. The APPS rule count is supplied separately by its
// containing record. The byte limit accounts for the native u16 narrowing.
func EncodeContentURIRules(rules []ContentURIRule) ([]byte, error) {
	if len(rules) > 65535 {
		return nil, fmt.Errorf("dmr: too many content-URI rules")
	}
	var out []byte
	for i, rule := range rules {
		var text strings.Builder
		if rule.Flag1 {
			text.WriteByte('s')
		}
		switch rule.RuntimeAccess {
		case 0:
		case 1:
			text.WriteByte('a')
		case 2:
			text.WriteByte('w')
		default:
			return nil, fmt.Errorf("dmr: invalid content-URI access %d", rule.RuntimeAccess)
		}
		if rule.Include {
			text.WriteByte('+')
		} else {
			text.WriteByte('-')
		}
		text.WriteString(rule.URI)
		b, err := terminatedString(text.String(), 65534-len(out))
		if err != nil {
			return nil, fmt.Errorf("dmr: content-URI rule %d: %w", i, err)
		}
		out = append(out, b...)
	}
	return out, nil
}

// ParseContentURIRules checks the explicit APPS count and byte extent. A rule
// separator is a UTF-16 NUL, not a byte delimiter or the end of the whole blob.
func ParseContentURIRules(data []byte, count uint16) ([]ContentURIRule, error) {
	if len(data) > 65534 || len(data)%2 != 0 {
		return nil, fmt.Errorf("dmr: invalid content-URI byte extent")
	}
	if int(count) > len(data)/4 {
		return nil, fmt.Errorf("dmr: content-URI count exceeds payload")
	}
	rules := make([]ContentURIRule, 0, int(count))
	offset := 0
	for i := 0; i < int(count); i++ {
		end := offset
		for end < len(data) && le.Uint16(data[end:]) != 0 {
			end += 2
		}
		if end == len(data) {
			return nil, fmt.Errorf("dmr: unterminated content-URI rule")
		}
		text, err := parseIdentityString(data[offset : end+2])
		if err != nil {
			return nil, err
		}
		rule := ContentURIRule{}
		if strings.HasPrefix(text, "s") {
			rule.Flag1 = true
			text = text[1:]
		}
		if strings.HasPrefix(text, "a") {
			rule.RuntimeAccess = 1
			text = text[1:]
		} else if strings.HasPrefix(text, "w") {
			rule.RuntimeAccess = 2
			text = text[1:]
		}
		if len(text) == 0 || (text[0] != '+' && text[0] != '-') {
			return nil, fmt.Errorf("dmr: missing content-URI include/exclude marker")
		}
		rule.Include, rule.URI = text[0] == '+', text[1:]
		rules = append(rules, rule)
		offset = end + 2
	}
	if offset != len(data) {
		return nil, fmt.Errorf("dmr: content-URI count leaves trailing bytes")
	}
	return rules, nil
}
