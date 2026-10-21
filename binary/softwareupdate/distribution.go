package softwareupdate

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/binary/plist"
	"github.com/tinyrange/trex/storage"
)

// Distribution reads display/version/build metadata and retains compatibility
// scripts as text. Neither scripts nor external entities are evaluated.
func Distribution(source storage.Reader) (map[string]any, error) {
	raw, err := readSource(source, MaxDistributionBytes)
	if err != nil {
		return nil, err
	}
	s := scanner{raw: raw, d: xml.NewDecoder(bytes.NewReader(raw))}
	if err := s.start("installer-gui-script"); err != nil {
		return nil, err
	}
	stack := []string{"installer-gui-script"}
	aux := map[string]any{}
	scripts := []any{}
	localizations := []any{}
	options := map[string]any{}
	title := ""
	titleSeen, auxSeen := false, false
	for len(stack) > 0 {
		t, err := s.token()
		if err != nil {
			return nil, err
		}
		switch x := t.(type) {
		case xml.StartElement:
			if len(stack) >= maxDepth {
				return nil, fmt.Errorf("softwareupdate: XML depth limit")
			}
			if x.Name.Space != "" {
				return nil, fmt.Errorf("softwareupdate: unexpected Distribution namespace")
			}
			if len(stack) == 1 && x.Name.Local == "auxinfo" {
				if auxSeen {
					return nil, fmt.Errorf("softwareupdate: duplicate auxinfo")
				}
				auxSeen = true
				fragment, err := s.value()
				if err != nil {
					return nil, err
				}
				v, err := plist.Decode(append(append([]byte("<plist>"), fragment...), []byte("</plist>")...))
				if err != nil {
					return nil, err
				}
				var ok bool
				aux, ok = v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("softwareupdate: expected auxinfo dictionary")
				}
				t, err := s.next()
				if err != nil || !end(t, "auxinfo") {
					return nil, fmt.Errorf("softwareupdate: malformed auxinfo")
				}
				continue
			}
			capture := len(stack) == 1 && (x.Name.Local == "title" || x.Name.Local == "script")
			capture = capture || (len(stack) == 2 && stack[1] == "localization" && x.Name.Local == "strings")
			if capture {
				text, err := s.text(x.Name.Local)
				if err != nil {
					return nil, err
				}
				attrs := map[string]any{}
				for _, a := range x.Attr {
					attrs[a.Name.Local] = a.Value
				}
				attrs["text"] = text
				switch x.Name.Local {
				case "title":
					if titleSeen {
						return nil, fmt.Errorf("softwareupdate: duplicate title")
					}
					titleSeen = true
					title = strings.TrimSpace(text)
				case "script":
					scripts = append(scripts, attrs)
				case "strings":
					localizations = append(localizations, attrs)
				}
				continue
			}
			if len(stack) == 1 && x.Name.Local == "options" {
				for _, a := range x.Attr {
					options[a.Name.Local] = a.Value
				}
			}
			stack = append(stack, x.Name.Local)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 1 && strings.TrimSpace(string(x)) != "" {
				return nil, fmt.Errorf("softwareupdate: unexpected root text")
			}
		}
	}
	if _, err := s.next(); err != io.EOF {
		return nil, fmt.Errorf("softwareupdate: trailing Distribution content")
	}
	rawTitle := title
	// Resolve the observed double-quoted .strings title assignment only.
	// Keep the raw title/localization blocks when a different grammar is used.
	if title != "" {
		re, err := regexp.Compile(`(?m)^\s*"` + regexp.QuoteMeta(title) + `"\s*=\s*("(?:[^"\\]|\\.)*")\s*;`)
		if err != nil {
			return nil, fmt.Errorf("softwareupdate: localization title pattern exceeds regexp limits")
		}
		for _, v := range localizations {
			match := re.FindStringSubmatch(v.(map[string]any)["text"].(string))
			if len(match) == 2 {
				if decoded, err := strconv.Unquote(match[1]); err == nil {
					title = decoded
					break
				}
			}
		}
	}
	version := firstString(aux, "macOSProductVersion", "VERSION")
	build := firstString(aux, "macOSProductBuildVersion", "BUILD")
	return map[string]any{"title": title, "raw_title": rawTitle, "version": version, "build": build, "auxinfo": aux, "scripts": scripts, "localizations": localizations, "options": options}, nil
}
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}
func (s *scanner) text(name string) (string, error) {
	var b strings.Builder
	for {
		t, err := s.token()
		if err != nil {
			return "", err
		}
		if end(t, name) {
			return b.String(), nil
		}
		switch x := t.(type) {
		case xml.CharData:
			b.Write(x)
		case xml.Comment:
			continue
		default:
			return "", fmt.Errorf("softwareupdate: unexpected element in %s", name)
		}
	}
}
