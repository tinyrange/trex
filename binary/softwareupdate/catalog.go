// Package softwareupdate reads Apple's published software-update metadata.
// It never fetches URLs or executes Distribution JavaScript.
package softwareupdate

import (
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tinyrange/trex/binary/plist"
	"github.com/tinyrange/trex/storage"
)

const MaxCatalogBytes = 128 << 20
const MaxDistributionBytes = 8 << 20
const maxTokens = 4000000
const maxDepth = 128

func readSource(source storage.Reader, maximum int64) ([]byte, error) {
	if source == nil || source.Size() <= 0 || source.Size() > maximum {
		return nil, fmt.Errorf("softwareupdate: input size limit")
	}
	raw := make([]byte, int(source.Size()))
	_, err := io.ReadFull(io.NewSectionReader(source, 0, source.Size()), raw)
	return raw, err
}

// Catalog returns installer products in product-ID order. The original product
// dictionaries are preserved, including package hashes, sizes and URLs. XML
// catalogs are decoded one product at a time to avoid a whole-catalog plist tree.
// Gzip files are detected by their signature, not their URL or filename.
func Catalog(source storage.Reader) ([]map[string]any, error) {
	raw, err := readSource(source, MaxCatalogBytes)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		z, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		raw, err = io.ReadAll(io.LimitReader(z, MaxCatalogBytes+1))
		closeErr := z.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(raw) > MaxCatalogBytes {
			return nil, fmt.Errorf("softwareupdate: expanded catalog size limit")
		}
	}
	if bytes.HasPrefix(raw, []byte("bplist00")) {
		v, err := plist.Decode(raw)
		if err != nil {
			return nil, err
		}
		root, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("softwareupdate: expected catalog dictionary")
		}
		products, ok := root["Products"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("softwareupdate: missing Products dictionary")
		}
		result := []map[string]any{}
		keys := make([]string, 0, len(products))
		for k := range products {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, id := range keys {
			p, ok := products[id].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("softwareupdate: product %s is not a dictionary", id)
			}
			if installer(p) {
				result = append(result, map[string]any{"id": id, "metadata": p})
			}
		}
		return result, nil
	}
	s := scanner{raw: raw, d: xml.NewDecoder(bytes.NewReader(raw))}
	if err := s.start("plist"); err != nil {
		return nil, err
	}
	if err := s.start("dict"); err != nil {
		return nil, err
	}
	result := []map[string]any{}
	seen := map[string]bool{}
	found := false
	for {
		t, err := s.next()
		if err != nil {
			return nil, err
		}
		if end(t, "dict") {
			break
		}
		key, err := s.key(t)
		if err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("softwareupdate: duplicate catalog key %q", key)
		}
		seen[key] = true
		if key != "Products" {
			if _, err := s.value(); err != nil {
				return nil, err
			}
			continue
		}
		found = true
		if err := s.start("dict"); err != nil {
			return nil, err
		}
		ids := map[string]bool{}
		for {
			t, err := s.next()
			if err != nil {
				return nil, err
			}
			if end(t, "dict") {
				break
			}
			id, err := s.key(t)
			if err != nil {
				return nil, err
			}
			if ids[id] {
				return nil, fmt.Errorf("softwareupdate: duplicate product %q", id)
			}
			ids[id] = true
			fragment, err := s.value()
			if err != nil {
				return nil, err
			}
			if len(fragment) > MaxDistributionBytes {
				return nil, fmt.Errorf("softwareupdate: product %s size limit", id)
			}
			v, err := plist.Decode(append(append([]byte("<plist>"), fragment...), []byte("</plist>")...))
			if err != nil {
				return nil, fmt.Errorf("softwareupdate: product %s: %w", id, err)
			}
			p, ok := v.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("softwareupdate: product %s is not a dictionary", id)
			}
			if installer(p) {
				result = append(result, map[string]any{"id": id, "metadata": p})
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("softwareupdate: missing Products dictionary")
	}
	t, err := s.next()
	if err != nil || !end(t, "plist") {
		return nil, fmt.Errorf("softwareupdate: expected plist end")
	}
	if _, err := s.next(); err != io.EOF {
		return nil, fmt.Errorf("softwareupdate: trailing catalog content")
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["id"].(string) < result[j]["id"].(string) })
	return result, nil
}

func installer(p map[string]any) bool {
	info, _ := p["ExtendedMetaInfo"].(map[string]any)
	ids, _ := info["InstallAssistantPackageIdentifiers"].(map[string]any)
	os, _ := ids["OSInstall"].(string)
	shared, _ := ids["SharedSupport"].(string)
	return os == "com.apple.mpkg.OSInstall" || strings.HasPrefix(shared, "com.apple.pkg.InstallAssistant")
}

type scanner struct {
	raw    []byte
	d      *xml.Decoder
	tokens int
}

func (s *scanner) token() (xml.Token, error) {
	s.tokens++
	if s.tokens > maxTokens {
		return nil, fmt.Errorf("softwareupdate: XML token limit")
	}
	return s.d.Token()
}
func (s *scanner) next() (xml.Token, error) {
	for {
		t, err := s.token()
		if err != nil {
			return nil, err
		}
		switch x := t.(type) {
		case xml.Comment, xml.Directive, xml.ProcInst:
			continue
		case xml.CharData:
			if strings.TrimSpace(string(x)) == "" {
				continue
			}
			return nil, fmt.Errorf("softwareupdate: unexpected XML text")
		default:
			return t, nil
		}
	}
}
func end(t xml.Token, name string) bool {
	e, ok := t.(xml.EndElement)
	return ok && e.Name.Local == name && e.Name.Space == ""
}
func (s *scanner) start(name string) error {
	t, err := s.next()
	if err != nil {
		return err
	}
	e, ok := t.(xml.StartElement)
	if !ok || e.Name.Local != name || e.Name.Space != "" {
		return fmt.Errorf("softwareupdate: expected %s", name)
	}
	return nil
}
func (s *scanner) key(t xml.Token) (string, error) {
	e, ok := t.(xml.StartElement)
	if !ok || e.Name.Local != "key" || e.Name.Space != "" {
		return "", fmt.Errorf("softwareupdate: expected dictionary key")
	}
	var b strings.Builder
	for {
		t, err := s.token()
		if err != nil {
			return "", err
		}
		if end(t, "key") {
			return b.String(), nil
		}
		x, ok := t.(xml.CharData)
		if !ok {
			return "", fmt.Errorf("softwareupdate: malformed key")
		}
		b.Write(x)
	}
}
func (s *scanner) value() ([]byte, error) {
	start := s.d.InputOffset()
	t, err := s.next()
	if err != nil {
		return nil, err
	}
	if _, ok := t.(xml.StartElement); !ok {
		return nil, fmt.Errorf("softwareupdate: expected value")
	}
	depth := 1
	for depth > 0 {
		t, err := s.token()
		if err != nil {
			return nil, err
		}
		switch t.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
		}
		if depth > maxDepth {
			return nil, fmt.Errorf("softwareupdate: XML depth limit")
		}
	}
	return s.raw[start:s.d.InputOffset()], nil
}
