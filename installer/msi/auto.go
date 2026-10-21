package msi

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/archive/cfb"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

// The root storage CLSID distinguishes MSI from unrelated compound documents.
var packageClassID = [16]byte{0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}

func init() { auto.Register("msi", 9, openView) }

func openView(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
	if !bytes.HasPrefix(prefix, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}) {
		return nil, auto.ErrNoMatch
	}
	container, err := cfb.Open(adapter.File(source))
	if err != nil {
		// Generic CFB recognition owns structural errors until MSI is confirmed.
		return nil, auto.ErrNoMatch
	}
	if container.ClassID != packageClassID {
		return nil, auto.ErrNoMatch
	}
	// Browsing streams must not require decoding every database table or its
	// codepage. The raw CFB reader and the database API retain their exact names.
	return streamView(container, o)
}

func streamView(container *cfb.Archive, o auto.Options) (auto.View, error) {
	var entries []auto.Entry
	seen := map[string]bool{}
	for _, raw := range container.Files() {
		decoded := strings.TrimPrefix(DecodeStreamName(raw), "/")
		parts := strings.Split(decoded, "/")
		table := strings.HasPrefix(parts[len(parts)-1], "\u4840")
		for i, part := range parts {
			// Render the table marker visibly and escape literal '!' and '[' so table
			// streams, ordinary streams, and property streams remain distinguishable.
			var b strings.Builder
			for at, r := range part {
				if at == 0 && r == 0x4840 {
					b.WriteByte('!')
				} else if r < 32 || r == 127 || r == '!' || r == '[' || r == 0x4840 || part == "." || part == ".." {
					fmt.Fprintf(&b, "[U+%04X]", r)
				} else {
					b.WriteRune(r)
				}
			}
			parts[i] = b.String()
		}
		display := strings.Join(parts, "/")
		if seen[display] {
			return nil, fmt.Errorf("msi: ambiguous displayed stream name %q", display)
		}
		seen[display] = true
		entries = append(entries, auto.Entry{Name: display, Kind: "file", Reader: container.Lookup(raw), Attributes: map[string]any{"cfb_path": raw, "msi_stream_name": decoded, "msi_table": table}})
	}
	return auto.Tree(entries, o)
}
