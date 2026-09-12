package aws

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("aws", 90, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		// AWS has no magic. Recognize the actual VM/370 volume-header record,
		// not arbitrary data that happens to resemble a six-byte block header.
		if len(p) < 9 || string(p[:6]) != "\x50\x00\x00\x00\xa0\x00" || string(p[6:9]) != "\xe5\xc8\xd9" {
			return nil, auto.ErrNoMatch
		}
		records, err := Open(adapter.File(r), o.MaxEntries)
		if err != nil {
			return nil, err
		}
		var entries []auto.Entry
		for i, record := range records {
			e := auto.Entry{Name: fmt.Sprintf("record-%d", i), Kind: "file", Attributes: map[string]any{"tape_mark": record.TapeMark, "offset": record.Offset, "blocks": record.Blocks}}
			if record.Data != nil {
				e.Reader = record.Data
			}
			entries = append(entries, e)
		}
		return auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil }), nil
	})
}
