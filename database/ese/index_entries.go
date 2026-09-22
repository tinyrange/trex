package ese

import (
	"fmt"
	"strings"
)

// IndexEntry preserves the persisted normalized key and its data. Secondary
// index data is the primary-key bookmark; primary index data is a raw record.
type IndexEntry struct{ Key, Data []byte }

// IndexEntries reads a bounded sequence directly from an index B+tree. It does
// not re-normalize keys using the current operating system's locale tables.
func (d *Database) IndexEntries(tableName, indexName string, maximum int) ([]IndexEntry, error) {
	if maximum < 0 {
		return nil, fmt.Errorf("ese: maximum entries must be non-negative")
	}
	index, ok := d.byName[strings.ToLower(tableName)]
	if !ok {
		return nil, fmt.Errorf("ese: table %q not found", tableName)
	}
	root, ok := d.tables[index].indexRoots[strings.ToLower(indexName)]
	if !ok {
		return nil, fmt.Errorf("ese: index %q not found in %q", indexName, tableName)
	}
	entries := make([]IndexEntry, 0, min(maximum, 1024))
	if maximum == 0 {
		return entries, nil
	}
	limit := fmt.Errorf("entry limit reached")
	err := d.walkNodes(root, func(page page, value pageValue) error {
		if len(entries) >= maximum {
			return limit
		}
		prefix, err := d.pageValue(page, 0)
		if err != nil {
			return err
		}
		key, data, err := keyedEntry(value, prefix.data)
		if err != nil {
			return err
		}
		entries = append(entries, IndexEntry{Key: key, Data: append([]byte(nil), data...)})
		return nil
	})
	if err != nil && err != limit {
		return nil, err
	}
	return entries, nil
}
