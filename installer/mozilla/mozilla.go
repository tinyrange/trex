// Package mozilla reads the zlib-framed FILE resources of legacy Mozilla
// self-extracting installers. It does not execute their installation programs.
package mozilla

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/binary/pe"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
)

func init() { auto.Register("mozilla_sfx", 19, Open) }

// Open validates and decodes each FILE resource, retaining the declared names.
func Open(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
	if !bytes.HasPrefix(prefix, []byte("MZ")) {
		return nil, auto.ErrNoMatch
	}
	maximum := o.MaxEntries
	if maximum <= 0 {
		maximum = 100000
	}
	resources, err := pe.Resources(source, maximum)
	if err != nil {
		return nil, auto.ErrNoMatch
	}
	var entries []auto.Entry
	seen := map[string]bool{}
	remaining := o.MaxExpandedBytes
	if remaining <= 0 {
		remaining = 512 << 20
	}
	for _, resource := range resources {
		parts := strings.Split(resource.Path, "/")
		if len(parts) != 3 || parts[0] != "FILE" {
			continue
		}
		var h [8]byte
		if _, err := resource.Data.ReadAt(h[:], 0); err != nil {
			return nil, fmt.Errorf("mozilla: truncated FILE resource: %w", err)
		}
		packed, size := int64(binary.LittleEndian.Uint32(h[:])), int64(binary.LittleEndian.Uint32(h[4:]))
		if packed != resource.Data.Size()-8 {
			return nil, fmt.Errorf("mozilla: resource %s length mismatch", resource.Path)
		}
		if size > remaining {
			return nil, auto.ErrLimit
		}
		stream, err := zlib.NewReader(io.NewSectionReader(resource.Data, 8, packed))
		if err != nil {
			return nil, fmt.Errorf("mozilla: %s: %w", resource.Path, err)
		}
		data, err := io.ReadAll(io.LimitReader(stream, size+1))
		closeErr := stream.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(data)) != size {
			return nil, fmt.Errorf("mozilla: expanded length mismatch for %s", resource.Path)
		}
		if seen[parts[1]] {
			return nil, fmt.Errorf("mozilla: ambiguous resource language for %s", parts[1])
		}
		seen[parts[1]] = true
		remaining -= size
		entries = append(entries, auto.Entry{Name: parts[1], Kind: "file", Reader: &starfile.Bytes{Name: parts[1], Data: data}, Attributes: map[string]any{"resource_path": resource.Path, "packed_size": packed}})
	}
	if len(entries) == 0 {
		return nil, auto.ErrNoMatch
	}
	return auto.Tree(entries, o)
}
