package msdelta

import "fmt"

// CLIPreprocessInfo describes the managed part of the PE preprocessing stream.
// Heap order is #Strings, #US, #Blob, #GUID, #~. Maps use heap byte offsets
// except for #GUID and the metadata tables, which use one-based row indexes.
type CLIPreprocessInfo struct {
	MetadataPresent                           bool
	MetadataOffset, MetadataSize, MetadataRVA uint32
	StreamCount, StreamHeadersEnd             uint32
	Streams                                   [5]CLIStreamInfo
	HeapWidths                                [3]uint8 // #Strings, #GUID, #Blob
	ValidTables                               uint64
	Rows                                      [64]uint32
	HeapMaps                                  [4][]PERiftEntry
	TableMaps                                 [64][]PERiftEntry
	legacyGenericParam                        bool
}

// CLIStreamInfo is a managed stream's file-relative byte extent.
type CLIStreamInfo struct{ Offset, Size uint32 }

func readCLIPreprocessMetadata(bits *bitReader) (*CLIPreprocessInfo, error) {
	present, err := bits.read(1)
	if err != nil || present == 0 {
		return nil, err
	}
	m := &CLIPreprocessInfo{MetadataPresent: true}
	fields := []*uint32{&m.MetadataOffset, &m.MetadataSize, &m.MetadataRVA, &m.StreamCount, &m.StreamHeadersEnd}
	for i := range m.Streams {
		fields = append(fields, &m.Streams[i].Offset, &m.Streams[i].Size)
	}
	for _, field := range fields {
		x, err := bits.read(32)
		if err != nil {
			return nil, fmt.Errorf("msdelta: CLI metadata: %w", err)
		}
		*field = uint32(x)
	}
	for i := range m.HeapWidths {
		x, err := bits.read(1)
		if err != nil {
			return nil, err
		}
		m.HeapWidths[i] = 2 + 2*uint8(x)
	}
	m.ValidTables, err = bits.read(64)
	if err != nil {
		return nil, err
	}
	for i := range m.Rows {
		if m.ValidTables&(uint64(1)<<i) == 0 {
			continue
		}
		if i > 44 {
			return nil, fmt.Errorf("msdelta: unknown CLI metadata table %#x", i)
		}
		x, err := bits.read(32)
		if err != nil {
			return nil, err
		}
		m.Rows[i] = uint32(x)
	}
	if _, err := layoutCLIMetadata(m); err != nil {
		return nil, err
	}
	return m, nil
}

func readCLIPreprocessMaps(bits *bitReader, m *CLIPreprocessInfo) (*CLIPreprocessInfo, error) {
	present, err := bits.read(1)
	if err != nil || present == 0 {
		return m, err
	}
	if m == nil {
		m = &CLIPreprocessInfo{}
	}
	var formats [4]*intFormat
	for i := range formats {
		formats[i], err = readIntFormat(bits)
		if err != nil {
			return nil, fmt.Errorf("msdelta: CLI map format %d: %w", i, err)
		}
	}
	totalEntries := 0
	for i := 0; i < 68; i++ {
		a, b := formats[2], formats[3]
		if i < 3 {
			a, b = formats[0], formats[1]
		}
		r, err := readRiftWithFormats(bits, a, b)
		if err != nil {
			return nil, fmt.Errorf("msdelta: CLI map %d: %w", i, err)
		}
		totalEntries += len(r.entries)
		if totalEntries > maxRiftEntries {
			return nil, fmt.Errorf("msdelta: CLI maps exceed %d entries", maxRiftEntries)
		}
		entries := make([]PERiftEntry, len(r.entries))
		for j, e := range r.entries {
			entries[j] = PERiftEntry{Source: e.source, Target: e.target}
		}
		if i < 4 {
			m.HeapMaps[i] = entries
		} else {
			m.TableMaps[i-4] = entries
		}
	}
	return m, nil
}
