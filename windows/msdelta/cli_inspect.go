package msdelta

import "fmt"

// CLISignatureReference identifies a metadata row referring to a signature
// overlapping an inspected source range. Row is one-based; Offset and Size
// describe the signature bytes, excluding the compressed blob-length prefix.
type CLISignatureReference struct {
	Table, Row, BlobIndex, Offset, Size int
}

// InspectCLISignatureReferences reports consumers in normalization order,
// retaining shared-blob references so their competing contexts are visible.
// It does not transform bytes or validate a reconstructed target.
func InspectCLISignatureReferences(source []byte, start, end int) ([]CLISignatureReference, error) {
	if start < 0 || end <= start || end > len(source) {
		return nil, fmt.Errorf("msdelta: invalid CLI signature inspection range")
	}
	pe, err := parsePELayout(source)
	if err != nil {
		return nil, err
	}
	if pe.directories[14].rva == 0 {
		return nil, nil
	}
	m, err := parseCLIMetadata(source, pe)
	if err != nil {
		return nil, err
	}
	return inspectCLISignatureReferences(source, m, start, end), nil
}

func inspectCLISignatureReferences(source []byte, m *cliMetadata, start, end int) []CLISignatureReference {
	var out []CLISignatureReference
	stream := m.Streams[2]
	limit := uint64(stream.Offset) + uint64(stream.Size)
	if limit > uint64(len(source)) {
		return nil
	}
	for table := range cliColumns {
		if !cliSignatureTable(table) {
			continue
		}
		for row := uint32(0); row < m.Rows[table]; row++ {
			off := m.tableOffsets[table] + int(row)*m.rowSizes[table]
			for _, kind := range m.columns(table) {
				width := m.columnWidth(kind)
				if kind == cliBlob {
					index := uint32(get16(source, off))
					if width == 4 {
						index = get32(source, off)
					}
					blob := uint64(stream.Offset) + uint64(index)
					if index != 0 && blob < limit {
						size, prefix := cliCompressed(source[blob:limit])
						payload := blob + uint64(prefix)
						if prefix != 0 && uint64(size) <= limit-payload && payload < uint64(end) && payload+uint64(size) > uint64(start) {
							out = append(out, CLISignatureReference{table, int(row) + 1, int(index), int(payload), int(size)})
						}
					}
				}
				off += width
			}
		}
	}
	return out
}
