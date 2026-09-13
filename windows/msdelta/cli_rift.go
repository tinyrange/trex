package msdelta

import (
	"bytes"
	"fmt"
)

// CLI stream and row maps are already target-file -> source-file copy
// coordinates. Overlay them after reversing the native PE coordinate chain.
func cliCompressionRift(source *cliMetadata, targetInfo *CLIPreprocessInfo, prepared []byte) (riftTable, error) {
	target, err := layoutCLIMetadata(targetInfo)
	if err != nil {
		return riftTable{}, err
	}
	var result riftTable
	zeroPair := -1
	appendMap := func(sourceOffset, targetOffset, sourceStride, targetStride int64, rows bool, entries []PERiftEntry) {
		if len(entries) == 0 {
			result.entries = append(result.entries, riftEntry{source: targetOffset, target: sourceOffset})
			return
		}
		firstSource := int64(0)
		if rows {
			firstSource = 1
		}
		if entries[0].Source > firstSource {
			// A missing initial breakpoint inherits the cyclic map's final
			// displacement. Materialize byte0 (or real RID1) so the preceding
			// stream/table cannot supply an unrelated byte displacement.
			last := entries[len(entries)-1]
			firstTarget := firstSource + last.Target - last.Source
			if firstTarget >= firstSource {
				result.entries = append(result.entries, riftEntry{source: targetOffset + (firstTarget-firstSource)*targetStride, target: sourceOffset})
			}
		}
		for index, entry := range entries {
			if entry.Source > int64(^uint32(0)) {
				break
			}
			a, b := entry.Source, entry.Target
			if rows {
				// RID0 describes the logical null mapping, not a row before
				// the table. Only its portion covering real rows contributes
				// copy coordinates. Otherwise it can overwrite the preceding
				// table's continuation in gaps before the first mapped row.
				if a == 0 {
					if index+1 < len(entries) && entries[index+1].Source <= 1 {
						continue
					}
					a++
					b++
				}
				a--
				b--
			}
			result.entries = append(result.entries, riftEntry{source: targetOffset + b*targetStride, target: sourceOffset + a*sourceStride})
		}
	}
	for i := 0; i < 4; i++ {
		if source.Streams[i].Size == 0 || target.Streams[i].Size == 0 {
			continue
		}
		stride := int64(1)
		if i == 3 {
			stride = 16
		}
		appendMap(int64(source.Streams[i].Offset), int64(target.Streams[i].Offset), stride, stride, i == 3, target.HeapMaps[i])
	}
	for table := range cliColumns {
		columns := source.columns(table)
		if source.Rows[table] == 0 || target.Rows[table] == 0 {
			continue
		}
		widthChanged := false
		for _, kind := range columns {
			if source.columnWidth(kind) != target.columnWidth(kind) {
				widthChanged = true
			}
		}
		if widthChanged {
			rowStart := len(result.entries)
			appendCell := func(targetOffset, sourceOffset int64) {
				if len(result.entries) > rowStart {
					last := result.entries[len(result.entries)-1]
					if last.target-last.source == sourceOffset-targetOffset {
						return
					}
				}
				result.entries = append(result.entries, riftEntry{source: targetOffset, target: sourceOffset})
			}
			// Rows no longer have a constant byte displacement when a heap or
			// coded-index width changes. Align each real row's cell starts in
			// the existing source representation with the target representation.
			// Widened high halves copy the first zero pair in the prepared
			// source. They must not continue into the next narrow source cell.
			remap := newCLIRemap(targetInfo)
			// Native's width-conversion row walk is upper-exclusive. A
			// final-row anchor would change continuation into unmapped target
			// rows (including rows of the following table).
			for row := uint32(1); row < source.Rows[table]; row++ {
				targetRow := cliMapIndex(remap.tables[table], row)
				if targetRow == 0 {
					continue
				}
				// Each row start must replace any prior table's anchor at the
				// same coordinate, even if the preceding row ended at this
				// displacement. Only redundant cells within a row are omitted.
				rowStart = len(result.entries)
				// A mapped row may extend past the declared target table. Its
				// copy coordinates still participate in the global rift, until
				// another table/heap supplies an overriding breakpoint.
				a := int64(source.tableOffsets[table]) + int64(row-1)*int64(source.rowSizes[table])
				b := int64(target.tableOffsets[table]) + int64(targetRow-1)*int64(target.rowSizes[table])
				for _, kind := range columns {
					sourceWidth, targetWidth := source.columnWidth(kind), target.columnWidth(kind)
					needed := 1
					if sourceWidth < targetWidth {
						needed++
					}
					if len(result.entries)+needed > maxRiftEntries {
						return riftTable{}, fmt.Errorf("msdelta: CLI column copy map exceeds %d entries", maxRiftEntries)
					}
					// Native emits displacement changes, not every column start.
					// Redundant cells would override another table's interleaved
					// anchors where mapped rows extend past their declared table.
					appendCell(b, a)
					if sourceWidth < targetWidth {
						if zeroPair < 0 {
							zeroPair = bytes.Index(prepared, []byte{0, 0})
							if zeroPair < 0 {
								return riftTable{}, fmt.Errorf("msdelta: CLI widening source has no zero pair")
							}
						}
						appendCell(b+int64(sourceWidth), int64(zeroPair))
					}
					a += int64(sourceWidth)
					b += int64(targetWidth)
				}
			}
			continue
		}
		appendMap(int64(source.tableOffsets[table]), int64(target.tableOffsets[table]), int64(source.rowSizes[table]), int64(target.rowSizes[table]), true, target.TableMaps[table])
	}
	return result, nil
}
