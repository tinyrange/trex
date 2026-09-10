package msdelta

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

type peSection struct {
	name              [8]byte
	rawStart, rawSize uint32
	rva, virtualSize  uint32
	characteristics   uint32
	rawSizeOffset     uint32
	rawPointerOffset  uint32
}

type peDirectory struct {
	rva, size uint32
}

type peLayout struct {
	machine         uint16
	timestampOffset uint32
	imageBase       uint64
	imageBaseOffset uint32
	imageBaseSize   uint32
	checksumOffset  uint32
	headerSize      uint32
	imageSize       uint32
	fileAlignment   uint32
	directories     [16]peDirectory
	sections        []peSection
}

type peRestore struct {
	imageBase uint64
	checksum  uint32
	timestamp uint32
	managed   *CLIPreprocessInfo
}

type pePreprocess struct {
	prefix          peRestore
	targetRVAtoFile riftTable
	rebuildChecksum bool
	targetToSource  riftTable
}

// PETransformInfo describes one AMD64 relative-operand rewrite performed
// while normalizing a source image for a delta patch.
type PETransformInfo struct {
	RawStart, RawEnd               int
	InstructionRaw, InstructionRVA int
	InstructionLength, Field       int
	Old, Mapped                    int32
	Target                         int64
	TargetReachable, TargetMarked  bool
}

type peTransformTrace struct {
	events []PETransformInfo
}

// PERiftEntry describes one breakpoint in a PE preprocessing coordinate map.
// It is exposed for bounded format inspection; applying a delta continues to
// use the internal rift representation directly.
type PERiftEntry struct {
	Source int64
	Target int64
}

// PEPreprocessInfo is the parsed, read-only description of a PE preprocessing
// stream embedded in a PA30/PA31 record.
type PEPreprocessInfo struct {
	ImageBase         uint64
	Checksum          uint32
	Timestamp         uint32
	TargetRVAtoFile   []PERiftEntry
	SourceToTargetRVA []PERiftEntry
	Managed           *CLIPreprocessInfo
}

// InspectPEPreprocess parses the structural maps used by PE normalization.
func InspectPEPreprocess(preprocess []byte) (PEPreprocessInfo, error) {
	prefix, targetRVAtoFile, sourceToTargetRVA, err := parsePEPreprocess(preprocess)
	if err != nil {
		return PEPreprocessInfo{}, err
	}
	result := PEPreprocessInfo{
		Managed:   prefix.managed,
		ImageBase: prefix.imageBase, Checksum: prefix.checksum, Timestamp: prefix.timestamp,
		TargetRVAtoFile:   make([]PERiftEntry, len(targetRVAtoFile.entries)),
		SourceToTargetRVA: make([]PERiftEntry, len(sourceToTargetRVA.entries)),
	}
	for index, entry := range targetRVAtoFile.entries {
		result.TargetRVAtoFile[index] = PERiftEntry{Source: entry.source, Target: entry.target}
	}
	for index, entry := range sourceToTargetRVA.entries {
		result.SourceToTargetRVA[index] = PERiftEntry{Source: entry.source, Target: entry.target}
	}
	return result, nil
}

func preparePE(source, preprocess []byte, flags int64) ([]byte, *pePreprocess, error) {
	return preparePETraced(source, preprocess, flags, nil)
}

func preparePETraced(source, preprocess []byte, flags int64, trace *peTransformTrace) ([]byte, *pePreprocess, error) {
	layout, err := parsePELayout(source)
	if err != nil {
		return nil, nil, fmt.Errorf("msdelta: PE preprocessing source: %w", err)
	}
	prefix, targetRVAtoFile, sourceToTargetRVA, err := parsePEPreprocess(preprocess)
	if err != nil {
		return nil, nil, err
	}
	var managedSource *cliMetadata
	legacyCLI := uint64(flags)&(peTransformCLI4Metadata|peTransformCLI4Disasm) == 0
	if m := prefix.managed; m != nil {
		m.legacyGenericParam = legacyCLI
		if _, err := layoutCLIMetadata(m); err != nil {
			return nil, nil, err
		}
	}
	// Source CLI normalization is independent of target metadata eligibility.
	// Cross-type records can have either a native basis or no managed target
	// descriptor; the latter still normalizes the source's metadata RVAs.
	if directory := layout.directories[14]; directory.rva != 0 || directory.size != 0 {
		managedSource, err = parseCLIMetadata(source, layout)
		if err != nil {
			return nil, nil, err
		}
		if legacyCLI {
			// A valid modern image can exceed its tables stream when read
			// with legacy's extra GenericParam.Kind column. Native MSDelta
			// then uses a plain PE basis, not partial CLI normalization.
			managedSource.legacyGenericParam = true
			managedSource, _ = layoutCLIMetadata(managedSource.CLIPreprocessInfo)
		}
	}

	transformed := append([]byte(nil), source...)
	binary.LittleEndian.PutUint32(transformed[layout.checksumOffset:], 0)
	if err := transformPESourceTraced(transformed, layout, sourceToTargetRVA, uint64(flags), prefix, trace, managedSource); err != nil {
		return nil, nil, err
	}
	if managedSource != nil && uint64(flags)&(peTransformCLIDisasm|peTransformCLI4Disasm) != 0 {
		if err := transformCLIMethodTokens(transformed, source, layout, managedSource, prefix.managed); err != nil {
			return nil, nil, err
		}
	}
	if managedSource != nil && uint64(flags)&(peTransformCLIMetadata|peTransformCLI4Metadata) != 0 {
		// CLI normalization observes earlier PE transforms, including
		// unaligned apparent pointers inside metadata cells. Snapshot this
		// phase's input so shared signatures are still remapped only once.
		if err := transformCLIMetadata(transformed, bytes.Clone(transformed), managedSource, prefix.managed, sourceToTargetRVA); err != nil {
			return nil, nil, err
		}
	}

	fileToRVA := layout.fileToRVA()
	mapping := fileToRVA.multiply(sourceToTargetRVA).multiply(targetRVAtoFile).reverse()
	if managedSource != nil && prefix.managed != nil {
		cliMapping, err := cliCompressionRift(managedSource, prefix.managed, transformed)
		if err != nil {
			return nil, nil, err
		}
		mapping.entries = append(mapping.entries, cliMapping.entries...)
		sort.SliceStable(mapping.entries, func(i, j int) bool { return mapping.entries[i].source < mapping.entries[j].source })
	}
	result := &pePreprocess{
		prefix: prefix, targetRVAtoFile: targetRVAtoFile,
		rebuildChecksum: binary.LittleEndian.Uint32(source[layout.checksumOffset:]) != 0,
		targetToSource:  mapping,
	}
	return transformed, result, nil
}

func (layout peLayout) fileToRVA() riftTable {
	rift := riftTable{entries: []riftEntry{{source: 0, target: 0}}}
	for _, section := range layout.sections {
		if section.rawStart != 0 && section.rva != 0 {
			rift.entries = append(rift.entries, riftEntry{source: int64(section.rawStart), target: int64(section.rva)})
		}
	}
	sort.SliceStable(rift.entries, func(i, j int) bool { return rift.entries[i].source < rift.entries[j].source })
	return rift
}

func parsePEPreprocess(preprocess []byte) (peRestore, riftTable, riftTable, error) {
	bits, err := newBitReader(preprocess)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, fmt.Errorf("msdelta: PE preprocessing stream: %w", err)
	}
	low, err := bits.read(32)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, err
	}
	high, err := bits.read(32)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, err
	}
	checksum, err := bits.read(32)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, err
	}
	timestamp, err := bits.read(32)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, err
	}
	targetRVAtoFile, err := readRiftTable(bits)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, fmt.Errorf("msdelta: target PE rift: %w", err)
	}
	managed, err := readCLIPreprocessMetadata(bits)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, err
	}
	sourceToTargetRVA, err := readRiftTable(bits)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, fmt.Errorf("msdelta: source PE rift: %w", err)
	}
	managed, err = readCLIPreprocessMaps(bits, managed)
	if err != nil {
		return peRestore{}, riftTable{}, riftTable{}, err
	}
	if !bits.atEnd() {
		return peRestore{}, riftTable{}, riftTable{}, errors.New("msdelta: trailing PE preprocessing data")
	}
	return peRestore{imageBase: low | high<<32, checksum: uint32(checksum), timestamp: uint32(timestamp), managed: managed}, targetRVAtoFile, sourceToTargetRVA, nil
}

func parsePELayout(data []byte) (peLayout, error) {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return peLayout{}, errors.New("missing DOS header")
	}
	peOffset := binary.LittleEndian.Uint32(data[0x3c:])
	if uint64(peOffset)+24 > uint64(len(data)) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return peLayout{}, errors.New("missing PE header")
	}
	sectionCount := binary.LittleEndian.Uint16(data[peOffset+6:])
	optionalSize := binary.LittleEndian.Uint16(data[peOffset+20:])
	optionalOffset := peOffset + 24
	sectionOffset := optionalOffset + uint32(optionalSize)
	if uint64(sectionOffset)+uint64(sectionCount)*40 > uint64(len(data)) || optionalSize < 68 {
		return peLayout{}, errors.New("truncated PE headers")
	}
	layout := peLayout{
		machine:         binary.LittleEndian.Uint16(data[peOffset+4:]),
		timestampOffset: peOffset + 8,
		checksumOffset:  optionalOffset + 64,
		headerSize:      binary.LittleEndian.Uint32(data[optionalOffset+60:]),
		imageSize:       binary.LittleEndian.Uint32(data[optionalOffset+56:]),
		fileAlignment:   binary.LittleEndian.Uint32(data[optionalOffset+36:]),
	}
	var directoryOffset uint32
	switch binary.LittleEndian.Uint16(data[optionalOffset:]) {
	case 0x10b:
		layout.imageBaseOffset, layout.imageBaseSize = optionalOffset+28, 4
		layout.imageBase = uint64(binary.LittleEndian.Uint32(data[layout.imageBaseOffset:]))
		directoryOffset = optionalOffset + 96
	case 0x20b:
		layout.imageBaseOffset, layout.imageBaseSize = optionalOffset+24, 8
		layout.imageBase = binary.LittleEndian.Uint64(data[layout.imageBaseOffset:])
		directoryOffset = optionalOffset + 112
	default:
		return peLayout{}, errors.New("unsupported PE optional header")
	}
	if uint64(layout.checksumOffset)+4 > uint64(len(data)) || uint64(layout.imageBaseOffset)+uint64(layout.imageBaseSize) > uint64(len(data)) {
		return peLayout{}, errors.New("truncated PE normalization fields")
	}
	for index := range layout.directories {
		offset := directoryOffset + uint32(index)*8
		if offset+8 > sectionOffset || uint64(offset)+8 > uint64(len(data)) {
			break
		}
		layout.directories[index] = peDirectory{rva: binary.LittleEndian.Uint32(data[offset:]), size: binary.LittleEndian.Uint32(data[offset+4:])}
	}
	layout.sections = make([]peSection, 0, sectionCount)
	for index := range int(sectionCount) {
		offset := sectionOffset + uint32(index)*40
		section := peSection{
			virtualSize:      binary.LittleEndian.Uint32(data[offset+8:]),
			rva:              binary.LittleEndian.Uint32(data[offset+12:]),
			rawSize:          binary.LittleEndian.Uint32(data[offset+16:]),
			rawStart:         binary.LittleEndian.Uint32(data[offset+20:]),
			characteristics:  binary.LittleEndian.Uint32(data[offset+36:]),
			rawSizeOffset:    offset + 16,
			rawPointerOffset: offset + 20,
		}
		copy(section.name[:], data[offset:offset+8])
		layout.sections = append(layout.sections, section)
	}
	return layout, nil
}

func (layout peLayout) rawOffset(rva uint32) (int, bool) {
	if rva < layout.headerSize {
		return int(rva), int(rva) < int(layout.headerSize)
	}
	for _, section := range layout.sections {
		span := max(section.virtualSize, section.rawSize)
		if rva >= section.rva && uint64(rva) < uint64(section.rva)+uint64(span) {
			offset := uint64(section.rawStart) + uint64(rva-section.rva)
			return int(offset), offset < uint64(^uint(0)>>1)
		}
	}
	return 0, false
}

func (p *pePreprocess) mapSource(_ []byte, position int) (int, int, error) {
	mapped, end := p.targetToSource.segment(int64(position))
	span := int64(^uint(0) >> 1)
	if end != int64(^uint64(0)>>1) {
		span = end - int64(position)
	}
	if mapped < int64(-int(^uint(0)>>1)-1) || mapped > int64(^uint(0)>>1) || span <= 0 {
		return 0, 0, errors.New("mapped source position is out of range")
	}
	return int(mapped), int(span), nil
}

func (p *pePreprocess) restore(target []byte) error {
	// An empty target descriptor permits a PE-normalized basis to produce
	// an opaque, already-final target, even if that target is itself a PE.
	// HostCompute/Hyper-V LZMS binary deltas use this form. Zero fields are
	// not instructions to erase its headers or use RVA identity as layout.
	if p.prefix.imageBase == 0 && p.prefix.checksum == 0 && p.prefix.timestamp == 0 && p.prefix.managed == nil && len(p.targetRVAtoFile.entries) == 0 {
		return nil
	}
	layout, err := parsePELayout(target)
	if err != nil {
		return fmt.Errorf("msdelta: PE postprocessing: %w", err)
	}
	binary.LittleEndian.PutUint32(target[layout.timestampOffset:], p.prefix.timestamp)
	if layout.imageBaseSize == 4 {
		if p.prefix.imageBase > uint64(^uint32(0)) {
			return errors.New("msdelta: PE32 image base overflows 32 bits")
		}
		binary.LittleEndian.PutUint32(target[layout.imageBaseOffset:], uint32(p.prefix.imageBase))
	} else {
		binary.LittleEndian.PutUint64(target[layout.imageBaseOffset:], p.prefix.imageBase)
	}
	for index, section := range layout.sections {
		// A virtual-only section has no file extent to restore. Its mapped
		// RVA may coincide with the following initialized section; rounding
		// VirtualSize here would invent raw bytes and corrupt the PE checksum.
		if section.rawStart == 0 && section.rawSize == 0 {
			continue
		}
		rawStart := p.targetRVAtoFile.mapForward(int64(section.rva))
		if rawStart < 0 || rawStart > int64(^uint32(0)) {
			return errors.New("msdelta: target section offset is out of range")
		}
		rawSize := uint64(0)
		// Virtual-only sections also cannot delimit the preceding file extent.
		// Their RVAs have no entry in the file map; interpolating one can extend
		// the preceding section into the following section's on-disk bytes.
		for _, following := range layout.sections[index+1:] {
			if following.rawStart == 0 && following.rawSize == 0 {
				continue
			}
			next := p.targetRVAtoFile.mapForward(int64(following.rva))
			if next >= rawStart {
				rawSize = uint64(next - rawStart)
			}
			break
		}
		if rawSize == 0 && layout.fileAlignment != 0 {
			rawSize = (uint64(section.virtualSize) + uint64(layout.fileAlignment) - 1) / uint64(layout.fileAlignment) * uint64(layout.fileAlignment)
		}
		if rawSize > uint64(^uint32(0)) {
			return errors.New("msdelta: target section size is out of range")
		}
		binary.LittleEndian.PutUint32(target[section.rawPointerOffset:], uint32(rawStart))
		binary.LittleEndian.PutUint32(target[section.rawSizeOffset:], uint32(rawSize))
	}
	// Source preprocessing zeros this field. A nonzero decoded checksum is
	// therefore supplied by the patch and must be preserved, even when it is
	// not a valid PE checksum (for example in resource-only theme images).
	if get32(target, int(layout.checksumOffset)) != 0 {
		return nil
	}
	if p.rebuildChecksum {
		binary.LittleEndian.PutUint32(target[layout.checksumOffset:], 0)
		binary.LittleEndian.PutUint32(target[layout.checksumOffset:], peChecksum(target))
	} else {
		binary.LittleEndian.PutUint32(target[layout.checksumOffset:], p.prefix.checksum)
	}
	return nil
}

// restorePETimestamps restores source timestamp copies in native PE targets
// whose layout, image-base, and checksum fields are already final. It is used
// for direct LZMS payloads, not ordinary LZX targets or nested binary deltas.
// LZX targets already contain final timestamps, including debug-directory
// timestamps that may intentionally equal the source header's timestamp.
func restorePETimestamps(source, target []byte, targetTimestamp uint32) error {
	sourceLayout, err := parsePELayout(source)
	if err != nil {
		return fmt.Errorf("msdelta: LZMS PE source: %w", err)
	}
	sourceTimestamp := get32(source, int(sourceLayout.timestampOffset))
	if sourceTimestamp == 0 || sourceTimestamp == targetTimestamp {
		return nil
	}
	targetLayout, err := parsePELayout(target)
	if err != nil {
		return fmt.Errorf("msdelta: LZMS PE target: %w", err)
	}
	replace := func(offset int) {
		if get32(target, offset) == sourceTimestamp {
			put32(target, offset, targetTimestamp)
		}
	}
	targetHeaderHasSourceTimestamp := get32(target, int(targetLayout.timestampOffset)) == sourceTimestamp
	replace(int(targetLayout.timestampOffset))

	export := targetLayout.directories[0]
	if base, ok := targetLayout.rawOffset(export.rva); ok && export.rva != 0 && base+8 <= len(target) {
		replace(base + 4)
	}

	debug := targetLayout.directories[6]
	if base, ok := targetLayout.rawOffset(debug.rva); ok && debug.rva != 0 && base <= len(target) {
		const debugDirectorySize = 28
		count := min(int(debug.size)/debugDirectorySize, (len(target)-base)/debugDirectorySize)
		for index := range count {
			entry := base + index*debugDirectorySize
			replace(entry + 4)
			if !targetHeaderHasSourceTimestamp {
				continue
			}
			rawSize := uint64(get32(target, entry+16))
			rawStart := uint64(get32(target, entry+24))
			if rawStart > uint64(len(target)) || rawSize > uint64(len(target))-rawStart {
				continue
			}
			for offset, end := int(rawStart), int(rawStart+rawSize); offset+4 <= end; {
				if get32(target, offset) == sourceTimestamp {
					put32(target, offset, targetTimestamp)
					offset += 4
				} else {
					offset++
				}
			}
		}
	}
	return nil
}

func peChecksum(data []byte) uint32 {
	var sum uint64
	for offset := 0; offset < len(data); offset += 2 {
		value := uint16(data[offset])
		if offset+1 < len(data) {
			value |= uint16(data[offset+1]) << 8
		}
		sum = (sum & 0xffff) + uint64(value) + (sum >> 16)
	}
	sum = (sum & 0xffff) + (sum >> 16)
	sum += sum >> 16
	return uint32(sum&0xffff) + uint32(len(data))
}
