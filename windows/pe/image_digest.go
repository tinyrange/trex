package pe

import (
	"encoding/binary"
	"fmt"
	"hash"
	"sort"
)

// ImageDigest writes the CBS HashTransforms.ImageDigest stream to h. Unlike
// Authenticode, this normalizes resource/debug layout, hashes only the DOS
// prefix, fixed NT header, rewritten section table and section bytes in table
// order, and excludes resource-directory bytes and .debug section content.
// Non-images are hashed verbatim. Recognizable malformed/unsupported images
// fail closed. Input and aggregate output are bounded to 512 MiB. Validation
// finishes before h is written; callers should provide a fresh hasher.
func ImageDigest(data []byte, h hash.Hash) error {
	const maximum = 512 << 20
	if h == nil || len(data) > maximum {
		return fmt.Errorf("image digest: invalid hasher or excessive input")
	}
	pe := 0
	if len(data) >= 2 && string(data[:2]) == "MZ" {
		if len(data) < 64 {
			return fmt.Errorf("image digest: truncated DOS header")
		}
		offset := uint64(binary.LittleEndian.Uint32(data[60:]))
		if offset < 64 || offset > uint64(len(data)) {
			return fmt.Errorf("image digest: invalid PE offset")
		}
		pe = int(offset)
	} else if len(data) < 4 || string(data[:4]) != "PE\x00\x00" {
		_, _ = h.Write(data)
		return nil
	}
	if pe > len(data)-24 || string(data[pe:pe+4]) != "PE\x00\x00" {
		return fmt.Errorf("image digest: invalid NT header")
	}
	optional := pe + 24
	optSize := int(binary.LittleEndian.Uint16(data[pe+20:]))
	if optSize < 2 || optSize > len(data)-optional {
		return fmt.Errorf("image digest: truncated optional header")
	}
	ntSize, directories := 0, 0
	switch binary.LittleEndian.Uint16(data[optional:]) {
	case 0x10b:
		ntSize, directories = 248, optional+96
	case 0x20b:
		ntSize, directories = 264, optional+112
	default:
		return fmt.Errorf("image digest: unsupported optional header")
	}
	if optSize != ntSize-24 || ntSize > len(data)-pe {
		return fmt.Errorf("image digest: unsupported NT header size")
	}
	if ntSize == 248 && data[optional+2] < 3 && data[optional+3] < 5 {
		return fmt.Errorf("image digest: unsupported old PE linker")
	}
	if binary.LittleEndian.Uint32(data[directories-4:]) < 6 {
		return fmt.Errorf("image digest: insufficient data directories")
	}
	count := int(binary.LittleEndian.Uint16(data[pe+6:]))
	table := optional + optSize
	if count == 0 || count > 4096 || count > (len(data)-table)/40 {
		return fmt.Errorf("image digest: invalid section count")
	}
	nt := append([]byte(nil), data[pe:pe+ntSize]...)
	headers := append([]byte(nil), data[table:table+40*count]...)
	u32 := func(p int) uint64 { return uint64(binary.LittleEndian.Uint32(data[p:])) }
	resource, resourceSize := u32(directories+16), u32(directories+20)
	relocation, relocationSize := u32(directories+40), u32(directories+44)
	type span struct{ start, end int }
	var sections, exclusions []span
	relocIndex, resourceIndex, debugIndex := -1, -1, -1
	var debugRVA uint64
	outputSize := uint64(pe + ntSize + 40*count)
	for i := 0; i < count; i++ {
		original := data[table+i*40 : table+(i+1)*40]
		header := headers[i*40 : (i+1)*40]
		va, vs := uint64(binary.LittleEndian.Uint32(original[12:])), uint64(binary.LittleEndian.Uint32(original[8:]))
		off, size := uint64(binary.LittleEndian.Uint32(original[20:])), uint64(binary.LittleEndian.Uint32(original[16:]))
		if off+size > uint64(len(data)) || (size != 0 && off < uint64(table+40*count)) {
			return fmt.Errorf("image digest: invalid section range")
		}
		outputSize += size
		if outputSize > maximum {
			return fmt.Errorf("image digest: excessive expanded stream")
		}
		sections = append(sections, span{int(off), int(off + size)})
		if relocationSize != 0 && va <= relocation && va+vs >= relocation+relocationSize {
			if relocIndex >= 0 {
				return fmt.Errorf("image digest: ambiguous relocation section")
			}
			relocIndex = i
		}
		if resourceSize != 0 && va <= resource && va+vs >= resource+resourceSize {
			if resourceIndex >= 0 {
				return fmt.Errorf("image digest: ambiguous resource section")
			}
			resourceIndex = i
			start := off + resource - va
			if start+resourceSize > off+size {
				return fmt.Errorf("image digest: resource outside raw section")
			}
			exclusions = append(exclusions, span{int(start), int(start + resourceSize)})
			clear(header[8:24])
		}
		if string(original[:7]) == ".debug\x00" {
			if debugIndex >= 0 {
				return fmt.Errorf("image digest: ambiguous debug section")
			}
			debugIndex = i
			debugRVA = uint64(binary.LittleEndian.Uint32(header[12:]))
			exclusions = append(exclusions, span{int(off), int(off + size)})
			clear(header[8:24])
		}
	}
	if resourceSize != 0 && resourceIndex < 0 {
		return fmt.Errorf("image digest: unmapped resource directory")
	}
	// Reject overlapping physical sections instead of hashing ambiguous aliases.
	physical := append([]span(nil), sections...)
	sort.Slice(physical, func(i, j int) bool { return physical[i].start < physical[j].start })
	end := 0
	for _, s := range physical {
		if s.start == s.end {
			continue
		}
		if s.start < end {
			return fmt.Errorf("image digest: overlapping sections")
		}
		end = s.end
	}
	zeroes := []int{optional + 8, optional + 56, optional + 64, directories + 16, directories + 20, directories + 32, directories + 36}
	if relocIndex >= 0 && (resource < relocation || (debugIndex >= 0 && debugRVA < relocation)) {
		zeroes = append(zeroes, directories+40)
		header := headers[relocIndex*40 : (relocIndex+1)*40]
		clear(header[12:16])
		clear(header[20:24])
	}
	for _, pos := range zeroes {
		clear(nt[pos-pe : pos-pe+4])
	}
	sort.Slice(exclusions, func(i, j int) bool { return exclusions[i].start < exclusions[j].start })
	_, _ = h.Write(data[:pe])
	_, _ = h.Write(nt)
	_, _ = h.Write(headers)
	for _, s := range sections {
		start := s.start
		for _, x := range exclusions {
			if x.start >= s.end || x.end <= start {
				continue
			}
			if x.start > start {
				_, _ = h.Write(data[start:x.start])
			}
			start = min(s.end, max(start, x.end))
		}
		_, _ = h.Write(data[start:s.end])
	}
	return nil
}
